"""Validate bounded log receipts before projecting exact chunk bytes as text."""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import posixpath
import re

from .file_text import ENCODINGS, decode_range
from .log_protocol import (
    LOG_MODELS,
    MAX_LOG_FILE_BYTES,
    MAX_LOG_RESPONSE_BYTES,
    MAX_LOG_TEXT_JSON_BYTES,
    query_digest,
)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _same_path(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    module = ntpath if ntpath.splitdrive(right)[0] or "\\" in right else posixpath
    return module.normcase(module.normpath(left)) == module.normcase(module.normpath(right))


def _integer(value):
    return type(value) is int


def _bytes(result, maximum):
    encoded = result["data_b64"]
    if not isinstance(encoded, str) or len(encoded) > 4 * ((maximum + 2) // 3):
        raise ValueError("Oversized log byte receipt")
    raw = base64.b64decode(encoded, validate=True)
    if (len(raw) > maximum or base64.b64encode(raw).decode("ascii") != encoded
            or result.get("data_sha256") != hashlib.sha256(raw).hexdigest()):
        raise ValueError("Invalid log byte receipt")
    return raw


def _base(parameters, result):
    if (not isinstance(result, dict) or not _same_path(result.get("path"), parameters["path"])
            or not _digest(result.get("version")) or result.get("version_kind") != "stat-identity-size-times"
            or result.get("whole_file_sha256") is not False
            or not _integer(result.get("file_size_bytes"))
            or not 0 <= result["file_size_bytes"] <= MAX_LOG_FILE_BYTES
            or result.get("text_encoding") not in ENCODINGS or not _integer(result.get("bom_bytes"))
            or result["bom_bytes"] not in {0, 3 if result["text_encoding"] == "utf-8" else
                                          2 if result["text_encoding"].startswith("utf-16") else 0}
            or parameters["encoding"] != "auto" and parameters["encoding"] != result["text_encoding"]
            or len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")) > MAX_LOG_RESPONSE_BYTES):
        raise ValueError("Invalid log identity receipt")


def _read(parameters, result):
    raw = _bytes(result, parameters["limit"])
    start, end, size = result.get("offset"), result.get("next_offset"), result["file_size_bytes"]
    if (not all(_integer(value) for value in (start, end, result.get("size_bytes")))
            or not 0 <= start <= end <= size or end != start + len(raw)
            or result["size_bytes"] != len(raw) or type(result.get("eof")) is not bool
            or type(result.get("response_limited")) is not bool
            or result["eof"] != (end == size) or not raw and end != size
            or result.get("tail_bytes") != parameters["tail_bytes"]
            or parameters["expected_version"] is not None and parameters["expected_version"] != result["version"]):
        raise ValueError("Invalid log range")
    tail = parameters["tail_bytes"]
    if tail is None:
        if start != parameters["offset"]:
            raise ValueError("Unexpected log offset")
    else:
        requested = max(0, size - min(tail, parameters["limit"]))
        if not requested <= start <= min(size, requested + 3) or len(raw) > min(tail, parameters["limit"]):
            raise ValueError("Unexpected log tail")
    text, consumed = decode_range(raw, result["text_encoding"], result["bom_bytes"], start)
    if (consumed != len(raw)
            or len(json.dumps(text, ensure_ascii=True).encode("ascii")) > MAX_LOG_TEXT_JSON_BYTES
            or result["response_limited"] and (result["eof"] or len(raw) >= parameters["limit"])):
        raise ValueError("Incomplete log text")
    return text


def _context(parameters, result, row):
    if not isinstance(row, dict):
        raise ValueError("Invalid log match")
    raw = _bytes(row, 1024)
    fields = [row.get(key) for key in ("context_offset", "offset", "end_offset", "context_end_offset")]
    if (not all(_integer(value) for value in fields)
            or not 0 <= fields[0] <= fields[1] < fields[2] <= fields[3] <= result["scanned_to"]
            or fields[3] - fields[0] != len(raw)
            or type(row.get("context_before_truncated")) is not bool
            or type(row.get("context_after_truncated")) is not bool
            or row["context_before_truncated"] != (fields[0] > 0)
            or row["context_after_truncated"] != (fields[3] < result["file_size_bytes"])):
        raise ValueError("Invalid log match extent")
    codec = result["text_encoding"]
    text, consumed = decode_range(raw, codec, 0, fields[0])
    if consumed != len(raw):
        raise ValueError("Invalid context decoding")
    left = fields[1] - fields[0]
    right = fields[2] - fields[0]
    before = raw[:left].decode(codec)
    matched = raw[left:right].decode(codec)
    if ("\x00" in text or not matched or len(before.encode(codec)) != left
            or (matched != parameters["query"] if parameters["case_sensitive"]
                else matched.casefold() != parameters["query"].casefold())):
        raise ValueError("The returned context does not contain the requested literal")
    return text, len(before), len(before) + len(matched)


def _search(parameters, result):
    cursor, size = parameters["cursor"], result["file_size_bytes"]
    start, end, next_offset = result.get("start_offset"), result.get("scanned_to"), result.get("next_offset")
    digest = query_digest(parameters, result["text_encoding"])
    if (not all(_integer(value) for value in (start, end, next_offset, result.get("scanned_bytes")))
            or not 0 <= start <= next_offset <= end <= size
            or not 0 <= result["scanned_bytes"] <= parameters["scan_bytes"]
            or end - start > result["scanned_bytes"] + (result["bom_bytes"] if start == 0 else 0)
            or result.get("query_sha256") != digest
            or start != (cursor["offset"] if cursor else 0)
            or cursor is not None and (cursor["version"] != result["version"]
                                       or cursor["query_sha256"] != digest
                                       or cursor["encoding"] != result["text_encoding"])
            or type(result.get("eof")) is not bool or type(result.get("truncated")) is not bool
            or result["truncated"] == result["eof"]
            or result.get("stop_reason") not in {"complete", "byte_limit", "time_limit", "match_limit"}
            or result["eof"] != (result["stop_reason"] == "complete")
            or result["eof"] and (next_offset != size or end != size)
            or not result["eof"] and next_offset <= start):
        raise ValueError("Invalid log search continuation")
    expected = (None if result["eof"] else {"offset": next_offset, "version": result["version"],
                                           "query_sha256": digest, "encoding": result["text_encoding"]})
    if result.get("next_cursor") != expected:
        raise ValueError("Unexpected log search continuation")
    rows = result.get("matches")
    if not isinstance(rows, list) or len(rows) > parameters["max_matches"]:
        raise ValueError("Invalid log match count")
    if result["stop_reason"] == "match_limit" and len(rows) != parameters["max_matches"]:
        raise ValueError("Invalid match limit receipt")
    previous = start
    for row in rows:
        _context(parameters, result, row)
        if row["offset"] < previous:
            raise ValueError("Overlapping or repeated log match")
        previous = row["end_offset"]
    if rows and next_offset < rows[-1]["end_offset"]:
        raise ValueError("Continuation would repeat an existing match")


def valid_log_evidence(action, parameters, result):
    """No whole-file content claim: stat version plus exact returned chunk SHA."""
    try:
        parameters = LOG_MODELS[action].model_validate(parameters).model_dump()
        _base(parameters, result)
        if action == "log_read":
            _read(parameters, result)
        else:
            _search(parameters, result)
        return True
    except (ValueError, TypeError, KeyError, UnicodeError, OSError):
        return False


def readable_log_result(action, result):
    """Project a verified receipt; limited prefixes retain their real continuation."""
    value = dict(result)
    if action == "log_read":
        raw = _bytes(value, 65536)
        value["text"] = decode_range(raw, value["text_encoding"], value["bom_bytes"], value["offset"])[0]
        value.pop("data_b64")
        return value
    rows = []
    for original in value["matches"]:
        row = dict(original)
        raw = _bytes(row, 1024)
        codec = value["text_encoding"]
        text = raw.decode(codec)
        left, right = row["offset"] - row["context_offset"], row["end_offset"] - row["context_offset"]
        row["text"] = text
        row["match_start"] = len(raw[:left].decode(codec))
        row["match_end"] = len(raw[:right].decode(codec))
        row.pop("data_b64")
        rows.append(row)
    value["matches"] = rows
    return value
