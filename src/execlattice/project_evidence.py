"""Validate project results against the submitted operation before acceptance."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import ntpath
import posixpath
import re
import warnings
from datetime import datetime

from .development_protocol import (
    MAX_EDIT_FILE_BYTES,
    MAX_FILE_OPERATION_BYTES,
    MAX_READ_MANY_BYTES,
    MAX_READ_MANY_FILES,
    MAX_READ_MANY_RESPONSE_BYTES,
    MAX_READ_MANY_RESULT_BYTES,
    MAX_SOURCE_IMAGE_BYTES,
    MAX_SOURCE_IMAGE_PIXELS,
    MAX_WORKSPACE_IMAGE_BYTES,
)
from .file_text import ENCODINGS, decode_range, text_format


def _path(value):
    return isinstance(value, str) and len(value) <= 4096 and not any(ord(c) < 32 for c in value)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _directory_identity(value):
    return (isinstance(value, dict) and set(value) == {"device", "file"}
            and all(type(number) is int and 0 <= number < 2 ** 128 for number in value.values()))


def _module(value):
    return ntpath if ntpath.splitdrive(value)[0] or "\\" in value else posixpath


def _normal(value):
    if not _path(value):
        raise ValueError("Invalid path evidence")
    if not value:
        return ""
    module = _module(value)
    return module.normcase(module.normpath(value))


def _same(left, right):
    return _normal(left) == _normal(right)


def _descendant(path, root):
    module = _module(root)
    return not _same(path, root) and module.commonpath([_normal(path), _normal(root)]) == _normal(root)


def _bytes(result, prefix=""):
    encoded = result[prefix + ("_b64" if prefix else "content_b64")]
    content = base64.b64decode(encoded, validate=True)
    digest = result[prefix + ("_sha256" if prefix else "sha256")]
    if (base64.b64encode(content).decode("ascii") != encoded or len(content) > 65536
            or not _digest(digest) or hashlib.sha256(content).hexdigest() != digest):
        raise ValueError("Invalid byte evidence")
    return content


def verified_workspace_image(result: dict) -> bytes:
    """Verify a file preview separately from desktop frames; return JPEG bytes."""
    from PIL import Image

    if not isinstance(result, dict):
        raise ValueError("Invalid image preview receipt")
    encoded = result.get("image_b64")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_WORKSPACE_IMAGE_BYTES + 2) // 3):
        raise ValueError("Invalid image preview bytes")
    raw = base64.b64decode(encoded, validate=True)
    width, height = result.get("width"), result.get("height")
    source_width, source_height = result.get("source_width"), result.get("source_height")
    if (not _path(result.get("path")) or not result["path"] or result.get("artifact_type") != "image"
            or not 1 <= len(raw) <= MAX_WORKSPACE_IMAGE_BYTES
            or base64.b64encode(raw).decode("ascii") != encoded
            or result.get("mime_type") != "image/jpeg"
            or not _digest(result.get("image_sha256"))
            or hashlib.sha256(raw).hexdigest() != result["image_sha256"]
            or not _digest(result.get("source_file_sha256"))
            or type(result.get("source_size_bytes")) is not int
            or not 1 <= result["source_size_bytes"] <= MAX_SOURCE_IMAGE_BYTES
            or any(type(value) is not int or not 1 <= value <= 1280 for value in (width, height))
            or any(type(value) is not int or not 1 <= value <= 32768 for value in (source_width, source_height))
            or source_width * source_height > MAX_SOURCE_IMAGE_PIXELS
            or result.get("source_format") not in {"PNG", "JPEG", "GIF", "WEBP", "BMP", "TIFF"}
            or type(result.get("frame_index")) is not int or result["frame_index"] != 0
            or result.get("control_ready") is not False
            or any(key in result for key in ("frame_id", "window_id", "bounds", "keyboard_ready", "capture_method"))):
        raise ValueError("Invalid image preview receipt")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as image:
                if image.format != "JPEG" or image.size != (width, height):
                    raise ValueError("Invalid image preview dimensions")
                image.load()
        observed = datetime.fromisoformat(result.get("observed_at", ""))
        if observed.tzinfo is None:
            raise ValueError("Image observation must be timezone aware")
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, OSError, SyntaxError, TypeError):
        raise ValueError("Invalid image preview") from None
    return raw


def _range_evidence(parameters, result):
    raw = base64.b64decode(result["data_b64"], validate=True)
    if (len(raw) > parameters.get("limit", 65536)
            or base64.b64encode(raw).decode("ascii") != result["data_b64"]
            or result.get("data_sha256") != hashlib.sha256(raw).hexdigest()
            or not _digest(result.get("sha256"))
            or parameters.get("expected_sha256") is not None
            and result["sha256"] != parameters["expected_sha256"]):
        return False
    offset, end, size = result.get("offset"), result.get("next_offset"), result.get("file_size_bytes")
    if (any(type(value) is not int for value in (offset, end, size, result.get("size_bytes")))
            or not 0 <= offset <= end <= size <= MAX_EDIT_FILE_BYTES
            or offset != parameters.get("offset", 0) or end != offset + len(raw)
            or result["size_bytes"] != len(raw) or type(result.get("eof")) is not bool
            or result["eof"] != (end == size) or not raw and not result["eof"]
            or offset == 0 and result["eof"] and result["sha256"] != result["data_sha256"]):
        return False
    encoding, bom = result.get("text_encoding"), result.get("bom_bytes")
    if type(bom) is not int:
        return False
    requested = parameters.get("encoding", "auto")
    if requested != "auto" and requested != encoding:
        return False
    if encoding == "binary":
        return requested == "binary" and bom == 0
    if encoding not in ENCODINGS:
        return False
    _, consumed = decode_range(raw, encoding, bom, offset)
    return consumed == len(raw)


def readable_many_result(result):
    """Project already verified batch bytes as text without changing receipts."""
    rows = []
    for original in result["files"]:
        row = dict(original)
        if row["state"] == "succeeded":
            value = dict(row["result"])
            raw = base64.b64decode(value.pop("content_b64"), validate=True)
            value["content"], _ = decode_range(raw, value["text_encoding"], value["bom_bytes"], 0)
            value["encoding"] = "text"
            row["result"] = value
        elif isinstance(row.get("error"), dict):
            row["error"] = dict(row["error"])
        rows.append(row)
    return {**result, "files": rows}


def _many_evidence(parameters, result):
    requests, rows = parameters["files"], result.get("files")
    if (set(result) != {"files", "total_read_bytes", "returned_bytes", "complete"}
            or not isinstance(rows, list) or not 1 <= len(rows) == len(requests) <= MAX_READ_MANY_FILES
            or any(type(result.get(key)) is not int for key in ("total_read_bytes", "returned_bytes"))
            or not 0 <= result["returned_bytes"] <= result["total_read_bytes"] <= MAX_READ_MANY_BYTES
            or type(result.get("complete")) is not bool
            or len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_READ_MANY_RESPONSE_BYTES):
        return False
    returned = 0
    for request, row in zip(requests, rows, strict=True):
        if (not isinstance(row, dict) or set(row) != {"path", "state", "result", "error"}
                or not _same(request["path"], row["path"])):
            return False
        if row["state"] == "failed":
            error = row["error"]
            if (row["result"] is not None or not isinstance(error, dict) or set(error) != {"code", "message"}
                    or error["code"] not in {"BATCH_READ_LIMIT", "FILE_TOO_LARGE", "FILE_NOT_TEXT", "RESULT_LIMIT",
                                             "NOT_A_FILE", "POLICY_DENIED", "FILE_NOT_FOUND", "ACCESS_DENIED", "FILESYSTEM_ERROR"}
                    or not isinstance(error["message"], str) or not 1 <= len(error["message"]) <= 200):
                return False
            continue
        value = row["result"]
        if (row["state"] != "succeeded" or row["error"] is not None or not isinstance(value, dict)
                or set(value) != {"content_b64", "encoding", "text_encoding", "bom_bytes", "size_bytes", "sha256"}
                or value["encoding"] != "base64" or type(value["size_bytes"]) is not int
                or type(value["bom_bytes"]) is not int):
            return False
        raw = _bytes(value)
        encoding, bom = text_format(raw, request.get("encoding", "auto"))
        _, consumed = decode_range(raw, encoding, bom, 0)
        if (len(raw) != value["size_bytes"] or consumed != len(raw)
                or value["text_encoding"] != encoding or value["bom_bytes"] != bom):
            return False
        returned += len(raw)
    return (returned == result["returned_bytes"]
            and result["complete"] == all(row["state"] == "succeeded" for row in rows)
            and len(json.dumps(readable_many_result(result), ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")) <= MAX_READ_MANY_RESULT_BYTES)


def _patch_error(value):
    return (value is None or isinstance(value, dict) and set(value) == {"code", "message"}
            and isinstance(value["code"], str) and re.fullmatch(r"[A-Z_]{1,64}", value["code"]) is not None
            and isinstance(value["message"], str) and 1 <= len(value["message"]) <= 200)


def _patch_evidence(task, result):
    """A valid receipt can describe partial/unknown work; never infer completion from task success."""
    parameters = task["parameters"]
    rows = result.get("files")
    if (set(result) != {"patch_id", "request_sha256", "state", "complete", "files", "error"}
            or result.get("patch_id") != parameters.get("patch_id")
            or not isinstance(result["patch_id"], str) or re.fullmatch(r"[0-9a-f]{32}", result["patch_id"]) is None
            or not _digest(result.get("request_sha256"))
            or result.get("state") not in {"applied", "preflight_failed", "partial", "unknown"}
            or type(result.get("complete")) is not bool
            or result["complete"] != (result["state"] == "applied")
            or not _patch_error(result.get("error"))
            or not isinstance(rows, list) or not 1 <= len(rows) <= 8
            or len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 32768):
        return False
    requests = None
    if task["action"] == "patch_status" and set(parameters) != {"patch_id"}:
        return False
    if task["action"] == "apply_patch":
        if task.get("input_text_omitted") is True:
            if (set(parameters) != {"patch_id", "request_sha256", "files"}
                    or not _digest(parameters["request_sha256"])):
                return False
            digest, requests = parameters["request_sha256"], parameters["files"]
            if (not isinstance(requests, list) or not 1 <= len(requests) <= 8
                    or any(not isinstance(item, dict)
                           or set(item) != {"path", "expected_sha256", "encoding", "edit_count"}
                           or not _path(item["path"]) or not item["path"]
                           or not _digest(item["expected_sha256"])
                           or item["encoding"] not in {"auto", *ENCODINGS}
                           or type(item["edit_count"]) is not int or not 1 <= item["edit_count"] <= 16
                           for item in requests)
                    or sum(item["edit_count"] for item in requests) > 64):
                return False
        else:
            from .development_protocol import WorkspaceApplyPatchParameters
            from .project_patch import patch_request_sha256

            values = WorkspaceApplyPatchParameters.model_validate(parameters).model_dump()
            digest = patch_request_sha256(values)
            requests = [{**item, "edit_count": len(item["edits"])} for item in values["files"]]
        if result["request_sha256"] != digest or len(rows) != len(requests):
            return False
    names, total_hunks = set(), 0
    for index, row in enumerate(rows):
        if (not isinstance(row, dict)
                or set(row) != {"path", "state", "expected_sha256", "result_sha256", "edits_applied", "error"}
                or not _path(row["path"]) or not row["path"] or row["path"] in names
                or not _digest(row["expected_sha256"])
                or row["state"] not in {"pending", "applied", "failed", "not_applied", "unknown"}
                or type(row["edits_applied"]) is not int or not 0 <= row["edits_applied"] <= 16
                or not _patch_error(row["error"])):
            return False
        names.add(row["path"])
        total_hunks += row["edits_applied"]
        if requests is not None:
            request = requests[index]
            if (not _same(row["path"], request["path"]) or row["expected_sha256"] != request["expected_sha256"]
                    or row["state"] == "applied" and row["edits_applied"] != request["edit_count"]):
                return False
        if row["state"] == "applied":
            if not _digest(row["result_sha256"]) or row["edits_applied"] < 1 or row["error"] is not None:
                return False
        elif row["result_sha256"] is not None or row["edits_applied"] != 0:
            return False
        if (row["state"] == "failed" and row["error"] is None
                or row["state"] in {"pending", "not_applied"} and row["error"] is not None):
            return False
    if total_hunks > 64 or sum(len(path.encode("utf-8")) for path in names) > 8192:
        return False
    states = [row["state"] for row in rows]
    if result["state"] == "applied":
        return all(state == "applied" for state in states) and result["error"] is None
    if result["error"] is None:
        return False
    if result["state"] == "preflight_failed":
        return "failed" in states and all(state in {"failed", "not_applied"} for state in states)
    if result["state"] == "partial":
        return "applied" in states and any(state != "applied" for state in states) and "pending" not in states
    return any(state != "applied" for state in states)


def valid_success_evidence(task: dict, result: dict) -> bool:
    try:
        if not isinstance(result, dict):
            return False
        if task["executor_type"] == "development":
            from .development_progress import valid_development_result

            capture = result.get("output_capture")
            return (valid_development_result(result) and result["exit_code"] == 0
                    and (capture is None or capture["source_kind"] == "task"
                         and capture["source_id"] == task.get("task_id")))
        action, parameters = task["action"], task["parameters"]
        if action in {"log_read", "log_search"}:
            from .log_evidence import valid_log_evidence

            return valid_log_evidence(action, parameters, result)
        if action in {"apply_patch", "patch_status"}:
            return _patch_evidence(task, result)
        if action == "read_many":
            return _many_evidence(parameters, result)
        if "directory_identity" in result and not _directory_identity(result["directory_identity"]):
            return False
        if "skipped_entries" in result and (type(result["skipped_entries"]) is not int
                                             or not 0 <= result["skipped_entries"] <= 20000):
            return False
        if not _path(result.get("path")):
            return False
        requested = parameters["path"]
        if requested and not _same(result["path"], requested):
            return False
        if action == "stat":
            kind = result.get("kind")
            return (type(result.get("modified_ns")) is int
                    and ("path_version" not in result or _digest(result["path_version"]))
                    and (kind == "directory" and result.get("size_bytes") is None and result.get("sha256") is None
                         or kind == "file" and type(result.get("size_bytes")) is int
                         and 0 <= result["size_bytes"] <= MAX_FILE_OPERATION_BYTES and _digest(result.get("sha256"))))
        if action == "mkdir":
            return (result.get("kind") == "directory" and type(result.get("created")) is bool
                    and (result["created"] is True or parameters.get("exist_ok", False) is True))
        if action == "delete":
            return (result.get("kind") in {"file", "directory"} and result.get("deleted") is True
                    and result.get("recursive") is False and _digest(result.get("previous_version"))
                    and result["previous_version"] == parameters["expected_version"])
        if action == "rename":
            module = _module(requested)
            return (result.get("kind") in {"file", "directory"} and result.get("renamed") is True
                    and result.get("source_removed") is True and _path(result.get("destination"))
                    and _same(result["destination"], parameters["destination"])
                    and not _same(requested, result["destination"])
                    and _same(module.dirname(requested), module.dirname(result["destination"]))
                    and _digest(result.get("previous_version")) and result["previous_version"] == parameters["expected_version"]
                    and _digest(result.get("path_version")) and result["path_version"] != result["previous_version"]
                    and (result["kind"] == "file" and _digest(result.get("sha256"))
                         and type(result.get("size_bytes")) is int and 0 <= result["size_bytes"] <= MAX_FILE_OPERATION_BYTES
                         or result["kind"] == "directory" and result.get("sha256") is None and result.get("size_bytes") is None
                         and _directory_identity(result.get("directory_identity"))))
        if action in {"copy", "move"}:
            common = (_path(result.get("destination")) and _same(result["destination"], parameters["destination"])
                      and not _same(result["path"], result["destination"])
                      and type(result.get("size_bytes")) is int
                      and 0 <= result["size_bytes"] <= MAX_FILE_OPERATION_BYTES
                      and _digest(result.get("sha256")) and result["sha256"] == parameters["expected_sha256"]
                      and type(result.get("created")) is bool)
            if action == "move":
                return common and result["created"] is True and result.get("source_removed") is True
            expected_target = parameters.get("expected_target_sha256")
            return (common and result.get("source_preserved") is True
                    and result["created"] == (expected_target is None)
                    and result.get("previous_target_sha256") == expected_target)
        if action == "read_image":
            verified_workspace_image(result)
            return (result["width"] <= parameters.get("max_width", 1280)
                    and result["height"] <= parameters.get("max_height", 1280)
                    and (parameters.get("expected_sha256") is None
                         or result["source_file_sha256"] == parameters["expected_sha256"]))
        if action == "read_range":
            return _range_evidence(parameters, result)
        if action == "edit":
            return (type(result.get("size_bytes")) is int and 0 <= result["size_bytes"] <= MAX_EDIT_FILE_BYTES
                    and _digest(result.get("sha256"))
                    and result.get("previous_sha256") == parameters["expected_sha256"]
                    and type(result.get("replacements")) is int and result["replacements"] == 1
                    and result.get("created") is False and result.get("text_encoding") in ENCODINGS
                    and parameters.get("encoding", "auto") in {"auto", result["text_encoding"]})
        if action == "read":
            content = _bytes(result)
            content.decode("utf-8-sig")
            return (type(result.get("size_bytes")) is int and len(content) == result["size_bytes"]
                    and b"\x00" not in content and result.get("encoding") == "base64"
                    and result.get("text_encoding") == "utf-8")
        if action == "write":
            content = base64.b64decode(parameters["content_b64"], validate=True)
            return (type(result.get("size_bytes")) is int and result["size_bytes"] == len(content)
                    and result.get("sha256") == hashlib.sha256(content).hexdigest()
                    and type(result.get("created")) is bool
                    and result["created"] == (parameters.get("expected_sha256") is None))
        if type(result.get("truncated")) is not bool:
            return False
        if action == "list_page":
            legacy = {**task, "action": "list"}
            if not valid_success_evidence(legacy, result):
                return False
            start, total = result.get("page_start"), result.get("snapshot_total")
            snapshot, cursor = result.get("snapshot_id"), result.get("next_cursor")
            complete = result.get("scan_complete")
            if (type(start) is not int or type(total) is not int or type(complete) is not bool
                    or not 0 <= start <= start + len(result["entries"]) <= total <= 20000):
                return False
            if not requested:
                return (snapshot is None and cursor is None and start == 0 and complete
                        and total == len(result["entries"]) and parameters.get("cursor") is None)
            if (not isinstance(snapshot, str) or re.fullmatch(r"[0-9a-f]{32}", snapshot) is None
                    or not _directory_identity(result.get("directory_identity"))):
                return False
            previous = parameters.get("cursor")
            if previous is None:
                if start != 0:
                    return False
            elif previous != f"{snapshot}:{start}":
                return False
            end = start + len(result["entries"])
            return (cursor == (f"{snapshot}:{end}" if end < total else None)
                    and (end == total or end > start)
                    and result["truncated"] == (end < total or not complete))
        if action == "list":
            entries = result.get("entries")
            if not requested:
                return (result["path"] == "" and result.get("parent") is None and isinstance(entries, list)
                        and len(entries) <= 26 and result["truncated"] is False
                        and all(isinstance(e, dict) and e.get("kind") == "drive"
                                and _same(e.get("name"), e.get("path")) and _path(e.get("path"))
                                and _module(e["path"]).isabs(e["path"])
                                and _same(_module(e["path"]).dirname(e["path"]), e["path"])
                                and e.get("size_bytes") is None and e.get("modified_ns") is None for e in entries))
            module = _module(requested)
            expected_parent = module.dirname(module.normpath(requested))
            expected_parent = "" if _same(expected_parent, requested) else expected_parent
            return (isinstance(entries, list) and len(entries) <= parameters.get("limit", 300)
                    and _same(result.get("parent"), expected_parent)
                    and all(isinstance(e, dict) and _path(e.get("path")) and _path(e.get("name"))
                            and e.get("kind") in {"directory", "file"}
                            and e["name"] not in {"", ".", ".."} and "/" not in e["name"] and "\\" not in e["name"]
                            and _same(e["path"], module.join(requested, e["name"]))
                            and (e.get("size_bytes") is None and e["kind"] != "file"
                                 or type(e.get("size_bytes")) is int and e["size_bytes"] >= 0)
                            and (e.get("modified_ns") is None and e["kind"] == "drive"
                                 or type(e.get("modified_ns")) is int) for e in entries))
        if action in {"search_page", "search_native_page"}:
            native = action == "search_native_page"
            if native and (result.get("backend") != "ripgrep"
                    or result.get("pattern_type") != parameters.get("pattern_type", "literal")
                    or result.get("scan_accounting") != "validated_candidate_upper_bounds"):
                return False
            if not valid_success_evidence({**task, "action": "search"}, result):
                return False
            start, total = result.get("page_start"), result.get("snapshot_total")
            identifier, cursor = result.get("snapshot_id"), result.get("next_cursor")
            complete, reason = result.get("search_complete"), result.get("stop_reason")
            if (type(start) is not int or type(total) is not int or type(complete) is not bool
                    or not 0 <= start <= start + len(result["matches"]) <= total <= 20000
                    or not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{32}", identifier) is None
                    or reason not in ({"complete", "directory_limit", "file_limit", "byte_limit", "time_limit",
                                       "cache_limit", "match_limit", "entry_limit"}
                                      | ({"backend_output_limit"} if native else set()))
                    or complete != (reason == "complete")
                    or type(result.get("scanned_directories")) is not int or not 0 <= result["scanned_directories"] <= 2000
                    or type(result.get("scanned_bytes")) is not int or not 0 <= result["scanned_bytes"] <= 16 * 1024 * 1024
                    or not 0 <= result["scanned_files"] <= 10000
                    or not all(_digest(row.get("file_sha256")) for row in result["matches"])):
                return False
            previous = parameters.get("cursor")
            if previous is None and start != 0 or previous is not None and previous != f"{identifier}:{start}":
                return False
            end = start + len(result["matches"])
            return (cursor == (f"{identifier}:{end}" if end < total else None)
                    and (end == total or end > start)
                    and result["truncated"] == (end < total or not complete))
        if action == "search":
            matches = result.get("matches")
            return (isinstance(matches, list) and len(matches) <= parameters.get("max_results", 100)
                    and type(result.get("scanned_files")) is int and result["scanned_files"] >= 0
                    and type(result.get("skipped_files")) is int and result["skipped_files"] >= 0
                    and all(isinstance(m, dict) and _path(m.get("path"))
                            and _descendant(m["path"], requested)
                            and type(m.get("line_number")) is int and m["line_number"] >= 1
                            and isinstance(m.get("line"), str) and len(m["line"]) <= 4096 for m in matches))
        return False
    except (KeyError, TypeError, ValueError, UnicodeError, OSError):
        return False
