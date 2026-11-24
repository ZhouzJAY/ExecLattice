"""Verify bounded localhost HTTP receipts against the original request."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime

from .localhost_protocol import (
    HEADER_NAME,
    MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HEADERS,
    request_body,
    validate_localhost_parameters,
)

_RESULT_FIELDS = frozenset({"scheme", "host", "port", "path", "method", "status_code", "headers",
                            "body_b64", "body_sha256", "body_bytes", "body_text", "body_complete", "truncated",
                            "content_encoding", "request_body_bytes", "request_body_sha256", "request_sent",
                            "response_received", "redirect_followed", "retry_count", "observed_at"})


def verified_localhost_body(result):
    if not isinstance(result, dict):
        raise ValueError("Invalid local HTTP body receipt")
    encoding = result.get("content_encoding")
    if (not isinstance(encoding, str) or not encoding or len(encoding) > MAX_HTTP_HEADER_BYTES
            or any(not 32 <= ord(char) <= 126 for char in encoding) or encoding != encoding.lower()
            or "body_text" not in result):
        raise ValueError("Invalid local HTTP encoding receipt")
    encoded = result.get("body_b64")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((65536 + 2) // 3):
        raise ValueError("Invalid local HTTP body receipt")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid local HTTP body receipt") from None
    if (len(raw) > 65536 or base64.b64encode(raw).decode("ascii") != encoded
            or type(result.get("body_bytes")) is not int or result["body_bytes"] != len(raw)
            or result.get("body_sha256") != hashlib.sha256(raw).hexdigest()):
        raise ValueError("Invalid local HTTP body receipt")
    expected = None
    if (result.get("content_encoding") == "identity"
            and not any(byte < 32 and byte not in {9, 10, 13} or byte == 127 for byte in raw)):
        try:
            expected = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            pass
    if result.get("body_text") != expected:
        raise ValueError("Invalid local HTTP text receipt")
    return raw


def valid_localhost_evidence(task, result):
    try:
        if (not isinstance(result, dict) or set(result) != _RESULT_FIELDS
                or task["executor_type"] != "localhost"):
            return False
        parameters = validate_localhost_parameters(task["action"], task["parameters"])
        if any(result.get(key) != parameters[key] for key in ("scheme", "host", "port", "path", "method")):
            return False
        if (type(result.get("port")) is not int or type(result.get("status_code")) is not int
                or not 200 <= result["status_code"] <= 599 or result.get("request_sent") is not True
                or result.get("response_received") is not True or result.get("redirect_followed") is not False
                or type(result.get("retry_count")) is not int or result["retry_count"] != 0
                or type(result.get("truncated")) is not bool or type(result.get("body_complete")) is not bool
                or result["body_complete"] == result["truncated"]):
            return False
        headers = result.get("headers")
        if not isinstance(headers, list) or len(headers) > MAX_HTTP_HEADERS:
            return False
        size, encodings, lengths, transfers = 0, [], [], []
        for pair in headers:
            if not isinstance(pair, list) or len(pair) != 2:
                return False
            name, value = pair
            if (not isinstance(name, str) or not HEADER_NAME.fullmatch(name) or not isinstance(value, str)
                    or any(ord(char) < 32 and char != "\t" or ord(char) == 127 or ord(char) > 255 for char in value)):
                return False
            size += len(name) + len(value) + 4
            if name.casefold() == "content-encoding":
                encodings.append(value)
            elif name.casefold() == "content-length":
                lengths.append(value)
            elif name.casefold() == "transfer-encoding":
                transfers.append(value)
        if size > MAX_HTTP_HEADER_BYTES or result.get("content_encoding") != ", ".join(encodings or ["identity"]).strip().lower():
            return False
        if (len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
                or lengths and not re.fullmatch(r"[0-9]{1,20}", lengths[0])
                or transfers and transfers[0].lower() != "chunked"):
            return False
        raw, sent = verified_localhost_body(result), request_body(parameters["body_b64"])
        if (len(raw) > parameters["max_response_bytes"]
                or result["truncated"] and len(raw) != parameters["max_response_bytes"]
                or type(result.get("request_body_bytes")) is not int or result["request_body_bytes"] != len(sent)
                or result.get("request_body_sha256") != hashlib.sha256(sent).hexdigest()
                or (parameters["method"] == "HEAD" or result["status_code"] in {204, 304}) and (raw or result["truncated"])):
            return False
        if lengths and parameters["method"] != "HEAD" and result["status_code"] not in {204, 304}:
            length = int(lengths[0])
            if len(raw) != min(length, parameters["max_response_bytes"]) or result["truncated"] != (length > len(raw)):
                return False
        observed = datetime.fromisoformat(result.get("observed_at", ""))
        return observed.tzinfo is not None and len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= 280000
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False
