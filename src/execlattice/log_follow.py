"""Append-aware passive byte observations, using watchfiles only as a wake hint.

Cursors bind the path, open-file identity and a bounded preceding-byte anchor.
They do not certify immutable earlier content or serve as edit preconditions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .log_protocol import MAX_LOG_FILE_BYTES
from .workspace_executor import _cancelled, _path

MAX_BYTES = 65536
ANCHOR_BYTES = 256


class FollowCursor(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_identity: str = Field(pattern=r"^[0-9a-f]{64}$")
    offset: int = Field(ge=0, le=MAX_LOG_FILE_BYTES)
    anchor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LogFollowParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    path: str = Field(min_length=1, max_length=4096)
    cursor: FollowCursor | None = None
    limit: int = Field(default=32768, ge=1, le=MAX_BYTES)
    tail_bytes: int = Field(default=8192, ge=0, le=MAX_BYTES)
    wait_ms: int = Field(default=1000, ge=0, le=2000)


class LogFollowError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _identity(info):
    values = [info.st_dev, info.st_ino, getattr(info, "st_birthtime_ns", None)]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _path_key(path):
    return hashlib.sha256(os.path.normcase(str(path)).encode("utf-8")).hexdigest()


def _bytes(fd, offset, count):
    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, count)


def _anchor(fd, offset):
    start = max(0, offset - ANCHOR_BYTES)
    data = _bytes(fd, start, offset - start)
    if len(data) != offset - start:
        raise LogFollowError("LOG_FOLLOW_CHANGED")
    return hashlib.sha256(data).hexdigest()


def read_log_increment(parameters, policy, stop, *, state_dir=None):
    from .workspace_executor import _open_scoped_file

    values = LogFollowParameters.model_validate(parameters).model_dump()
    if policy.get("desktop_access", {}).get("mode") not in {"full", "read_only"}:
        raise LogFollowError("POLICY_DENIED")
    _cancelled(stop)
    path = _path(values["path"], state_dir)
    with _open_scoped_file(path, state_dir) as (fd, before):
        if before.st_size > MAX_LOG_FILE_BYTES:
            raise LogFollowError("FILE_TOO_LARGE")
        identity, key, cursor = _identity(before), _path_key(path), values["cursor"]
        reason = None
        if cursor is not None:
            if cursor["path_sha256"] != key:
                raise LogFollowError("LOG_FOLLOW_CURSOR_INVALID")
            offset = cursor["offset"]
            if identity != cursor["file_identity"]:
                reason = "rotated"
            elif before.st_size < offset:
                reason = "truncated"
            elif _anchor(fd, offset) != cursor["anchor_sha256"]:
                reason = "rewritten"
        else:
            offset = max(0, before.st_size - values["tail_bytes"])
        raw = b"" if reason else _bytes(fd, offset, min(values["limit"], before.st_size - offset))
        end = offset + len(raw)
        anchor = None if reason else _anchor(fd, end)
        after = os.fstat(fd)
        # Appends are allowed. Truncation/rewrite during this observation is
        # rejected; the anchor is checked both before and after reading.
        if (_identity(after) != identity or after.st_size < before.st_size
                or after.st_size == before.st_size and
                (after.st_mtime_ns, after.st_ctime_ns) != (before.st_mtime_ns, before.st_ctime_ns)):
            raise LogFollowError("LOG_FOLLOW_CHANGED")
        if not reason:
            if cursor is not None and _anchor(fd, offset) != cursor["anchor_sha256"]:
                raise LogFollowError("LOG_FOLLOW_CHANGED")
            if _anchor(fd, end) != anchor:
                raise LogFollowError("LOG_FOLLOW_CHANGED")
        _cancelled(stop)
        # A path replaced while its old handle is readable must never be
        # represented as current. Revalidate the full path and its identity.
        if _identity(_path(values["path"], state_dir).stat()) != identity:
            raise LogFollowError("LOG_FOLLOW_CHANGED")
    result = {"path_sha256": key, "file_identity": identity, "offset": offset,
              "next_offset": end, "file_size_bytes": after.st_size, "size_bytes": len(raw),
              "data_sha256": hashlib.sha256(raw).hexdigest(), "state": "reset_required" if reason else "observed",
              "reset_reason": reason, "next_cursor": None if reason else {
                  "path_sha256": key, "file_identity": identity, "offset": end, "anchor_sha256": anchor},
              "caught_up": not reason and end == after.st_size, "whole_file_sha256": False,
              "continuity": "open-file-identity-and-preceding-256-bytes"}
    return result, raw


def valid_log_follow_frame(result, raw, parameters):
    try:
        values = LogFollowParameters.model_validate(parameters).model_dump()
        if (type(result) is not dict or set(result) != {
            "path_sha256", "file_identity", "offset", "next_offset", "file_size_bytes", "size_bytes",
            "data_sha256", "state", "reset_reason", "next_cursor", "caught_up", "whole_file_sha256", "continuity"}
                or not isinstance(raw, bytes) or len(raw) > values["limit"]
                or result["data_sha256"] != hashlib.sha256(raw).hexdigest()
                or result["path_sha256"] != _path_key(Path(values["path"]))
                or not isinstance(result["file_identity"], str)
                or re.fullmatch(r"[0-9a-f]{64}", result["file_identity"]) is None
                or result["whole_file_sha256"] is not False
                or result["continuity"] != "open-file-identity-and-preceding-256-bytes"
                or type(result["caught_up"]) is not bool):
            return False
        for key in ("offset", "next_offset", "file_size_bytes", "size_bytes"):
            if type(result[key]) is not int or not 0 <= result[key] <= MAX_LOG_FILE_BYTES:
                return False
        if result["next_offset"] != result["offset"] + len(raw) or result["size_bytes"] != len(raw):
            return False
        old = values["cursor"]
        if old is not None and result["offset"] != old["offset"]:
            return False
        if result["state"] == "reset_required":
            return (old is not None and not raw and result["reset_reason"] in {"rotated", "truncated", "rewritten"}
                    and result["next_cursor"] is None and result["caught_up"] is False)
        if result["state"] != "observed" or result["reset_reason"] is not None:
            return False
        cursor = FollowCursor.model_validate(result["next_cursor"]).model_dump()
        return (cursor["offset"] == result["next_offset"] and cursor["path_sha256"] == result["path_sha256"]
                and cursor["file_identity"] == result["file_identity"]
                and (old is None or old["file_identity"] == result["file_identity"])
                and result["next_offset"] <= result["file_size_bytes"]
                and result["caught_up"] == (result["next_offset"] == result["file_size_bytes"]))
    except (TypeError, ValueError, KeyError):
        return False


def iter_log_increments(parameters, policy, stop, *, state_dir=None):
    """Watch at most one parent for <=30s; events never authorize file reads."""
    from watchfiles import watch

    values = LogFollowParameters.model_validate(parameters).model_dump()
    path = _path(values["path"], state_dir)
    watcher = watch(path.parent, recursive=False, watch_filter=None, debounce=50, step=10,
                    rust_timeout=100, yield_on_timeout=True, stop_event=stop,
                    debug=False, force_polling=False, ignore_permission_denied=False)
    deadline = time.monotonic() + 30
    first = True
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            wait_until = time.monotonic() + values["wait_ms"] / 1000
            while True:
                result, raw = read_log_increment(values, policy, stop, state_dir=state_dir)
                if raw or result["state"] == "reset_required" or first and values["cursor"] is None:
                    break
                if time.monotonic() >= wait_until or stop.is_set():
                    break
                # A timeout is also a wake: missed filesystem events cannot
                # indefinitely hide an append, rotation or path replacement.
                try:
                    next(watcher)
                except StopIteration:
                    return
            if stop.is_set():
                return
            if not valid_log_follow_frame(result, raw, values):
                raise LogFollowError("LOG_FOLLOW_INVALID")
            yield result, raw
            first = False
            if result["state"] == "reset_required":
                return
            values["cursor"] = result["next_cursor"]
            if not raw and values["wait_ms"] == 0:
                return
    finally:
        watcher.close()


def readable_log_increment(result, raw):
    value = {**result, "data_b64": base64.b64encode(raw).decode("ascii"),
             "observation_only": True, "task_created": False}
    try:
        value["text_utf8"] = raw.decode("utf-8")
    except UnicodeError:
        value["text_utf8"] = None
    return value
