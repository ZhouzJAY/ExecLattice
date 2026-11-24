"""Bounded random reads and streaming literal search, without whole-file hashing."""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
import os
import threading
import time

from .file_text import text_format
from .log_protocol import (
    LOG_MODELS,
    MAX_LOG_FILE_BYTES,
    MAX_LOG_RESPONSE_BYTES,
    MAX_LOG_SCAN_SECONDS,
    MAX_LOG_TEXT_JSON_BYTES,
    query_digest,
)
from .workspace_executor import (
    WorkspaceDenied,
    _Cancelled,
    _cancelled,
    _failure,
    _open_scoped_file,
    _path,
    _success,
)

_CHUNK = 65536
_ALIGN = 4096
_CONTEXT = 1024


class _Conflict(ValueError):
    pass


class _Limit(ValueError):
    pass


def file_version(info):
    """An optimistic metadata version, never a digest of the complete file."""
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode("ascii")).hexdigest()


def _read(fd, offset, count, cancel):
    os.lseek(fd, offset, os.SEEK_SET)
    result = bytearray()
    while len(result) < count:
        _cancelled(cancel)
        chunk = os.read(fd, min(_CHUNK, count - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _decode(data, encoding, *, final):
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    text = decoder.decode(data, final=final)
    if "\x00" in text:
        raise UnicodeError("Binary NUL is not a text log")
    buffered, _ = decoder.getstate()
    return text, len(data) - len(buffered)


def _boundary(fd, offset, size, encoding, bom, cancel, *, advance=False):
    if offset == 0 or offset == size:
        return offset
    if offset < bom:
        if advance:
            return bom
        raise UnicodeError("Offset is inside the byte-order mark")
    if encoding == "utf-8":
        probe = _read(fd, offset, min(4, size - offset), cancel)
        skipped = 0
        while skipped < len(probe) and 0x80 <= probe[skipped] <= 0xBF:
            skipped += 1
        if skipped and (not advance or skipped > 3):
            raise UnicodeError("Offset is inside a UTF-8 character")
        return offset + skipped
    if encoding.startswith("utf-16"):
        if offset % 2:
            if not advance:
                raise UnicodeError("Offset is inside a UTF-16 code unit")
            offset += 1
        raw = _read(fd, offset, min(2, size - offset), cancel)
        if len(raw) == 2 and 0xDC00 <= int.from_bytes(raw, "little" if encoding.endswith("le") else "big") <= 0xDFFF:
            if not advance:
                raise UnicodeError("Offset is inside a UTF-16 surrogate pair")
            offset += 2
        return min(offset, size)
    # GB18030 trail bytes can themselves resemble lead bytes. A nearby ASCII
    # separator that cannot occur inside either GB18030 sequence gives a real
    # anchor; guessing from a four-byte suffix would silently misdecode some logs.
    beginning = max(bom, offset - _ALIGN)
    prefix = _read(fd, beginning, offset - beginning, cancel)
    anchor = 0 if beginning == bom else None
    for index, byte in enumerate(prefix):
        if byte < 0x30 or 0x3A <= byte <= 0x3F or byte == 0x7F:
            anchor = index + 1
    if anchor is None:
        raise UnicodeError("No unambiguous GB18030 boundary within the bounded lookbehind")
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    decoder.decode(prefix[anchor:], final=False)
    buffered, _ = decoder.getstate()
    if not buffered:
        return offset
    if not advance:
        raise UnicodeError("Offset is inside a GB18030 character")
    for count in range(1, 4):
        byte = _read(fd, offset + count - 1, 1, cancel)
        decoder.decode(byte, final=offset + count >= size)
        buffered, _ = decoder.getstate()
        if not buffered:
            return offset + count
    raise UnicodeError("Cannot align a GB18030 tail")


def _base(path, version, size, encoding, bom):
    return {"path": str(path), "version": version, "version_kind": "stat-identity-size-times",
            "whole_file_sha256": False, "file_size_bytes": size,
            "text_encoding": encoding, "bom_bytes": bom}


def _range(fd, info, path, version, encoding, bom, parameters, cancel):
    tail = parameters["tail_bytes"]
    limit = min(parameters["limit"], tail) if tail is not None else parameters["limit"]
    offset = max(0, info.st_size - limit) if tail is not None else parameters["offset"]
    if offset > info.st_size:
        raise UnicodeError("Offset exceeds the current log size")
    offset = _boundary(fd, offset, info.st_size, encoding, bom, cancel, advance=tail is not None)
    raw = _read(fd, offset, min(limit, info.st_size - offset), cancel)
    prefix = bom if offset == 0 else 0
    text, consumed = _decode(raw[prefix:], encoding, final=offset + len(raw) == info.st_size)
    raw = raw[:prefix + consumed]
    response_limited = False
    # Escaped control characters and UTF-16 surrogate escapes can inflate the
    # MCP text projection far beyond the original byte page. Return an exact,
    # character-complete prefix with its real continuation instead of allowing
    # a large decoded response or pretending that a shortened tail reached EOF.
    while len(json.dumps(text, ensure_ascii=True).encode("ascii")) > MAX_LOG_TEXT_JSON_BYTES:
        count = max(4, (len(raw) - prefix) // 2)
        text, consumed = _decode(raw[prefix:prefix + count], encoding, final=False)
        raw = raw[:prefix + consumed]
        response_limited = True
    end = offset + len(raw)
    result = _base(path, version, info.st_size, encoding, bom)
    result.update({"offset": offset, "next_offset": end, "size_bytes": len(raw),
                   "data_b64": base64.b64encode(raw).decode("ascii"),
                   "data_sha256": hashlib.sha256(raw).hexdigest(), "eof": end == info.st_size,
                   "tail_bytes": tail, "response_limited": response_limited})
    return result


def _boundaries(text, encoding, offset):
    offsets = [offset]
    for char in text:
        offsets.append(offsets[-1] + len(char.encode(encoding)))
    return offsets


def _find(text, query, sensitive):
    """Yield non-overlapping character extents, preserving casefold expansions."""
    if sensitive:
        cursor = 0
        while (found := text.find(query, cursor)) >= 0:
            cursor = found + len(query)
            yield found, cursor
        return
    folded, owners = [], []
    for index, char in enumerate(text):
        value = char.casefold()
        folded.append(value)
        owners.extend([index] * len(value))
    haystack, needle, cursor = "".join(folded), query.casefold(), 0
    while (found := haystack.find(needle, cursor)) >= 0:
        finish = found + len(needle)
        cursor = finish
        # A partial expansion (e.g. one 's' from 'ß') is not a whole text match.
        if (found and owners[found - 1] == owners[found]
                or finish < len(owners) and owners[finish - 1] == owners[finish]):
            continue
        yield owners[found], owners[finish - 1] + 1


def _match(text, start, end, offsets, encoding, size):
    left, right = max(0, start - 64), min(len(text), end + 64)
    while (offsets[right] - offsets[left] > _CONTEXT
           or len(json.dumps(text[left:right], ensure_ascii=True).encode("ascii")) > _CONTEXT):
        if start - left >= right - end and left < start:
            left += 1
        elif right > end:
            right -= 1
        else:
            raise _Limit("The matched literal exceeds the context byte bound")
    raw = text[left:right].encode(encoding)
    return {"offset": offsets[start], "end_offset": offsets[end],
            "context_offset": offsets[left], "context_end_offset": offsets[right],
            "data_b64": base64.b64encode(raw).decode("ascii"),
            "data_sha256": hashlib.sha256(raw).hexdigest(),
            "context_before_truncated": offsets[left] > 0,
            "context_after_truncated": offsets[right] < size}


def _search(fd, info, path, version, encoding, bom, parameters, cancel):
    cursor = parameters["cursor"]
    digest = query_digest(parameters, encoding)
    if cursor is not None and (cursor["query_sha256"] != digest or cursor["encoding"] != encoding):
        raise ValueError("Continuation does not match this search")
    start = cursor["offset"] if cursor else 0
    if start > info.st_size:
        raise ValueError("Continuation is outside this file")
    _boundary(fd, start, info.st_size, encoding, bom, cancel)
    position = start + (bom if start == 0 else 0)
    scanned, matches, carry = 0, [], ""
    carry_offset, next_offset = position, position
    reason, begun = "complete", time.monotonic()
    query = parameters["query"]
    # For casefold matches, a source character can supply multiple needle code
    # points; keeping len(query.casefold()) characters is conservative.
    overlap = max(0, len(query.casefold()) - 1 if not parameters["case_sensitive"] else len(query) - 1)
    while position < info.st_size:
        _cancelled(cancel)
        if time.monotonic() - begun >= MAX_LOG_SCAN_SECONDS:
            reason = "time_limit"
            break
        remaining = parameters["scan_bytes"] - scanned
        if remaining < 4:
            reason = "byte_limit"
            break
        raw = _read(fd, position, min(_CHUNK, remaining, info.st_size - position), cancel)
        scanned += len(raw)
        decoded, consumed = _decode(raw, encoding, final=position + len(raw) == info.st_size)
        if not consumed:
            reason = "byte_limit"
            break
        text = carry + decoded
        text_offset = carry_offset if carry else position
        offsets = _boundaries(text, encoding, text_offset)
        last_end = 0
        for left, right in _find(text, query, parameters["case_sensitive"]):
            _cancelled(cancel)
            matches.append(_match(text, left, right, offsets, encoding, info.st_size))
            last_end = right
            if len(matches) == parameters["max_matches"]:
                next_offset, reason = offsets[right], "match_limit"
                break
        position += consumed
        if reason == "match_limit":
            break
        keep = min(overlap, len(text) - last_end)
        carry = text[-keep:] if keep else ""
        carry_offset = offsets[len(text) - keep]
        next_offset = carry_offset
    if position >= info.st_size and reason != "match_limit":
        next_offset, reason = info.st_size, "complete"
    elif next_offset >= info.st_size:
        reason = "complete"
    next_cursor = ({"offset": next_offset, "version": version, "query_sha256": digest,
                    "encoding": encoding} if reason != "complete" else None)
    result = _base(path, version, info.st_size, encoding, bom)
    result.update({"query_sha256": digest, "start_offset": start, "scanned_to": position,
                   "scanned_bytes": scanned, "next_offset": next_offset,
                   "next_cursor": next_cursor, "eof": reason == "complete",
                   "truncated": reason != "complete", "stop_reason": reason, "matches": matches})
    return result


def execute_log(action, parameters, cancel: threading.Event, state_dir=None):
    """Observe one regular file through a verified handle; never retry effects."""
    from .executors import ExecutionDenied

    try:
        parameters = LOG_MODELS[action].model_validate(parameters).model_dump()
        _cancelled(cancel)
        path = _path(parameters["path"], state_dir)
        with _open_scoped_file(path, state_dir) as (fd, before):
            if before.st_size > MAX_LOG_FILE_BYTES:
                return _failure("FILE_TOO_LARGE", "Log tools support regular files up to 2 GiB")
            version = file_version(before)
            expected = (parameters["expected_version"] if action == "log_read"
                        else parameters["cursor"]["version"] if parameters["cursor"] else None)
            if expected is not None and version != expected:
                raise _Conflict()
            header = _read(fd, 0, min(4, before.st_size), cancel)
            encoding, bom = text_format(header, parameters["encoding"])
            function = _range if action == "log_read" else _search
            result = function(fd, before, path, version, encoding, bom, parameters, cancel)
            if file_version(os.fstat(fd)) != version:
                raise _Conflict()
        if len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")) > MAX_LOG_RESPONSE_BYTES:
            return _failure("RESULT_LIMIT", "Log observation exceeds the bounded response size")
        return _success(result)
    except _Cancelled:
        return _failure("CANCELLED", "Log observation was cancelled", state="cancelled")
    except _Conflict:
        return _failure("LOG_CHANGED", "The log changed or grew; inspect its current version before continuing")
    except UnicodeError:
        return _failure("INVALID_TEXT_RANGE", "Text encoding or byte boundary is invalid or ambiguous; use a returned offset or a UTF-8 log")
    except _Limit:
        return _failure("RESULT_LIMIT", "The matched literal exceeds the bounded observation size")
    except (WorkspaceDenied, ExecutionDenied):
        return _failure("POLICY_DENIED", "The selected path is not available to log tools")
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "The selected log does not exist")
    except PermissionError:
        return _failure("ACCESS_DENIED", "The current user cannot read the selected log")
    except IsADirectoryError:
        return _failure("NOT_A_FILE", "The selected path is not a regular file")
    except OSError:
        return _failure("FILESYSTEM_ERROR", "The log observation could not be completed")
    except (ValueError, TypeError, KeyError):
        return _failure("INVALID_PARAMETERS", "Log parameters or continuation are invalid")
