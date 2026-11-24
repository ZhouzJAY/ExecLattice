"""Explicit native search: validated candidates, native matching, verified hits.

Unlike compatible search this uses ripgrep's Unicode case matching, LF line
numbers and (when requested) Rust regex syntax. It does not honor ignore files.
Only hit files are decoded/hashed in Python; ripgrep does the content search.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat

from . import ripgrep_backend as backend
from .directory_listing import _directory, _scope
from .file_management import metadata_info
from .workspace_executor import WorkspaceDenied, _cancelled, _path, _read_bytes


def _groups(candidates):
    group, units = [], 0
    for candidate in candidates:
        cost = len(str(candidate[0]).encode("utf-16-le")) // 2 + 3
        if group and units + cost > 20000:
            yield group
            group, units = [], 0
        group.append(candidate)
        units += cost
    if group:
        yield group


def _text(value):
    if not isinstance(value, dict) or set(value) != {"text"} or not isinstance(value["text"], str):
        raise backend.RipgrepError("SEARCH_BACKEND_FAILED")
    return value["text"]


def _checked_hit(event, candidates, loaded, cancel, state_dir):
    from .search_listing import MAX_FILE_BYTES, _SearchError, _signature

    raw = _text(event.get("path"))
    key = os.path.normcase(os.path.abspath(raw))
    if key not in candidates:
        raise backend.RipgrepError("SEARCH_BACKEND_FAILED")
    path, expected = candidates[key]
    if key not in loaded:
        content = _read_bytes(_path(str(path), state_dir), MAX_FILE_BYTES, cancel, state_dir=state_dir)
        if content is None:
            raise _SearchError("SEARCH_CHANGED")
        data, info = content
        current = metadata_info(path, state_dir, directory=False)
        if _signature(info) != expected or _signature(current) != expected:
            raise _SearchError("SEARCH_CHANGED")
        try:
            if b"\0" in data:
                raise UnicodeError()
            data.decode("utf-8-sig")
            # Preserve each native LF-delimited line, including CRLF. Strip a
            # UTF-8 BOM only for ripgrep's first-line text projection.
            logical = data[3:] if data.startswith(b"\xef\xbb\xbf") else data
            lines = logical.split(b"\n")
            loaded[key] = lines, hashlib.sha256(data).hexdigest()
        except UnicodeError:
            loaded[key] = None
    if loaded[key] is None:
        return None
    lines, digest = loaded[key]
    number, submatches = event.get("line_number"), event.get("submatches")
    if (type(number) is not int or not 1 <= number <= len(lines)
            or not isinstance(submatches, list) or not submatches):
        raise backend.RipgrepError("SEARCH_BACKEND_FAILED")
    wire = _text(event.get("lines")).encode("utf-8")
    original = lines[number - 1]
    if wire not in (original, original + b"\n"):
        raise _SearchError("SEARCH_CHANGED")
    for item in submatches:
        start, end = item.get("start"), item.get("end")
        if (type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(wire)
                or _text(item.get("match")).encode("utf-8") != wire[start:end]):
            raise backend.RipgrepError("SEARCH_BACKEND_FAILED")
    try:
        position = len(wire[:submatches[0]["start"]].decode("utf-8"))
        text = original.decode("utf-8").removesuffix("\r")
    except UnicodeError:
        raise backend.RipgrepError("SEARCH_BACKEND_FAILED") from None
    start = max(0, position - 60)
    return {"path": str(path), "line_number": number, "line": text[start:start + 256], "file_sha256": digest}


def capture(parameters, cancel, state_dir, manager):
    from .executors import ExecutionDenied
    from .search_listing import (
        MAX_CACHE_BYTES,
        MAX_FILE_BYTES,
        MAX_MATCHES,
        MAX_SCAN_BYTES,
        MAX_SCAN_DIRECTORIES,
        MAX_SCAN_ENTRIES,
        MAX_SCAN_FILES,
        MAX_SCAN_SECONDS,
        _query_key,
        _signature,
    )

    backend.verified_executable()
    path, _ = _directory(parameters["path"], state_dir)
    pending, observed, candidates, rows = [path], [], [], []
    files = directories = skipped = reserved_bytes = scanned_entries = 0
    memory, reason = 4096 + 4 * len(str(path)), "complete"
    deadline = manager.clock() + MAX_SCAN_SECONDS

    def keep_identity(child, info):
        nonlocal memory
        cost = 512 + 4 * len(str(child))
        if memory + cost > MAX_CACHE_BYTES:
            return False
        observed.append((str(child), _signature(info), stat.S_ISDIR(info.st_mode)))
        memory += cost
        return True

    while pending and reason == "complete":
        _cancelled(cancel)
        if manager.clock() >= deadline:
            reason = "time_limit"
            break
        if directories >= MAX_SCAN_DIRECTORIES:
            reason = "directory_limit"
            break
        directory = _path(str(pending.pop()), state_dir)
        if not keep_identity(directory, metadata_info(directory, state_dir, directory=True)):
            reason = "cache_limit"
            break
        directories += 1
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                _cancelled(cancel)
                if manager.clock() >= deadline or scanned_entries >= MAX_SCAN_ENTRIES:
                    reason = "time_limit" if manager.clock() >= deadline else "entry_limit"
                    break
                scanned_entries += 1
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: (item.name.casefold(), item.name)):
            if reason != "complete":
                break
            _cancelled(cancel)
            if manager.clock() >= deadline:
                reason = "time_limit"
                break
            try:
                child = _path(entry.path, state_dir)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if directories + len(pending) >= MAX_SCAN_DIRECTORIES:
                        reason = "directory_limit"
                        break
                    pending.append(child)
                    continue
                if not stat.S_ISREG(info.st_mode) or not fnmatch.fnmatch(entry.name, parameters["glob"]):
                    continue
                if files >= MAX_SCAN_FILES or reserved_bytes >= MAX_SCAN_BYTES:
                    reason = "file_limit" if files >= MAX_SCAN_FILES else "byte_limit"
                    break
                files += 1
                current = metadata_info(child, state_dir, directory=False)
                if current.st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                if current.st_size > MAX_SCAN_BYTES - reserved_bytes:
                    reason = "byte_limit"
                    break
                if not keep_identity(child, current):
                    reason = "cache_limit"
                    break
                reserved_bytes += current.st_size
                candidates.append((child, _signature(current)))
            except (OSError, WorkspaceDenied, ExecutionDenied):
                skipped += 1

    enumeration_reason, hit_keys = reason, set()
    for group in _groups(candidates):
        _cancelled(cancel)
        if manager.clock() >= deadline:
            reason = "time_limit"
            break
        expected = {os.path.normcase(os.path.abspath(child)): (child, signature) for child, signature in group}
        events, scan_reason = backend.search_batch([child for child, _ in group], parameters, cancel,
                                                   deadline=deadline, clock=manager.clock)
        loaded, loaded_key, rejected = {}, None, set()
        for event in events:
            _cancelled(cancel)
            if manager.clock() >= deadline:
                scan_reason = "time_limit"
                break
            event_key = os.path.normcase(os.path.abspath(_text(event.get("path"))))
            if event_key != loaded_key:
                # Native --threads=1 emits each file together. Keep at most
                # one 1-MiB decoded hit file, not a batch of expanded line lists.
                loaded.clear()
                loaded_key = event_key
            row = _checked_hit(event, expected, loaded, cancel, state_dir)
            if row is None:
                rejected.add(event_key)
                continue
            identity = row["path"], row["line_number"]
            if identity in hit_keys:
                raise backend.RipgrepError("SEARCH_BACKEND_FAILED")
            encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            cost = len(encoded) + 128
            if len(rows) >= MAX_MATCHES or memory + cost > MAX_CACHE_BYTES:
                scan_reason = "match_limit" if len(rows) >= MAX_MATCHES else "cache_limit"
                break
            rows.append(encoded)
            hit_keys.add(identity)
            memory += cost
        skipped += len(rejected)
        # execute_search_page revalidates every candidate and directory before
        # AND after projecting any page. This includes non-matches and avoids
        # adding two more redundant full metadata walks for each native batch.
        if scan_reason != "complete":
            reason = scan_reason
            break
    else:
        reason = enumeration_reason
    rows.sort(key=lambda encoded: (json.loads(encoded)["path"].casefold(), json.loads(encoded)["path"],
                                   json.loads(encoded)["line_number"]))
    return manager._publish({"owner": parameters["owner_id"], "scope": _scope(state_dir),
        "query_key": _query_key(parameters), "path": str(path), "rows": tuple(rows), "observed": tuple(observed),
        "scanned_files": files, "skipped_files": skipped, "scanned_directories": directories,
        "scanned_bytes": reserved_bytes, "complete": reason == "complete", "stop_reason": reason,
        "memory_bytes": memory, "backend": "ripgrep", "pattern_type": parameters["pattern_type"]})
