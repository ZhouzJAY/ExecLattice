"""Bounded literal-search result snapshots; continuation does not scan again."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from .directory_listing import _directory, _key, _scope
from .file_management import metadata_info
from .workspace_executor import (
    WorkspaceDenied,
    _Cancelled,
    _cancelled,
    _failure,
    _path,
    _read_bytes,
    _success,
)

MAX_SNAPSHOTS = 4
MAX_CACHE_BYTES = 8 * 1024 * 1024
SNAPSHOT_TTL_SECONDS = 60
MAX_SCAN_FILES = 10000
MAX_SCAN_DIRECTORIES = 2000
MAX_SCAN_ENTRIES = 20000
MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_SCAN_SECONDS = 10
MAX_MATCHES = 20000
MAX_PAGE_BYTES = 180000
_CURSOR = re.compile(r"^([0-9a-f]{32}):([1-9][0-9]{0,4})$")
_MESSAGES = {
    "SEARCH_CURSOR_EXPIRED": "The search result snapshot expired or was evicted; start a new search",
    "SEARCH_CURSOR_MISMATCH": "The search cursor belongs to a different connection, path or query",
    "SEARCH_CHANGED": "A searched entry changed; start a new search instead of mixing versions",
    "SEARCH_SNAPSHOT_LIMIT": "The search snapshot cannot fit within its bounded cache",
    "SEARCH_PAGE_LIMIT": "A search result cannot fit within the bounded response",
    "INVALID_PARAMETERS": "Search paging parameters are invalid",
    "SEARCH_BACKEND_UNAVAILABLE": "The pinned bundled native search engine is unavailable; compatible search remains available",
    "SEARCH_BACKEND_FAILED": "Native search did not return a valid complete process result",
    "SEARCH_PATTERN_INVALID": "The native search pattern is not supported Rust regex syntax",
    "SEARCH_STOP_UNCONFIRMED": "Native search process termination could not be confirmed",
}


class _SearchError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@dataclass(frozen=True, slots=True)
class _Snapshot:
    identifier: str
    owner: str
    scope: str
    query_key: tuple
    path: str
    rows: tuple
    observed: tuple
    scanned_files: int
    skipped_files: int
    scanned_directories: int
    scanned_bytes: int
    complete: bool
    stop_reason: str
    expires_at: float
    memory_bytes: int
    backend: str = "compatible"
    pattern_type: str = "literal"


class SearchListingManager:
    def __init__(self, *, clock=time.monotonic):
        self.clock, self._lock = clock, threading.RLock()
        self._snapshots, self._bytes = OrderedDict(), 0

    def _discard(self, identifier):
        with self._lock:
            snapshot = self._snapshots.pop(identifier, None)
            if snapshot is not None:
                self._bytes -= snapshot.memory_bytes

    def _purge(self):
        for identifier, snapshot in list(self._snapshots.items()):
            if self.clock() >= snapshot.expires_at:
                self._discard(identifier)

    def _get(self, identifier):
        with self._lock:
            self._purge()
            snapshot = self._snapshots.get(identifier)
            if snapshot is None:
                raise _SearchError("SEARCH_CURSOR_EXPIRED")
            self._snapshots.move_to_end(identifier)
            return snapshot

    def _publish(self, values):
        with self._lock:
            self._purge()
            cost = values["memory_bytes"]
            if cost > MAX_CACHE_BYTES or MAX_SNAPSHOTS < 1:
                raise _SearchError("SEARCH_SNAPSHOT_LIMIT")
            while self._snapshots and (len(self._snapshots) >= MAX_SNAPSHOTS or self._bytes + cost > MAX_CACHE_BYTES):
                self._discard(next(iter(self._snapshots)))
            for _ in range(4):
                identifier = secrets.token_hex(16)
                if identifier not in self._snapshots:
                    break
            else:
                raise _SearchError("SEARCH_SNAPSHOT_LIMIT")
            snapshot = _Snapshot(identifier=identifier, expires_at=self.clock() + SNAPSHOT_TTL_SECONDS, **values)
            self._snapshots[identifier] = snapshot
            self._bytes += cost
            return snapshot


_MANAGER = SearchListingManager()


def _query_key(parameters):
    base = _key(parameters["path"]), parameters["query"], parameters["glob"], parameters["case_sensitive"]
    return (*base, "ripgrep", parameters["pattern_type"]) if "pattern_type" in parameters else base


def _capture(parameters, cancel, state_dir, manager):
    from .executors import ExecutionDenied

    path, _ = _directory(parameters["path"], state_dir)
    pending, observed, rows = [path], [], []
    files = directories = skipped = byte_count = scanned_entries = 0
    memory = 4096 + 4 * len(str(path))
    reason = "complete"
    deadline = manager.clock() + MAX_SCAN_SECONDS
    query = parameters["query"] if parameters["case_sensitive"] else parameters["query"].casefold()

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
        if directories >= MAX_SCAN_DIRECTORIES:
            reason = "directory_limit"
            break
        directory = pending.pop()
        directory = _path(str(directory), state_dir)
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
                if files >= MAX_SCAN_FILES or byte_count >= MAX_SCAN_BYTES:
                    reason = "file_limit" if files >= MAX_SCAN_FILES else "byte_limit"
                    break
                files += 1
                loaded = _read_bytes(child, min(MAX_FILE_BYTES, MAX_SCAN_BYTES - byte_count), cancel,
                                     state_dir=state_dir)
                if loaded is None:
                    if info.st_size <= MAX_FILE_BYTES and info.st_size > MAX_SCAN_BYTES - byte_count:
                        reason = "byte_limit"
                        break
                    skipped += 1
                    continue
                content, info = loaded
                current = metadata_info(child, state_dir, directory=False)
                if _signature(current) != _signature(info):
                    raise _SearchError("SEARCH_CHANGED")
                if not keep_identity(child, current):
                    reason = "cache_limit"
                    break
                byte_count += len(content)
                if b"\x00" in content:
                    raise UnicodeError()
                text = content.decode("utf-8-sig")
                digest = hashlib.sha256(content).hexdigest()
                for number, line in enumerate(text.splitlines(), 1):
                    _cancelled(cancel)
                    if manager.clock() >= deadline:
                        reason = "time_limit"
                        break
                    position = (line if parameters["case_sensitive"] else line.casefold()).find(query)
                    if position < 0:
                        continue
                    start = max(0, position - 60)
                    encoded = json.dumps({"path": str(child), "line_number": number, "line": line[start:start + 256],
                                          "file_sha256": digest}, ensure_ascii=False, separators=(",", ":")).encode()
                    cost = len(encoded) + 128
                    if len(rows) >= MAX_MATCHES or memory + cost > MAX_CACHE_BYTES:
                        reason = "match_limit" if len(rows) >= MAX_MATCHES else "cache_limit"
                        break
                    rows.append(encoded)
                    memory += cost
            except (OSError, UnicodeError, WorkspaceDenied, ExecutionDenied):
                skipped += 1
    rows.sort(key=lambda encoded: (json.loads(encoded)["path"].casefold(), json.loads(encoded)["path"],
                                  json.loads(encoded)["line_number"]))
    return manager._publish({"owner": parameters["owner_id"], "scope": _scope(state_dir),
        "query_key": _query_key(parameters), "path": str(path), "rows": tuple(rows), "observed": tuple(observed),
        "scanned_files": files, "skipped_files": skipped, "scanned_directories": directories,
        "scanned_bytes": byte_count, "complete": reason == "complete", "stop_reason": reason, "memory_bytes": memory})


def _assert_current(snapshot, cancel, state_dir):
    for raw, signature, directory in snapshot.observed:
        _cancelled(cancel)
        try:
            current = metadata_info(_path(raw, state_dir), state_dir, directory=directory)
            if _signature(current) != signature or not stat.S_ISDIR(current.st_mode) and current.st_nlink != 1:
                raise _SearchError("SEARCH_CHANGED")
        except (OSError, WorkspaceDenied):
            raise _SearchError("SEARCH_CHANGED") from None


def _page(snapshot, start, limit, cancel):
    result = {"path": snapshot.path, "matches": [], "scanned_files": snapshot.scanned_files,
        "skipped_files": snapshot.skipped_files, "scanned_directories": snapshot.scanned_directories,
        "scanned_bytes": snapshot.scanned_bytes, "snapshot_id": snapshot.identifier, "page_start": start,
        "snapshot_total": len(snapshot.rows), "search_complete": snapshot.complete, "stop_reason": snapshot.stop_reason,
        "next_cursor": None, "truncated": not snapshot.complete}
    if snapshot.backend == "ripgrep":
        result.update(backend="ripgrep", pattern_type=snapshot.pattern_type,
                      scan_accounting="validated_candidate_upper_bounds")
    for encoded in snapshot.rows[start:start + limit]:
        _cancelled(cancel)
        result["matches"].append(json.loads(encoded))
        end = start + len(result["matches"])
        result["next_cursor"] = f"{snapshot.identifier}:{end}" if end < len(snapshot.rows) else None
        result["truncated"] = end < len(snapshot.rows) or not snapshot.complete
        if len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_PAGE_BYTES:
            result["matches"].pop()
            break
    end = start + len(result["matches"])
    if end == start and start < len(snapshot.rows):
        raise _SearchError("SEARCH_PAGE_LIMIT")
    result["next_cursor"] = f"{snapshot.identifier}:{end}" if end < len(snapshot.rows) else None
    result["truncated"] = end < len(snapshot.rows) or not snapshot.complete
    return result


def execute_search_page(parameters, cancel, *, state_dir=None, manager=None, native=False):
    from .ripgrep_backend import RipgrepError

    manager = _MANAGER if manager is None else manager
    try:
        _cancelled(cancel)
        cursor = parameters["cursor"]
        if cursor is None:
            if native:
                from .ripgrep_search import capture

                snapshot, start = capture(parameters, cancel, state_dir, manager), 0
            else:
                snapshot, start = _capture(parameters, cancel, state_dir, manager), 0
        else:
            match = _CURSOR.fullmatch(cursor)
            if match is None:
                raise _SearchError("INVALID_PARAMETERS")
            identifier, start = match.group(1), int(match.group(2))
            snapshot = manager._get(identifier)
            if (snapshot.owner != parameters["owner_id"] or snapshot.scope != _scope(state_dir)
                    or snapshot.query_key != _query_key(parameters)):
                raise _SearchError("SEARCH_CURSOR_MISMATCH")
            if start >= len(snapshot.rows):
                raise _SearchError("INVALID_PARAMETERS")
        _assert_current(snapshot, cancel, state_dir)
        result = _page(snapshot, start, parameters["max_results"], cancel)
        _assert_current(snapshot, cancel, state_dir)
        return _success(result)
    except _SearchError as error:
        return _failure(error.code, _MESSAGES[error.code])
    except RipgrepError as error:
        return _failure(error.code, _MESSAGES[error.code], state=error.state)
    except _Cancelled:
        return _failure("CANCELLED", "Search observation was cancelled", state="cancelled")
    except WorkspaceDenied:
        return _failure("POLICY_DENIED", "The selected search directory is not available")
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "The selected search directory does not exist")
    except PermissionError:
        return _failure("ACCESS_DENIED", "The current user cannot search this directory")
    except NotADirectoryError:
        return _failure("NOT_A_DIRECTORY", "Search requires a directory")
    except OSError:
        return _failure("FILESYSTEM_ERROR", "Search could not inspect the selected directory")
    except (ValueError, TypeError, KeyError):
        return _failure("INVALID_PARAMETERS", "Search paging parameters are invalid")
