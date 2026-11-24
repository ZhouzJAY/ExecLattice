"""Bounded read-only directory snapshots; continuation pages never rescan."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .workspace_executor import (
    WorkspaceDenied,
    _Cancelled,
    _cancelled,
    _failure,
    _link,
    _path,
    _private_root,
    _roots,
    _success,
)

MAX_SNAPSHOTS = 4
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_SCAN_ENTRIES = 20000
MAX_SCAN_SECONDS = 10
SNAPSHOT_TTL_SECONDS = 60
MAX_PAGE_BYTES = 180000
_IDENTIFIER = re.compile(r"^[0-9a-f]{32}$")
_CURSOR = re.compile(r"^([0-9a-f]{32}):([1-9][0-9]{0,4})$")
_MESSAGES = {
    "DIRECTORY_CURSOR_EXPIRED": "The directory snapshot expired or was evicted; start a new listing",
    "DIRECTORY_CURSOR_MISMATCH": "The cursor belongs to a different connection or directory",
    "DIRECTORY_CHANGED": "The directory changed; start a new listing",
    "DIRECTORY_SNAPSHOT_LIMIT": "The directory snapshot cannot fit within the cache limit",
    "DIRECTORY_PAGE_LIMIT": "One directory entry cannot fit within the response limit",
    "INVALID_PARAMETERS": "Directory paging parameters are invalid",
}


class _ListingError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    identifier: str
    path: str
    path_key: str
    owner: str
    scope: str
    signature: tuple[int, int, int]
    rows: tuple[bytes, ...]
    skipped: int
    scanned: int
    complete: bool
    expires_at: float
    memory_bytes: int


def _key(raw):
    return os.path.normcase(os.path.abspath(raw))


def _scope(state_dir):
    private = _private_root(state_dir)
    return "" if private is None else _key(str(private))


def _signature(info):
    return info.st_dev, info.st_ino, info.st_mtime_ns


def _directory(raw, state_dir):
    path = _path(raw, state_dir)
    # Recheck the native path too, so an 8.3 alias cannot bypass private state.
    native = _path(str(path.resolve(strict=True)), state_dir)
    before, resolved = path.stat(), native.stat()
    if not stat.S_ISDIR(before.st_mode):
        raise NotADirectoryError()
    if _signature(before) != _signature(resolved):
        raise _ListingError("DIRECTORY_CHANGED")
    return path, _signature(before)


def _base_cost(path, owner, scope, signature):
    # Include conservative bookkeeping, tuple references and Python byte-object
    # overhead, rather than counting only serialized entry payloads.
    values = (path, _key(path), owner, scope, signature, *signature)
    return 1024 + sum(sys.getsizeof(value) for value in values)


class DirectoryListingManager:
    """Inert bounded cache; the clock seam only controls observation expiry."""

    def __init__(self, *, clock=time.monotonic):
        self.clock = clock
        self._lock = threading.RLock()
        self._snapshots: OrderedDict[str, _Snapshot] = OrderedDict()
        self._bytes = 0

    def _purge(self):
        now = self.clock()
        for identifier, snapshot in list(self._snapshots.items()):
            if now >= snapshot.expires_at:
                self._discard(identifier)

    def _discard(self, identifier):
        with self._lock:
            snapshot = self._snapshots.pop(identifier, None)
            if snapshot is not None:
                self._bytes -= snapshot.memory_bytes

    def _get(self, identifier):
        with self._lock:
            self._purge()
            snapshot = self._snapshots.get(identifier)
            if snapshot is None:
                raise _ListingError("DIRECTORY_CURSOR_EXPIRED")
            self._snapshots.move_to_end(identifier)
            return snapshot

    def _publish(self, path, owner, scope, signature, rows, skipped, scanned, complete, memory_bytes):
        with self._lock:
            self._purge()
            if memory_bytes > MAX_CACHE_BYTES or MAX_SNAPSHOTS < 1:
                raise _ListingError("DIRECTORY_SNAPSHOT_LIMIT")
            for _ in range(4):
                identifier = secrets.token_hex(16)
                if identifier not in self._snapshots:
                    break
            else:
                raise _ListingError("DIRECTORY_SNAPSHOT_LIMIT")
            while self._snapshots and (len(self._snapshots) >= MAX_SNAPSHOTS
                                      or self._bytes + memory_bytes > MAX_CACHE_BYTES):
                self._discard(next(iter(self._snapshots)))
            snapshot = _Snapshot(identifier, path, _key(path), owner, scope, signature, tuple(rows),
                                 skipped, scanned, complete, self.clock() + SNAPSHOT_TTL_SECONDS, memory_bytes)
            self._snapshots[identifier] = snapshot
            self._bytes += memory_bytes
            return snapshot


_MANAGER = DirectoryListingManager()


def _parameters(parameters, owner_id):
    if (type(parameters) is not dict or set(parameters) - {"path", "limit", "cursor", "owner_id"}
            or type(owner_id) is not str):
        raise _ListingError("INVALID_PARAMETERS")
    path, limit, cursor = parameters.get("path", ""), parameters.get("limit", 300), parameters.get("cursor")
    owner = parameters.get("owner_id", owner_id)
    if (type(path) is not str or len(path) > 4096 or type(limit) is not int or not 1 <= limit <= 500
            or type(owner) is not str or not _IDENTIFIER.fullmatch(owner)
            or owner_id and owner_id != owner or cursor is not None and type(cursor) is not str):
        raise _ListingError("INVALID_PARAMETERS")
    if cursor is None:
        return path, limit, None, 0, owner
    match = _CURSOR.fullmatch(cursor)
    if match is None or not path:
        raise _ListingError("INVALID_PARAMETERS")
    identifier, index = match.groups()
    if int(index) > MAX_SCAN_ENTRIES:
        raise _ListingError("INVALID_PARAMETERS")
    return path, limit, identifier, int(index), owner


def _capture(raw, owner, cancel, state_dir, manager):
    path, signature = _directory(raw, state_dir)
    scope = _scope(state_dir)
    memory_bytes = _base_cost(str(path), owner, scope, signature)
    if memory_bytes > MAX_CACHE_BYTES:
        raise _ListingError("DIRECTORY_SNAPSHOT_LIMIT")
    records, scanned, skipped, complete = [], 0, 0, True
    deadline = manager.clock() + MAX_SCAN_SECONDS
    with os.scandir(path) as iterator:
        for entry in iterator:
            _cancelled(cancel)
            if scanned >= MAX_SCAN_ENTRIES or manager.clock() >= deadline:
                complete = False
                break
            scanned += 1
            try:
                child = _path(entry.path, state_dir)
                _path(str(child.resolve(strict=True)), state_dir)
                info = child.lstat()  # Do not trust Windows DirEntry link-count caches.
                if (_link(info) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    skipped += 1
                    continue
                directory = stat.S_ISDIR(info.st_mode)
                row = {"name": entry.name, "path": str(child), "kind": "directory" if directory else "file",
                       "size_bytes": None if directory else info.st_size, "modified_ns": info.st_mtime_ns}
                encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                cost = sys.getsizeof(encoded) + 8  # Immutable bytes plus its tuple reference.
                if memory_bytes + cost > MAX_CACHE_BYTES:
                    complete = False
                    break
                records.append(((not directory, entry.name.casefold(), entry.name), encoded))
                memory_bytes += cost
            except (OSError, WorkspaceDenied):
                skipped += 1
    _cancelled(cancel)
    _, after = _directory(str(path), state_dir)
    if after != signature:
        raise _ListingError("DIRECTORY_CHANGED")
    records.sort(key=lambda record: record[0])
    return manager._publish(str(path), owner, scope, signature, [record[1] for record in records],
                            skipped, scanned, complete, memory_bytes)


def _assert_current(snapshot, cancel, state_dir, manager):
    _cancelled(cancel)
    try:
        _, signature = _directory(snapshot.path, state_dir)
        if signature != snapshot.signature:
            raise ValueError()
    except (OSError, WorkspaceDenied, ValueError):
        manager._discard(snapshot.identifier)
        raise _ListingError("DIRECTORY_CHANGED") from None
    if manager.clock() >= snapshot.expires_at:
        manager._discard(snapshot.identifier)
        raise _ListingError("DIRECTORY_CURSOR_EXPIRED")


def _page(snapshot, start, limit, cancel):
    total = len(snapshot.rows)
    result = {"path": snapshot.path,
              "parent": str(Path(snapshot.path).parent) if Path(snapshot.path).parent != Path(snapshot.path) else "",
              "entries": [], "truncated": not snapshot.complete, "skipped_entries": snapshot.skipped,
              "scanned_entries": snapshot.scanned,
              "directory_identity": {"device": snapshot.signature[0], "file": snapshot.signature[1]},
              "snapshot_id": snapshot.identifier, "page_start": start, "snapshot_total": total,
              "scan_complete": snapshot.complete, "next_cursor": None}
    base_bytes = len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    entry_bytes = 0
    for encoded in snapshot.rows[start:start + limit]:
        _cancelled(cancel)
        end = start + len(result["entries"]) + 1
        cursor = f"{snapshot.identifier}:{end}" if end < total else None
        truncated = end < total or not snapshot.complete
        added_bytes = len(encoded) + bool(result["entries"])
        cursor_delta = len(json.dumps(cursor)) - 4  # Header initially contains JSON null.
        truncated_delta = len(str(truncated).lower()) - len(str(result["truncated"]).lower())
        if base_bytes + entry_bytes + added_bytes + cursor_delta + truncated_delta > MAX_PAGE_BYTES:
            break
        result["entries"].append(json.loads(encoded))
        entry_bytes += added_bytes
    end = start + len(result["entries"])
    if not result["entries"] and start < total:
        raise _ListingError("DIRECTORY_PAGE_LIMIT")
    result["next_cursor"] = f"{snapshot.identifier}:{end}" if end < total else None
    result["truncated"] = end < total or not snapshot.complete
    if len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_PAGE_BYTES:
        raise _ListingError("DIRECTORY_PAGE_LIMIT")
    return result


def execute_directory_page(parameters, cancel, *, state_dir=None, manager=None, owner_id=""):
    """Return a bounded observation; owner is injected by the authenticated bridge."""
    manager = _MANAGER if manager is None else manager
    try:
        raw, limit, identifier, start, owner = _parameters(parameters, owner_id)
        _cancelled(cancel)
        if not raw:
            report = _roots(cancel, state_dir)
            result = report["result"]
            result.update(snapshot_id=None, page_start=0, snapshot_total=len(result["entries"]),
                          scan_complete=True, next_cursor=None, skipped_entries=0, scanned_entries=len(result["entries"]))
            return report
        if identifier is None:
            snapshot = _capture(raw, owner, cancel, state_dir, manager)
        else:
            snapshot = manager._get(identifier)
            if snapshot.owner != owner or snapshot.path_key != _key(raw) or snapshot.scope != _scope(state_dir):
                raise _ListingError("DIRECTORY_CURSOR_MISMATCH")
            if start >= len(snapshot.rows):
                raise _ListingError("INVALID_PARAMETERS")
        _assert_current(snapshot, cancel, state_dir, manager)
        result = _page(snapshot, start, limit, cancel)
        _assert_current(snapshot, cancel, state_dir, manager)
        return _success(result)
    except _ListingError as error:
        return _failure(error.code, _MESSAGES[error.code])
    except _Cancelled:
        return _failure("CANCELLED", "Directory listing was cancelled", state="cancelled")
    except WorkspaceDenied:
        return _failure("POLICY_DENIED", "The selected directory is not available to project tools")
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "The selected directory does not exist")
    except PermissionError:
        return _failure("ACCESS_DENIED", "The Windows user cannot list the selected directory")
    except NotADirectoryError:
        return _failure("NOT_A_DIRECTORY", "The selected path is not a directory")
    except OSError:
        return _failure("FILESYSTEM_ERROR", "The directory listing could not be completed")
    except (ValueError, TypeError, KeyError):
        return _failure("INVALID_PARAMETERS", "Directory paging parameters are invalid")
