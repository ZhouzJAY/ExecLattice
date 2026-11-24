"""Desktop file operations in the authenticated user's ordinary filesystem.

Read-only/full is a simple product mode, not an operating-system sandbox. Full
development commands can access everything the current user can access. These
file tools reject ambiguous paths and protect the app's own state from accidental
editing; they never claim to constrain an independently authorized command.
"""

from __future__ import annotations

import base64
import contextlib
import fnmatch
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import threading
import time
import warnings
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

from .development_protocol import (
    MAX_EDIT_FILE_BYTES,
    MAX_FILE_OPERATION_BYTES,
    MAX_READ_MANY_BYTES,
    MAX_READ_MANY_RESULT_BYTES,
    MAX_SOURCE_IMAGE_BYTES,
    MAX_SOURCE_IMAGE_PIXELS,
    MAX_TEXT_BYTES,
    MAX_WORKSPACE_IMAGE_BYTES,
    validate_workspace_parameters,
)
from .file_text import decode_range, text_format

MAX_RESULT_BYTES = 180000
MAX_SEARCH_FILES = 10000
MAX_SEARCH_DIRECTORIES = 2000
MAX_SEARCH_BYTES = 16 * 1024 * 1024
MAX_SEARCH_FILE_BYTES = 1024 * 1024
MAX_SEARCH_SECONDS = 10
MAX_LIST_SCAN = 20000
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RESERVED = {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
_RESERVED.update(f"{prefix}{suffix}" for prefix in ("com", "lpt") for suffix in "123456789¹²³")
_WRITE_LOCK = threading.Lock()
_UNSCOPED_STATE = object()


class WorkspaceDenied(ValueError):
    pass


class _Cancelled(Exception):
    pass


class _AclPreservationError(OSError):
    pass


class _FileChanged(ValueError):
    pass


class _FileLimit(ValueError):
    pass


def _failure(code, message, *, state="failed"):
    return {"state": state, "result": None, "error": {"code": code, "message": message}}


def _success(result):
    return {"state": "succeeded", "result": result, "error": None}


def _cancelled(cancel):
    if cancel.is_set():
        raise _Cancelled()


def _link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE)


def _private_root(state_dir):
    if state_dir is None:
        return None
    root = Path(state_dir).absolute()
    if root.parent.name.lower() in {".execlattice", ".omniagent"}:
        root = root.parent
    return root


def _is_private(path, state_dir):
    private = _private_root(state_dir)
    return private is not None and path.is_relative_to(private)


def _no_link_ancestors(path, *, missing=False):
    """Validate the original spelling before native name expansion."""
    exists = True
    for ancestor in reversed((path, *path.parents)):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            if missing and ancestor == path:
                exists = False
                break
            raise
        if _link(info):
            raise WorkspaceDenied("Symbolic links and reparse points are not supported")
        if ancestor != path and not stat.S_ISDIR(info.st_mode):
            raise WorkspaceDenied("Path ancestor is not a directory")
    return exists


def _canonical_private_root(state_dir):
    """Canonicalize a state DEFINITION, including not-yet-created components.

    This never authorizes a request. A missing definition suffix has no native
    short alias yet; only its existing, no-link directory prefix is expanded.
    Ordinary requests do not use this multi-component definition handling.
    """
    from .executors import _windows_long_path

    current, suffix = Path(state_dir).absolute(), []
    while True:
        try:
            info = current.lstat()
            break
        except FileNotFoundError:
            part = current.name
            if (current == current.parent or part in {"", ".", ".."} or part.endswith((" ", "."))
                    or any(ord(c) < 32 or ord(c) == 127 or c in ':<>"|?*' for c in part)
                    or part.split(".", 1)[0].lower() in _RESERVED):
                raise WorkspaceDenied("Invalid application state path") from None
            suffix.append(part)
            current = current.parent
    _no_link_ancestors(current)
    if not stat.S_ISDIR(info.st_mode):
        raise WorkspaceDenied("Application state prefix is not a directory")
    expanded = _windows_long_path(current)
    _no_link_ancestors(current)
    expanded_info = expanded.lstat()
    if (_link(expanded_info) or not stat.S_ISDIR(expanded_info.st_mode)
            or (expanded_info.st_dev, expanded_info.st_ino) != (info.st_dev, info.st_ino)):
        raise WorkspaceDenied("Application state prefix changed during name verification")
    # Expand state_dir BEFORE identifying .execlattice/.omniagent's parent:
    # its short spelling must protect sibling controller/worker state too.
    return _private_root(expanded.joinpath(*reversed(suffix)))


def _checked_path(raw, state_dir=None, *, missing=False):
    if (not isinstance(raw, str) or not raw or len(raw) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in raw)
            or raw.startswith(("\\\\", "//"))):
        raise WorkspaceDenied("An ordinary absolute local path is required")
    path = Path(raw)
    if not path.is_absolute():
        raise WorkspaceDenied("An absolute local path is required")
    if os.name == "nt":
        windows = PureWindowsPath(raw)
        if not re.fullmatch(r"[A-Za-z]:", windows.drive) or windows.root != "\\":
            raise WorkspaceDenied("Only local drive paths are supported")
        lexical = raw[3:] if len(raw) > 2 and raw[2] in "/\\" else raw[2:]
    else:
        lexical = raw[1:]
        if "\\" in raw:
            raise WorkspaceDenied("Backslash paths are not supported on this host")
    for part in re.split(r"[\\/]", lexical):
        if not part:
            continue
        if (part in {".", ".."} or part.endswith((" ", "."))
                or any(c in ':<>"|?*' for c in part)
                or part.split(".", 1)[0].lower() in _RESERVED):
            raise WorkspaceDenied("Unsafe local path")
    path = path.absolute()
    if _is_private(path, state_dir):
        raise WorkspaceDenied("Application private state is not a project file")
    exists = _no_link_ancestors(path, missing=missing)
    canonical = None
    if os.name == "nt":
        from .executors import _windows_long_path

        # For create-only calls the parent must already exist. Never expand a
        # non-existing multi-component request or accept native API failures.
        canonical = _windows_long_path(path) if exists else _windows_long_path(path.parent) / path.name
        if state_dir is not None and canonical.is_relative_to(_canonical_private_root(state_dir)):
            raise WorkspaceDenied("Application private state is not a project file")
    return path, canonical


def _path(raw, state_dir=None, *, missing=False):
    return _checked_path(raw, state_dir, missing=missing)[0]


@contextlib.contextmanager
def _open_scoped_file(path: Path, state_dir):
    """Open one explicitly scoped file under a fixed private-checked name.

    ``state_dir`` is intentionally required. None means the caller knows no
    application-private root is configured; omission never grants alias access.
    The native handle cannot substitute its own name for this authorization.
    """
    from .executors import _open_verified

    requested, canonical = _checked_path(str(path), state_dir)
    with _open_verified(Path(requested.anchor), list(requested.parts[1:]),
                        expected_canonical=canonical) as opened:
        yield opened


def _read_bytes(path, limit, cancel, *, read_budget=None, state_dir=_UNSCOPED_STATE):
    # Reuse the handle-based read verification already exercised by the legacy
    # executor. Import inside the operation so the dispatcher can import us.
    from .executors import _open_verified

    anchor = Path(path.anchor)
    context = (_open_verified(anchor, list(path.parts[1:])) if state_dir is _UNSCOPED_STATE else
               _open_scoped_file(path, state_dir))
    with context as (fd, before):
        if before.st_size > limit:
            return None
        data = bytearray()
        while len(data) <= limit:
            _cancelled(cancel)
            count = min(16384, limit + 1 - len(data))
            if read_budget is not None:
                count = min(count, read_budget[0])
                if count == 0:
                    # The final fstat still detects growth or replacement. Do
                    # not spend an extra EOF probe byte beyond a batch budget.
                    if len(data) == before.st_size:
                        break
                    return None
            chunk = os.read(fd, count)
            if read_budget is not None:
                read_budget[0] -= len(chunk)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise WorkspaceDenied("File changed during the read")
        if len(data) > limit:
            return None
        return bytes(data), before


def _fits(result):
    return len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= MAX_RESULT_BYTES


def _roots(cancel, state_dir):
    if os.name == "nt":
        import ctypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetLogicalDrives.restype = ctypes.c_uint32
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel.GetDriveTypeW.restype = ctypes.c_uint32
        mask = kernel.GetLogicalDrives()
        # Mapped network drives are not ordinary local filesystem paths and
        # probing unavailable optical drives can block a simple browse action.
        candidates = [Path(f"{chr(65 + i)}:/") for i in range(26) if mask & (1 << i)
                      and kernel.GetDriveTypeW(f"{chr(65 + i)}:/") in {2, 3, 6}]
    else:
        candidates = [Path("/")]
    entries = []
    for path in candidates:
        _cancelled(cancel)
        try:
            _path(str(path), state_dir)
            if path.is_dir():
                entries.append({"name": str(path), "path": str(path), "kind": "drive",
                                "size_bytes": None, "modified_ns": None})
        except (OSError, WorkspaceDenied):
            continue
    return _success({"path": "", "parent": None, "entries": entries, "truncated": False})


def _list(parameters, cancel, state_dir):
    if not parameters["path"]:
        return _roots(cancel, state_dir)
    path = _path(parameters["path"], state_dir)
    before = path.stat()
    if not stat.S_ISDIR(before.st_mode):
        return _failure("NOT_A_DIRECTORY", "The selected path is not a directory")
    result = {"path": str(path), "parent": str(path.parent) if path != path.parent else "",
              "entries": [], "truncated": False, "skipped_entries": 0}
    deadline = time.monotonic() + MAX_SEARCH_SECONDS
    with os.scandir(path) as iterator:
        for count, entry in enumerate(iterator):
            _cancelled(cancel)
            if count >= MAX_LIST_SCAN or time.monotonic() >= deadline:
                result["truncated"] = True
                break
            try:
                child = _path(entry.path, state_dir)
                # Windows DirEntry caches may report an unknown link count.
                # A fresh stat also makes omitted hardlinks visible to the
                # directory manifest instead of presenting an unreadable file.
                info = child.lstat()
                if (_link(info) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    result["skipped_entries"] += 1
                    continue
                row = {"name": entry.name, "path": str(child),
                       "kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
                       "size_bytes": info.st_size if stat.S_ISREG(info.st_mode) else None,
                       "modified_ns": info.st_mtime_ns}
                if len(result["entries"]) >= parameters["limit"]:
                    result["truncated"] = True
                    break
                result["entries"].append(row)
                if not _fits(result):
                    result["entries"].pop()
                    result["truncated"] = True
                    break
            except (OSError, WorkspaceDenied):
                result["skipped_entries"] += 1
                continue
    after = _path(str(path), state_dir).stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise WorkspaceDenied("Directory changed during listing")
    result["entries"].sort(key=lambda row: (row["kind"] != "directory", row["name"].casefold()))
    return _success(result)


def _text_read(parameters, cancel, state_dir):
    path = _path(parameters["path"], state_dir)
    loaded = _read_bytes(path, MAX_TEXT_BYTES, cancel, state_dir=state_dir)
    if loaded is None:
        return _failure("FILE_TOO_LARGE", "Text editing supports files up to 64 KiB")
    content, _ = loaded
    try:
        if b"\x00" in content:
            raise UnicodeError()
        content.decode("utf-8-sig")
    except UnicodeError:
        return _failure("FILE_NOT_TEXT", "The selected file is not UTF-8 text")
    return _success({"path": str(path), "content_b64": base64.b64encode(content).decode("ascii"),
                     "encoding": "base64", "text_encoding": "utf-8", "size_bytes": len(content),
                     "sha256": hashlib.sha256(content).hexdigest()})


def _batch_error(path, code, message):
    return {"path": path, "state": "failed", "result": None, "error": {"code": code, "message": message}}


def _read_many(parameters, cancel, state_dir):
    from .executors import ExecutionDenied
    from .project_evidence import readable_many_result

    # Preallocate one explicit receipt per input, including those not read
    # because an earlier item exhausted the shared byte or response budget.
    rows = [_batch_error(item["path"], "BATCH_READ_LIMIT", "The shared read budget is exhausted")
            for item in parameters["files"]]
    budget = [MAX_READ_MANY_BYTES]
    for index, item in enumerate(parameters["files"]):
        _cancelled(cancel)
        raw_path = item["path"]
        try:
            path = _path(raw_path, state_dir)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                rows[index] = _batch_error(raw_path, "NOT_A_FILE", "The selected path is not a regular file")
                continue
            if info.st_size > MAX_TEXT_BYTES:
                rows[index] = _batch_error(raw_path, "FILE_TOO_LARGE", "Use read_file_range for files over 64 KiB")
                continue
            loaded = _read_bytes(path, min(MAX_TEXT_BYTES, budget[0]), cancel, read_budget=budget, state_dir=state_dir)
            if loaded is None:
                continue
            content, _ = loaded
            try:
                encoding, bom = text_format(content, item["encoding"])
                _, consumed = decode_range(content, encoding, bom, 0)
                if consumed != len(content):
                    raise UnicodeError()
            except UnicodeError:
                rows[index] = _batch_error(raw_path, "FILE_NOT_TEXT", "Choose the correct text encoding")
                continue
            row = {"path": raw_path, "state": "succeeded", "error": None, "result": {
                "content_b64": base64.b64encode(content).decode("ascii"), "encoding": "base64",
                "text_encoding": encoding, "bom_bytes": bom, "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }}
            rows[index] = row
            candidate = {"files": rows, "total_read_bytes": MAX_READ_MANY_BYTES - budget[0],
                         "returned_bytes": sum(r["result"]["size_bytes"] for r in rows if r["result"] is not None),
                         "complete": all(r["state"] == "succeeded" for r in rows)}
            # JSON escaping can make decoded text larger than its base64
            # receipt. Both representations must fit, without truncating text.
            if (not _fits(candidate) or len(json.dumps(readable_many_result(candidate), ensure_ascii=False,
                                                       separators=(",", ":")).encode("utf-8")) > MAX_READ_MANY_RESULT_BYTES):
                rows[index] = _batch_error(raw_path, "RESULT_LIMIT", "The full text would exceed the batch response limit")
        except (WorkspaceDenied, ExecutionDenied):
            rows[index] = _batch_error(raw_path, "POLICY_DENIED", "The selected path is not available to project tools")
        except FileNotFoundError:
            rows[index] = _batch_error(raw_path, "FILE_NOT_FOUND", "The selected file does not exist")
        except PermissionError:
            rows[index] = _batch_error(raw_path, "ACCESS_DENIED", "The current user cannot read the selected file")
        except IsADirectoryError:
            rows[index] = _batch_error(raw_path, "NOT_A_FILE", "The selected path is not a regular file")
        except OSError:
            rows[index] = _batch_error(raw_path, "FILESYSTEM_ERROR", "The selected file could not be read")
    return _success({"files": rows, "total_read_bytes": MAX_READ_MANY_BYTES - budget[0],
                     "returned_bytes": sum(r["result"]["size_bytes"] for r in rows if r["result"] is not None),
                     "complete": all(r["state"] == "succeeded" for r in rows)})


def _read_range(parameters, cancel, state_dir):
    path = _path(parameters["path"], state_dir)
    loaded = _read_bytes(path, MAX_EDIT_FILE_BYTES, cancel, state_dir=state_dir)
    if loaded is None:
        return _failure("FILE_TOO_LARGE", "Range reading supports files up to 8 MiB")
    content, _ = loaded
    digest = hashlib.sha256(content).hexdigest()
    expected = parameters["expected_sha256"]
    if expected is not None and expected != digest:
        return _failure("FILE_CONFLICT", "File changed; restart reading from its current version")
    offset = parameters["offset"]
    if offset > len(content):
        return _failure("INVALID_TEXT_RANGE", "The requested offset is beyond the end of the file")
    end = min(len(content), offset + parameters["limit"])
    data = content[offset:end]
    encoding, bom_bytes = "binary", 0
    if parameters["encoding"] != "binary":
        try:
            encoding, bom_bytes = text_format(content, parameters["encoding"])
            _, consumed = decode_range(data, encoding, bom_bytes, offset, final=end == len(content))
            data = data[:consumed]
            end = offset + consumed
        except UnicodeError:
            return _failure("INVALID_TEXT_RANGE", "Choose the correct text encoding and use the previous next_offset")
    return _success({
        "path": str(path), "data_b64": base64.b64encode(data).decode("ascii"),
        "data_sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
        "file_size_bytes": len(content), "sha256": digest,
        "offset": offset, "next_offset": end, "eof": end == len(content),
        "text_encoding": encoding, "bom_bytes": bom_bytes,
    })


def _edit(parameters, cancel, state_dir):
    path = _path(parameters["path"], state_dir)
    loaded = _read_bytes(path, MAX_EDIT_FILE_BYTES, cancel, state_dir=state_dir)
    if loaded is None:
        return _failure("FILE_TOO_LARGE", "Precise editing supports files up to 8 MiB")
    content, _ = loaded
    if hashlib.sha256(content).hexdigest() != parameters["expected_sha256"]:
        return _failure("FILE_CONFLICT", "File changed; reload before editing")
    try:
        encoding, bom_bytes = text_format(content, parameters["encoding"])
        text, _ = decode_range(content, encoding, bom_bytes, 0)
        old, new = parameters["old_text"], parameters["new_text"]
        # Uniform CRLF files retain their line ending when a model supplies
        # ordinary LF text. Mixed-line-ending files are matched literally.
        if "\r\n" in text and "\n" not in text.replace("\r\n", "") and "\r" not in text.replace("\r\n", ""):
            old = old.replace("\r\n", "\n").replace("\n", "\r\n")
            new = new.replace("\r\n", "\n").replace("\n", "\r\n")
        count = text.count(old)
        if count != 1:
            return _failure("EDIT_NOT_UNIQUE", "The old text must occur exactly once; read a larger unique context")
        replacement = content[:bom_bytes] + text.replace(old, new, 1).encode(encoding)
    except UnicodeError:
        return _failure("FILE_NOT_TEXT", "The file or replacement is not valid in the selected text encoding")
    if len(replacement) > MAX_EDIT_FILE_BYTES:
        return _failure("FILE_TOO_LARGE", "The edited file would exceed 8 MiB")
    report = _save(str(path), replacement, parameters["expected_sha256"], cancel, state_dir,
                   file_limit=MAX_EDIT_FILE_BYTES)
    if report["state"] == "succeeded":
        report["result"].update(previous_sha256=parameters["expected_sha256"], replacements=1,
                                text_encoding=encoding)
    return report


def _search(parameters, cancel, state_dir):
    from .executors import ExecutionDenied

    path = _path(parameters["path"], state_dir)
    if not path.is_dir():
        return _failure("NOT_A_DIRECTORY", "Search requires a directory")
    result = {"path": str(path), "matches": [], "truncated": False, "scanned_files": 0, "skipped_files": 0}
    pending, seen_dirs, scanned_bytes = [path], 0, 0
    deadline = time.monotonic() + MAX_SEARCH_SECONDS
    query = parameters["query"] if parameters["case_sensitive"] else parameters["query"].casefold()
    while pending:
        _cancelled(cancel)
        if (seen_dirs >= MAX_SEARCH_DIRECTORIES or time.monotonic() >= deadline
                or result["scanned_files"] >= MAX_SEARCH_FILES or scanned_bytes >= MAX_SEARCH_BYTES):
            result["truncated"] = True
            break
        directory = pending.pop()
        seen_dirs += 1
        try:
            _path(str(directory), state_dir)
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    _cancelled(cancel)
                    if (time.monotonic() >= deadline or result["scanned_files"] >= MAX_SEARCH_FILES
                            or scanned_bytes >= MAX_SEARCH_BYTES):
                        result["truncated"] = True
                        return _success(result)
                    try:
                        child = _path(entry.path, state_dir)
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if seen_dirs + len(pending) >= MAX_SEARCH_DIRECTORIES:
                                result["truncated"] = True
                            else:
                                pending.append(child)
                            continue
                        if not stat.S_ISREG(info.st_mode) or not fnmatch.fnmatch(entry.name, parameters["glob"]):
                            continue
                        # Windows scandir may leave st_nlink as 0 (unknown);
                        # the opened handle check still verifies it exactly.
                        if info.st_nlink > 1:
                            result["skipped_files"] += 1
                            continue
                        result["scanned_files"] += 1
                        loaded = _read_bytes(child, min(MAX_SEARCH_FILE_BYTES, MAX_SEARCH_BYTES - scanned_bytes), cancel,
                                             state_dir=state_dir)
                        if loaded is None:
                            result["skipped_files"] += 1
                            continue
                        content, _ = loaded
                        scanned_bytes += len(content)
                        if b"\x00" in content:
                            raise UnicodeError()
                        text = content.decode("utf-8-sig")
                        for number, line in enumerate(text.splitlines(), 1):
                            _cancelled(cancel)
                            comparable = line if parameters["case_sensitive"] else line.casefold()
                            position = comparable.find(query)
                            if position < 0:
                                continue
                            # Return a bounded excerpt around the match instead
                            # of allowing one generated line to fill a report.
                            start = max(0, position - 60)
                            excerpt = line[start:start + 256]
                            row = {"path": str(child), "line_number": number, "line": excerpt}
                            if len(result["matches"]) >= parameters["max_results"]:
                                result["truncated"] = True
                                return _success(result)
                            result["matches"].append(row)
                            if not _fits(result):
                                result["matches"].pop()
                                result["truncated"] = True
                                return _success(result)
                    except (OSError, UnicodeError, WorkspaceDenied, ExecutionDenied):
                        result["skipped_files"] += 1
        except (OSError, WorkspaceDenied):
            result["skipped_files"] += 1
    return _success(result)


def _file_signature(path, cancel, limit=MAX_TEXT_BYTES, *, state_dir=_UNSCOPED_STATE):
    loaded = _read_bytes(path, limit, cancel, state_dir=state_dir)
    if loaded is None:
        return None
    content, info = loaded
    return hashlib.sha256(content).hexdigest(), (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns), info


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _stream_digest(fd, before, cancel, output=None):
    """Hash one verified ordinary file without materializing it in memory."""
    if before.st_size > MAX_FILE_OPERATION_BYTES:
        raise _FileLimit()
    digest, total = hashlib.sha256(), 0
    while True:
        _cancelled(cancel)
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_OPERATION_BYTES:
            raise _FileLimit()
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    if total != before.st_size or _identity(os.fstat(fd)) != _identity(before):
        raise _FileChanged()
    return digest.hexdigest()


def _binary_signature(path, cancel, state_dir):
    with _open_scoped_file(path, state_dir) as (fd, before):
        digest = _stream_digest(fd, before, cancel)
        if _identity(_path(str(path), state_dir).stat()) != _identity(before):
            raise _FileChanged()
        return digest, _identity(before), before


def _stat(parameters, cancel, state_dir):
    from .file_management import metadata_info, path_version

    path = _path(parameters["path"], state_dir)
    info = path.stat()
    if stat.S_ISDIR(info.st_mode):
        info = metadata_info(path, state_dir, directory=True)
        return _success({"path": str(path), "kind": "directory", "size_bytes": None,
                         "sha256": None, "modified_ns": info.st_mtime_ns,
                         "path_version": path_version(path, info, None),
                         "directory_identity": {"device": info.st_dev, "file": info.st_ino}})
    signature = _binary_signature(path, cancel, state_dir)
    return _success({"path": str(path), "kind": "file", "size_bytes": signature[2].st_size,
                     "sha256": signature[0], "modified_ns": signature[2].st_mtime_ns,
                     "path_version": path_version(path, signature[2], signature[0])})


def _mkdir(parameters, cancel, state_dir):
    with _WRITE_LOCK:
        path = _path(parameters["path"], state_dir, missing=True)
        parent = _path(str(path.parent), state_dir)
        parent_identity = parent.stat()
        _cancelled(cancel)
        try:
            path.mkdir()
        except FileExistsError:
            current = _path(str(path), state_dir)
            if not parameters["exist_ok"] or not current.is_dir():
                return _failure("FILE_CONFLICT", "The selected path already exists")
            created = False
        else:
            created = True
        try:
            current = _path(str(path), state_dir)
            after = _path(str(parent), state_dir).stat()
            if not current.is_dir() or (after.st_dev, after.st_ino) != (parent_identity.st_dev, parent_identity.st_ino):
                raise WorkspaceDenied("Created directory changed")
        except Exception:
            return _failure("DIRECTORY_CHANGED", "Directory creation could not be confirmed", state="unknown")
        info = current.stat()
        return _success({"path": str(path), "kind": "directory", "created": created,
                         "directory_identity": {"device": info.st_dev, "file": info.st_ino}})


def _copy(parameters, cancel, state_dir):

    with _WRITE_LOCK:
        source = _path(parameters["path"], state_dir)
        target = _path(parameters["destination"], state_dir, missing=True)
        if source == target:
            return _failure("FILE_CONFLICT", "Source and destination must differ")
        parent = _path(str(target.parent), state_dir)
        parent_identity = parent.stat()
        expected_target = parameters["expected_target_sha256"]
        original = None
        if target.exists():
            if expected_target is None:
                return _failure("FILE_CONFLICT", "Destination exists; read its current version before replacing")
            original = _binary_signature(target, cancel, state_dir)
            if original[0] != expected_target:
                return _failure("FILE_CONFLICT", "Destination changed; read its current version")
            if os.name == "nt" and not original[2].st_mode & stat.S_IWRITE:
                return _failure("ACCESS_DENIED", "Destination has the Windows read-only attribute")
        elif expected_target is not None:
            return _failure("FILE_CONFLICT", "Destination no longer exists")
        descriptor, temporary = tempfile.mkstemp(prefix=".execlattice-copy-", dir=parent)
        staged = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as output:
                with _open_scoped_file(source, state_dir) as (fd, before):
                    digest = _stream_digest(fd, before, cancel, output)
                    if (digest != parameters["expected_sha256"]
                            or _identity(_path(str(source), state_dir).stat()) != _identity(before)):
                        return _failure("FILE_CONFLICT", "Source changed; read its current version")
                output.flush()
                os.fsync(output.fileno())
            acl_identity = None
            if original is not None:
                os.chmod(staged, stat.S_IMODE(original[2].st_mode))
                if os.name == "nt":
                    acl_identity = _copy_windows_dacl(target, staged)
            _cancelled(cancel)
            current = _path(str(target), state_dir, missing=True)
            now_parent = _path(str(parent), state_dir).stat()
            if ((now_parent.st_dev, now_parent.st_ino) != (parent_identity.st_dev, parent_identity.st_ino)
                    or current.parent != staged.parent):
                raise WorkspaceDenied("Copy directory changed")
            if original is None:
                try:
                    os.link(staged, current)
                except FileExistsError:
                    return _failure("FILE_CONFLICT", "Destination was created by another operation")
            else:
                if not current.exists() or _binary_signature(current, cancel, state_dir)[:2] != original[:2]:
                    return _failure("FILE_CONFLICT", "Destination changed during copying")
                if acl_identity is not None and _windows_dacl(current)[2] != acl_identity:
                    raise _AclPreservationError("Destination permissions changed during copying")
                os.replace(staged, current)
            return _success({"path": str(source), "destination": str(target), "size_bytes": before.st_size,
                             "sha256": digest, "source_preserved": True, "created": original is None,
                             "previous_target_sha256": expected_target})
        finally:
            with contextlib.suppress(FileNotFoundError):
                staged.unlink()


def _rename_no_replace(source, target):
    """Atomic same-volume, create-only rename; never emulate it by delete/copy."""
    if os.name == "nt":
        os.rename(source, target)
        return
    if os.name == "posix":
        import ctypes
        import errno

        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise OSError(errno.ENOTSUP, "Atomic create-only rename is unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1):
            number = ctypes.get_errno()
            raise OSError(number, "Atomic create-only rename failed")
        return
    raise OSError("Atomic create-only rename is unavailable")


def _windows_move_locked(source, target, expected, cancel, state_dir):
    """Hash and rename the same write/delete-locked Windows file handle.

    Rename information uses ReplaceIfExists=False. Holding a destination parent
    handle without delete sharing also prevents a directory/junction swap while
    the new path is resolved. No other process or arbitrary path is terminated.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    from .executors import _windows_final_path

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    parent_handle = kernel.CreateFileW(str(target.parent), 0x80, 0x3, None, 3, 0x02200000, None)
    if parent_handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    source_handle = None
    descriptor = None
    try:
        _path(str(target.parent), state_dir)
        source_handle = kernel.CreateFileW(str(source), 0x80010000, 0x1, None, 3, 0x00200000, None)
        if source_handle == invalid:
            source_handle = None
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = msvcrt.open_osfhandle(source_handle, os.O_RDONLY | os.O_BINARY)
        source_handle = None  # The CRT descriptor now owns this exact handle.
        if os.path.normcase(str(_windows_final_path(descriptor))) != os.path.normcase(str(source)):
            raise WorkspaceDenied("Move source handle changed")
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _link(before):
            raise WorkspaceDenied("Only an ordinary single-link file can be moved")
        if _stream_digest(descriptor, before, cancel) != expected:
            return _failure("FILE_CONFLICT", "Source changed; read its current version")
        _cancelled(cancel)
        _path(str(source), state_dir)
        _path(str(target), state_dir, missing=True)
        if _identity(source.stat()) != _identity(before):
            return _failure("FILE_CONFLICT", "Move source identity changed")
        if before.st_dev != target.parent.stat().st_dev:
            return _failure("CROSS_VOLUME_MOVE", "Only same-volume moves are supported")
        encoded = str(target).encode("utf-16-le")

        class RenameInformation(ctypes.Structure):
            _fields_ = [("Flags", wintypes.DWORD), ("RootDirectory", wintypes.HANDLE),
                        ("FileNameLength", wintypes.DWORD), ("FileName", wintypes.WCHAR * (len(encoded) // 2 + 1))]

        information = RenameInformation()
        information.Flags = 0  # FileRenameInfo: first BOOLEAN is ReplaceIfExists=False.
        information.FileNameLength = len(encoded)
        ctypes.memmove(ctypes.addressof(information) + RenameInformation.FileName.offset, encoded, len(encoded))
        if not kernel.SetFileInformationByHandle(msvcrt.get_osfhandle(descriptor), 3,
                                                ctypes.byref(information), ctypes.sizeof(information)):
            code = ctypes.get_last_error()
            if code in {80, 183}:
                return _failure("FILE_CONFLICT", "Destination was created by another operation")
            raise ctypes.WinError(code)
        try:
            if (os.path.normcase(str(_windows_final_path(descriptor))) != os.path.normcase(str(target))
                    or _identity(os.fstat(descriptor)) != _identity(before)
                    or _identity(_path(str(target), state_dir).stat()) != _identity(before)
                    or source.exists()):
                raise _FileChanged()
        except Exception:
            return _failure("MOVE_UNCONFIRMED", "Move result could not be verified; inspect both original paths",
                            state="unknown")
        return _success({"path": str(source), "destination": str(target), "size_bytes": before.st_size,
                         "sha256": expected, "source_removed": True, "created": True})
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if source_handle is not None:
            kernel.CloseHandle(source_handle)
        kernel.CloseHandle(parent_handle)


def _move(parameters, cancel, state_dir):
    with _WRITE_LOCK:
        source = _path(parameters["path"], state_dir)
        target = _path(parameters["destination"], state_dir, missing=True)
        parent = _path(str(target.parent), state_dir)
        if source == target or target.exists():
            return _failure("FILE_CONFLICT", "Destination must be a different, absent path")
        if os.name == "nt":
            return _windows_move_locked(source, target, parameters["expected_sha256"], cancel, state_dir)
        original = _binary_signature(source, cancel, state_dir)
        if original[0] != parameters["expected_sha256"]:
            return _failure("FILE_CONFLICT", "Source changed; read its current version")
        if original[2].st_dev != parent.stat().st_dev:
            return _failure("CROSS_VOLUME_MOVE", "Only same-volume moves are supported; use copy for another volume")
        parent_identity = parent.stat()
        _cancelled(cancel)
        _path(str(target), state_dir, missing=True)
        if _identity(_path(str(source), state_dir).stat()) != original[1]:
            return _failure("FILE_CONFLICT", "Source changed before moving")
        current_parent = _path(str(parent), state_dir).stat()
        if (current_parent.st_dev, current_parent.st_ino) != (parent_identity.st_dev, parent_identity.st_ino):
            raise WorkspaceDenied("Move directory changed")
        try:
            _rename_no_replace(source, target)
        except FileExistsError:
            return _failure("FILE_CONFLICT", "Destination was created by another operation")
        # Verify the moved identity and bytes. If an external writer raced the
        # rename, report uncertainty; never try to move an unknown file back.
        try:
            moved = _binary_signature(_path(str(target), state_dir), cancel, state_dir)
            if source.exists() or moved[:2] != original[:2]:
                raise _FileChanged()
        except Exception:
            return _failure("MOVE_UNCONFIRMED", "Move result could not be verified; inspect both original paths",
                            state="unknown")
        return _success({"path": str(source), "destination": str(target), "size_bytes": original[2].st_size,
                         "sha256": original[0], "source_removed": True, "created": True})


def _read_image(parameters, cancel, state_dir):
    from PIL import Image, ImageOps, UnidentifiedImageError

    path = _path(parameters["path"], state_dir)
    loaded = _read_bytes(path, MAX_SOURCE_IMAGE_BYTES, cancel, state_dir=state_dir)
    if loaded is None:
        return _failure("FILE_TOO_LARGE", "Image viewing supports source files up to 16 MiB")
    content, _ = loaded
    digest = hashlib.sha256(content).hexdigest()
    if parameters["expected_sha256"] is not None and parameters["expected_sha256"] != digest:
        return _failure("FILE_CONFLICT", "Image changed; read its current version")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(content)) as source:
                source_size, source_format = source.size, source.format
                if (source_format not in {"PNG", "JPEG", "GIF", "WEBP", "BMP", "TIFF"}
                        or not 1 <= source.width <= 32768 or not 1 <= source.height <= 32768
                        or source.width * source.height > MAX_SOURCE_IMAGE_PIXELS):
                    return _failure("IMAGE_LIMIT", "The image dimensions or format exceed the viewer limits")
                source.seek(0)
                source.load()
                _cancelled(cancel)
                oriented = ImageOps.exif_transpose(source)
                if oriented.mode == "RGBA" or oriented.mode == "P" and "transparency" in oriented.info:
                    image = Image.new("RGB", oriented.size, "white")
                    alpha = oriented.convert("RGBA")
                    image.paste(alpha, mask=alpha.getchannel("A"))
                else:
                    image = oriented.convert("RGB")
                image.thumbnail((parameters["max_width"], parameters["max_height"]), Image.Resampling.LANCZOS)
                for _ in range(6):
                    for quality in (85, 65, 45, 25):
                        _cancelled(cancel)
                        output = io.BytesIO()
                        image.save(output, "JPEG", quality=quality, optimize=False)
                        raw = output.getvalue()
                        if len(raw) <= MAX_WORKSPACE_IMAGE_BYTES:
                            return _success({
                                "path": str(path), "artifact_type": "image", "source_file_sha256": digest,
                                "source_size_bytes": len(content), "source_width": source_size[0],
                                "source_height": source_size[1], "source_format": source_format, "frame_index": 0,
                                "image_b64": base64.b64encode(raw).decode("ascii"),
                                "image_sha256": hashlib.sha256(raw).hexdigest(), "mime_type": "image/jpeg",
                                "width": image.width, "height": image.height, "control_ready": False,
                                "observed_at": datetime.now(UTC).isoformat(),
                            })
                    image = image.resize((max(1, image.width * 3 // 4), max(1, image.height * 3 // 4)),
                                         Image.Resampling.LANCZOS)
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        return _failure("FILE_NOT_IMAGE", "The selected file is not a supported, decodable image")
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        return _failure("IMAGE_LIMIT", "The image exceeds safe decoding limits")
    return _failure("IMAGE_LIMIT", "The image preview could not fit the bounded transfer size")


def _windows_security_api():
    """Only ordinary DACL access; no owner, SACL or elevated privileges."""
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.GetFileSecurityW.restype = wintypes.BOOL
    api.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                 ctypes.POINTER(wintypes.DWORD)]
    api.GetSecurityDescriptorControl.restype = wintypes.BOOL
    api.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    api.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    api.SetFileSecurityW.restype = wintypes.BOOL
    return api


def _windows_dacl(path):
    """Return an owned descriptor and its DACL identity/protection flag."""
    import ctypes
    from ctypes import wintypes

    api = _windows_security_api()
    required = wintypes.DWORD()
    api.GetFileSecurityW(str(path), 0x4, None, 0, ctypes.byref(required))
    if not 20 <= required.value <= 131072:
        raise _AclPreservationError("Cannot determine existing file permissions")
    descriptor = ctypes.create_string_buffer(required.value)
    if not api.GetFileSecurityW(str(path), 0x4, descriptor, len(descriptor), ctypes.byref(required)):
        raise _AclPreservationError("Cannot read existing file permissions")
    control, revision = wintypes.WORD(), wintypes.DWORD()
    present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
    if (not api.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
            or not api.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                  ctypes.byref(dacl), ctypes.byref(defaulted))):
        raise _AclPreservationError("Cannot inspect existing file permissions")
    if not present.value:
        # Do not silently substitute a present NULL DACL for an absent DACL.
        raise _AclPreservationError("Cannot preserve an absent file DACL")
    raw = None
    if dacl.value:
        begin, end = ctypes.addressof(descriptor), ctypes.addressof(descriptor) + len(descriptor)
        if not begin <= dacl.value <= end - 8:
            raise _AclPreservationError("Invalid file permission descriptor")
        size = ctypes.c_ushort.from_address(dacl.value + 2).value
        if size < 8 or dacl.value + size > end:
            raise _AclPreservationError("Invalid file permission descriptor")
        raw = ctypes.string_at(dacl.value, size)
    return descriptor, dacl, (bool(control.value & 0x1000), raw)


def _copy_windows_dacl(source, staged):
    """Preserve existing DACL and inheritance behavior before atomic publish.

    Setting the ordinary DACL on our own temporary file needs no SACL access.
    Exact read-back verification fails closed if Windows changes the ACL while
    applying it. The source file is never modified by this operation.
    """
    descriptor, _, identity = _windows_dacl(source)
    information = 0x4 | (0x80000000 if identity[0] else 0x20000000)
    api = _windows_security_api()
    # The compatibility API preserves the supplied ACL rather than appending
    # inherited ACEs to an unprotected ACL as SetNamedSecurityInfo would. Read
    # back both ACL and protection state; no success is inferred from BOOL alone.
    if not api.SetFileSecurityW(str(staged), information, descriptor):
        raise _AclPreservationError("Cannot apply the existing file permissions")
    if _windows_dacl(staged)[2] != identity:
        raise _AclPreservationError("File permission preservation could not be verified")
    return identity


def _write(parameters, cancel, state_dir):
    content = base64.b64decode(parameters["content_b64"], validate=True)
    expected = parameters["expected_sha256"]
    return _save(parameters["path"], content, expected, cancel, state_dir)


def _save(raw_path, content, expected, cancel, state_dir, *, file_limit=MAX_TEXT_BYTES):
    # Tasks are already serialized per Worker. This lock additionally prevents
    # two local adapters from racing the same replacement in one process.
    with _WRITE_LOCK:
        _cancelled(cancel)
        path = _path(raw_path, state_dir, missing=True)
        _path(str(path.parent), state_dir)
        original = None
        if path.exists():
            if expected is None:
                return _failure("FILE_CONFLICT", "File already exists; reload before saving")
            original = _file_signature(path, cancel, file_limit, state_dir=state_dir)
            if original is None or original[0] != expected:
                return _failure("FILE_CONFLICT", "File changed; reload before saving")
            if os.name == "nt" and not original[2].st_mode & stat.S_IWRITE:
                return _failure("ACCESS_DENIED", "The file has the Windows read-only attribute")
        elif expected is not None:
            return _failure("FILE_CONFLICT", "File no longer exists; reload before saving")
        descriptor, temporary = tempfile.mkstemp(prefix=".execlattice-save-", dir=path.parent)
        staged = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if original is not None:
                os.chmod(staged, stat.S_IMODE(original[2].st_mode))
            acl_identity = _copy_windows_dacl(path, staged) if original is not None and os.name == "nt" else None
            _cancelled(cancel)
            # Verify resolved, absolute targets before the Windows replacement.
            # Only this known same-directory owned temporary file is removed.
            current = _path(str(path), state_dir, missing=True)
            if current.parent.resolve(strict=True) != staged.parent.resolve(strict=True):
                raise WorkspaceDenied("Save directory changed")
            if original is None:
                # A hard-link publish is atomic create-if-absent on the same
                # volume, preserving a concurrently created destination.
                try:
                    os.link(staged, current)
                except FileExistsError:
                    return _failure("FILE_CONFLICT", "File was created by another operation; reload")
            else:
                if not current.exists():
                    return _failure("FILE_CONFLICT", "File no longer exists; reload before saving")
                latest = _file_signature(current, cancel, file_limit, state_dir=state_dir)
                if latest is None or latest[:2] != original[:2]:
                    return _failure("FILE_CONFLICT", "File changed while saving; reload before saving")
                if acl_identity is not None and _windows_dacl(current)[2] != acl_identity:
                    raise _AclPreservationError("File permissions changed while saving")
                os.replace(staged, current)
            return _success({"path": str(path), "size_bytes": len(content),
                             "sha256": hashlib.sha256(content).hexdigest(), "created": original is None})
        finally:
            with contextlib.suppress(FileNotFoundError):
                staged.unlink()


def execute_workspace(action, parameters, policy, cancel, *, state_dir=None):
    """Execute one validated desktop operation; never retry writes implicitly."""
    from .executors import ExecutionDenied

    access = policy.get("desktop_access", {}) if isinstance(policy, dict) else {}
    mode = access.get("mode") if isinstance(access, dict) else None
    if mode not in {"read_only", "full"} or action in {"write", "edit", "apply_patch", "mkdir", "copy", "move", "delete", "rename"} and mode != "full":
        return _failure("POLICY_DENIED", "This connection mode does not permit this operation")
    try:
        parameters = validate_workspace_parameters(action, parameters)
        _cancelled(cancel)
        if action in {"log_read", "log_search"}:
            from .log_executor import execute_log

            return execute_log(action, parameters, cancel, state_dir)
        if action in {"apply_patch", "patch_status"}:
            from .project_patch import execute_project_patch

            return execute_project_patch(action, parameters, cancel, state_dir)
        if action == "list_page":
            from .directory_listing import execute_directory_page

            return execute_directory_page(parameters, cancel, state_dir=state_dir)
        if action in {"search_page", "search_native_page"}:
            from .search_listing import execute_search_page

            return execute_search_page(parameters, cancel, state_dir=state_dir, native=action == "search_native_page")
        if action in {"delete", "rename"}:
            from .file_management import execute_path_mutation

            return execute_path_mutation(action, parameters, cancel, state_dir)
        function = {"list": _list, "search": _search, "read": _text_read, "read_many": _read_many, "write": _write,
                    "read_range": _read_range, "edit": _edit, "stat": _stat, "mkdir": _mkdir,
                    "copy": _copy, "move": _move, "read_image": _read_image}[action]
        return function(parameters, cancel, state_dir)
    except _Cancelled:
        return _failure("CANCELLED", "Task was cancelled before the operation completed", state="cancelled")
    except _FileChanged:
        return _failure("FILE_CONFLICT", "The file changed while being read; inspect its current version")
    except _FileLimit:
        return _failure("FILE_TOO_LARGE", "This file operation supports ordinary files up to 2 GiB")
    except (WorkspaceDenied, ExecutionDenied):
        return _failure("POLICY_DENIED", "The selected path is not available to project tools")
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "The selected file or directory does not exist")
    except PermissionError:
        return _failure("ACCESS_DENIED", "The Windows user cannot access the selected path")
    except IsADirectoryError:
        return _failure("NOT_A_FILE", "The selected path is not a regular file")
    except _AclPreservationError:
        return _failure("ACL_PRESERVATION_FAILED", "Existing Windows file permissions could not be preserved")
    except OSError:
        return _failure("FILESYSTEM_ERROR", "The filesystem operation could not be completed")
    except (ValueError, TypeError, KeyError):
        return _failure("INVALID_PARAMETERS", "Workspace parameters are invalid")
