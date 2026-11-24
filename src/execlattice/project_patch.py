"""Bounded project patches with durable, observation-only replay receipts.

All files are checked before the first save, but this is not a filesystem
transaction: other programs can still edit a file between checks. Each save
retains the existing editor's hash checks, encoding and ACL preservation. An
interrupted commit is deliberately unknown, never retried or inferred successful
by comparing current file contents.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path

from .development_protocol import MAX_EDIT_FILE_BYTES
from .file_text import decode_range, text_format
from .security import _reject_link_ancestors, protect_directory, replace_private_json, write_private_json

MAX_PATCH_PREFLIGHT_BYTES = 16 * 1024 * 1024
MAX_PATCH_JOURNALS = 1024
MAX_PATCH_JOURNAL_BYTES = 32768
_PATCH_LOCK = threading.Lock()
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[0-9a-f]{32}$")


class _PatchBusy(OSError):
    pass


def patch_request_sha256(parameters):
    """Hash the validated parameters, including inserted encoding defaults."""
    data = json.dumps(parameters, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _error(code, message):
    return {"code": code, "message": message}


def _valid_error(value):
    return value is None or (isinstance(value, dict) and set(value) == {"code", "message"}
                             and isinstance(value["code"], str)
                             and re.fullmatch(r"[A-Z_]{1,64}", value["code"])
                             and isinstance(value["message"], str) and 1 <= len(value["message"]) <= 200)


def _valid_receipt(value, patch_id):
    if (not isinstance(value, dict)
            or set(value) != {"patch_id", "request_sha256", "state", "complete", "files", "error"}
            or value["patch_id"] != patch_id or not _ID.fullmatch(patch_id)
            or not isinstance(value["request_sha256"], str) or not _HEX.fullmatch(value["request_sha256"])
            or value["state"] not in {"applied", "preflight_failed", "partial", "unknown"}
            or type(value["complete"]) is not bool
            or not isinstance(value["files"], list) or not 1 <= len(value["files"]) <= 8
            or not _valid_error(value["error"])):
        return False
    paths, applied, hunks = set(), 0, 0
    for row in value["files"]:
        if (not isinstance(row, dict) or set(row) != {
            "path", "state", "expected_sha256", "result_sha256", "edits_applied", "error"}
                or not isinstance(row["path"], str) or not 1 <= len(row["path"]) <= 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in row["path"])
                or row["path"] in paths
                or row["state"] not in {"pending", "applied", "failed", "not_applied", "unknown"}
                or not isinstance(row["expected_sha256"], str) or not _HEX.fullmatch(row["expected_sha256"])
                or type(row["edits_applied"]) is not int or not 0 <= row["edits_applied"] <= 16
                or not _valid_error(row["error"])):
            return False
        paths.add(row["path"])
        if row["state"] == "applied":
            if (not isinstance(row["result_sha256"], str) or not _HEX.fullmatch(row["result_sha256"])
                    or row["edits_applied"] == 0 or row["error"] is not None):
                return False
            applied += 1
            hunks += row["edits_applied"]
        elif row["result_sha256"] is not None or row["edits_applied"] != 0:
            return False
        if row["state"] == "failed" and row["error"] is None:
            return False
        if row["state"] in {"pending", "not_applied"} and row["error"] is not None:
            return False
    if sum(len(path.encode("utf-8")) for path in paths) > 8192 or hunks > 64:
        return False
    if value["state"] == "applied":
        return value["complete"] and applied == len(paths) and value["error"] is None
    if value["complete"]:
        return False
    if value["error"] is None:
        return False
    if value["state"] == "preflight_failed":
        return (applied == 0 and any(row["state"] == "failed" for row in value["files"])
                and all(row["state"] in {"failed", "not_applied"} for row in value["files"]))
    if value["state"] == "partial":
        return 0 < applied < len(paths) and all(row["state"] != "pending" for row in value["files"])
    return applied < len(paths)


def _directory(state_dir, *, create):
    if state_dir is None:
        raise ValueError("Patch persistence is required")
    path = Path(state_dir).absolute() / "project-patches"
    _reject_link_ancestors(path)
    # Normalize the owned store's existing names without following a link or
    # trusting a resolve result after its original prefix has changed.
    prefix, suffix = path, []
    while True:
        try:
            before = prefix.lstat()
            break
        except FileNotFoundError:
            from .workspace_executor import _RESERVED

            part = prefix.name
            if (prefix == prefix.parent or part in {"", ".", ".."} or part.endswith((" ", "."))
                    or any(ord(c) < 32 or ord(c) == 127 or c in ':<>"|?*' for c in part)
                    or part.split(".", 1)[0].lower() in _RESERVED):
                raise ValueError("Invalid patch directory") from None
            suffix.append(part)
            prefix = prefix.parent
    if os.name == "nt":
        from .executors import _windows_long_path

        canonical = _windows_long_path(prefix)
    else:
        canonical = prefix
    _reject_link_ancestors(prefix)
    _reject_link_ancestors(canonical)
    after, native = prefix.lstat(), canonical.lstat()
    identity = before.st_dev, before.st_ino
    if any(not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
           or getattr(info, "st_file_attributes", 0) & 0x400
           or (info.st_dev, info.st_ino) != identity for info in (before, after, native)):
        raise ValueError("Patch directory changed during name verification")
    path = canonical.joinpath(*reversed(suffix))
    _reject_link_ancestors(path)
    if create:
        protect_directory(path)
    elif not path.exists():
        return None
    if not path.is_dir():
        raise ValueError("Invalid patch directory")
    return path


def _read_receipt(path, patch_id):
    from .executors import _open_verified

    _reject_link_ancestors(path)
    with _open_verified(Path(path.anchor), list(path.parts[1:])) as (descriptor, before):
        if before.st_size > MAX_PATCH_JOURNAL_BYTES:
            raise ValueError("Invalid patch journal")
        data = os.read(descriptor, MAX_PATCH_JOURNAL_BYTES + 1)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(data) != before.st_size):
            raise ValueError("Patch journal changed")
    value = json.loads(data, object_pairs_hook=_unique_object)
    if (not isinstance(value, dict) or set(value) != {"format", "receipt"}
            or type(value["format"]) is not int or value["format"] != 1
            or not _valid_receipt(value["receipt"], patch_id)):
        raise ValueError("Invalid patch journal")
    return value["receipt"]


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate patch journal key")
        value[key] = item
    return value


def _persist(path, receipt, *, initial=False):
    value = {"format": 1, "receipt": receipt}
    encoded = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    if not _valid_receipt(receipt, receipt["patch_id"]) or len(encoded) + 1 > MAX_PATCH_JOURNAL_BYTES:
        raise ValueError("Patch journal exceeds its bounds")
    (write_private_json if initial else replace_private_json)(path, value)
    # write_private_json is exclusive; explicitly make the initial intent
    # durable before any project mutation, as replacements already do.
    if initial:
        _reject_link_ancestors(path)
        before = path.lstat()
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                raise ValueError("Patch intent changed before durable flush")
            # Windows FlushFileBuffers requires a writable handle even when
            # merely flushing bytes already written by exclusive creation.
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def _journal_lock(directory):
    """A nonblocking OS lock also bounds journal creation across processes."""
    path = directory / "patches.lock"
    _reject_link_ancestors(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "r+b") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Invalid patch lock")
        try:
            if os.name == "nt":
                import msvcrt

                if info.st_size == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise _PatchBusy() from None
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _capacity(directory):
    count = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name == "patches.lock":
                continue
            count += 1
            # Windows DirEntry caches do not reliably populate st_nlink;
            # request actual file metadata before validating replay guards.
            info = os.stat(entry.path, follow_symlinks=False)
            if (count >= MAX_PATCH_JOURNALS or not stat.S_ISREG(info.st_mode)
                    or info.st_size > MAX_PATCH_JOURNAL_BYTES
                    or info.st_nlink != 1):
                return False
    return True


def _prepare(item, state_dir, cancel, budget, identities):
    from . import workspace_executor as workspace

    path = workspace._path(item["path"], state_dir)
    info = path.lstat()
    identity = (info.st_dev, info.st_ino)
    key = os.path.normcase(str(path.resolve(strict=True)))
    if key in identities or identity in identities:
        return None, _error("DUPLICATE_PATCH_FILE", "A patch must name each ordinary file only once")
    identities.add(key)
    identities.add(identity)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return None, _error("POLICY_DENIED", "Only ordinary files without links may be patched")
    if os.name == "nt" and not info.st_mode & stat.S_IWRITE:
        return None, _error("ACCESS_DENIED", "The file has the Windows read-only attribute")
    if info.st_size > MAX_EDIT_FILE_BYTES:
        return None, _error("FILE_TOO_LARGE", "A patch supports files up to 8 MiB")
    if info.st_size > budget[0]:
        return None, _error("PATCH_READ_LIMIT", "Combined patch source files exceed 16 MiB")
    loaded = workspace._read_bytes(path, MAX_EDIT_FILE_BYTES, cancel, read_budget=budget,
                                   state_dir=state_dir)
    if loaded is None:
        return None, _error("PATCH_READ_LIMIT", "Patch source files exceed their read limits")
    content, opened = loaded
    if (opened.st_dev, opened.st_ino) != identity:
        return None, _error("FILE_CONFLICT", "The file changed during patch preparation")
    if os.name == "nt" and not opened.st_mode & stat.S_IWRITE:
        return None, _error("ACCESS_DENIED", "The file has the Windows read-only attribute")
    if hashlib.sha256(content).hexdigest() != item["expected_sha256"]:
        return None, _error("FILE_CONFLICT", "File changed; read it before preparing a new patch")
    try:
        encoding, bom_bytes = text_format(content, item["encoding"])
        text, _ = decode_range(content, encoding, bom_bytes, 0)
        crlf = ("\r\n" in text and "\n" not in text.replace("\r\n", "")
                and "\r" not in text.replace("\r\n", ""))
        matches = []
        for edit in item["edits"]:
            old, new = edit["old_text"], edit["new_text"]
            if crlf:
                old = old.replace("\r\n", "\n").replace("\n", "\r\n")
                new = new.replace("\r\n", "\n").replace("\n", "\r\n")
            start = text.find(old)
            if start < 0 or text.find(old, start + 1) >= 0:
                return None, _error("EDIT_NOT_UNIQUE", "Each old text must occur exactly once in the original file")
            matches.append((start, start + len(old), new))
        matches.sort(key=lambda match: (match[0], match[1]))
        if any(left[1] > right[0] for left, right in zip(matches, matches[1:])):
            return None, _error("OVERLAPPING_EDITS", "Patch hunks must not overlap in the original file")
        chunks, previous = [], 0
        for start, end, new in matches:
            chunks.extend((text[previous:start], new))
            previous = end
        chunks.append(text[previous:])
        replacement = content[:bom_bytes] + "".join(chunks).encode(encoding)
    except UnicodeError:
        return None, _error("FILE_NOT_TEXT", "The file or replacement is invalid in the selected encoding")
    if len(replacement) > MAX_EDIT_FILE_BYTES:
        return None, _error("FILE_TOO_LARGE", "A patched file must remain within 8 MiB")
    return (str(path), replacement), None


def _caught_error(exc):
    from . import workspace_executor as workspace
    from .executors import ExecutionDenied

    if isinstance(exc, workspace._Cancelled):
        return _error("CANCELLED", "The patch was cancelled; inspect its receipt before further changes")
    if isinstance(exc, (workspace.WorkspaceDenied, ExecutionDenied)):
        return _error("POLICY_DENIED", "The selected path is not available to project tools")
    if isinstance(exc, FileNotFoundError):
        return _error("FILE_NOT_FOUND", "The selected existing file does not exist")
    if isinstance(exc, PermissionError):
        return _error("ACCESS_DENIED", "The current user cannot modify the selected file")
    if isinstance(exc, workspace._AclPreservationError):
        return _error("ACL_PRESERVATION_FAILED", "Existing file permissions could not be preserved")
    return _error("FILESYSTEM_ERROR", "The filesystem operation could not be confirmed")


def _not_applied(receipt, start):
    for row in receipt["files"][start:]:
        row.update(state="not_applied", result_sha256=None, edits_applied=0)


def _initial(parameters):
    return {"patch_id": parameters["patch_id"], "request_sha256": patch_request_sha256(parameters),
            "state": "unknown", "complete": False,
            "files": [{"path": item["path"], "state": "pending", "expected_sha256": item["expected_sha256"],
                       "result_sha256": None, "edits_applied": 0, "error": None} for item in parameters["files"]],
            "error": _error("PATCH_INCOMPLETE", "The durable receipt does not confirm completion; observe this patch ID")}


def _apply(parameters, cancel, state_dir, directory, path):
    from . import workspace_executor as workspace

    receipt = _initial(parameters)
    _persist(path, receipt, initial=True)
    prepared, budget, identities = [], [MAX_PATCH_PREFLIGHT_BYTES], set()
    for index, item in enumerate(parameters["files"]):
        try:
            workspace._cancelled(cancel)
            replacement, error = _prepare(item, state_dir, cancel, budget, identities)
        except Exception as exc:
            replacement, error = None, _caught_error(exc)
        if error is not None:
            _not_applied(receipt, 0)
            receipt["files"][index].update(state="failed", error=error)
            receipt.update(state="preflight_failed", error=error)
            _persist(path, receipt)
            return receipt
        prepared.append(replacement)
    for index, (item, (raw_path, content)) in enumerate(zip(parameters["files"], prepared, strict=True)):
        row = receipt["files"][index]
        if cancel.is_set():
            _not_applied(receipt, index)
            error = _error("CANCELLED", "The patch was cancelled before this file was committed")
            row.update(state="failed", error=error)
            receipt.update(state="partial" if index else "preflight_failed", error=error)
            _persist(path, receipt)
            return receipt
        # Never advertise a pending mutation after it may have happened. A
        # crash or failed receipt write preserves this unknown commit intent.
        row["state"] = "unknown"
        _not_applied(receipt, index + 1)
        _persist(path, receipt)
        try:
            report = workspace._save(raw_path, content, item["expected_sha256"], cancel, state_dir,
                                     file_limit=MAX_EDIT_FILE_BYTES)
        except Exception as exc:
            error = _caught_error(exc)
            row["error"] = error
            receipt.update(state="unknown", error=error)
            _persist(path, receipt)
            return receipt
        if report["state"] != "succeeded":
            error = report["error"]
            row.update(state="failed", error=error)
            receipt.update(state="partial" if index else "preflight_failed", error=error)
            _persist(path, receipt)
            return receipt
        row.update(state="applied", result_sha256=report["result"]["sha256"],
                   edits_applied=len(item["edits"]), error=None)
        if index + 1 == len(prepared):
            receipt.update(state="applied", complete=True, error=None)
        _persist(path, receipt)
    return receipt


def execute_project_patch(action, parameters, cancel, state_dir):
    """Return an original durable receipt; no automatic mutation retries."""
    from . import workspace_executor as workspace

    if state_dir is None:
        return workspace._failure("PATCH_PERSISTENCE_REQUIRED", "Patch operations require durable application state")
    patch_id = parameters["patch_id"]
    try:
        directory = _directory(state_dir, create=action == "apply_patch")
        if directory is None:
            return workspace._failure("PATCH_NOT_FOUND", "No durable receipt exists for this patch ID")
        path = directory / (patch_id + ".json")
        if path.exists():
            receipt = _read_receipt(path, patch_id)
            if action == "apply_patch" and receipt["request_sha256"] != patch_request_sha256(parameters):
                return workspace._failure("PATCH_ID_CONFLICT", "This patch ID belongs to a different original request")
            return workspace._success(copy.deepcopy(receipt))
        if action == "patch_status":
            return workspace._failure("PATCH_NOT_FOUND", "No durable receipt exists for this patch ID")
        if not _PATCH_LOCK.acquire(blocking=False):
            return workspace._failure("PATCH_BUSY", "Another patch is committing; observe its receipt before retrying")
        try:
            with _journal_lock(directory):
                if path.exists():
                    receipt = _read_receipt(path, patch_id)
                    if receipt["request_sha256"] != patch_request_sha256(parameters):
                        return workspace._failure("PATCH_ID_CONFLICT", "This patch ID belongs to a different original request")
                    return workspace._success(receipt)
                if not _capacity(directory):
                    return workspace._failure("PATCH_JOURNAL_LIMIT", "Patch receipt capacity is full; existing replay guards are retained")
                receipt = _apply(parameters, cancel, state_dir, directory, path)
                return workspace._success(receipt)
        finally:
            _PATCH_LOCK.release()
    except FileExistsError:
        return workspace._failure("PATCH_BUSY", "An exclusive patch intent already exists; query its status")
    except _PatchBusy:
        return workspace._failure("PATCH_BUSY", "Another patch process is committing; observe before retrying")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return workspace._failure("PATCH_JOURNAL_INVALID", "The durable patch journal is invalid; no mutation was retried")
    except OSError:
        # A persistence error may follow a successful project save. Report no
        # success and preserve the preceding intent for observation only.
        return workspace._failure("PATCH_PERSISTENCE_ERROR", "Patch persistence could not be confirmed; query the original patch ID")
