"""Bounded durable command-output prefixes, independent from execution receipts.

An open artifact is not proof that a command is still running. Only published,
fsynced bytes are readable; capture failures never restart or stop a command.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .security import _reject_link_ancestors, protect_directory, replace_private_json, write_private_json

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_STORE_BYTES = 512 * 1024 * 1024
LEGACY_MAX_ARTIFACTS = 64
MAX_ARTIFACTS = 512
RETENTION_SECONDS = 30 * 86400
READ_LEASE_SECONDS = 300
MAX_IDENTITIES = 262144
MAX_IDENTITY_BYTES = 64 * 1024 * 1024
MAX_GC_CANDIDATES = 8
MAX_GC_READ_BYTES = 64 * 1024 * 1024
MAX_GC_SECONDS = 1.0
MAX_READ_BYTES = 65536
_RAW_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
_LOCAL_LOCK = threading.RLock()
_STREAMS = ("stdout", "stderr")
_STATES = {"succeeded", "failed", "cancelled", "timed_out", "unknown"}
_ERRORS = {None, "OUTPUT_CAPTURE_LIMIT", "OUTPUT_CAPTURE_IO", "OUTPUT_CAPTURE_UNCONFIRMED"}


class OutputArtifactError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class OutputReadParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    source_kind: Literal["task", "job"]
    source_id: str = Field(min_length=32, max_length=36)
    stream: Literal["stdout", "stderr"] = "stdout"
    offset: int = Field(default=0, ge=0, le=2**63 - 1)
    limit: int = Field(default=32768, ge=1, le=MAX_READ_BYTES)

    @model_validator(mode="after")
    def identity(self):
        artifact_key(self.source_kind, self.source_id)
        return self


def artifact_key(kind, source_id):
    if kind == "task" and isinstance(source_id, str):
        try:
            if str(UUID(source_id)) == source_id:
                return "task-" + UUID(source_id).hex
        except ValueError:
            pass
    if kind == "job" and isinstance(source_id, str) and re.fullmatch(r"[0-9a-f]{32}", source_id):
        return "job-" + source_id
    raise OutputArtifactError("OUTPUT_ID_INVALID")


def _root(state_dir, *, create=False):
    if state_dir is None:
        raise OutputArtifactError("OUTPUT_STATE_UNAVAILABLE")
    root = Path(state_dir).absolute() / "output-artifacts"
    _reject_link_ancestors(root)
    if create:
        protect_directory(root)
    if not root.is_dir():
        raise OutputArtifactError("OUTPUT_NOT_FOUND")
    if os.name != "nt":
        return root
    from .executors import _windows_long_path

    # This owned private namespace has source-key authority, rather than the
    # public-project scope. Expand its spelling independently before deriving
    # record paths; strict handle reads below keep their original guards.
    before = root.lstat()
    canonical = _windows_long_path(root)
    _reject_link_ancestors(root)
    _reject_link_ancestors(canonical)
    after, expanded = root.lstat(), canonical.lstat()
    if (any(not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400 for info in (before, after, expanded))
            or len({(info.st_dev, info.st_ino) for info in (before, after, expanded)}) != 1):
        raise OutputArtifactError("OUTPUT_STATE_UNAVAILABLE")
    return canonical


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate output metadata key")
        result[key] = value
    return result


def _valid_metadata(value):
    try:
        fields = {"format", "source_kind", "source_id", "streams", "generation", "finalized",
                  "truncated", "capture_error", "completion"}
        if type(value) is not dict or type(value.get("format")) is not int or value["format"] not in {1, 2}:
            return False
        if value["format"] == 2:
            fields.add("retention")
            retention = value["retention"]
            if (type(retention) is not dict or set(retention) != {"created_at", "retain_until", "read_lease_until", "pinned"}
                    or any(type(retention[name]) is not int or not 0 <= retention[name] <= 2**63 - 1
                           for name in ("created_at", "retain_until", "read_lease_until"))
                    or retention["retain_until"] < retention["created_at"] or type(retention["pinned"]) is not bool):
                return False
        if (set(value) != fields
                or type(value["generation"]) is not int or not 0 <= value["generation"] <= 2**63 - 1
                or type(value["finalized"]) is not bool or type(value["truncated"]) is not bool
                or value["capture_error"] not in _ERRORS or set(value["streams"]) != set(_STREAMS)):
            return False
        artifact_key(value["source_kind"], value["source_id"])
        total = 0
        for channel in _STREAMS:
            row = value["streams"][channel]
            if (type(row) is not dict or set(row) != {"durable_bytes", "observed_bytes", "sha256"}
                    or type(row["durable_bytes"]) is not int or type(row["observed_bytes"]) is not int
                    or not 0 <= row["durable_bytes"] <= row["observed_bytes"] <= 2**63 - 1
                    or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                    or row["durable_bytes"] == 0 and row["sha256"] != hashlib.sha256(b"").hexdigest()
                    or value["capture_error"] is None and row["durable_bytes"] != row["observed_bytes"]):
                return False
            total += row["durable_bytes"]
        if total > MAX_ARTIFACT_BYTES or value["capture_error"] == "OUTPUT_CAPTURE_LIMIT" and not value["truncated"]:
            return False
        completion = value["completion"]
        return ((not value["finalized"] and completion is None)
                or (value["finalized"] and type(completion) is dict
                    and set(completion) == {"command_state", "exit_code", "output_complete"}
                    and completion["command_state"] in _STATES
                    and (completion["exit_code"] is None or type(completion["exit_code"]) is int)
                    and (completion["command_state"] != "succeeded" or completion["exit_code"] == 0)
                    and type(completion["output_complete"]) is bool))
    except (KeyError, TypeError, ValueError):
        return False


def _metadata(path):
    from .executors import _open_verified

    with _open_verified(Path(path.anchor), list(path.parts[1:])) as (fd, before):
        if before.st_size > 8192:
            raise OutputArtifactError("OUTPUT_METADATA_INVALID")
        data = os.read(fd, 8193)
        if len(data) != before.st_size:
            raise OutputArtifactError("OUTPUT_METADATA_INVALID")
    value = json.loads(data, object_pairs_hook=_unique)
    if not _valid_metadata(value) or artifact_key(value["source_kind"], value["source_id"]) != path.stem:
        raise OutputArtifactError("OUTPUT_METADATA_INVALID")
    return value


@contextlib.contextmanager
def _capacity_lock(root):
    with _LOCAL_LOCK:
        path = root / "capacity.lock"
        _reject_link_ancestors(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | _RAW_FLAGS | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OutputArtifactError("OUTPUT_METADATA_INVALID")
            if os.name == "nt":
                import msvcrt

                if not info.st_size:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                if os.name == "nt":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _persist(path, value, *, initial=False):
    if not _valid_metadata(value):
        raise OutputArtifactError("OUTPUT_METADATA_INVALID")
    if initial:
        write_private_json(path, value)
        fd = os.open(path, os.O_RDWR | _RAW_FLAGS | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        replace_private_json(path, value)


def _v2_root(root, *, create=False):
    result = root / "v2"
    _reject_link_ancestors(result)
    if create:
        protect_directory(result)
    return result


@contextlib.contextmanager
def _identities(root, *, create=False):
    """Bounded identity ledger survives payload expiry; never authorizes execution."""
    path = _v2_root(root, create=create) / "identities.sqlite3"
    _reject_link_ancestors(path)
    if not path.exists() and not create:
        yield None
        return
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_IDENTITY_BYTES:
            raise OutputArtifactError("OUTPUT_IDENTITY_INVALID")
    connection = None
    try:
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            _reject_link_ancestors(sidecar)
            if sidecar.exists():
                info = sidecar.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_IDENTITY_BYTES:
                    raise OutputArtifactError("OUTPUT_IDENTITY_INVALID")
        connection = sqlite3.connect(path if create else path.as_uri() + "?mode=ro",
                                     timeout=0, isolation_level=None, uri=not create)
        if create:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            connection.execute(f"PRAGMA max_page_count={MAX_IDENTITY_BYTES // page_size}")
            connection.execute("CREATE TABLE IF NOT EXISTS identities (source_key TEXT PRIMARY KEY, expired INTEGER NOT NULL CHECK(expired IN (0,1))) WITHOUT ROWID")
        yield connection
    except sqlite3.DatabaseError:
        raise OutputArtifactError("OUTPUT_IDENTITY_INVALID") from None
    finally:
        if connection is not None:
            connection.close()


def _claim_identity(root, key):
    with _identities(root, create=True) as connection:
        if connection.execute("SELECT 1 FROM identities WHERE source_key=?", (key,)).fetchone():
            raise OutputArtifactError("OUTPUT_ALREADY_EXISTS")
        if connection.execute("SELECT count(*) FROM identities").fetchone()[0] >= MAX_IDENTITIES:
            raise OutputArtifactError("OUTPUT_IDENTITY_FULL")
        try:
            connection.execute("INSERT INTO identities VALUES (?,0)", (key,))
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise OutputArtifactError("OUTPUT_IDENTITY_FULL") from None
            raise


def _expired_identity(root, key):
    with _identities(root) as connection:
        return connection is not None and connection.execute(
            "SELECT expired FROM identities WHERE source_key=?", (key,)).fetchone() == (1,)


def _records(root):
    records = []
    for directory in (root, _v2_root(root)):
        if directory.is_dir():
            records.extend((path, _metadata(path)) for path in directory.glob("*.json"))
    return records


def _reserved(records):
    return sum(sum(row["durable_bytes"] for row in value["streams"].values())
               if value["finalized"] else MAX_ARTIFACT_BYTES for _, value in records)


def _reclaimable(value):
    return (value["format"] == 2 and value["finalized"] and value["completion"]["output_complete"]
            and value["completion"]["command_state"] in {"succeeded", "failed"}
            and not value["capture_error"] and not value["truncated"]
            and not value["retention"]["pinned"])


def _eligible(value, now):
    return (_reclaimable(value) and value["retention"]["retain_until"] <= now
            and value["retention"]["read_lease_until"] <= now)


def _evict(root, path, value, budget):
    """Only exact complete v2 payloads; legacy and uncertain evidence are immutable."""
    from .executors import _open_verified

    targets = []
    for name in _STREAMS:
        target = path.with_suffix("." + name + ".bin")
        with _open_verified(Path(target.anchor), list(target.parts[1:])) as (fd, before):
            row = value["streams"][name]
            if before.st_nlink != 1 or before.st_size != row["durable_bytes"]:
                return False
            digest = hashlib.sha256()
            while True:
                if time.monotonic() >= budget["deadline"]:
                    raise OutputArtifactError("OUTPUT_RETENTION_BUSY")
                data = os.read(fd, min(65536, budget["bytes"] + 1))
                if not data:
                    break
                if len(data) > budget["bytes"]:
                    raise OutputArtifactError("OUTPUT_RETENTION_BUSY")
                budget["bytes"] -= len(data)
                digest.update(data)
            if digest.hexdigest() != row["sha256"]:
                return False
            targets.append((target, before))
    for target, before in targets:
        _reject_link_ancestors(target)
        after = target.stat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            return False
    # Persist expiry before deleting bytes: a partial deletion must never make
    # an old identity available to start an execution again.
    with _identities(root, create=True) as connection:
        if not connection.execute("SELECT 1 FROM identities WHERE source_key=?", (path.stem,)).fetchone():
            return False  # An absent identity index is not permission to forget an execution.
        connection.execute("UPDATE identities SET expired=1 WHERE source_key=?", (path.stem,))
    for target, _ in targets:
        target.unlink()
    path.unlink()
    return True


def _make_capacity(root, version):
    records = _records(root)
    deferred = False

    def full():
        directory = _v2_root(root) if version == 2 else root
        count = sum(path.parent == directory for path, _ in records)
        return (count >= (MAX_ARTIFACTS if version == 2 else LEGACY_MAX_ARTIFACTS)
                or _reserved(records) + MAX_ARTIFACT_BYTES > MAX_STORE_BYTES)

    if version == 2 and full():
        now = int(time.time())
        budget = {"bytes": MAX_GC_READ_BYTES, "deadline": time.monotonic() + MAX_GC_SECONDS}
        candidates = sorted(((path, value) for path, value in records if path.parent == _v2_root(root)
                             and _eligible(value, now)), key=lambda row: row[1]["retention"]["retain_until"])
        for index, (path, value) in enumerate(candidates):
            if index >= MAX_GC_CANDIDATES or time.monotonic() >= budget["deadline"]:
                deferred = True
                break
            try:
                if _evict(root, path, value, budget):
                    records.remove((path, value))
            except OutputArtifactError as error:
                if error.code == "OUTPUT_RETENTION_BUSY":
                    deferred = True
                    break
                continue
            except (OSError, ValueError):
                # Corrupt or unremovable evidence is protected, not silently
                # treated as an absent execution or repaired by replay.
                continue
            if not full():
                break
    if full():
        raise OutputArtifactError("OUTPUT_RETENTION_BUSY" if deferred else "OUTPUT_STORE_FULL")


def pin_output_artifact(state_dir, source_kind, source_id, *, pinned=True):
    """Internal retention hook for a durable reference, not an execution operation."""
    if type(pinned) is not bool:
        raise OutputArtifactError("OUTPUT_METADATA_INVALID")
    root = _root(state_dir)
    key = artifact_key(source_kind, source_id)
    with _capacity_lock(root):
        legacy = root / (key + ".json")
        if legacy.exists():
            return  # Existing v1 artifacts are permanently protected.
        path = _v2_root(root) / (key + ".json")
        value = _metadata(path)
        value["retention"]["pinned"] = pinned
        _persist(path, value)


def capture_result(source_kind, source_id, *, writer=None, reason=None):
    """Capture outcome is independent of the command exit and side effects."""
    result = {"version": 2, "source_kind": source_kind, "source_id": source_id,
              "state": "unavailable", "reason": reason, "retention_expires_at": None,
              "retention": "unavailable", "durable_bytes": None, "observed_bytes": None}
    if writer is None:
        return result
    try:
        value = _metadata(writer.path)
    except (OSError, ValueError):
        result.update(state="unconfirmed", reason="OUTPUT_CAPTURE_UNCONFIRMED")
        return result
    complete = (value["finalized"] and not value["truncated"] and value["capture_error"] is None
                and value["completion"]["output_complete"])
    result.update(state="complete" if complete else "partial" if value["finalized"] else "unconfirmed",
                  reason=None if complete else value["capture_error"] or "OUTPUT_CAPTURE_UNCONFIRMED",
                  durable_bytes={name: row["durable_bytes"] for name, row in value["streams"].items()},
                  observed_bytes={name: row["observed_bytes"] for name, row in value["streams"].items()})
    if not _reclaimable(value):
        result["retention"] = "protected"
    else:
        result.update(retention="at_least_until", retention_expires_at=value["retention"]["retain_until"])
    return result


def valid_capture_result(value, totals):
    """Reject forged completeness and unsupported reasons in command receipts."""
    try:
        if (type(value) is not dict or set(value) != {"version", "source_kind", "source_id", "state", "reason",
                "retention_expires_at", "retention", "durable_bytes", "observed_bytes"}
                or type(value["version"]) is not int or value["version"] != 2):
            return False
        artifact_key(value["source_kind"], value["source_id"])
        state = value["state"]
        if state not in {"complete", "partial", "unavailable", "unconfirmed"}:
            return False
        reasons = {"OUTPUT_STORE_FULL", "OUTPUT_CAPTURE_IO", "OUTPUT_METADATA_INVALID", "OUTPUT_CAPTURE_LIMIT",
                   "OUTPUT_STATE_UNAVAILABLE", "OUTPUT_CAPTURE_UNCONFIRMED", "OUTPUT_IDENTITY_INVALID", "OUTPUT_IDENTITY_FULL",
                   "OUTPUT_RETENTION_BUSY"}
        if (state == "complete" and value["reason"] is not None
                or state != "complete" and value["reason"] not in reasons):
            return False
        if value["retention"] not in {"at_least_until", "protected", "unavailable"}:
            return False
        expiry = value["retention_expires_at"]
        if (value["retention"] == "at_least_until" and (type(expiry) is not int or not 0 <= expiry <= 2**63 - 1)
                or value["retention"] != "at_least_until" and expiry is not None):
            return False
        if value["durable_bytes"] is None or value["observed_bytes"] is None:
            return (state in {"unavailable", "unconfirmed"} and value["durable_bytes"] is None
                    and value["observed_bytes"] is None and value["retention"] == "unavailable")
        if state == "unavailable" or value["retention"] == "unavailable":
            return False
        for field in ("durable_bytes", "observed_bytes"):
            if type(value[field]) is not dict or set(value[field]) != set(_STREAMS):
                return False
        for name in _STREAMS:
            durable, observed = value["durable_bytes"][name], value["observed_bytes"][name]
            if (type(durable) is not int or type(observed) is not int
                    or not 0 <= durable <= observed <= totals[name]
                    or state == "complete" and not durable == observed == totals[name]):
                return False
        return sum(value["durable_bytes"].values()) <= MAX_ARTIFACT_BYTES
    except (KeyError, TypeError, ValueError):
        return False


class OutputArtifactWriter:
    """One original execution's capture; existing identities are never resumed."""

    def __init__(self, state_dir, source_kind, source_id, *, storage_version=2):
        self.key = artifact_key(source_kind, source_id)
        if type(storage_version) is not int or storage_version not in {1, 2}:
            raise OutputArtifactError("OUTPUT_METADATA_INVALID")
        self.base_root = _root(state_dir, create=True)
        self.root = _v2_root(self.base_root, create=True) if storage_version == 2 else self.base_root
        self.path = self.root / (self.key + ".json")
        self.lock = threading.RLock()
        self.files, self.hashes, self.stored = {}, {}, [0, 0]
        self.closed = False
        self.dirty = False
        empty_hash = hashlib.sha256(b"").hexdigest()
        self.value = {"format": storage_version, "source_kind": source_kind, "source_id": source_id,
                      "streams": {name: {"durable_bytes": 0, "observed_bytes": 0, "sha256": empty_hash}
                                  for name in _STREAMS}, "generation": 0, "finalized": False,
                      "truncated": False, "capture_error": None, "completion": None}
        if storage_version == 2:
            now = int(time.time())
            self.value["retention"] = {"created_at": now, "retain_until": now + RETENTION_SECONDS,
                                       "read_lease_until": 0, "pinned": False}
        with _capacity_lock(self.base_root):
            if any((directory / (self.key + ".json")).exists()
                   for directory in (self.base_root, _v2_root(self.base_root))):
                raise OutputArtifactError("OUTPUT_ALREADY_EXISTS")
            # A payload can expire, but its original identity must not become
            # a new command. This ledger is distinct from Controller idempotency.
            _claim_identity(self.base_root, self.key)
            _make_capacity(self.base_root, storage_version)
            _persist(self.path, self.value, initial=True)
            try:
                for name in _STREAMS:
                    target = self.root / (self.key + "." + name + ".bin")
                    _reject_link_ancestors(target)
                    # Windows CRT defaults to text mode: os.write would turn
                    # LF into CRLF while returning the original byte count.
                    self.files[name] = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _RAW_FLAGS, 0o600)
                    self.hashes[name] = hashlib.sha256()
            except BaseException:
                for fd in self.files.values():
                    os.close(fd)
                # The durable open reservation remains. It is never treated as
                # an absent execution or silently reused on another launch.
                raise

    def append(self, channel, data):
        with self.lock:
            if self.closed or not data:
                return
            name = _STREAMS[channel]
            row = self.value["streams"][name]
            row["observed_bytes"] += len(data)
            self.dirty = True
            if self.value["capture_error"] in {"OUTPUT_CAPTURE_IO", "OUTPUT_CAPTURE_UNCONFIRMED"}:
                return
            available = max(0, MAX_ARTIFACT_BYTES - sum(self.stored))
            captured = memoryview(data)[:available]
            if len(captured) != len(data):
                self.value.update(truncated=True, capture_error="OUTPUT_CAPTURE_LIMIT")
            try:
                while captured:
                    count = os.write(self.files[name], captured)
                    if count <= 0:
                        raise OSError("Output write made no progress")
                    self.hashes[name].update(captured[:count])
                    self.stored[channel] += count
                    captured = captured[count:]
            except OSError:
                self.value["capture_error"] = "OUTPUT_CAPTURE_IO"

    def checkpoint(self, *, completion=None):
        with self.lock:
            if self.closed:
                return False
            if not self.dirty and completion is None:
                return True
            try:
                for index, name in enumerate(_STREAMS):
                    os.fsync(self.files[name])
                    self.value["streams"][name].update(durable_bytes=self.stored[index],
                                                      sha256=self.hashes[name].hexdigest())
                self.value["generation"] += 1
                if completion is not None:
                    self.value.update(finalized=True, completion=completion)
                with _capacity_lock(self.base_root):
                    if self.value["format"] == 2:
                        # A concurrent read/reference pin belongs to the same
                        # original artifact and must survive this checkpoint.
                        self.value["retention"] = _metadata(self.path)["retention"]
                    _persist(self.path, self.value)
                self.dirty = False
                return True
            except (OSError, ValueError):
                # Old published lengths remain the only confirmed evidence.
                self.value["capture_error"] = "OUTPUT_CAPTURE_UNCONFIRMED"
                return False

    def finish(self, command_state, exit_code, *, output_complete):
        with self.lock:
            if self.closed:
                return False
            try:
                return self.checkpoint(completion={"command_state": command_state, "exit_code": exit_code,
                                                   "output_complete": output_complete})
            finally:
                self.closed = True
                for fd in self.files.values():
                    os.close(fd)


def read_output_artifact(parameters, policy, cancel, *, state_dir):
    """Pure bounded observation; never starts a host or resumes an execution."""
    if policy.get("desktop_access", {}).get("mode") not in {"full", "read_only"}:
        raise OutputArtifactError("POLICY_DENIED")
    values = OutputReadParameters.model_validate(parameters).model_dump()
    if cancel.is_set():
        raise OutputArtifactError("CANCELLED")
    root = _root(state_dir)
    # Readers and reclamation share the same short lock. The read lease then
    # protects the original bytes between subsequent bounded page requests.
    with _capacity_lock(root):
        return _read_output_locked(values, root, cancel)


def _read_output_locked(values, root, cancel):
    from .executors import _open_verified

    key = artifact_key(values["source_kind"], values["source_id"])
    directory = root if (root / (key + ".json")).exists() else _v2_root(root)
    path = directory / (key + ".json")
    if directory != root and _expired_identity(root, key):
        # Expiry is committed before deleting payloads. A partial GC/crash must
        # not turn leftover bytes into an apparently complete old artifact.
        raise OutputArtifactError("OUTPUT_EXPIRED")
    try:
        metadata = _metadata(path)
    except FileNotFoundError:
        raise OutputArtifactError("OUTPUT_EXPIRED" if _expired_identity(root, key) else "OUTPUT_NOT_FOUND") from None
    try:
        row = metadata["streams"][values["stream"]]
        if values["offset"] > row["durable_bytes"]:
            raise OutputArtifactError("OUTPUT_CURSOR_INVALID")
        path = directory / (key + "." + values["stream"] + ".bin")
        with _open_verified(Path(path.anchor), list(path.parts[1:])) as (fd, before):
            if (before.st_size < row["durable_bytes"] or before.st_size > MAX_ARTIFACT_BYTES
                    or metadata["finalized"] and before.st_size != row["durable_bytes"]):
                raise OutputArtifactError("OUTPUT_DATA_INVALID")
            os.lseek(fd, values["offset"], os.SEEK_SET)
            raw = os.read(fd, min(values["limit"], row["durable_bytes"] - values["offset"]))
            if len(raw) != min(values["limit"], row["durable_bytes"] - values["offset"]):
                raise OutputArtifactError("OUTPUT_DATA_INVALID")
            after = os.fstat(fd)
            if (after.st_size < row["durable_bytes"] or after.st_size > MAX_ARTIFACT_BYTES
                    or metadata["finalized"] and after.st_size != row["durable_bytes"]):
                raise OutputArtifactError("OUTPUT_DATA_INVALID")
        if cancel.is_set():
            raise OutputArtifactError("CANCELLED")
        if _reclaimable(metadata):
            lease = int(time.time()) + READ_LEASE_SECONDS
            if lease > metadata["retention"]["read_lease_until"]:
                metadata["retention"]["read_lease_until"] = lease
                try:
                    _persist(directory / (key + ".json"), metadata)
                except OSError:
                    raise OutputArtifactError("OUTPUT_CAPTURE_IO") from None
        return {"artifact": metadata, "stream": values["stream"], "offset": values["offset"],
                "next_offset": values["offset"] + len(raw), "size_bytes": len(raw),
                "data_b64": base64.b64encode(raw).decode("ascii"), "sha256": hashlib.sha256(raw).hexdigest(),
                "eof": values["offset"] + len(raw) == row["durable_bytes"],
                "capture_complete": metadata["finalized"] and not metadata["truncated"]
                    and metadata["capture_error"] is None and metadata["completion"]["output_complete"]}
    except FileNotFoundError:
        raise OutputArtifactError("OUTPUT_DATA_INVALID") from None


def valid_output_artifact_result(value, parameters):
    try:
        values = OutputReadParameters.model_validate(parameters).model_dump()
        if (type(value) is not dict or set(value) != {"artifact", "stream", "offset", "next_offset", "size_bytes",
                "data_b64", "sha256", "eof", "capture_complete"} or not _valid_metadata(value["artifact"])):
            return False
        metadata = value["artifact"]
        if (metadata["source_kind"] != values["source_kind"] or metadata["source_id"] != values["source_id"]
                or value["stream"] != values["stream"] or value["offset"] != values["offset"]
                or type(value["offset"]) is not int or type(value["next_offset"]) is not int
                or type(value["size_bytes"]) is not int or type(value["eof"]) is not bool
                or type(value["capture_complete"]) is not bool or not isinstance(value["data_b64"], str)
                or len(value["data_b64"]) > 4 * ((values["limit"] + 2) // 3)):
            return False
        raw = base64.b64decode(value["data_b64"], validate=True)
        end = value["offset"] + len(raw)
        durable = metadata["streams"][values["stream"]]["durable_bytes"]
        complete = (metadata["finalized"] and not metadata["truncated"] and metadata["capture_error"] is None
                    and metadata["completion"]["output_complete"])
        return (base64.b64encode(raw).decode("ascii") == value["data_b64"] and len(raw) == value["size_bytes"]
                and len(raw) <= values["limit"] and value["next_offset"] == end <= durable
                and value["sha256"] == hashlib.sha256(raw).hexdigest() and value["eof"] == (end == durable)
                and value["capture_complete"] == complete)
    except (KeyError, TypeError, ValueError):
        return False
