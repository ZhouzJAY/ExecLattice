"""Pinned, bundled ripgrep process; no shell, PATH lookup or user configuration."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

VERSION = "15.2.0"
EXECUTABLE_SHA256 = "14231169855ec5205cf5a1b6f1db358ff4aed4247c86b69ce8aae647c77f6680"
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 16384


class RipgrepError(Exception):
    def __init__(self, code, *, state="failed"):
        self.code, self.state = code, state
        super().__init__(code)


def bundled_executable():
    root = Path(sys.executable).absolute().parent if getattr(sys, "frozen", False) else Path(__file__).absolute().parents[2]
    return root / "third_party" / "ripgrep" / "rg.exe"


def available():
    """Cheap declaration only; execution always verifies the exact file digest."""
    path = bundled_executable()
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def verified_executable():
    path = bundled_executable()
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise RipgrepError("SEARCH_BACKEND_UNAVAILABLE")
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or digest != EXECUTABLE_SHA256):
            raise RipgrepError("SEARCH_BACKEND_UNAVAILABLE")
        return path
    except OSError:
        raise RipgrepError("SEARCH_BACKEND_UNAVAILABLE") from None


def capability():
    return {"version": 1, "engine": "ripgrep", "engine_version": VERSION,
            "engine_sha256": EXECUTABLE_SHA256, "pattern_types": ["literal", "regex"],
            "ignore_files": False, "encoding": "utf-8", "case_matching": "ripgrep_unicode",
            "scan_accounting": "validated_candidate_upper_bounds"}


def valid_capability(value):
    expected = capability()
    return isinstance(value, dict) and value == expected and all(type(value.get(key)) is type(item)
                                                               for key, item in expected.items())


def search_batch(paths, parameters, cancel, *, deadline, clock=time.monotonic):
    """Search only caller-validated explicit files; caller verifies every returned byte.

    Output is bounded independently of the result cache. A partial read-only
    scan is explicit; a failed process or malformed stream never means no match.
    """
    from .executors import _stop_process, _WindowsJob
    from .workspace_executor import _Cancelled

    if cancel.is_set():
        raise _Cancelled()
    if clock() >= deadline:
        return [], "time_limit"
    executable = verified_executable()
    arguments = [str(executable), "--no-config", "--json", "--no-ignore", "--hidden", "--no-follow",
                 "--no-mmap", "--crlf", "--threads", "1", "--engine", "default", "--encoding", "utf-8",
                 "--color", "never", "--max-filesize", "1M", "--max-count", "20001",
                 "--case-sensitive" if parameters["case_sensitive"] else "--ignore-case"]
    if parameters["pattern_type"] == "literal":
        arguments.append("--fixed-strings")
    arguments.extend(["--regexp", parameters["query"], "--", *map(str, paths)])
    environment = os.environ.copy()
    environment.pop("RIPGREP_CONFIG_PATH", None)
    creation = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, close_fds=True,
                                   creationflags=creation, start_new_session=os.name != "nt", env=environment)
    except OSError:
        raise RipgrepError("SEARCH_BACKEND_UNAVAILABLE") from None
    buffers, overflow, read_failed = [bytearray(), bytearray()], threading.Event(), threading.Event()

    def drain(index, stream, limit):
        try:
            while chunk := os.read(stream.fileno(), 16384):
                remaining = limit - len(buffers[index])
                buffers[index].extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    break
        except OSError:
            read_failed.set()
        finally:
            stream.close()

    readers = [threading.Thread(target=drain, args=(index, stream, limit), daemon=True)
               for index, stream, limit in ((0, process.stdout, MAX_OUTPUT_BYTES),
                                             (1, process.stderr, MAX_STDERR_BYTES))]
    job, stopped, reason = None, False, "complete"
    try:
        if os.name == "nt":
            try:
                job = _WindowsJob(process)
            except OSError:
                raise RipgrepError("SEARCH_BACKEND_UNAVAILABLE") from None
        for reader in readers:
            reader.start()
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if cancel.is_set():
                raise _Cancelled()
            if clock() >= deadline or overflow.is_set():
                reason = "time_limit" if clock() >= deadline else "backend_output_limit"
                stopped = _stop_process(process, job)
                if not stopped:
                    raise RipgrepError("SEARCH_STOP_UNCONFIRMED", state="unknown")
                break
            time.sleep(.01)
        for reader in readers:
            reader.join(timeout=1)
        if any(reader.is_alive() for reader in readers):
            raise RipgrepError("SEARCH_STOP_UNCONFIRMED", state="unknown")
        if read_failed.is_set():
            raise RipgrepError("SEARCH_BACKEND_FAILED")
        if reason == "complete" and process.returncode not in {0, 1}:
            # A Rust regex syntax error is explicit, never a Python-regex or
            # literal fallback. Suppress raw stderr, which contains user paths.
            code = "SEARCH_PATTERN_INVALID" if b"regex parse error:" in buffers[1] else "SEARCH_BACKEND_FAILED"
            raise RipgrepError(code)
        output = bytes(buffers[0])
        if reason != "complete" and output and not output.endswith(b"\n"):
            output = output.rsplit(b"\n", 1)[0] + b"\n" if b"\n" in output else b""
        events = []
        try:
            for line in output.splitlines():
                event = json.loads(line)
                if not isinstance(event, dict) or event.get("type") not in {"begin", "match", "end", "summary"}:
                    raise ValueError()
                if event["type"] == "match":
                    events.append(event["data"])
            return events, reason
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise RipgrepError("SEARCH_BACKEND_FAILED") from None
    finally:
        if process.poll() is None or job is not None and not stopped and job.active():
            if not _stop_process(process, job):
                raise RipgrepError("SEARCH_STOP_UNCONFIRMED", state="unknown")
        if job is not None:
            job.close()
        for reader in readers:
            if reader.ident is not None:
                reader.join(timeout=1)
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed and not any(reader.is_alive() for reader in readers):
                stream.close()
