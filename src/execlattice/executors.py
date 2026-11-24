"""Legacy fixed profiles and authenticated desktop project task dispatch.

The desktop's full mode deliberately permits current-user development commands;
read-only mode rejects commands and writes. Neither mode is an OS sandbox.
Legacy CLI profiles retain their original fixed argv and root policy.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import re
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path, PureWindowsPath
from typing import Any

_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SHELLS = {
    "cmd",
    "powershell",
    "pwsh",
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
}
_RESERVED = {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
_RESERVED.update(f"{prefix}{suffix}" for prefix in ("com", "lpt") for suffix in "123456789¹²³")
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ExecutionDenied(ValueError):
    """A request crossed the worker's local permission boundary."""


def validate_policy(policy: dict) -> dict:
    """Validate and normalize a locally administered policy without executing it."""
    if not isinstance(policy, dict) or set(policy) - {
        "roots",
        "commands",
        "max_file_bytes",
        "max_output_bytes",
        "desktop_access",
    }:
        raise ValueError("Invalid policy keys")
    roots, commands = policy.get("roots", {}), policy.get("commands", {})
    if not isinstance(roots, dict) or not isinstance(commands, dict):
        raise ValueError("Policy roots and commands must be objects")  # noqa: TRY004 - public policy validation contract
    if len(roots) > 32 or len(commands) > 128:
        raise ValueError("Policy is too large")
    normalized: dict[str, Any] = {"roots": {}, "commands": {}}
    if "desktop_access" in policy:
        desktop = policy["desktop_access"]
        if (not isinstance(desktop, dict) or set(desktop) != {"mode"}
                or not isinstance(desktop["mode"], str) or desktop["mode"] not in {"read_only", "full"}):
            raise ValueError("Invalid desktop access mode")
        normalized["desktop_access"] = {"mode": desktop["mode"]}
    for name, raw in roots.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(raw, str):
            raise ValueError("Invalid root name or path")
        root = Path(raw)
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("Roots must be existing absolute directories")
        normalized["roots"][name] = str(root.resolve(strict=True))
    for name, command in commands.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("Invalid command profile name")
        if not isinstance(command, dict) or set(command) != {"argv", "cwd"}:
            raise ValueError("Command profiles require exactly argv and cwd")
        argv = command["argv"]
        if (
            not isinstance(argv, list)
            or not 1 <= len(argv) <= 128
            or any(not isinstance(arg, str) or "\x00" in arg for arg in argv)
            or sum(map(len, argv)) > 30000
        ):
            raise ValueError("Invalid fixed command argv")
        executable = Path(argv[0])
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError("Profile executable must be an existing absolute file")
        executable = executable.resolve(strict=True)
        stem = executable.stem.lower()
        if stem in _SHELLS or executable.suffix.lower() in {".bat", ".cmd", ".ps1", ".vbs", ".js"}:
            raise ValueError("Shell and script-launcher profiles are disabled")
        interpreter = stem.startswith(("python", "pypy")) or stem in {"node", "nodejs", "ruby", "perl"}
        if interpreter and any(
            arg.lower() in {"-c", "-m", "-e", "--eval", "--print", "-p"} for arg in argv[1:]
        ):
            raise ValueError("Interpreter evaluation flags are disabled")
        cwd = command["cwd"]
        if not isinstance(cwd, str) or cwd not in normalized["roots"]:
            raise ValueError("Profile cwd must name an authorized root")
        normalized["commands"][name] = {"argv": [str(executable), *argv[1:]], "cwd": cwd}
    for name in ("max_file_bytes", "max_output_bytes"):
        value = policy.get(name, 65536)
        if type(value) is not int or not 1 <= value <= 65536:
            raise ValueError("Byte limits must be integers between 1 and 65536")
        normalized[name] = value
    return normalized


def capabilities(policy: dict) -> list[dict]:
    """Advertise only operations actually enabled in the local policy."""
    policy = validate_policy(policy)
    items = []
    if policy["roots"]:
        items.append(
            {
                "executor_type": "file",
                "actions": ["read"],
                "available": True,
                "roots": sorted(policy["roots"]),
                "max_file_bytes": policy["max_file_bytes"],
                "verification": "sha256",
                "permission": "local-policy-root",
                "parameters_schema": {
                    "type": "object",
                    "required": ["root", "path"],
                    "additionalProperties": False,
                    "properties": {
                        "root": {"type": "string", "enum": sorted(policy["roots"])},
                        "path": {"type": "string"},
                    },
                },
            }
        )
    if policy["commands"] and policy.get("desktop_access", {}).get("mode") != "read_only":
        from .task_lanes import concurrency_capability

        items.append(
            {
                "executor_type": "command",
                "actions": ["run"],
                "task_concurrency": concurrency_capability(),
                "available": True,
                "profiles": sorted(policy["commands"]),
                "max_output_bytes": policy["max_output_bytes"],
                "verification": "exit-code-and-output-sha256",
                "permission": "local-policy-profile",
                "parameters_schema": {
                    "type": "object",
                    "required": ["profile"],
                    "additionalProperties": False,
                    "properties": {"profile": {"type": "string", "enum": sorted(policy["commands"])}},
                },
            }
        )
    items.extend(project_capabilities(policy))
    return items


def project_capabilities(policy: dict) -> list[dict]:
    """Desktop mode selects current-user project access without profile setup."""
    from .observation_capabilities import (
        log_access_capability,
        software_backend_capability,
        uia_observation_capability,
    )
    from .project_patch_capability import project_patch_capability
    from .system_diagnostics_protocol import diagnostic_capability
    from .system_tool_registry import SYSTEM_TOOLS, system_capabilities

    mode = policy.get("desktop_access", {}).get("mode")
    if mode not in {"read_only", "full"}:
        return []
    items = [{"executor_type": "workspace", "available": True,
              "actions": ["list", "list_page", "search", "search_page", "read", "read_many", "read_range", "stat", "read_image", "patch_status", "log_read", "log_search"]
                         + (["write", "edit", "mkdir", "copy", "move", "delete", "rename", "apply_patch"] if mode == "full" else []),
              "mode": mode, "permission": "current-user-local-paths", "max_file_bytes": 65536,
              "max_range_file_bytes": 8 * 1024 * 1024,
              "max_batch_files": 16, "max_batch_read_bytes": 65536, "max_batch_response_bytes": 180000,
              "project_patch": project_patch_capability(),
              "log_access": log_access_capability(),
              "log_follow_v1": True, "output_artifacts_v1": True,
              "directory_manifest": 1, "directory_identity": True,
              "verification": "bounded listing/search; exact bytes and sha256; conflict-checked write/edit"}]
    from .ripgrep_backend import available as native_search_available
    from .ripgrep_backend import capability as native_search_capability

    if native_search_available():
        items[0]["actions"].append("search_native_page")
        items[0]["native_search"] = native_search_capability()
    if mode == "full":
        items.append({"executor_type": "development", "available": True, "actions": ["run"],
                      "mode": "full", "permission": "current-user-command-environment",
                      "verification": "exit code, output sha256, cancellation and timeout",
                      "max_timeout_seconds": 3600, "live_output": True,
                      "limitations": ["no automatic elevation", "not a sandbox", "no interactive stdin"]})
        from .command_toolchain import command_toolchain_capability

        command_tools = command_toolchain_capability()
        if command_tools is not None:
            items[-1]["bundled_command_tools"] = command_tools
    from .transfer_protocol import MAX_TRANSFER_BYTES, TRANSFER_MODELS, TRANSFER_READ_ACTIONS

    items.append({"executor_type": "transfer", "available": True, "mode": mode,
                  "actions": [action for action in TRANSFER_MODELS if mode == "full" or action in TRANSFER_READ_ACTIONS],
                  "permission": "current-user-local-paths", "max_transfer_bytes": MAX_TRANSFER_BYTES,
                  "chunk_bytes": 65536, "verification": "sha256 chunks; atomic conflict-checked commit"})
    from .data_channel_protocol import SFTP_DATA_CAPABILITY

    items[-1]["sftp_data_v1"] = dict(SFTP_DATA_CAPABILITY)
    items.append({"executor_type": "localhost", "available": True, "mode": mode, "actions": ["request"],
                  "permission": "current-user-loopback-http", "max_response_bytes": 65536, "http_request": 1,
                  "schemes": ["http", "https"], "hosts": ["127.0.0.1", "::1"],
                  "methods": ["GET", "HEAD"] + (["POST", "PUT", "PATCH", "DELETE"] if mode == "full" else []),
                  "verification": "bounded HTTP status, headers and response SHA-256; no redirects or retries",
                  "limitations": ["loopback HTTP/HTTPS only", "no browser DOM or general TCP forwarding"]})
    if os.name == "nt":
        from .browser_protocol import (
            BROWSER_MODELS,
            BROWSER_READ_ACTIONS,
            browser_capabilities,
            browser_observation_capabilities,
            browser_workflow_capability,
        )

        items.append({"executor_type": "browser", "available": True, "mode": mode,
                      "actions": [action for action in BROWSER_MODELS
                                  if mode == "full" or action in BROWSER_READ_ACTIONS],
                      "browser_controls": browser_capabilities(), "browser_observation": browser_observation_capabilities(),
                      **({"browser_workflow": browser_workflow_capability()} if mode == "full" else {}),
                      "permission": "current-user-agent-browser",
                      "verification": "dedicated profile; observed single-use controls; no effect retries",
                      "limitations": ["requires installed Edge or Chrome", "top document semantic projection",
                                      "no password input controls or existing user browser profiles"]})
        items.append({"executor_type": "computer", "available": True,
                      "actions": ["info", "windows", "capture", "inspect", "environment", "ui_tree", "clipboard_read", "ui_wait"]
                                 + (["input", "launch", "window", "ui_action", "clipboard_write", "ui_action_observe", "ui_workflow", "ui_workflow_target"] if mode == "full" else []) + ["diagnose"] + list(SYSTEM_TOOLS),
                      "mode": mode, "permission": "current-user-interactive-desktop",
                      "desktop_input": mode == "full",
                      "capture_updates_v1": True,
                      "system_diagnostics": diagnostic_capability(),
                      **system_capabilities(),
                      "uia_observation": uia_observation_capability(),
                      "software_backend": software_backend_capability(),
                      "uia_operations": ["invoke", "focus", "set_value", "toggle", "select", "expand", "collapse", "scroll_into_view"],
                      "verification": "bounded image sha256; fresh single-use session-bound input; no automatic replay",
                      "limitations": ["unlocked interactive desktop required", "no automatic elevation",
                                      "no secure desktop or lock-screen control"]})
        if mode == "full":
            from .software_workflow import software_workflow_capability, software_workflow_target_capability

            items[-1]["software_workflow"] = software_workflow_capability()
            items[-1]["software_workflow_target"] = software_workflow_target_capability()
            from .terminal_protocol import TERMINAL_MODELS, WINPTY_COMPATIBILITY

            items.append({"executor_type": "terminal", "available": True, "actions": list(TERMINAL_MODELS),
                          "mode": "full", "permission": "current-user-command-environment",
                          "backend": "windows-conpty", "interactive_stdin": True, "max_read_wait_ms": 10000,
                          "compatibility_backend": dict(WINPTY_COMPATIBILITY), "parallel_host_role": "execution-v3",
                          "verification": "owner-bound live shell; sequenced input; hash-checked cursor output",
                          "limitations": ["no automatic elevation", "sessions close on disconnect or restart"]})
    return items


def _relative_parts(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        raise ExecutionDenied("A nonempty relative file path is required")
    windows = PureWindowsPath(raw)
    if windows.drive or windows.root or Path(raw).is_absolute():
        raise ExecutionDenied("Absolute, drive, and UNC paths are forbidden")
    parts = re.split(r"[\\/]", raw)
    for part in parts:
        if (
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or any(ord(char) < 32 or char in ':<>"|?*' for char in part)
            or part.split(".", 1)[0].lower() in _RESERVED
        ):
            raise ExecutionDenied("Unsafe relative file path")
    return parts


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE)


def _windows_final_path(fd: int) -> Path:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(fd)
    size = function(handle, None, 0, 0)
    if not size:
        raise ExecutionDenied("Cannot verify the opened file handle")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = function(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise ExecutionDenied("Cannot verify the opened file handle")
    path = buffer.value
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return Path(path)


def _windows_long_path(path: Path) -> Path:
    """Expand an existing ordinary caller path independently of an opened handle.

    GetLongPathNameW is required even without a tilde: 8.3 names are not
    reliably identifiable from their spelling. An API failure is never a
    reason to trust a handle's own final path as the expected name.
    """
    import ctypes
    from ctypes import wintypes

    def ordinary(value):
        windows = PureWindowsPath(value)
        if (not isinstance(value, str) or not value or len(value) > 32767
                or value.startswith(("\\\\", "//")) or not windows.is_absolute()
                or not re.fullmatch(r"[A-Za-z]:", windows.drive) or windows.root != "\\"
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            return False
        return all(not part or part not in {".", ".."} and not part.endswith((" ", "."))
                   and not any(c in ':<>"|?*' for c in part)
                   and part.split(".", 1)[0].lower() not in _RESERVED
                   for part in re.split(r"[\\/]", value[3:]))

    requested = str(path)
    if not ordinary(requested):
        raise ExecutionDenied("Cannot canonicalize an ordinary local path")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.GetLongPathNameW
    function.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    function.restype = wintypes.DWORD
    size = function(requested, None, 0)
    if not size or size > 32768:
        raise ExecutionDenied("Cannot verify the caller's long path")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = function(requested, buffer, len(buffer))
    if (not written or written >= len(buffer)
            or written != len(buffer.value.encode("utf-16-le")) // 2 or not ordinary(buffer.value)):
        raise ExecutionDenied("Cannot verify the caller's long path")
    return Path(buffer.value)


@contextlib.contextmanager
def _open_verified(root: Path, parts: list[str], *, expected_canonical: Path | None = None):
    """Open first, verify the actual handle, and never read unverified contents."""
    expected = root.joinpath(*parts)
    root_identity = root.stat()
    if _is_link(root.lstat()):
        raise ExecutionDenied("Authorized root has changed into a link")
    current = root
    for part in parts:
        current /= part
        if _is_link(current.lstat()):
            raise ExecutionDenied("Symbolic links and reparse points are forbidden")
    descriptors: list[int] = []
    fd = None
    try:
        if os.name == "nt":
            if expected_canonical is None:
                # Consumers without an independent authorization snapshot keep
                # their previous strict spelling rule. Name expansion alone
                # cannot authorize a newly supported alias on their behalf.
                canonical_expected = os.path.normcase(str(expected))
                if os.path.normcase(str(_windows_long_path(expected))) != canonical_expected:
                    raise ExecutionDenied("An authorized canonical path snapshot is required")
            else:
                # The caller checked this exact snapshot against its own policy
                # (including app-private state). Do not re-expand and replace it
                # after an alias can have changed its target.
                canonical_expected = os.path.normcase(str(expected_canonical))
            fd = os.open(expected, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
            if os.path.normcase(str(_windows_final_path(fd))) != canonical_expected:
                raise ExecutionDenied("Opened file escaped the authorized path")
        else:
            # Anchored directory descriptors and O_NOFOLLOW close ancestor-link races.
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(root, flags)
            descriptors.append(directory)
            for part in parts[:-1]:
                directory = os.open(part, flags, dir_fd=directory)
                descriptors.append(directory)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ExecutionDenied("Only regular files with a single hard link are readable")
        yield fd, info
        after = root.stat()
        if (after.st_dev, after.st_ino) != (root_identity.st_dev, root_identity.st_ino):
            raise ExecutionDenied("Authorized root changed during the read")
        if os.name == "nt" and os.path.normcase(str(_windows_final_path(fd))) != canonical_expected:
            raise ExecutionDenied("Opened file moved during the read")
    finally:
        if fd is not None:
            os.close(fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _file_read(parameters: dict, policy: dict, cancel: threading.Event) -> dict:
    if set(parameters) != {"root", "path"}:
        raise ExecutionDenied("File reads require exactly root and path")
    root_name = parameters["root"]
    if not isinstance(root_name, str) or root_name not in policy["roots"]:
        raise ExecutionDenied("Root is not authorized")
    parts = _relative_parts(parameters["path"])
    root = Path(policy["roots"][root_name])
    expected = None
    if os.name == "nt":
        # Preserve the original missing-file diagnostic and reject raw reparse
        # ancestors before asking Windows to expand any part of the name.
        current = root
        if _is_link(current.lstat()):
            raise ExecutionDenied("Authorized root has changed into a link")
        for part in parts:
            current /= part
            if _is_link(current.lstat()):
                raise ExecutionDenied("Symbolic links and reparse points are forbidden")
        expected = _windows_long_path(root.joinpath(*parts))
    with _open_verified(root, parts, expected_canonical=expected) as (fd, before):
        if before.st_size > policy["max_file_bytes"]:
            return _failure("FILE_TOO_LARGE", "File exceeds the configured byte limit")
        data = bytearray()
        while len(data) <= policy["max_file_bytes"]:
            if cancel.is_set():
                return _failure(
                    "CANCELLED", "Task was cancelled before the read completed", state="cancelled"
                )
            chunk = os.read(fd, min(65536, policy["max_file_bytes"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) > policy["max_file_bytes"]:
            return _failure("FILE_TOO_LARGE", "File exceeds the configured byte limit")
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ):
            return _failure("FILE_CHANGED", "File changed during the read; retry explicitly")
    return {
        "state": "succeeded",
        "result": {
            "content_b64": base64.b64encode(data).decode("ascii"),
            "encoding": "base64",
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "error": None,
    }


class _WindowsJob:
    """A kill-on-close Windows job, containing approved process descendants.

    Assignment is immediately after Popen. This is resource cleanup for trusted
    local profiles, not isolation from a deliberately escaping executable.
    """

    def __init__(self, process: subprocess.Popen):
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IOCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IOCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class Accounting(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_int64),
                ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64),
                ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        self.ctypes, self.accounting_type = ctypes, Accounting
        kernel = self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        kernel.IsProcessInJob.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("Cannot create process job")
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise OSError("Cannot configure process job")
        if not kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close()
            raise OSError("Cannot contain approved process")

    def active(self) -> int:
        accounting = self.accounting_type()
        if not self.kernel.QueryInformationJobObject(
            self.handle, 1, self.ctypes.byref(accounting), self.ctypes.sizeof(accounting), None
        ):
            raise OSError("Cannot verify process job")
        return accounting.ActiveProcesses

    def terminate(self) -> bool:
        return bool(self.kernel.TerminateJobObject(self.handle, 1))

    def process_handles(self) -> list:
        """Hold only this Job's members, so PID reuse cannot prove termination."""
        from ctypes import wintypes

        capacity = 32
        handles = []
        try:
            for _ in range(4):
                buffer = self.ctypes.create_string_buffer(8 + self.ctypes.sizeof(self.ctypes.c_size_t) * capacity)
                success = self.kernel.QueryInformationJobObject(self.handle, 3, buffer, len(buffer), None)
                assigned, count = (wintypes.DWORD * 2).from_buffer(buffer)
                if count > capacity or assigned > 4096:
                    raise OSError("Cannot bound process job membership")
                if success and count >= assigned:
                    break
                if not success and self.ctypes.get_last_error() != 234:
                    raise OSError("Cannot query process job membership")
                capacity = max(capacity * 2, assigned)
            else:
                raise OSError("Process job membership changed during verification")
            pids = (self.ctypes.c_size_t * count).from_buffer(buffer, 8)
            for pid in pids:
                handle = self.kernel.OpenProcess(0x00101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION.
                if not handle:
                    if self.ctypes.get_last_error() == 87:  # It already exited.
                        continue
                    raise OSError("Cannot retain a process job member")
                member = wintypes.BOOL()
                if not self.kernel.IsProcessInJob(handle, self.handle, self.ctypes.byref(member)):
                    self.kernel.CloseHandle(handle)
                    raise OSError("Cannot verify retained process membership")
                if member.value:
                    handles.append(handle)
                else:
                    self.kernel.CloseHandle(handle)
            return handles
        except BaseException:
            self.close_processes(handles)
            raise

    def wait_processes(self, handles: list, deadline: float) -> bool:
        # TerminateJobObject initiates asynchronous termination. Accounting may
        # reach zero before a descendant's process object becomes signaled.
        for handle in handles:
            milliseconds = max(0, int((deadline - time.monotonic()) * 1000))
            if self.kernel.WaitForSingleObject(handle, milliseconds) != 0:
                return False
        return True

    def close_processes(self, handles: list) -> None:
        for handle in handles:
            self.kernel.CloseHandle(handle)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _stop_process(process: subprocess.Popen, job: _WindowsJob | None) -> bool:
    """Return true only when process termination was verified."""
    try:
        if os.name == "nt":
            if job is not None:
                until = time.monotonic() + 3
                handles, captured = [], True
                try:
                    try:
                        handles = job.process_handles()
                    except OSError:
                        captured = False
                    if not job.terminate():
                        return False
                    signaled = job.wait_processes(handles, until)
                    while job.active() and time.monotonic() < until:
                        time.sleep(0.02)
                    process.wait(timeout=max(.01, until - time.monotonic()))
                    return captured and signaled and job.active() == 0
                finally:
                    job.close_processes(handles)
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
            stopped = subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            process.wait(timeout=1)
            return stopped.returncode == 0
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)
        return process.poll() is not None
    except (OSError, subprocess.TimeoutExpired):
        with contextlib.suppress(OSError):
            process.kill()
        return False


def _child_environment() -> dict[str, str]:
    allowed = ("SystemRoot", "SYSTEMROOT", "WINDIR", "SystemDrive", "TEMP", "TMP", "LANG", "LC_ALL")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result["PATH"] = os.defpath
    result["PYTHONIOENCODING"] = "utf-8"
    return result


def _command_run(parameters: dict, policy: dict, timeout: int, cancel: threading.Event) -> dict:
    if policy.get("desktop_access", {}).get("mode") == "read_only":
        raise ExecutionDenied("Read-only mode does not execute commands")
    if set(parameters) != {"profile"}:
        raise ExecutionDenied("Commands require exactly a configured profile")
    profile = parameters["profile"]
    if not isinstance(profile, str) or profile not in policy["commands"]:
        raise ExecutionDenied("Command profile is not authorized")
    definition = policy["commands"][profile]
    started = time.monotonic()
    creation = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        definition["argv"],
        cwd=policy["roots"][definition["cwd"]],
        env=_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        creationflags=creation,
        start_new_session=os.name != "nt",
    )
    job = None
    if os.name == "nt":
        try:
            job = _WindowsJob(process)
        except OSError:
            # No execution without a process-tree cleanup mechanism.
            stopped = _stop_process(process, None)
            process.stdout.close()
            process.stderr.close()
            return _failure(
                "PROCESS_CONTAINMENT_FAILED",
                "Cannot contain the approved process",
                state="failed" if stopped else "unknown",
            )
    outputs = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    read_error = threading.Event()
    limit = policy["max_output_bytes"]

    def consume(stream, index):
        try:
            while chunk := os.read(stream.fileno(), 4096):
                with lock:
                    remaining = max(0, limit - sum(map(len, outputs)))
                    outputs[index].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
        except OSError:
            read_error.set()
        finally:
            stream.close()

    readers = [
        threading.Thread(target=consume, args=(stream, index), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))
    ]
    for reader in readers:
        reader.start()
    state, error = "succeeded", None
    try:
        while True:
            if cancel.is_set():
                state, error = (
                    "cancelled",
                    {"code": "CANCELLED", "message": "Task cancellation was confirmed"},
                )
                break
            if overflow.is_set():
                state, error = (
                    "failed",
                    {"code": "OUTPUT_LIMIT", "message": "Command exceeded the output byte limit"},
                )
                break
            if time.monotonic() - started >= timeout:
                state, error = (
                    "timed_out",
                    {"code": "TIMEOUT", "message": "Command exceeded its execution timeout"},
                )
                break
            if process.poll() is not None and not any(reader.is_alive() for reader in readers):
                break
            time.sleep(0.02)
        # A signaled process handle can precede the job's accounting update by
        # a few scheduler ticks. Give accounting a short bounded settle period
        # before classifying any remaining members as orphaned descendants.
        settle_until = time.monotonic() + 0.2
        if state == "succeeded" and job is not None:
            while job.active() and time.monotonic() < settle_until:
                time.sleep(0.01)
        descendants_alive = job is not None and job.active() > 0
        if state != "succeeded" or descendants_alive:
            if not _stop_process(process, job):
                state, error = (
                    "unknown",
                    {"code": "STOP_UNCONFIRMED", "message": "Process-tree termination could not be verified"},
                )
            elif state == "succeeded":
                state, error = (
                    "failed",
                    {
                        "code": "CHILD_PROCESSES_REMAIN",
                        "message": "Approved command left child processes running",
                    },
                )
        for reader in readers:
            reader.join(timeout=1)
        if any(reader.is_alive() for reader in readers):
            state, error = (
                "unknown",
                {"code": "OUTPUT_INCOMPLETE", "message": "Command output pipes did not close"},
            )
        elif overflow.is_set() and state == "succeeded":
            state, error = (
                "failed",
                {"code": "OUTPUT_LIMIT", "message": "Command exceeded the output byte limit"},
            )
        elif read_error.is_set() and state == "succeeded":
            state, error = (
                "unknown",
                {"code": "OUTPUT_INCOMPLETE", "message": "Command output could not be read completely"},
            )
        elif state == "succeeded" and process.returncode != 0:
            state, error = (
                "failed",
                {"code": "COMMAND_EXIT", "message": "Approved command returned a nonzero exit code"},
            )
        stdout, stderr = bytes(outputs[0]), bytes(outputs[1])
        return {
            "state": state,
            "result": {
                # Human display is separately bounded because JSON escaping can
                # expand a single raw byte into six characters. Raw evidence is
                # exact and remains available in the base64 fields.
                "stdout": stdout.decode("utf-8", errors="replace")[:8192],
                "stderr": stderr.decode("utf-8", errors="replace")[:8192],
                "stdout_b64": base64.b64encode(stdout).decode("ascii"),
                "stderr_b64": base64.b64encode(stderr).decode("ascii"),
                "exit_code": process.poll(),
                "duration_ms": round((time.monotonic() - started) * 1000),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "output_truncated": overflow.is_set(),
                "display_truncated": len(stdout.decode("utf-8", errors="replace")) > 8192
                or len(stderr.decode("utf-8", errors="replace")) > 8192,
            },
            "error": error,
        }
    finally:
        if process.poll() is None:
            _stop_process(process, job)
        if job is not None:
            job.close()


def _failure(code: str, message: str, *, state: str = "failed") -> dict:
    return {"state": state, "result": None, "error": {"code": code, "message": message}}


def execute_task(task: dict, policy: dict, cancel: threading.Event | None = None, *,
                 state_dir: Path | None = None, progress=None) -> dict:
    """Execute one schema-constrained task and return only verified outcomes."""
    cancel = cancel or threading.Event()
    try:
        policy = validate_policy(policy)
        if not isinstance(task, dict) or not isinstance(task.get("parameters"), dict):
            raise ExecutionDenied("Invalid task parameters")
        timeout = task.get("timeout_seconds", 30)
        maximum = 3600 if task.get("executor_type") == "development" else 300
        if type(timeout) is not int or not 1 <= timeout <= maximum:
            raise ExecutionDenied("Timeout is outside the executor's supported range")
        if cancel.is_set():
            return _failure("CANCELLED", "Task was cancelled before execution", state="cancelled")
        operation = task.get("executor_type"), task.get("action")
        if operation == ("file", "read"):
            return _file_read(task["parameters"], policy, cancel)
        if operation == ("command", "run"):
            return _command_run(task["parameters"], policy, timeout, cancel)
        if operation[0] == "workspace":
            from .workspace_executor import execute_workspace

            return execute_workspace(operation[1], task["parameters"], policy, cancel, state_dir=state_dir)
        if operation == ("development", "run"):
            from .development_executor import execute_development

            if state_dir is not None:
                return execute_development(task["parameters"], policy, timeout, cancel, progress=progress,
                                           state_dir=state_dir, source_id=task.get("task_id"))
            if progress is None:
                return execute_development(task["parameters"], policy, timeout, cancel)
            return execute_development(task["parameters"], policy, timeout, cancel, progress=progress)
        if operation[0] == "computer":
            from .computer_executor import execute_computer

            return execute_computer(operation[1], task["parameters"], policy, cancel, state_dir=state_dir)
        if operation[0] == "terminal":
            if state_dir is not None and (Path(state_dir) / "worker" / "worker.json").is_file():
                from .execution_host_client import execute_host_task

                return execute_host_task(task["task_id"], "terminal", operation[1], task["parameters"],
                                         policy, Path(state_dir), timeout=timeout)
            from .terminal_executor import execute_terminal

            return execute_terminal(operation[1], task["parameters"], policy, cancel, state_dir=state_dir)
        if operation[0] == "job":
            from .execution_host_client import execute_host_task

            if state_dir is None:
                return _failure("EXECUTION_HOST_UNAVAILABLE", "Persistent jobs require the authenticated execution host")
            return execute_host_task(task["task_id"], "job", operation[1], task["parameters"],
                                     policy, Path(state_dir), timeout=timeout)
        if operation[0] == "transfer":
            from .transfer_executor import execute_transfer

            return execute_transfer(operation[1], task["parameters"], policy, cancel, state_dir=state_dir)
        if operation[0] == "localhost":
            from .localhost_executor import execute_localhost

            return execute_localhost(operation[1], task["parameters"], policy, cancel,
                                     state_dir=state_dir, timeout=timeout)
        if operation[0] == "browser":
            from .browser_executor import execute_browser

            return execute_browser(operation[1], task["parameters"], policy, cancel,
                                   state_dir=state_dir, timeout=timeout)
        raise ExecutionDenied("Executor or action is not authorized")
    except ExecutionDenied as exc:
        return _failure("POLICY_DENIED", str(exc))
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "Authorized file or configured executable was not found")
    except PermissionError:
        return _failure("ACCESS_DENIED", "Operating system denied access")
    except (ValueError, TypeError):
        return _failure("INVALID_CONFIGURATION", "Worker policy or task configuration is invalid")
    except OSError:
        # OS exceptions often contain full private filesystem paths; keep them out of reports.
        return _failure("IO_ERROR", "Operating system operation failed")
