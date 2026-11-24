"""Pinned command tools in an individual development process environment.

The parent's environment and persistent Windows PATH are never changed. Presence
is only a cheap declaration; the bundled executable is verified at every command
start before its directory is preferred over user-provided command locations.
"""

from __future__ import annotations

import ntpath
import os
from collections.abc import Mapping
from pathlib import Path

from . import ripgrep_backend


def _path_identity(value: str) -> str:
    """Lexical Windows PATH equivalence; do not touch arbitrary user directories."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return ntpath.normcase(ntpath.normpath(value))


def _environment_value(environment: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in environment.items() if key.casefold() == name.casefold()), None)


def _core_module_directory(value: str) -> bool:
    """Recognize a local PowerShell Core engine, never probe UNC module roots."""
    normalized = _path_identity(value)
    drive, _ = ntpath.splitdrive(normalized)
    if (len(drive) != 2 or drive[1] != ":" or not ntpath.isabs(normalized)
            or ntpath.basename(normalized) != "modules"):
        return False
    try:
        return (Path(normalized).parent / "pwsh.exe").is_file()
    except OSError:
        return False


def _documents_directory(environment: Mapping[str, str]) -> str | None:
    """Use Windows' redirected Documents folder only for this actual user."""
    profile = _environment_value(environment, "USERPROFILE")
    current = _environment_value(os.environ, "USERPROFILE")
    if os.name == "nt" and profile and current and _path_identity(profile) == _path_identity(current):
        import ctypes
        from ctypes import wintypes

        try:
            api = ctypes.WinDLL("shell32", use_last_error=True).SHGetFolderPathW
            api.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR]
            api.restype = ctypes.c_long
            buffer = ctypes.create_unicode_buffer(32768)
            if api(None, 5, None, 0, buffer) == 0 and buffer.value:  # CSIDL_PERSONAL.
                return buffer.value
        except (OSError, AttributeError):
            pass
    return ntpath.join(profile, "Documents") if profile else None


def build_windows_powershell_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Remove recognizable PS7 injections for an explicitly selected WinPS child.

    PowerShell 7 only fixes PSModulePath when it starts powershell.exe directly;
    an intermediate Python host otherwise passes incompatible Core modules on.
    Match the documented three Core paths, retaining unrelated/custom entries
    and their order. A custom-only path without Core engine evidence is intact.
    No parent, user setting or registry value is changed.
    """
    environment = os.environ.copy() if base is None else dict(base)
    keys = [key for key in environment if key.casefold() == "psmodulepath"]
    if not keys:
        return environment
    key = "PSMODULEPATH" if "PSMODULEPATH" in keys else keys[0]
    entries = environment[key].split(";")
    core = {_path_identity(entry) for entry in entries if _core_module_directory(entry)}
    if not core:
        return environment
    documents = _documents_directory(environment)
    program_files = _environment_value(environment, "ProgramFiles")
    for directory in (documents, program_files):
        if directory:
            core.add(_path_identity(ntpath.join(directory, "PowerShell", "Modules")))
    kept = [entry for entry in entries if _path_identity(entry) not in core]
    # A Core-only inherited path cannot autoload WinPS' own cmdlets. Restore its
    # engine location for this child, without deleting custom search locations.
    system_root = _environment_value(environment, "SystemRoot") or r"C:\Windows"
    native = ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0", "Modules")
    if _path_identity(native) not in {_path_identity(entry) for entry in kept}:
        kept.append(native)
    for other in keys:
        if other != key:
            del environment[other]
    environment[key] = ";".join(kept)
    return environment


def build_development_environment(base: Mapping[str, str] | None = None, *,
                                  windows_powershell: bool = False) -> dict[str, str]:
    """Copy the caller environment and prefer bundled rg only after verification.

    Missing/corrupted assets degrade to the original environment so unrelated
    development commands remain usable. Other PATH entries, empty entries, and
    variables (including ripgrep configuration) keep their original values.
    """
    environment = (build_windows_powershell_environment(base) if windows_powershell
                   else os.environ.copy() if base is None else dict(base))
    try:
        executable = ripgrep_backend.verified_executable()
    except (ripgrep_backend.RipgrepError, OSError):
        return environment

    directory = str(executable.parent)
    path_keys = [key for key in environment if key.upper() == "PATH"]
    path_key = "PATH" if "PATH" in path_keys else next(iter(path_keys), "PATH")
    original = environment.get(path_key)
    identity = _path_identity(directory)
    entries = [] if original is None else original.split(os.pathsep)
    entries = [entry for entry in entries if _path_identity(entry) != identity]
    # Explicit test dictionaries can contain both Path and PATH, although the
    # actual Windows process environment is case-insensitive. Publish one key.
    for key in path_keys:
        if key != path_key:
            del environment[key]
    environment[path_key] = os.pathsep.join([directory, *entries])
    return environment


def command_toolchain_capability() -> dict | None:
    """Declare package presence and verification policy, never a verified claim."""
    if not ripgrep_backend.available():
        return None
    return {
        "version": 1,
        "command": "rg",
        "engine": "ripgrep",
        "engine_version": ripgrep_backend.VERSION,
        "engine_sha256": ripgrep_backend.EXECUTABLE_SHA256,
        "scope": "development_process",
        "verification": "on_command_start",
        "declaration": "bundled_presence_only",
        "hint": ("For multi-pattern log context: rg --no-config -n -C 2 --max-count N "
                 "-e PATTERN -e PATTERN -- LOG. Exit 1 means no matches. Existing output "
                 "limits apply; inspect original output artifacts when capture is truncated. "
                 "A bounded search does not establish complete-file or business success."),
    }
