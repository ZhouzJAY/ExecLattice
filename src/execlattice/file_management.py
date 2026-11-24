"""Version-pinned single-entry Windows mutations; no recursive deletion."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
from pathlib import Path


def path_version(path, info, digest):
    material = {"format": 1, "path": os.path.normcase(str(Path(path).resolve(strict=True))),
                "device": info.st_dev, "file": info.st_ino, "modified_ns": info.st_mtime_ns,
                "changed_ns": info.st_ctime_ns, "size_bytes": info.st_size,
                "kind": "directory" if stat.S_ISDIR(info.st_mode) else "file", "sha256": digest}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def directory_info(path):
    """Inspect an already canonical directory using handle change-time."""
    return _entry_info(path, directory=True)


def metadata_info(path, state_dir, *, directory):
    """Read native metadata without opening or rescanning file contents."""
    canonical = _ordinary(str(path), state_dir, allow_root=directory)
    return _entry_info(canonical, directory=directory)


def _entry_info(path, *, directory):
    """Compare the opened handle to a fixed canonical path, never a late resolve."""
    from .workspace_executor import WorkspaceDenied, _link

    expected = os.path.normcase(str(path))
    if os.name != "nt":
        info = path.stat()
        if _link(info) or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise WorkspaceDenied("Ordinary filesystem metadata is required")
        return info
    import msvcrt
    from ctypes import wintypes as wt

    from .executors import _windows_final_path
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel.CreateFileW.restype = wt.HANDLE
    handle = kernel.CreateFileW(str(path), 0x80, 0x7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle.argtypes = [wt.HANDLE]
        kernel.CloseHandle(handle)
        raise
    try:
        info = os.fstat(descriptor)
        if (_link(info) or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)
                or os.path.normcase(str(_windows_final_path(descriptor))) != expected):
            raise WorkspaceDenied("Filesystem metadata handle changed")
        return info
    finally:
        os.close(descriptor)


def _ordinary(raw, state_dir, *, allow_root=False):
    from .workspace_executor import WorkspaceDenied, _identity, _path

    path = _path(raw, state_dir)
    native = _path(str(path.resolve(strict=True)), state_dir)
    if _identity(path.stat()) != _identity(native.stat()) or not allow_root and native == Path(native.anchor):
        raise WorkspaceDenied("A verified non-root filesystem entry is required")
    return native


def execute_path_mutation(action, parameters, cancel, state_dir):
    from .workspace_executor import _WRITE_LOCK, _cancelled, _failure

    if os.name != "nt":
        return _failure("NATIVE_FILE_MUTATION_UNAVAILABLE", "Version-pinned mutations require the Windows native backend")
    with _WRITE_LOCK:
        source = _ordinary(parameters["path"], state_dir)
        _cancelled(cancel)
        return _windows_mutate(action, parameters, source, cancel, state_dir)


def _windows_mutate(action, parameters, source, cancel, state_dir):
    import msvcrt
    from ctypes import wintypes as wt

    from .executors import _windows_final_path
    from .workspace_executor import (
        WorkspaceDenied,
        _binary_signature,
        _cancelled,
        _failure,
        _identity,
        _link,
        _path,
        _stream_digest,
        _success,
    )

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel.CreateFileW.restype = wt.HANDLE
    kernel.SetFileInformationByHandle.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    kernel.SetFileInformationByHandle.restype = wt.BOOL
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    invalid = ctypes.c_void_p(-1).value
    parent = _path(str(source.parent), state_dir)
    parent_handle = kernel.CreateFileW(str(parent), 0x81, 0x3, None, 3, 0x02200000, None)
    if parent_handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    source_handle, descriptor, committed = None, None, False
    try:
        source_handle = kernel.CreateFileW(str(source), 0x80010000, 0x1, None, 3, 0x02200000, None)
        if source_handle == invalid:
            source_handle = None
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = msvcrt.open_osfhandle(source_handle, os.O_RDONLY | os.O_BINARY)
        source_handle = None
        if os.path.normcase(str(_windows_final_path(descriptor))) != os.path.normcase(str(source)):
            raise WorkspaceDenied("Filesystem handle changed")
        before = os.fstat(descriptor)
        directory = stat.S_ISDIR(before.st_mode)
        if _link(before) or not directory and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1):
            raise WorkspaceDenied("Only an ordinary single entry is supported")
        digest = None if directory else _stream_digest(descriptor, before, cancel)
        version = path_version(source, before, digest)
        if version != parameters["expected_version"]:
            return _failure("PATH_VERSION_CONFLICT", "The selected entry changed; inspect its current version")
        kind = "directory" if directory else "file"
        _cancelled(cancel)
        if _identity(_path(str(source), state_dir).stat()) != _identity(before):
            return _failure("PATH_VERSION_CONFLICT", "The selected entry identity changed")
        if action == "delete":
            if directory:
                with os.scandir(source) as entries:
                    if next(entries, None) is not None:
                        return _failure("DIRECTORY_NOT_EMPTY", "Only empty directories can be deleted")
            deleted = wt.BOOL(True)
            if not kernel.SetFileInformationByHandle(msvcrt.get_osfhandle(descriptor), 4,
                                                     ctypes.byref(deleted), ctypes.sizeof(deleted)):
                code = ctypes.get_last_error()
                if code == 145:
                    return _failure("DIRECTORY_NOT_EMPTY", "The directory is no longer empty")
                raise ctypes.WinError(code)
            committed = True
            os.close(descriptor)
            descriptor = None
            # A successful disposition applies only to the pinned object. A
            # delayed deletion is not falsely reported as confirmed absence.
            try:
                after = source.lstat()
            except FileNotFoundError:
                pass
            else:
                if (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino):
                    return _failure("DELETE_UNCONFIRMED", "Original deletion is pending; inspect the original task", state="unknown")
            return _success({"path": parameters["path"], "kind": kind, "deleted": True,
                             "previous_version": version, "recursive": False})
        target = _path(parameters["destination"], state_dir, missing=True)
        target_parent = _ordinary(str(target.parent), state_dir, allow_root=True)
        if target_parent != parent or target == source or target.exists():
            return _failure("FILE_CONFLICT", "Rename requires the same directory and a different absent destination")
        encoded = target.name.encode("utf-16-le")

        class RenameInformation(ctypes.Structure):
            _fields_ = [("Flags", wt.DWORD), ("RootDirectory", wt.HANDLE),
                        ("FileNameLength", wt.DWORD), ("FileName", wt.WCHAR * (len(encoded) // 2 + 1))]

        information = RenameInformation()
        information.Flags = 0
        information.RootDirectory = parent_handle
        information.FileNameLength = len(encoded)
        ctypes.memmove(ctypes.addressof(information) + RenameInformation.FileName.offset, encoded, len(encoded))
        _cancelled(cancel)
        # Win32 SetFileInformationByHandle expands a relative name against the
        # process CWD on some Windows releases. Use the native handle-relative
        # operation so the already pinned parent, rather than a raced pathname,
        # remains the destination authority.
        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtSetInformationFile.argtypes = [wt.HANDLE, ctypes.POINTER(IoStatusBlock), ctypes.c_void_p,
                                              wt.ULONG, ctypes.c_int]
        ntdll.NtSetInformationFile.restype = wt.LONG
        ntdll.RtlNtStatusToDosError.argtypes = [wt.LONG]
        ntdll.RtlNtStatusToDosError.restype = wt.ULONG
        status = ntdll.NtSetInformationFile(msvcrt.get_osfhandle(descriptor), ctypes.byref(IoStatusBlock()),
                                          ctypes.byref(information), ctypes.sizeof(information), 10)
        if status != 0:
            if status == 0x103:
                committed = True
                return _failure("RENAME_UNCONFIRMED", "The original native rename is still pending", state="unknown")
            code = ntdll.RtlNtStatusToDosError(status)
            if code in {80, 183}:
                return _failure("FILE_CONFLICT", "Rename destination already exists")
            raise ctypes.WinError(code)
        committed = True
        if (os.path.normcase(str(_windows_final_path(descriptor))) != os.path.normcase(str(target))
                or (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (before.st_dev, before.st_ino)):
            return _failure("RENAME_UNCONFIRMED", "Original rename could not be confirmed", state="unknown")
        # NTFS publishes the rename change-time when this handle closes. Take
        # the resulting version afterwards and verify the same original object
        # and bytes; an intervening replacement is unknown, never rolled back.
        os.close(descriptor)
        descriptor = None
        if directory:
            after = directory_info(_path(str(target), state_dir))
        else:
            actual_digest, _, after = _binary_signature(_path(str(target), state_dir), cancel, state_dir)
            if actual_digest != digest:
                return _failure("RENAME_UNCONFIRMED", "Renamed file changed before confirmation", state="unknown")
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            return _failure("RENAME_UNCONFIRMED", "Renamed entry identity changed", state="unknown")
        result = {"path": parameters["path"], "destination": parameters["destination"], "kind": kind,
                  "renamed": True, "source_removed": True, "previous_version": version,
                  "path_version": path_version(target, after, digest), "size_bytes": None if directory else after.st_size,
                  "sha256": digest}
        if directory:
            result["directory_identity"] = {"device": after.st_dev, "file": after.st_ino}
        return _success(result)
    except Exception:
        if committed:
            return _failure("DELETE_UNCONFIRMED" if action == "delete" else "RENAME_UNCONFIRMED",
                            "Original filesystem effect could not be confirmed; query the original task", state="unknown")
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if source_handle is not None:
            kernel.CloseHandle(source_handle)
        kernel.CloseHandle(parent_handle)
