"""OS-protected local state and standard TLS; no custom cryptographic protocol."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def _reject_link_ancestors(path: Path) -> None:
    for candidate in (*reversed(path.parents), path):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("State directory and ancestors cannot be links or reparse points")


def _windows_directory_acl_status(advapi, kernel, directory, expected, expected_owner) -> tuple[bool, bool]:
    """Read the current owner/protected DACL on this exact open handle.

    There is no cached permission verdict: an external ACL/owner change is
    observed on the next call. Normalized SDDL avoids comparing pointer layout,
    ACL padding or SID aliases. SACL/group are not changed by this operation.
    """
    import ctypes
    from ctypes import wintypes as wt

    advapi.GetSecurityInfo.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD,
        wt.LPVOID, wt.LPVOID, wt.LPVOID, wt.LPVOID, ctypes.POINTER(wt.LPVOID)]
    advapi.GetSecurityInfo.restype = wt.DWORD
    advapi.EqualSid.argtypes = [wt.LPVOID, wt.LPVOID]
    advapi.EqualSid.restype = wt.BOOL
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wt.LPVOID, wt.DWORD, wt.DWORD, ctypes.POINTER(wt.LPWSTR), wt.LPVOID]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wt.BOOL
    current, owner = wt.LPVOID(), wt.LPVOID()
    try:
        if (advapi.GetSecurityInfo(directory, 1, 5, ctypes.byref(owner), None, None, None, ctypes.byref(current))
                or not current or not owner):
            raise OSError("Cannot inspect current protected state ACL; initialization stopped")
        if not advapi.EqualSid(owner, expected_owner):
            return False, False

        def normalized(descriptor):
            value = wt.LPWSTR()
            try:
                if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 5, ctypes.byref(value), None
                ) or value.value is None:
                    raise OSError("Cannot compare protected state ACL; initialization stopped")
                text = value.value
                # SetSecurityInfo adds SE_DACL_AUTO_INHERITED (AI), a record
                # that propagation occurred; it does not grant access. Keep
                # protection (P), inheritance request (AR), owner and every
                # ACE exact while ignoring only that bookkeeping difference.
                start = text.index("D:") + 2
                end = text.find("(", start)
                if end < 0:
                    end = len(text)
                return text[:start] + text[start:end].replace("AI", "") + text[end:]
            finally:
                if value:
                    kernel.LocalFree(value)

        return True, normalized(current) == normalized(expected)
    finally:
        if current:
            kernel.LocalFree(current)


def _set_windows_directory_acl(advapi, directory, owner, dacl) -> None:
    # SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
    # Request an ownership change only when the directory has a different owner.
    flags = 0x80000004 | (1 if owner is not None else 0)
    if advapi.SetSecurityInfo(directory, 1, flags, owner, None, dacl, None):
        raise OSError("Cannot enforce exact protected state ACL; initialization stopped")


def _protect_windows_directory(path: Path) -> None:
    """Verify the exact DACL/owner, replacing only a different descriptor.

    Unlike icacls /grant:r, this removes pre-existing explicit grants to other
    principals. The directory is new or empty when bootstrap calls this helper;
    children created later inherit only the current user's full-access ACE.
    """
    import ctypes
    from ctypes import wintypes as wt

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wt.HANDLE
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    kernel.LocalFree.argtypes = [wt.LPVOID]
    kernel.LocalFree.restype = wt.LPVOID
    kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel.CreateFileW.restype = wt.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wt.BOOL
    advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi.OpenProcessToken.restype = wt.BOOL
    advapi.GetTokenInformation.argtypes = [
        wt.HANDLE,
        ctypes.c_int,
        wt.LPVOID,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
    ]
    advapi.GetTokenInformation.restype = wt.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wt.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        ctypes.POINTER(wt.LPVOID),
        ctypes.POINTER(wt.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wt.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        wt.LPVOID,
        ctypes.POINTER(wt.BOOL),
        ctypes.POINTER(wt.LPVOID),
        ctypes.POINTER(wt.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wt.BOOL
    advapi.GetSecurityDescriptorOwner.argtypes = [
        wt.LPVOID,
        ctypes.POINTER(wt.LPVOID),
        ctypes.POINTER(wt.BOOL),
    ]
    advapi.GetSecurityDescriptorOwner.restype = wt.BOOL
    advapi.SetSecurityInfo.argtypes = [
        wt.HANDLE,
        ctypes.c_int,
        wt.DWORD,
        wt.LPVOID,
        wt.LPVOID,
        wt.LPVOID,
        wt.LPVOID,
    ]
    advapi.SetSecurityInfo.restype = wt.DWORD

    token, sid_text, descriptor = wt.HANDLE(), wt.LPWSTR(), wt.LPVOID()
    directory = None
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise OSError("Cannot determine current user SID; initialization stopped")
        length = wt.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        if not length.value:
            raise OSError("Cannot inspect current user SID; initialization stopped")
        buffer = ctypes.create_string_buffer(length.value)
        if not advapi.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise OSError("Cannot inspect current user SID; initialization stopped")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError("Cannot inspect current user SID; initialization stopped")
        # Explicit owner prevents a previous directory owner from restoring
        # their own access after broad explicit ACEs have been removed.
        sddl = f"O:{sid_text.value}D:P(A;OICI;FA;;;{sid_text.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise OSError("Cannot build protected state ACL; initialization stopped")
        dacl, owner, present, defaulted = wt.LPVOID(), wt.LPVOID(), wt.BOOL(), wt.BOOL()
        if (
            not advapi.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            )
            or not present.value
            or not dacl
            or not advapi.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted))
        ):
            raise OSError("Cannot inspect protected state ACL; initialization stopped")
        # No FILE_SHARE_DELETE: the directory cannot be replaced while locked.
        # An owner always needs the DACL rights, but may lack WRITE_OWNER.
        acl_access = 0x60080  # READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES
        invalid_handles = (None, ctypes.c_void_p(-1).value)
        can_change_owner = True
        directory = kernel.CreateFileW(str(path), acl_access | 0x80000, 0x3, None, 3, 0x02200000, None)
        if directory in invalid_handles and ctypes.get_last_error() == 5:  # ERROR_ACCESS_DENIED
            can_change_owner = False
            directory = kernel.CreateFileW(str(path), acl_access, 0x3, None, 3, 0x02200000, None)
        if directory in invalid_handles:
            directory = None
            raise OSError("Cannot open state directory securely; initialization stopped")
        attributes = (wt.DWORD * 2)()
        if (
            not kernel.GetFileInformationByHandleEx(directory, 9, attributes, ctypes.sizeof(attributes))
            or not attributes[0] & 0x10
            or attributes[0] & 0x400
        ):
            raise OSError("State directory must be a regular directory; initialization stopped")
        # Setting an already-identical inheritable ACL can propagate metadata
        # writes through existing state trees. Keep all handle/reparse checks,
        # but avoid that write when the current owner and protected DACL match.
        current_owner, exact_acl = _windows_directory_acl_status(advapi, kernel, directory, descriptor, owner)
        if not current_owner and not can_change_owner:
            raise OSError("Choose a state directory owned by the current user.")
        if not exact_acl:
            _set_windows_directory_acl(advapi, directory, None if current_owner else owner, dacl)
            if not _windows_directory_acl_status(advapi, kernel, directory, descriptor, owner)[1]:
                raise OSError("Cannot verify exact protected state ACL; initialization stopped")
    finally:
        if directory is not None:
            kernel.CloseHandle(directory)
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(sid_text)
        if token:
            kernel.CloseHandle(token)


def protect_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    _reject_link_ancestors(path)
    path.mkdir(parents=True, exist_ok=True)
    _reject_link_ancestors(path)
    if os.name == "nt":
        _protect_windows_directory(path)
    else:
        path.chmod(0o700)
    _reject_link_ancestors(path)
    return path


def write_private_json(path: Path, value: dict) -> None:
    """Create, never overwrite; parent must already be protected."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def replace_private_json(path: Path, value: dict) -> None:
    """Atomically replace one existing private JSON file in its protected directory."""
    path = Path(os.path.abspath(path))
    _reject_link_ancestors(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("Private configuration must be a regular unlinked file")
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12) + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        _reject_link_ancestors(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("Configuration must be an object")
    return value


def validate_url(url: str) -> str:
    if not isinstance(url, str) or any(character.isspace() or ord(character) < 32 for character in url):
        raise ValueError("Controller URL must be a valid HTTPS origin")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.port is not None
        and not 1 <= parsed.port <= 65535
    ):
        raise ValueError("Controller URL must be an HTTPS origin without credentials or path")
    return url.rstrip("/")


def tls_context(ca_file: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def create_certificate(state_dir: Path, hosts: list[str]) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ExecLattice local controller")])
    alternatives = []
    for host in dict.fromkeys(["localhost", "127.0.0.1", "::1", *hosts]):
        try:
            alternatives.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            alternatives.append(x509.DNSName(host))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    for filename, data in [
        (
            "server-key.pem",
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ),
        ("server-cert.pem", cert.public_bytes(serialization.Encoding.PEM)),
    ]:
        fd = os.open(str(state_dir / filename), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)


def cert_fingerprint(path: Path) -> str:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex()
