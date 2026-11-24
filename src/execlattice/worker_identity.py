"""Stable identity for one authenticated worker and its controller trust pin."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from uuid import UUID

from .security import _reject_link_ancestors, validate_url

_OWNER_ID = re.compile(r"[0-9a-f]{32}")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def valid_execution_identity(value: object) -> bool:
    return (
        type(value) is dict
        and value.keys() == {"version", "owner_id"}
        and type(value["version"]) is int
        and value["version"] == 1
        and isinstance(value["owner_id"], str)
        and _OWNER_ID.fullmatch(value["owner_id"]) is not None
    )


def execution_owner_id(capabilities: object) -> str | None:
    """Return the single valid command-capability marker, if one was retained."""
    if not isinstance(capabilities, list):
        return None
    descriptors = [
        capability for capability in capabilities
        if isinstance(capability, dict) and "execution_identity" in capability
    ]
    if len(descriptors) != 1 or descriptors[0].get("executor_type") != "command":
        return None
    value = descriptors[0]["execution_identity"]
    return value["owner_id"] if valid_execution_identity(value) else None


def _plain_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _file_version(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _read_state_file(path: Path, limit: int) -> bytes:
    _reject_link_ancestors(path)
    before = path.lstat()
    if not _plain_file(before) or not 0 < before.st_size <= limit:
        raise ValueError()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not _plain_file(opened) or _file_version(opened) != _file_version(before):
            raise ValueError()
        data = stream.read(limit + 1)
    _reject_link_ancestors(path)
    after = path.lstat()
    if not _plain_file(after) or _file_version(after) != _file_version(before) or len(data) != before.st_size:
        raise ValueError()
    return data


def worker_execution_identity(config: dict, state_dir: Path | None = None) -> dict:
    """Bind the v1 marker to intact pairing state without exposing its inputs."""
    try:
        certificate = Path(config["ca_file"])
        state = certificate.parent if state_dir is None else state_dir.absolute()
        if not certificate.is_absolute() or certificate != state / "controller-cert.pem":
            raise ValueError()
        stored = json.loads(_read_state_file(state / "worker.json", 65536).decode("utf-8"))
        if stored != config:
            raise ValueError()
        device = config["device_id"]
        token = config["token"]
        origin = validate_url(config["controller_url"])
        if (not isinstance(device, str) or str(UUID(device)) != device or not isinstance(token, str)
                or not 32 <= len(token) <= 256 or any(not 33 <= ord(char) <= 126 for char in token)):
            raise ValueError()
        certificate_hash = hashlib.sha256(_read_state_file(certificate, 16384)).hexdigest()
        material = json.dumps([device, origin, token, certificate_hash], separators=(",", ":")).encode()
        fingerprint = hashlib.sha256(material).hexdigest()
        owner_id = hashlib.sha256(("execlattice-execution-owner-v1:" + fingerprint).encode()).hexdigest()[:32]
        return {"version": 1, "owner_id": owner_id}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("Worker identity requires intact protected pairing state.") from None
