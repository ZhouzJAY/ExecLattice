"""Fixed negotiated SFTP byte channel; no general socket or port forwarding."""
from __future__ import annotations

import re
from uuid import UUID

SFTP_DATA_CAPABILITY = {"version": 1, "protocol": "sftp-v3", "path": "/payload",
                        "block_bytes": 262144, "max_requests": 4, "durable_close": True}
CHANNEL_CAPABILITY = {"version": 1}
MAX_CHANNELS = 4
MAX_CHUNK = 65536
MAX_SECONDS = 1800
HEX_ID = re.compile("[a-f0-9]{32}")


def valid_sftp_data_capability(value):
    return (type(value) is dict and set(value) == set(SFTP_DATA_CAPABILITY)
            and all(type(value[k]) is type(v) and value[k] == v for k, v in SFTP_DATA_CAPABILITY.items()))


def channel_request(value):
    if type(value) is not dict or set(value) != {"device_id", "transfer_id", "direction", "authorization_task_id", "client_public_key"}:
        raise ValueError("Invalid SFTP channel request")
    if (str(UUID(value["device_id"])) != value["device_id"]
            or str(UUID(value["authorization_task_id"])) != value["authorization_task_id"]
            or not isinstance(value["transfer_id"], str) or not HEX_ID.fullmatch(value["transfer_id"])
            or value["direction"] not in {"upload", "download"}):
        raise ValueError("Invalid SFTP channel identity")
    public_key(value["client_public_key"])
    return dict(value)


def public_key(value):
    if (not isinstance(value, str) or not 64 <= len(value) <= 2048 or not value.startswith("ssh-ed25519 ")
            or any(c in value.rstrip("\n") for c in "\r\n\0")):
        raise ValueError("Invalid pinned SSH key")
    import asyncssh

    try:
        key = asyncssh.import_public_key(value)
    except (ValueError, TypeError, asyncssh.Error):
        raise ValueError("Invalid pinned SSH key") from None
    if key.get_algorithm() != "ssh-ed25519":
        raise ValueError("Only fixed Ed25519 keys are accepted")
    return value.strip()
