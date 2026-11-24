"""Bounded command output snapshots; truncation never terminates the command.

The retained bytes are a tail across both streams, ordered by their observation
at the reader threads. Totals refer to all observed bytes; hashes refer only to
the exact retained bytes. Snapshots are immutable to callers and contain no
claim about completion.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from collections import deque

_PROGRESS_FIELDS = frozenset({
    "stdout", "stderr", "stdout_b64", "stderr_b64", "stdout_sha256", "stderr_sha256",
    "stdout_total_bytes", "stderr_total_bytes", "duration_ms", "sequence", "output_truncated", "display_truncated",
})
_LEGACY_FIELDS = _PROGRESS_FIELDS - {"sequence", "stdout_total_bytes", "stderr_total_bytes"}


def _validated_output(value: dict) -> tuple[bytes, bytes]:
    channels = []
    for channel in ("stdout", "stderr"):
        encoded = value[channel + "_b64"]
        if not isinstance(encoded, str) or len(encoded) > 4 * ((65536 + 2) // 3):
            raise ValueError("Invalid command output")
        data = base64.b64decode(encoded, validate=True)
        if (len(data) > 65536 or base64.b64encode(data).decode("ascii") != encoded
                or value[channel + "_sha256"] != hashlib.sha256(data).hexdigest()
                or value[channel] != data.decode("utf-8", errors="replace")[:8192]):
            raise ValueError("Command output receipt does not match retained bytes")
        channels.append(data)
    if (sum(map(len, channels)) > 65536
            or type(value["duration_ms"]) is not int or not 0 <= value["duration_ms"] <= 86400000
            or type(value["display_truncated"]) is not bool
            or value["display_truncated"] != any(len(data.decode("utf-8", errors="replace")) > 8192
                                                 for data in channels)):
        raise ValueError("Invalid command output metadata")
    return tuple(channels)


def valid_progress(value: dict) -> bool:
    """Validate bounded running evidence before a Controller stores or exposes it."""
    try:
        if not isinstance(value, dict) or set(value) != _PROGRESS_FIELDS:
            return False
        channels = _validated_output(value)
        totals = [value[channel + "_total_bytes"] for channel in ("stdout", "stderr")]
        return (type(value["sequence"]) is int and 1 <= value["sequence"] <= 2**63 - 1
                and all(type(total) is int and len(data) <= total <= 2**63 - 1
                        for total, data in zip(totals, channels, strict=True))
                and type(value["output_truncated"]) is bool
                and value["output_truncated"] == (sum(totals) > sum(map(len, channels))))
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


def valid_development_result(value: dict) -> bool:
    """Accept exact tail receipts or complete legacy receipts, with a real exit code.

    A nonzero exit is valid evidence of failure. A success caller must separately
    require exit_code == 0. Missing codes never prove that a command completed.
    """
    try:
        if not isinstance(value, dict) or type(value.get("exit_code")) is not int:
            return False
        payload = {key: item for key, item in value.items() if key not in {"exit_code", "output_capture"}}
        if "output_capture" in value:
            from .output_artifacts import valid_capture_result

            if (set(payload) != _PROGRESS_FIELDS or not valid_capture_result(value["output_capture"],
                    {name: payload.get(name + "_total_bytes") for name in ("stdout", "stderr")})):
                return False
        if set(payload) == _PROGRESS_FIELDS:
            return valid_progress(payload)
        if set(payload) != _LEGACY_FIELDS:
            return False
        _validated_output(payload)
        return payload["output_truncated"] is False
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


class CommandOutput:
    def __init__(self, limit: int, started: float):
        self.limit = limit
        self.started = started
        self._chunks = deque()
        self._retained = 0
        self._totals = [0, 0]
        self._sequence = 0
        self._lock = threading.Lock()

    def append(self, channel: int, data: bytes) -> None:
        if not data:
            return
        with self._lock:
            self._totals[channel] += len(data)
            self._chunks.append((channel, data))
            self._retained += len(data)
            while self._retained > self.limit:
                index, chunk = self._chunks.popleft()
                excess = self._retained - self.limit
                removed = min(excess, len(chunk))
                self._retained -= removed
                if removed < len(chunk):
                    self._chunks.appendleft((index, chunk[removed:]))

    def snapshot(self) -> dict:
        with self._lock:
            channels = [bytearray(), bytearray()]
            for index, data in self._chunks:
                channels[index].extend(data)
            totals = tuple(self._totals)
            self._sequence += 1
            sequence = self._sequence
        stdout, stderr = map(bytes, channels)
        text = [data.decode("utf-8", errors="replace") for data in (stdout, stderr)]
        return {
            "stdout": text[0][:8192], "stderr": text[1][:8192],
            "stdout_b64": base64.b64encode(stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(stderr).decode("ascii"),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout_total_bytes": totals[0], "stderr_total_bytes": totals[1],
            "duration_ms": round((time.monotonic() - self.started) * 1000),
            "sequence": sequence,
            "output_truncated": sum(totals) > len(stdout) + len(stderr),
            "display_truncated": any(len(value) > 8192 for value in text),
        }
