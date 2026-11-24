"""HTTPS transport adapter shared by CLI, Worker and MCP."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .connection import connection_origin
from .protocol import TERMINAL_STATES
from .request_timing import timed_function
from .security import _reject_link_ancestors, read_json, tls_context, validate_url


class APIError(Exception):
    def __init__(self, code: str, status: int):
        self.code = code
        self.status = status
        super().__init__(f"{code} (HTTP {status})")


def _pool_identity(configuration, scope):
    """Re-read the small trust anchor; never retain a stale CA by pathname."""
    path = Path(configuration["ca_file"]).absolute()
    _reject_link_ancestors(path)

    def identity(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 65536
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Invalid Controller trust anchor")
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    with path.open("rb") as stream:
        before = identity(os.fstat(stream.fileno()))
        data = stream.read(65537)
        after = identity(os.fstat(stream.fileno()))
    _reject_link_ancestors(path)
    # On Windows CPython fstat reports metadata-change time as st_ctime,
    # while path.stat still exposes creation time there. Compare the handle
    # change-time to itself; path/handle binding uses device, inode, size, mtime.
    if before != after or before[:4] != identity(path.stat())[:4] or len(data) != before[2]:
        raise ValueError("Controller trust anchor changed while reading")
    encoded = json.dumps(configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return scope, hashlib.sha256(encoded).digest(), before, hashlib.sha256(data).digest()


class _ControllerLease:
    """A short-lived lease; closing it cannot abort another request or wait."""

    def __init__(self, pool, entry):
        self._pool, self._entry = pool, entry
        self._lock = threading.Lock()
        self._closed, self._active, self._released = False, 0, False

    def _call(self, name, *args, **kwargs):
        with self._lock:
            if self._closed:
                raise RuntimeError("Controller client lease is closed")
            self._pool._check(self._entry)
            self._active += 1
        try:
            # No transport-error retry: a lost POST response can mean committed.
            return getattr(self._entry["client"], name)(*args, **kwargs)
        finally:
            with self._lock:
                self._active -= 1
                release = self._closed and not self._active and not self._released
                if release:
                    self._released = True
            if release:
                self._pool._release(self._entry)

    def request(self, method, path, body=None):
        return self._call("request", method, path, body)

    def wait(self, task_id, seconds=40):
        return self._call("wait", task_id, seconds=seconds)

    def close(self):
        with self._lock:
            self._closed = True
            release = not self._active and not self._released
            if release:
                self._released = True
        if release:
            self._pool._release(self._entry)


class ControllerClientPool:
    """Bounded transport reuse inside one DesktopSession, never shared globally.

    Each acquisition binds exact credentials, route, CA bytes, peer and handle.
    Retirement prevents further calls through old leases; an already executing
    call keeps its transport alive until its lease is closed and I/O finishes.
    Streaming/notification clients remain separate, with independent timeouts.
    """

    def __init__(self, max_entries=8):
        if type(max_entries) is not int or not 1 <= max_entries <= 16:
            raise ValueError("Invalid Controller pool bound")
        self._max_entries = max_entries
        self._lock = threading.RLock()
        self._entries = []
        self._closed = False

    @timed_function("controller_prepare")
    def acquire(self, configuration, scope, *, factory=None):
        configuration = copy.deepcopy(configuration)
        key = _pool_identity(configuration, scope)
        factory = factory or ControllerClient
        with self._lock:
            if self._closed:
                raise RuntimeError("Controller client pool is closed")
            for entry in self._entries:
                if not entry["retired"] and entry["key"] == key and entry["factory"] is factory:
                    entry["references"] += 1
                    return _ControllerLease(self, entry)
            self._retire_locked()
            if len(self._entries) >= self._max_entries:
                raise RuntimeError("Controller client pool is busy")
            client = factory(configuration)
            try:
                # Do not publish a client if its trust file changed during SSL
                # context construction. The caller can observe the failure;
                # no request, especially no submission, is automatically retried.
                if _pool_identity(configuration, scope) != key:
                    raise ValueError("Controller trust anchor changed during client creation")
            except BaseException:
                client.close()
                raise
            entry = {"key": key, "factory": factory, "client": client, "references": 1, "retired": False}
            self._entries.append(entry)
            return _ControllerLease(self, entry)

    def _check(self, entry):
        with self._lock:
            if self._closed or entry["retired"]:
                raise RuntimeError("Controller client binding changed")

    def _release(self, entry):
        with self._lock:
            entry["references"] -= 1
            if entry["retired"] and not entry["references"]:
                self._entries.remove(entry)
                entry["client"].close()

    def _retire_locked(self):
        for entry in list(self._entries):
            entry["retired"] = True
            if not entry["references"]:
                self._entries.remove(entry)
                entry["client"].close()

    def invalidate(self):
        with self._lock:
            self._retire_locked()

    def close(self):
        with self._lock:
            self._closed = True
            self._retire_locked()


class ControllerClient:
    def __init__(self, config: dict):
        if config.get("lan_preview") != 1 or {"connection_url", "public_relay"} & config.keys():
            raise ValueError("Use a fresh direct configuration generated by the LAN preview")
        self._configuration = dict(config)
        self.url = validate_url(config["controller_url"])
        self.connection_url = connection_origin(config)
        canonical = urlsplit(self.url)
        hostname = canonical.hostname
        host = f"[{hostname}]" if ":" in hostname else hostname
        self._authority = host + (f":{canonical.port}" if canonical.port is not None else "")
        self._tls_hostname = hostname
        self._alternate_route = self.connection_url != self.url
        self.http = httpx.Client(
            base_url=self.connection_url,
            verify=tls_context(config["ca_file"]),
            headers={"Authorization": "Bearer " + config["token"]},
            timeout=httpx.Timeout(10, connect=5),
            trust_env=False,
            follow_redirects=False,
        )

    @classmethod
    def from_file(cls, path: Path):
        return cls(read_json(path))

    def close(self):
        self.http.close()

    def notification_client(self):
        """A dedicated HTTPS connection; long waits cannot hold task I/O."""
        client = ControllerClient(self._configuration)
        client.http.timeout = httpx.Timeout(1.5, connect=1)
        return client

    def reporting_client(self):
        """Independent Worker result I/O; never share a blocking poll socket."""
        return ControllerClient(self._configuration)

    @staticmethod
    def worker_poll_path(wait_ms=0):
        if type(wait_ms) is not int or not 0 <= wait_ms <= 5000:
            raise ValueError("Invalid Worker dispatch wait")
        return "/v1/worker/poll" + (f"?wait_ms={wait_ms}" if wait_ms else "")

    @timed_function("controller_http")
    def request(self, method: str, path: str, body: dict | None = None):
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or "#" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise ValueError("Controller request path must stay within its configured origin")
        options = {}
        if self._alternate_route:
            # HTTPX's documented SNI extension sets the hostname checked by TLS.
            # Both CA and hostname verification stay enabled. Only TCP routing
            # changes; the Controller identity and Authorization remain fixed.
            options = {
                "headers": {"Host": self._authority},
                "extensions": {"sni_hostname": self._tls_hostname},
            }
        response = self.http.request(method, path, json=body, **options)
        if not response.is_success:
            try:
                code = response.json()["error"]["code"]
                if not isinstance(code, str) or len(code) > 128:
                    code = "controller_request_failed"
            except (KeyError, ValueError, TypeError):
                code = "controller_request_failed"
            raise APIError(code, response.status_code)
        return response.json()

    def observation_client(self):
        client = ControllerClient(self._configuration)
        client.http.timeout = httpx.Timeout(5, connect=2, write=2, pool=2)
        return client

    def _observation_options(self):
        # The streaming path has precisely the same CA, SNI, Host and bearer
        # authority as ordinary requests; a dial route never changes identity.
        return ({"headers": {"Host": self._authority}, "extensions": {"sni_hostname": self._tls_hostname}}
                if self._alternate_route else {})

    def observation_frames(self, identifier, stop):
        import re

        from .live_observation import ObservationError, PacketDecoder

        if not isinstance(identifier, str) or re.fullmatch("[0-9a-f]{32}", identifier) is None:
            raise ValueError("Invalid observation identity")
        decoder = PacketDecoder()
        with self.http.stream("GET", "/v1/observations/" + identifier, **self._observation_options()) as response:
            if not response.is_success:
                raise ObservationError("observation_unavailable", response.status_code)
            if response.headers.get("content-type", "").split(";")[0] != "application/vnd.execlattice.observation":
                raise ValueError("Invalid observation content type")
            # No fixed chunk_size: filling one would delay small interactive
            # terminal writes until 16 KiB or EOF instead of delivering them now.
            for chunk in response.iter_bytes():
                if stop.is_set():
                    return
                for offset in range(0, len(chunk), 65536):
                    for header, payload in decoder.feed(chunk[offset:offset + 65536]):
                        if stop.is_set():
                            return
                        yield header, payload
            decoder.finish()

    def publish_observation(self, identifier, nonce, frames):
        import re

        if (not isinstance(identifier, str) or re.fullmatch("[0-9a-f]{32}", identifier) is None
                or not isinstance(nonce, str) or re.fullmatch("[0-9a-f]{64}", nonce) is None):
            raise ValueError("Invalid observation authority")
        options = self._observation_options()
        options["headers"] = {**options.get("headers", {}), "Content-Type": "application/vnd.execlattice.observation",
                              "X-Observation-Nonce": nonce}
        with self.http.stream("POST", f"/v1/worker/observations/{identifier}/output", content=frames, **options) as response:
            if not response.is_success:
                raise APIError("observation_publish_failed", response.status_code)

    def wait(self, task_id: str, seconds: float = 40) -> dict:
        deadline = time.monotonic() + max(0, seconds)
        while True:
            if not getattr(self, "_legacy_task_wait", False):
                wait_ms = min(5000, max(0, int((deadline - time.monotonic()) * 1000)))
                try:
                    task = self.request("GET", f"/v1/tasks/{task_id}/wait?wait_ms={wait_ms}")
                except APIError as exc:
                    if exc.status not in (404, 405):
                        raise
                    # This is an observational read fallback only. A missing
                    # task stays missing; no execution is submitted or retried.
                    self._legacy_task_wait = True
                    task = self.request("GET", f"/v1/tasks/{task_id}")
            else:
                task = self.request("GET", f"/v1/tasks/{task_id}")
            if task["state"] in TERMINAL_STATES or time.monotonic() >= deadline:
                return task
            if getattr(self, "_legacy_task_wait", False):
                time.sleep(min(.2, max(0, deadline - time.monotonic())))
