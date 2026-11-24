"""One-shot, cancellable HTTP/1.1 access to the remote computer's loopback.

Literal socket addresses avoid DNS and all system/environment proxy settings.
No redirects, decompression, authentication negotiation or automatic retry is
performed. A write whose response cannot be confirmed has an unknown outcome.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import json
import re
import select
import socket
import ssl
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .localhost_protocol import (
    HEADER_NAME,
    MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HEADERS,
    READ_METHODS,
    request_body,
    validate_localhost_parameters,
)


class LocalhostError(Exception):
    def __init__(self, code, message, *, state="failed"):
        self.code, self.message, self.state = code, message, state
        super().__init__(message)


def _private_ports(state_dir):
    """Read only known bounded metadata files; malformed existing state denies."""
    if state_dir is None:
        return set()
    root = Path(state_dir).absolute()
    if root.parent.name.casefold() in {".execlattice", ".omniagent"}:
        root = root.parent
    candidates = [("desktop/agent-bridge.json", ("url",)),
                  ("controller/client.json", ("controller_url", "connection_url")),
                  ("controller/admin.json", ("controller_url", "connection_url")),
                  ("worker/worker.json", ("controller_url", "connection_url"))]
    ports = set()
    for relative, fields in candidates:
        path = root / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise LocalhostError("POLICY_DENIED", "Application endpoint metadata could not be verified") from None
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise LocalhostError("POLICY_DENIED", "Application endpoint metadata could not be verified")
        # The private directory is maintained by the software. Avoid following
        # an unexpected symlink/reparse ancestor if the state was moved.
        for ancestor in (path.parent, root, *root.parents):
            try:
                ancestor_info = ancestor.lstat()
            except OSError:
                raise LocalhostError("POLICY_DENIED", "Application endpoint metadata could not be verified") from None
            if stat.S_ISLNK(ancestor_info.st_mode) or getattr(ancestor_info, "st_file_attributes", 0) & 0x400:
                raise LocalhostError("POLICY_DENIED", "Application endpoint metadata could not be verified")
        try:
            with path.open("rb") as source:
                encoded = source.read(65537)
            if len(encoded) > 65536:
                raise ValueError()
            value = json.loads(encoded)
            if not isinstance(value, dict) or fields[0] not in value:
                raise ValueError()
            for field in fields:
                if field not in value:
                    continue
                url = value[field]
                if not isinstance(url, str):
                    raise ValueError()
                parsed = urlsplit(url)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                        or parsed.username or parsed.password or parsed.fragment):
                    raise ValueError()
                ports.add(parsed.port or (443 if parsed.scheme == "https" else 80))
        except (ValueError, UnicodeError, OSError):
            raise LocalhostError("POLICY_DENIED", "Application endpoint metadata could not be verified") from None
    return ports


class _Wire:
    """Nonblocking I/O with one deadline, including TLS and slow header reads."""
    def __init__(self, parameters, cancel, timeout):
        self.parameters, self.cancel = parameters, cancel
        self.deadline = time.monotonic() + timeout
        self.socket = None
        self.buffer = bytearray()
        self.sent = False

    def check(self):
        if self.cancel.is_set():
            raise LocalhostError("CANCELLED", "HTTP request was cancelled", state="cancelled")
        if time.monotonic() >= self.deadline:
            raise LocalhostError("LOCALHOST_TIMEOUT", "HTTP request exceeded its deadline", state="timed_out")

    def wait(self, *, write=False):
        while True:
            self.check()
            readers, writers, errors = select.select([] if write else [self.socket],
                                                     [self.socket] if write else [], [self.socket],
                                                     min(.05, max(0, self.deadline - time.monotonic())))
            if errors:
                raise OSError("Loopback socket failed")
            if readers or writers:
                return

    def connect(self):
        self.check()
        host, port = self.parameters["host"], self.parameters["port"]
        self.socket = socket.socket(socket.AF_INET6 if host == "::1" else socket.AF_INET, socket.SOCK_STREAM)
        self.socket.set_inheritable(False)
        self.socket.setblocking(False)
        code = self.socket.connect_ex((host, port))
        if code not in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035, 10036, 10037}:
            raise OSError("Loopback connection refused")
        if code:
            self.wait(write=True)
            if self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                raise OSError("Loopback connection failed")
        if self.parameters["scheme"] == "https":
            context = ssl.create_default_context()
            self.socket = context.wrap_socket(self.socket, server_hostname=host, do_handshake_on_connect=False)
            while True:
                self.check()
                try:
                    self.socket.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    self.wait()
                except ssl.SSLWantWriteError:
                    self.wait(write=True)

    def send(self, content):
        view = memoryview(content)
        while view:
            self.check()
            try:
                # Even a TLS/socket error can follow a partial send. Once a
                # mutating request is attempted, failure cannot prove that the
                # server did nothing, including failure of the first send.
                self.sent = True
                sent = self.socket.send(view[:16384])
                if not sent:
                    raise OSError("HTTP send stopped")
                view = view[sent:]
            except (BlockingIOError, ssl.SSLWantWriteError):
                self.wait(write=True)
            except ssl.SSLWantReadError:
                self.wait()

    def recv(self):
        while True:
            self.check()
            try:
                return self.socket.recv(4096)
            except (BlockingIOError, ssl.SSLWantReadError):
                self.wait()
            except ssl.SSLWantWriteError:
                self.wait(write=True)

    def line(self, limit):
        while True:
            split = self.buffer.find(b"\r\n")
            if split >= 0:
                if split + 2 > limit:
                    raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP response headers exceeded their limit")
                value = bytes(self.buffer[:split])
                del self.buffer[:split + 2]
                return value
            if len(self.buffer) >= limit:
                raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP response headers exceeded their limit")
            chunk = self.recv()
            if not chunk:
                raise LocalhostError("LOCALHOST_INCOMPLETE_RESPONSE", "HTTP response ended before completion")
            self.buffer.extend(chunk)

    def take(self, size):
        while not self.buffer:
            chunk = self.recv()
            if not chunk:
                return b""
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def exact(self, size):
        content = bytearray()
        while len(content) < size:
            chunk = self.take(size - len(content))
            if not chunk:
                raise LocalhostError("LOCALHOST_INCOMPLETE_RESPONSE", "HTTP response ended before completion")
            content.extend(chunk)
        return bytes(content)

    def close(self):
        if self.socket is not None:
            with contextlib.suppress(OSError):
                self.socket.close()


def _headers(wire):
    # Bound all informational headers as part of the same response header cap.
    budget, interim = MAX_HTTP_HEADER_BYTES, 0
    while True:
        line = wire.line(min(1024, budget))
        budget -= len(line) + 2
        status = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e\x80-\xff]*)?", line)
        if status is None:
            raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "Local service returned an invalid HTTP status")
        status_code, headers = int(status[1]), []
        while True:
            line = wire.line(budget)
            budget -= len(line) + 2
            if not line:
                break
            name, sep, value = line.partition(b":")
            try:
                name = name.decode("ascii")
            except UnicodeError:
                name = ""
            if (not sep or not HEADER_NAME.fullmatch(name) or len(headers) >= MAX_HTTP_HEADERS
                    or any(char < 32 and char != 9 or char == 127 for char in value)):
                raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "Local service returned invalid HTTP headers")
            headers.append([name, value.strip(b" \t").decode("latin-1")])
        if status_code >= 200:
            return status_code, headers
        interim += 1
        if status_code == 101 or interim > 4:
            raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP upgrades and excessive interim responses are unsupported")


def _body(wire, status_code, headers, maximum, method):
    values = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)
    encodings = values.get("content-encoding", ["identity"])
    encoding = ", ".join(encodings).strip().lower()
    lengths, transfers = values.get("content-length", []), values.get("transfer-encoding", [])
    if (len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
            or lengths and not re.fullmatch(r"[0-9]{1,20}", lengths[0])
            or transfers and transfers[0].lower() != "chunked"):
        raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP response has ambiguous or unsupported framing")
    if method == "HEAD" or status_code in {204, 304}:
        return b"", False, encoding
    length = int(lengths[0]) if lengths else None
    if length is not None:
        # A declared larger body is intentionally bounded, not an incomplete
        # transport error. The digest always describes only returned bytes.
        return wire.exact(min(length, maximum)), length > maximum, encoding
    result = bytearray()
    if transfers:
        chunks, chunk_metadata = 0, 0
        while True:
            line = wire.line(1024)
            chunks += 1
            chunk_metadata += len(line) + 2
            # Extensions are not needed for local preview. Reject rather than
            # interpreting unbounded or ambiguous chunk syntax.
            if (not re.fullmatch(rb"[0-9a-fA-F]{1,16}", line) or chunks > 65538
                    or chunk_metadata > MAX_HTTP_HEADER_BYTES):
                raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP chunk framing exceeded its supported bounds")
            size = int(line, 16)
            if not size:
                # Do not return unverified arbitrary trailer metadata.
                if wire.line(2) != b"":
                    raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP response trailers are unsupported")
                return bytes(result), False, encoding
            allowed = min(size, maximum - len(result))
            if allowed:
                result.extend(wire.exact(allowed))
            if allowed < size:
                return bytes(result), True, encoding
            if wire.exact(2) != b"\r\n":
                raise LocalhostError("LOCALHOST_INVALID_RESPONSE", "HTTP chunk framing is invalid")
    while len(result) <= maximum:
        chunk = wire.take(min(4096, maximum + 1 - len(result)))
        if not chunk:
            return bytes(result), False, encoding
        result.extend(chunk)
    return bytes(result[:maximum]), True, encoding


def _response(parameters, body, wire):
    host = f"[{parameters['host']}]" if parameters["host"] == "::1" else parameters["host"]
    fields = [("Host", f"{host}:{parameters['port']}"), ("Connection", "close"), ("Accept-Encoding", "identity")]
    fields.extend(parameters["headers"].items())
    if parameters["method"] not in READ_METHODS:
        fields.append(("Content-Length", str(len(body))))
    head = (f"{parameters['method']} {parameters['path']} HTTP/1.1\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in fields) + "\r\n").encode("ascii")
    wire.connect()
    wire.send(head)
    if body:
        wire.send(body)
    status_code, headers = _headers(wire)
    raw, truncated, encoding = _body(wire, status_code, headers, parameters["max_response_bytes"], parameters["method"])
    text = None
    if encoding == "identity" and not any(byte < 32 and byte not in {9, 10, 13} or byte == 127 for byte in raw):
        with contextlib.suppress(UnicodeError):
            text = raw.decode("utf-8", errors="strict")
    return {**{key: parameters[key] for key in ("scheme", "host", "port", "path", "method")},
            "status_code": status_code, "headers": headers, "body_b64": base64.b64encode(raw).decode("ascii"),
            "body_sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": len(raw), "body_text": text,
            "body_complete": not truncated, "truncated": truncated, "content_encoding": encoding,
            "request_body_bytes": len(body), "request_body_sha256": hashlib.sha256(body).hexdigest(),
            "request_sent": True, "response_received": True, "redirect_followed": False, "retry_count": 0,
            "observed_at": datetime.now(UTC).isoformat()}


def execute_localhost(action, parameters, policy, cancel, *, state_dir=None, timeout=30):
    """Execute once. A sent mutating request never becomes a safe retry."""
    wire, modifying = None, False
    try:
        parameters = validate_localhost_parameters(action, parameters)
        mode = policy.get("desktop_access", {}).get("mode")
        modifying = parameters["method"] not in READ_METHODS
        if mode not in {"read_only", "full"} or modifying and mode != "full":
            raise LocalhostError("POLICY_DENIED", "This connection mode does not permit this HTTP method")
        if type(timeout) is not int or not 1 <= timeout <= 300:
            raise ValueError()
        if cancel.is_set():
            raise LocalhostError("CANCELLED", "HTTP request was cancelled before sending", state="cancelled")
        if parameters["port"] in _private_ports(state_dir):
            raise LocalhostError("POLICY_DENIED", "Application control endpoints are unavailable to project HTTP tools")
        body = request_body(parameters["body_b64"])
        wire = _Wire(parameters, cancel, timeout)
        result = _response(parameters, body, wire)
        return {"state": "succeeded", "result": result, "error": None}
    except LocalhostError as error:
        code, message, state = error.code, error.message, error.state
    except ssl.SSLCertVerificationError:
        code, message, state = "LOCALHOST_TLS_UNTRUSTED", "The local HTTPS certificate is not trusted for this address", "failed"
    except (OSError, ssl.SSLError):
        code, message, state = "LOCALHOST_CONNECTION_FAILED", "The local HTTP connection could not be completed", "failed"
    except (ValueError, TypeError, KeyError, AttributeError):
        code, message, state = "INVALID_LOCALHOST_REQUEST", "The local HTTP request is invalid", "failed"
    finally:
        if wire is not None:
            wire.close()
    if modifying and wire is not None and wire.sent:
        code, message, state = ("LOCALHOST_OUTCOME_UNKNOWN",
                                "The request may have reached the service; its outcome is unconfirmed. Do not repeat it.", "unknown")
    return {"state": state, "result": None, "error": {"code": code, "message": message}}
