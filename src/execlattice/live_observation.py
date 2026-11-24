"""Bounded passive binary observations; no task, command or input dispatcher.

The Worker still connects outbound over the original authenticated HTTPS route.
Terminal bytes flow independently of durable mutation/task traffic. All state
here is ephemeral: reconnecting can only read again from a confirmed cursor.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import struct
import time
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from fastapi import Request

MAX_HEADER = 8192
MAX_PAYLOAD = 160000
MAX_DURATION = 30
MAX_STREAMS = 8
CAPABILITY = {"version": 1, "framing": "length-json-bytes", "max_duration_seconds": 30,
              "max_frame_bytes": 32768}


class ObservationError(Exception):
    def __init__(self, code="observation_unavailable", status=409):
        self.code, self.status = code, status
        super().__init__(code)


def valid_output_stream(value):
    return (type(value) is dict and set(value) == set(CAPABILITY)
            and all(type(value.get(key)) is type(expected) and value[key] == expected
                    for key, expected in CAPABILITY.items()))


def checked_parameters(kind, parameters):
    if kind == "workspace_read":
        from .workspace_observation import checked_workspace_read

        return checked_workspace_read(parameters)
    if kind == "log":
        from .log_follow import LogFollowParameters

        return LogFollowParameters.model_validate(parameters).model_dump()
    if kind == "command_output":
        from .output_artifacts import OutputReadParameters

        value = OutputReadParameters.model_validate(parameters).model_dump()
        if value["source_kind"] != "task":
            raise ValueError("Only original ordinary command output is exposed")
        return value
    if kind == "terminal":
        from .terminal_protocol import TerminalReadParameters

        value = TerminalReadParameters.model_validate(parameters).model_dump()
        if value["wait_ms"] > 1000:
            raise ValueError("Observation wait exceeds bound")
        return value
    if kind == "desktop":
        from .computer_protocol import COMPUTER_MODELS

        return COMPUTER_MODELS["capture"].model_validate(parameters).model_dump()
    raise ValueError("Unknown observation kind")


def authorize(store, device, kind, parameters):
    try:
        if str(UUID(device)) != device:
            raise ValueError()
        values = checked_parameters(kind, parameters)
    except (TypeError, ValueError, AttributeError):
        raise ObservationError("invalid_observation", 422) from None
    row = next((item for item in store.devices() if item["device_id"] == device), None)
    if row is None or row.get("status") != "online":
        raise ObservationError("observation_device_unavailable")
    executor = "workspace" if kind in {"log", "command_output", "workspace_read"} else "terminal" if kind == "terminal" else "computer"
    cap = next((item for item in row.get("capabilities", []) if item.get("executor_type") == executor), {})
    if cap.get("available") is not True:
        raise ObservationError("observation_unsupported")
    if kind == "workspace_read":
        from .workspace_observation import workspace_read_allowed

        if not workspace_read_allowed(row.get("capabilities", []), values,
                                      store.authenticated_worker_contacts(), device):
            raise ObservationError("observation_unsupported")
    elif kind == "terminal":
        host = cap.get("execution_host", {})
        if (cap.get("mode") != "full" or not valid_output_stream(cap.get("output_stream"))
                or host.get("owner_id") != values["owner_id"]):
            raise ObservationError("terminal_stream_unsupported")
    elif kind in {"log", "command_output"}:
        marker = "log_follow_v1" if kind == "log" else "output_artifacts_v1"
        if cap.get(marker) is not True or cap.get("mode") not in {"read_only", "full"}:
            raise ObservationError("observation_unsupported")
    elif cap.get("capture_updates_v1") is not True or "capture" not in cap.get("actions", []):
        raise ObservationError("observation_unsupported")
    return values


def packet(sequence, result, payload=b"", *, error=None):
    if type(sequence) is not int or not 0 <= sequence < 100000 or not isinstance(payload, bytes):
        raise ValueError("Invalid observation packet")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("Observation payload exceeds bound")
    header = {"version": 1, "sequence": sequence, "size_bytes": len(payload),
              "payload_sha256": hashlib.sha256(payload).hexdigest(), "result": result, "error": error}
    raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_HEADER:
        raise ValueError("Observation header exceeds bound")
    return struct.pack("!I", len(raw)) + raw + payload


class PacketDecoder:
    """Incremental framing with a bounded buffer, even on a malicious peer."""

    def __init__(self):
        self.buffer = bytearray()
        self.sequence = 0

    def feed(self, chunk):
        if not isinstance(chunk, bytes) or len(chunk) > 65536:
            raise ValueError("Invalid observation input chunk")
        self.buffer.extend(chunk)
        while len(self.buffer) >= 4:
            size = struct.unpack("!I", self.buffer[:4])[0]
            if not 1 <= size <= MAX_HEADER:
                raise ValueError("Invalid observation header length")
            if len(self.buffer) < 4 + size:
                break
            header = json.loads(bytes(self.buffer[4:4 + size]))
            if (type(header) is not dict or set(header) != {"version", "sequence", "size_bytes", "payload_sha256", "result", "error"}
                    or type(header["version"]) is not int or header["version"] != 1
                    or type(header["sequence"]) is not int or header["sequence"] != self.sequence
                    or type(header["size_bytes"]) is not int or not 0 <= header["size_bytes"] <= MAX_PAYLOAD
                    or not isinstance(header["payload_sha256"], str)
                    or re.fullmatch("[0-9a-f]{64}", header["payload_sha256"]) is None):
                raise ValueError("Invalid observation envelope")
            end = 4 + size + header["size_bytes"]
            if len(self.buffer) < end:
                break
            payload = bytes(self.buffer[4 + size:end])
            if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
                raise ValueError("Invalid observation payload hash")
            if header["error"] is not None:
                if (header["result"] is not None or payload or not isinstance(header["error"], str)
                        or re.fullmatch("[a-zA-Z0-9_]{1,80}", header["error"]) is None):
                    raise ValueError("Invalid observation error")
            elif type(header["result"]) is not dict:
                raise ValueError("Invalid observation result")
            del self.buffer[:end]
            self.sequence += 1
            yield header, payload
        if len(self.buffer) > 4 + MAX_HEADER + MAX_PAYLOAD:
            raise ValueError("Observation buffer exceeds bound")

    def finish(self):
        if self.buffer:
            raise ValueError("Incomplete observation frame")


@dataclass
class Subscription:
    identifier: str
    principal: str
    device: str
    kind: str
    parameters: dict
    nonce: str
    created: float = field(default_factory=time.monotonic)
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=2))
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    claimed: bool = False
    attached: bool = False
    uploading: bool = False


class ObservationHub:
    def __init__(self, store):
        self.store = store
        self.items = {}
        self.changed = asyncio.Condition()

    def prune(self):
        for identifier, item in list(self.items.items()):
            if item.closed.is_set() or time.monotonic() - item.created >= MAX_DURATION:
                item.closed.set()
                self.items.pop(identifier, None)

    async def create(self, principal, device, kind, parameters):
        values = await asyncio.to_thread(authorize, self.store, device, kind, parameters)
        self.prune()
        if (len(self.items) >= MAX_STREAMS or sum(item.device == device for item in self.items.values()) >= 4
                or sum(item.principal == principal for item in self.items.values()) >= 4):
            raise ObservationError("observation_capacity", 429)
        item = Subscription(uuid4().hex, principal, device, kind, values, uuid4().hex + uuid4().hex)
        self.items[item.identifier] = item
        async with self.changed:
            self.changed.notify_all()
        return {"observation_id": item.identifier, "kind": kind, "max_duration_seconds": MAX_DURATION}

    def lookup(self, identifier, *, principal=None, device=None):
        if not isinstance(identifier, str) or re.fullmatch("[0-9a-f]{32}", identifier) is None:
            raise ObservationError("observation_not_owned", 404)
        self.prune()
        item = self.items.get(identifier)
        if item is None or principal is not None and item.principal != principal or device is not None and item.device != device:
            raise ObservationError("observation_not_owned", 404)
        return item

    async def claim(self, device, request):
        deadline = time.monotonic() + 1
        while True:
            self.prune()
            for item in list(self.items.values()):
                if item.device == device and not item.claimed:
                    await asyncio.to_thread(authorize, self.store, device, item.kind, item.parameters)
                    if item.claimed or item.closed.is_set() or self.items.get(item.identifier) is not item:
                        continue
                    item.claimed = True
                    return {"observation": {"observation_id": item.identifier, "kind": item.kind,
                                             "parameters": item.parameters, "upload_nonce": item.nonce,
                                             "max_duration_seconds": MAX_DURATION}}
            if time.monotonic() >= deadline or await request.is_disconnected():
                return {"observation": None}
            async with self.changed:
                try:
                    await asyncio.wait_for(self.changed.wait(), .1)
                except TimeoutError:
                    pass

    def close(self, identifier, *, principal=None):
        item = self.lookup(identifier, principal=principal)
        item.closed.set()
        self.items.pop(identifier, None)

    def close_device(self, device):
        for identifier, item in list(self.items.items()):
            if item.device == device:
                item.closed.set()
                self.items.pop(identifier, None)

    def shutdown(self):
        for item in self.items.values():
            item.closed.set()
        self.items.clear()

    async def frames(self, item, request):
        try:
            while not item.closed.is_set() and time.monotonic() - item.created < MAX_DURATION:
                try:
                    data = await asyncio.wait_for(item.queue.get(), .2)
                except TimeoutError:
                    if await request.is_disconnected():
                        break
                    continue
                if data is None:
                    break
                if item.kind == "workspace_read":
                    await asyncio.to_thread(authorize, self.store, item.device, item.kind, item.parameters)
                    if (item.closed.is_set() or self.items.get(item.identifier) is not item
                            or time.monotonic() - item.created >= MAX_DURATION):
                        break
                yield data
        finally:
            item.closed.set()
            self.items.pop(item.identifier, None)

    async def _await_open(self, item, operation):
        """Race one body/queue wait against closure and the original deadline."""
        remaining = MAX_DURATION - (time.monotonic() - item.created)
        if item.closed.is_set() or remaining <= 0:
            item.closed.set()
            self.items.pop(item.identifier, None)
            return False, None
        active = asyncio.ensure_future(operation())
        closed = asyncio.create_task(item.closed.wait())
        try:
            done, _ = await asyncio.wait({active, closed}, timeout=remaining,
                                         return_when=asyncio.FIRST_COMPLETED)
            if (closed in done or active not in done or item.closed.is_set()
                    or time.monotonic() - item.created >= MAX_DURATION):
                item.closed.set()
                self.items.pop(item.identifier, None)
                return False, None
            return True, await active
        except asyncio.CancelledError:
            item.closed.set()
            self.items.pop(item.identifier, None)
            raise
        finally:
            # Await cancelled child tasks before closing the body iterator.
            # Caller cancellation still propagates after this cleanup.
            for pending in (active, closed):
                if not pending.done():
                    pending.cancel()
            await asyncio.gather(active, closed, return_exceptions=True)

    async def publish(self, item, request):
        decoder, stream = PacketDecoder(), request.stream().__aiter__()
        try:
            while True:
                opened, incoming = await self._await_open(item, lambda: anext(stream))
                if not opened:
                    return
                # ASGI transport chunks are arbitrary; slice before the decoder.
                for offset in range(0, len(incoming), 65536):
                    for header, payload in decoder.feed(incoming[offset:offset + 65536]):
                        if item.kind == "terminal" and len(payload) > 32768:
                            raise ValueError("Terminal frame exceeds bound")
                        if item.kind == "workspace_read":
                            from .workspace_observation import ERRORS, verified_workspace_read

                            if header["sequence"] != 0:
                                raise ValueError("Workspace observation is one frame")
                            if header["error"] is None:
                                verified_workspace_read(header["result"], payload, item.parameters)
                            elif header["error"] not in ERRORS:
                                raise ValueError("Invalid workspace observation error")
                        data = packet(header["sequence"], header["result"], payload, error=header["error"])
                        opened, _ = await self._await_open(item, lambda: item.queue.put(data))
                        if not opened:
                            return
        except StopAsyncIteration:
            if not item.closed.is_set():
                try:
                    decoder.finish()
                except BaseException:
                    item.closed.set()
                    self.items.pop(item.identifier, None)
                    raise
        except BaseException:
            # No new sentinel wait on cancellation or invalid/disconnected
            # bodies. Wake consumers and retain the original exception.
            item.closed.set()
            self.items.pop(item.identifier, None)
            raise
        finally:
            try:
                close = getattr(stream, "aclose", None)
                if close is not None:
                    await close()
            except BaseException:
                item.closed.set()
                self.items.pop(item.identifier, None)
                raise
            finally:
                if not item.closed.is_set():
                    await self._await_open(item, lambda: item.queue.put(None))


def install_routes(app, store, operator, worker, hub):
    from fastapi import Depends, Header
    from fastapi.responses import JSONResponse, StreamingResponse

    @app.exception_handler(ObservationError)
    async def observation_error(request, error):
        return JSONResponse({"error": {"code": error.code}}, status_code=error.status)

    @app.post("/v1/observations")
    async def create_observation(request: Request, identity=Depends(operator)):
        try:
            body = await request.json()
            if type(body) is not dict or set(body) != {"device_id", "kind", "parameters"}:
                raise ValueError()
            return await hub.create(identity["identity"], body["device_id"], body["kind"], body["parameters"])
        except (TypeError, ValueError, KeyError):
            raise ObservationError("invalid_observation", 422) from None

    @app.get("/v1/observations/{identifier}")
    async def read_observation(identifier: str, request: Request, identity=Depends(operator)):
        item = hub.lookup(identifier, principal=identity["identity"])
        if item.attached:
            raise ObservationError("observation_already_attached")
        item.attached = True
        return StreamingResponse(hub.frames(item, request), media_type="application/vnd.execlattice.observation",
                                 headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.delete("/v1/observations/{identifier}")
    async def close_observation(identifier: str, identity=Depends(operator)):
        hub.close(identifier, principal=identity["identity"])
        return JSONResponse({"closed": True}, headers={"Connection": "close"})

    @app.post("/v1/worker/observations/claim")
    async def claim_observation(request: Request, device=Depends(worker)):
        return await hub.claim(device, request)

    @app.post("/v1/worker/observations/{identifier}/output")
    async def upload_observation(identifier: str, request: Request, device=Depends(worker),
                                 x_observation_nonce: str = Header(default="")):
        item = hub.lookup(identifier, device=device)
        if (not item.claimed or item.uploading or re.fullmatch("[0-9a-f]{64}", x_observation_nonce) is None
                or not hmac.compare_digest(x_observation_nonce, item.nonce)
                or request.headers.get("content-type") != "application/vnd.execlattice.observation"):
            raise ObservationError("observation_upload_denied", 403)
        await asyncio.to_thread(authorize, store, device, item.kind, item.parameters)
        # Authorization yields to other publishers and revocation. Claim the
        # producer slot only after rechecking the same live subscription.
        if (item.uploading or not item.claimed or item.closed.is_set()
                or hub.items.get(identifier) is not item):
            raise ObservationError("observation_upload_denied", 403)
        item.uploading = True
        try:
            await hub.publish(item, request)
        except (ValueError, TypeError, KeyError):
            item.closed.set()
            raise ObservationError("invalid_observation_frame", 422) from None
        return JSONResponse({"closed": True}, headers={"Connection": "close"})
