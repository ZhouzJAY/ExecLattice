"""Authenticated HTTPS API. Network input never reaches a local shell."""

from __future__ import annotations

import asyncio
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator

from . import __version__
from .protocol import Heartbeat, PairRequest, ProtocolModel, ReportRequest, TaskRequest
from .store import Store, StoreError
from .task_lanes import valid_task_concurrency
from .task_notifications import (
    NotificationLimit,
    notification_capability,
    valid_task_notifications,
    valid_worker_action_notifications,
    worker_poll_capability,
)
from .worker_dispatch_wait import supports_dispatch_wait, valid_dispatch_wait
from .worker_identity import valid_execution_identity
from .worker_report_isolation import supports_report_isolation, valid_report_isolation
from .worker_session import valid_worker_session


class WorkerPoll(Heartbeat):
    claim: bool = False
    active_task_ids: list[str] | None = Field(default=None, max_length=8)

    @field_validator("active_task_ids")
    @classmethod
    def canonical_active_tasks(cls, value):
        from uuid import UUID

        if value is not None and (len(set(value)) != len(value) or any(str(UUID(item)) != item for item in value)):
            raise ValueError("Invalid original active task IDs")
        return value


class MaintenanceRelease(ProtocolModel):
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$")


_CAPABILITY_METADATA = {"available", "actions", "executor_type", "permission",
                        "verification", "parameters_schema", "dependencies", "limitations"}
_COMMAND_MARKERS = {
    "task_concurrency": valid_task_concurrency,
    "task_notifications": valid_task_notifications,
    "worker_action_notifications": valid_worker_action_notifications,
    "worker_dispatch_wait": valid_dispatch_wait,
    "worker_report_isolation": valid_report_isolation,
    "worker_session": valid_worker_session,
    "execution_identity": valid_execution_identity,
}
_CAPABILITY_FIELDS = {
    "command": _CAPABILITY_METADATA | {"profiles"} | _COMMAND_MARKERS.keys(),
    "file": _CAPABILITY_METADATA | {"roots"},
    "workspace": _CAPABILITY_METADATA | {"mode"},
    "development": _CAPABILITY_METADATA | {"mode"},
}


def validate_capabilities(caps: list[dict]) -> None:
    """Validate the supported LAN execution surface without loading other products."""
    seen = set()
    for cap in caps:
        executor = cap.get("executor_type")
        if (not isinstance(executor, str) or executor not in _CAPABILITY_FIELDS
                or executor in seen or not isinstance(cap.get("available"), bool)):
            raise StoreError("invalid_capability", 422)
        if cap.keys() - _CAPABILITY_FIELDS[executor]:
            raise StoreError("unsupported_capability", 422)
        seen.add(executor)

        if executor == "command":
            if any(name in cap and not validator(cap[name]) for name, validator in _COMMAND_MARKERS.items()):
                raise StoreError("invalid_capability", 422)
            expected_actions = ["run"]
        elif executor == "file":
            expected_actions = ["read"]
        elif executor == "workspace":
            mode = cap.get("mode")
            if mode not in ("read_only", "full") or not cap["available"]:
                raise StoreError("invalid_capability", 422)
            expected_actions = ["list", "search", "read"] + (["write"] if mode == "full" else [])
        else:
            if cap.get("mode") != "full" or not cap["available"]:
                raise StoreError("invalid_capability", 422)
            expected_actions = ["run"]

        if cap.get("actions") != expected_actions:
            raise StoreError("invalid_capability", 422)
        if executor in {"command", "file"}:
            names = cap.get("profiles" if executor == "command" else "roots")
            if (not isinstance(names, list) or len(names) > (128 if executor == "command" else 32)
                    or any(not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name)
                           for name in names)
                    or len(set(names)) != len(names)):
                raise StoreError("invalid_capability", 422)


class InputLimits:
    """Bound streamed bodies before parsing, including chunked requests."""

    def __init__(self, app):
        self.app = app
        self.attempts = defaultdict(deque)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == "/v1/pair":
            host = (scope.get("client") or ("unknown",))[0]
            now = time.monotonic()
            # Bounded global bucket: no attacker-controlled map growth.
            host = host if host in self.attempts or len(self.attempts) < 128 else "overflow"
            queue = self.attempts[host]
            while queue and queue[0] < now - 60:
                queue.popleft()
            if len(queue) >= 20:
                return await JSONResponse({"error": {"code": "pairing_rate_limited"}}, 429)(
                    scope, receive, send
                )
            queue.append(now)
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > 310000:
                return await JSONResponse({"error": {"code": "request_too_large"}}, 413)(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


async def _maintain_store(store, *, pause=None):
    """Defer a rejected maintenance read; never replay a task or an uncertain write."""
    while True:
        await (pause or asyncio.sleep)(2)
        try:
            await asyncio.to_thread(store.recover)
        except StoreError as error:
            if (error.code != "controller_storage_busy" or type(error.status) is not int
                    or error.status != 503):
                raise


def create_app(store: Store) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        store.migrate()
        store.begin_controller_session()
        store.recover(restart=True)

        task = asyncio.create_task(_maintain_store(store))
        yield
        store.notifications.close()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    app = FastAPI(
        title="ExecLattice local prototype",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(InputLimits)
    app.state.store = store

    @app.exception_handler(StoreError)
    async def domain_error(request: Request, exc: StoreError):
        return JSONResponse({"error": {"code": exc.code}}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Never echo a pairing credential, task input, or raw validation object.
        return JSONResponse({"error": {"code": "invalid_request_schema"}}, status_code=422)

    def auth(authorization: str = Header(default="")):
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not 32 <= len(token) <= 256:
            raise StoreError("unauthenticated", 401)
        return store.authenticate(token)

    def operator(identity=Depends(auth)):
        if identity["role"] not in ("agent", "admin"):
            raise StoreError("forbidden_role", 403)
        return identity

    def admin(identity=Depends(auth)):
        if identity["role"] != "admin":
            raise StoreError("forbidden_role", 403)
        return identity

    def worker(identity=Depends(auth)):
        if identity["role"] != "worker":
            raise StoreError("forbidden_role", 403)
        return identity["identity"]

    def sdk_scope(device_id, owner_id, principal):
        if device_id is None and owner_id is None:
            return None
        if device_id is None or owner_id is None:
            raise StoreError("invalid_request_schema", 422)
        try:
            device = TaskRequest.canonical_device_id(device_id)
        except ValueError:
            raise StoreError("invalid_request_schema", 422) from None
        return device, owner_id, principal

    @app.get("/health")
    def health():
        return {"service": "execlattice", "version": __version__, "task_notifications": notification_capability()}

    @app.post("/v1/pair")
    def pair(body: PairRequest):
        validate_capabilities(body.capabilities)
        return store.register(body.model_dump())

    @app.get("/v1/devices")
    def devices(identity=Depends(operator)):
        return store.devices()

    @app.post("/v1/devices/{device_id}/revoke")
    async def revoke(device_id: str, identity=Depends(admin)):
        await asyncio.to_thread(store.revoke, device_id)
        return {"device_id": device_id, "status": "revoked"}

    @app.post("/v1/tasks")
    def submit(body: TaskRequest, identity=Depends(operator)):
        return store.submit(body.model_dump(), identity["identity"])

    @app.get("/v1/tasks/{task_id}")
    def get_task(task_id: str, target_device_id: str | None = Query(default=None, min_length=36, max_length=36),
                 expected_execution_owner_id: str | None = Query(default=None, pattern=r"^[0-9a-f]{32}$"),
                 identity=Depends(operator)):
        return store.get_task(task_id, sdk_scope=sdk_scope(
            target_device_id, expected_execution_owner_id, identity["identity"]))

    @app.get("/v1/task-lookup")
    def task_lookup(target_device_id: str = Query(min_length=36, max_length=36),
                    idempotency_key: str = Query(pattern=r"^agent-[0-9a-f]{64}$"),
                    expected_execution_owner_id: str | None = Query(default=None, pattern=r"^[0-9a-f]{32}$"),
                    identity=Depends(operator)):
        try:
            TaskRequest.canonical_device_id(target_device_id)
        except ValueError:
            raise StoreError("invalid_request_schema", 422) from None
        return {"task": store.find_task_by_key(target_device_id, idempotency_key, identity["identity"],
                                                expected_owner=expected_execution_owner_id)}

    @app.get("/v1/tasks/{task_id}/wait")
    async def wait_task(task_id: str, request: Request, wait_ms: int = Query(default=5000, ge=0, le=5000),
                        identity=Depends(operator)):
        # No claim, execution, or replay occurs here. Bounded async waits do
        # not retain a database transaction or occupy the sync request pool.
        from .protocol import TERMINAL_STATES

        key = "task:" + task_id
        deadline = time.monotonic() + wait_ms / 1000
        while True:
            cursor = store.notifications.cursor(key)
            task = await asyncio.to_thread(store.get_task, task_id)
            if task["state"] in TERMINAL_STATES or time.monotonic() >= deadline or await request.is_disconnected():
                return task
            try:
                await store.notifications.wait(key, cursor, deadline - time.monotonic(), request.is_disconnected)
            except NotificationLimit:
                raise StoreError("task_wait_capacity", 429) from None

    @app.post("/v1/tasks/{task_id}/cancel")
    def cancel(task_id: str, target_device_id: str | None = Query(default=None, min_length=36, max_length=36),
               expected_execution_owner_id: str | None = Query(default=None, pattern=r"^[0-9a-f]{32}$"),
               identity=Depends(operator)):
        return store.cancel(task_id, identity["identity"], sdk_scope=sdk_scope(
            target_device_id, expected_execution_owner_id, identity["identity"]))

    @app.post("/v1/tasks/{task_id}/consume_payload")
    def consume_payload(task_id: str, identity=Depends(operator)):
        return store.consume_transfer_payload(task_id, identity["identity"])

    @app.get("/v1/audit")
    def audit(task_id: str | None = None, identity=Depends(admin)):
        return store.audit(task_id)

    @app.get("/v1/diagnostics/storage")
    def storage_diagnostics(identity=Depends(admin)):
        return store.storage_diagnostics()

    @app.post("/v1/worker/heartbeat")
    async def heartbeat(body: Heartbeat, device_id=Depends(worker)):
        validate_capabilities(body.capabilities)
        result = await asyncio.to_thread(store.heartbeat, device_id, body.capabilities, body.worker_version)
        result["worker_poll"] = worker_poll_capability()
        return result

    @app.post("/v1/worker/poll")
    async def poll(body: WorkerPoll, request: Request, wait_ms: int = Query(default=0, ge=0, le=5000),
                   authorization: str = Header(default=""), device_id=Depends(worker)):
        # Reuse the complete authenticated heartbeat path: capability policy,
        # Worker session contact, live subscription invalidation and lease data
        # are never bypassed by this round-trip optimization. A claim remains a
        # durable dispatch; a lost response is observed as unknown, not retried.
        if body.active_task_ids is not None and not supports_report_isolation(body.capabilities):
            raise StoreError("invalid_worker_state")
        key = "worker:" + device_id
        cursor = store.notifications.cursor(key) if wait_ms and supports_dispatch_wait(body.capabilities) else None
        deadline = time.monotonic() + wait_ms / 1000
        result = await heartbeat(body, device_id)
        if cursor is None and body.active_task_ids is None:
            result["task"] = await asyncio.to_thread(store.claim, device_id) if body.claim else None
            return result
        from .security import digest

        token = authorization.partition(" ")[2]
        fence = await asyncio.to_thread(store.worker_poll_fence, device_id, body.capabilities, digest(token))
        fresh, idle = await asyncio.to_thread(store.worker_poll_state, fence, claim=body.claim,
                                             active_task_ids=body.active_task_ids)
        fresh["worker_poll"] = result["worker_poll"]
        while (cursor is not None and body.claim and idle and fresh["task"] is None
               and time.monotonic() < deadline and not await request.is_disconnected()):
            waited_after = cursor
            try:
                await store.notifications.wait(key, cursor, deadline - time.monotonic(), request.is_disconnected,
                                               per_key=1, capacity_group="worker_dispatch")
            except NotificationLimit:
                raise StoreError("worker_wait_capacity", 429) from None
            if await request.is_disconnected():
                return fresh
            # Observe before claiming so a submission racing this read remains
            # visible to the next wait. No lock/transaction survives the wait.
            cursor = store.notifications.cursor(key)
            fresh, idle = await asyncio.to_thread(store.worker_poll_state, fence, claim=True,
                                                 active_task_ids=body.active_task_ids)
            fresh["worker_poll"] = result["worker_poll"]
            if cursor == waited_after:
                # Timeout or a closed notifier ends this observation. The
                # final fresh fence above still rejects a revoked session.
                break
        return fresh

    @app.get("/v1/worker/maintenance")
    def worker_maintenance(device_id=Depends(worker)):
        return store.device_dispatch_maintenance(device_id)

    @app.post("/v1/worker/maintenance/release")
    def release_maintenance(body: MaintenanceRelease, device_id=Depends(worker)):
        return store.release_device_dispatch(device_id, body.job_id)

    @app.post("/v1/worker/claim")
    def claim(device_id=Depends(worker)):
        return {"task": store.claim(device_id)}

    @app.get("/v1/worker/notifications")
    async def notifications(request: Request, cursor: str = Query(default="", max_length=64),
                            wait_ms: int = Query(default=1000, ge=0, le=5000),
                            kind: str = Query(default="legacy", pattern="^(legacy|action)$"), device_id=Depends(worker)):
        current = await asyncio.to_thread(store.worker_notification_cursor, device_id, kind=kind)
        if cursor and cursor == current and wait_ms:
            try:
                await store.notifications.wait(("device:" if kind == "legacy" else "worker:") + device_id,
                                               cursor, wait_ms / 1000,
                                               request.is_disconnected, per_key=1)
            except NotificationLimit:
                raise StoreError("worker_wait_capacity", 429) from None
        # Recheck revocation and exact negotiated declaration after every wait.
        current = await asyncio.to_thread(store.worker_notification_cursor, device_id, kind=kind)
        return {"cursor": current, "changed": current != cursor}

    @app.get("/v1/worker/tasks/{task_id}")
    def worker_task(task_id: str, device_id=Depends(worker)):
        doc = store.get_task(task_id, device_id)
        # Result content is only retrieved through the authenticated operator API.
        doc.pop("result", None)
        doc.pop("recovery_evidence", None)
        doc.pop("progress", None)
        return doc

    @app.post("/v1/worker/tasks/{task_id}/start")
    def start(task_id: str, device_id=Depends(worker)):
        return store.start(task_id, device_id)

    @app.post("/v1/worker/tasks/{task_id}/report")
    def report(task_id: str, body: ReportRequest, device_id=Depends(worker)):
        return store.report(task_id, device_id, body.model_dump())

    @app.post("/v1/worker/tasks/{task_id}/progress")
    def progress(task_id: str, body: dict, device_id=Depends(worker)):
        return store.progress(task_id, device_id, body)

    @app.post("/v1/worker/tasks/{task_id}/reconcile")
    def reconcile(task_id: str, body: ReportRequest, device_id=Depends(worker)):
        return store.reconcile(task_id, device_id, body.model_dump())

    return app
