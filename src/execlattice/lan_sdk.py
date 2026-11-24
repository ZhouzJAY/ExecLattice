"""Python client for tasks scoped to one paired LAN worker."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from urllib.parse import urlencode
from uuid import UUID

import httpx

from .agent_operations import valid_operation_id
from .client import APIError, ControllerClient
from .execution_outcome import public_task_receipt
from .protocol import TASK_STATES, TERMINAL_STATES, TaskRequest
from .worker_identity import execution_owner_id

_OWNER_ID = re.compile(r"[0-9a-f]{32}")
_CONTROLLER_ERRORS = frozenset({
    "unauthenticated", "forbidden_role", "invalid_request_schema", "device_not_found",
    "device_offline", "device_revoked", "device_binding_changed",
    "idempotency_key_conflict", "capability_or_policy_denied", "task_not_found",
    "task_cannot_cancel", "task_wait_capacity", "device_execution_unconfirmed",
})


class LanSdkError(RuntimeError):
    """A fixed error code, with an HTTP status when the controller replied."""

    def __init__(self, code: str, status: int | None = None):
        self.code = code
        self.status = status
        super().__init__(code)


def _canonical_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and len(value) == 36 and str(UUID(value)) == value
    except ValueError:
        return False


def _worker_owner(devices, device_id: str) -> str:
    if not isinstance(devices, list):
        raise LanSdkError("invalid_device_list")
    matches = [device for device in devices if isinstance(device, dict) and device.get("device_id") == device_id]
    if len(matches) != 1 or matches[0].get("status") != "online":
        raise LanSdkError("device_unavailable")
    device = matches[0]
    if device.get("sdk_ready") is not True:
        raise LanSdkError("device_execution_unconfirmed")
    owner = execution_owner_id(device.get("capabilities"))
    if owner is None:
        raise LanSdkError("device_binding_unavailable")
    return owner


class LanSession:
    """Bind to an online worker advertised by a pinned HTTPS controller."""

    def __init__(self, client: ControllerClient, device_id: str, *, expected_execution_owner_id: str | None = None):
        if not _canonical_uuid(device_id):
            raise LanSdkError("invalid_device_id")
        if (expected_execution_owner_id is not None
                and (not isinstance(expected_execution_owner_id, str)
                     or not _OWNER_ID.fullmatch(expected_execution_owner_id))):
            raise LanSdkError("invalid_execution_owner_id")
        self._client = client
        self._closed = False
        self._device_id = device_id
        self._owner = _worker_owner(self._request("GET", "/v1/devices"), device_id)
        if expected_execution_owner_id is not None and self._owner != expected_execution_owner_id:
            raise LanSdkError("device_binding_changed")
        self._scope = {
            "target_device_id": device_id,
            "expected_execution_owner_id": self._owner,
        }

    @classmethod
    def open(cls, config_path: str | Path, device_id: str, *,
             expected_execution_owner_id: str | None = None) -> LanSession:
        """Open from local controller credentials and optionally verify a saved binding."""
        try:
            client = ControllerClient.from_file(Path(config_path))
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, httpx.RequestError):
            raise LanSdkError("controller_configuration_unavailable") from None
        try:
            return cls(client, device_id, expected_execution_owner_id=expected_execution_owner_id)
        except BaseException:
            client.close()
            raise

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def execution_owner_id(self) -> str:
        """The authenticated owner ID, suitable for a saved local binding."""
        return self._owner

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._client.close()

    def __enter__(self) -> LanSession:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _request(self, method: str, path: str, body: dict | None = None, *, submitting: bool = False):
        if self._closed:
            raise LanSdkError("session_closed")
        try:
            return self._client.request(method, path, body)
        except APIError as error:
            code = error.code if error.code in _CONTROLLER_ERRORS else "controller_request_failed"
            if submitting and (error.status >= 500 or error.status == 408):
                code = "submission_unconfirmed"
            raise LanSdkError(code, error.status) from None
        except (httpx.RequestError, ValueError, RuntimeError):
            code = "submission_unconfirmed" if submitting else "controller_response_unavailable"
            raise LanSdkError(code) from None

    def _operation_key(self, operation_id: str) -> str:
        if not valid_operation_id(operation_id):
            raise LanSdkError("invalid_operation_id")
        encoded = f"execlattice-lan-sdk-v1:{self._device_id}:{self._owner}:{operation_id}".encode("utf-8")
        return "agent-" + hashlib.sha256(encoded).hexdigest()

    def _receipt(self, value, *, task_id: str | None = None, key: str | None = None,
                 request: TaskRequest | None = None) -> dict:
        if (not isinstance(value, dict) or not _canonical_uuid(value.get("task_id"))
                or value.get("target_device_id") != self._device_id
                or value.get("expected_execution_owner_id") != self._owner
                or not isinstance(value.get("state"), str) or value["state"] not in TASK_STATES
                or task_id is not None and value["task_id"] != task_id
                or key is not None and value.get("idempotency_key") != key
                or request is not None and (value.get("executor_type"), value.get("action"))
                != (request.executor_type, request.action)):
            # A malformed response to a POST can follow a committed request.
            raise LanSdkError("submission_unconfirmed" if request is not None else "invalid_task_receipt")
        return public_task_receipt(value)

    def submit(self, operation_id: str, executor_type: str, action: str, parameters: dict, *,
               timeout_seconds: int = 30) -> dict:
        """Submit once. Save the operation ID before calling so it can be queried after a lost response."""
        key = self._operation_key(operation_id)
        try:
            request = TaskRequest(
                target_device_id=self._device_id, executor_type=executor_type, action=action,
                parameters=parameters, timeout_seconds=timeout_seconds, idempotency_key=key,
                expected_execution_owner_id=self._owner,
            )
        except (ValueError, TypeError):
            raise LanSdkError("invalid_task_request") from None
        value = self._request("POST", "/v1/tasks", request.model_dump(), submitting=True)
        return self._receipt(value, key=key, request=request)

    def query_original(self, operation_id: str) -> dict | None:
        """Look up the original operation, including through a retained session after revocation."""
        key = self._operation_key(operation_id)
        query = urlencode({**self._scope, "idempotency_key": key})
        response = self._request("GET", f"/v1/task-lookup?{query}")
        if not isinstance(response, dict) or "task" not in response:
            raise LanSdkError("invalid_task_receipt")
        return self._receipt(response["task"], key=key) if response["task"] is not None else None

    def wait(self, operation_id: str, *, timeout_seconds: float = 40) -> dict | None:
        """Poll the original operation within a bounded budget and return its latest receipt."""
        if type(timeout_seconds) not in (int, float) or not 0 <= timeout_seconds <= 3600:
            raise LanSdkError("invalid_wait_timeout")
        deadline = time.monotonic() + timeout_seconds
        while True:
            task = self.query_original(operation_id)
            remaining = deadline - time.monotonic()
            if task is None or task["state"] in TERMINAL_STATES or remaining <= 0:
                return task
            time.sleep(min(0.25, remaining))

    def _task_request(self, method: str, task_id: str, suffix: str = "") -> dict:
        if not _canonical_uuid(task_id):
            raise LanSdkError("invalid_task_id")
        return self._receipt(self._request(
            method, f"/v1/tasks/{task_id}{suffix}?{urlencode(self._scope)}",
        ), task_id=task_id)

    def get_task(self, task_id: str) -> dict:
        """Retrieve one task by its canonical ID within the pinned scope."""
        return self._task_request("GET", task_id)

    def cancel(self, task_id: str) -> dict:
        """Request cancellation of one task within the pinned scope."""
        return self._task_request("POST", task_id, "/cancel")
