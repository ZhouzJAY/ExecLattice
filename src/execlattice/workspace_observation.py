"""One bounded current filesystem observation, without a durable execution task.

The same workspace executor and evidence checks are used as durable reads.
Large hashing stat calls keep their original 300 second task budget; they are
deliberately absent here. An attempted observation never falls back to a task.
The 30 second observation lifetime is a logical cancellation budget. Existing
authority checks and a blocked OS/network read can return after that budget;
late bytes are rejected rather than presented as a current result.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time

from .development_protocol import WORKSPACE_MODELS
from .observation_capabilities import valid_workspace_read_capability
from .worker_session import worker_session_id

OPERATIONS = {"list_directory": "list", "read_project_file": "read", "read_project_files": "read_many"}
ACTIONS = frozenset({"list", "list_page", "read", "read_many"})
MAX_RESULT_BYTES = 160000
MAX_SECONDS = 30
ERRORS = frozenset({"POLICY_DENIED", "FILE_NOT_FOUND", "ACCESS_DENIED", "NOT_A_FILE", "NOT_A_DIRECTORY",
                    "FILE_TOO_LARGE", "FILE_NOT_TEXT", "FILE_CONFLICT", "FILESYSTEM_ERROR", "INVALID_PARAMETERS", "CANCELLED",
                    "DIRECTORY_CURSOR_EXPIRED", "DIRECTORY_CURSOR_MISMATCH", "DIRECTORY_CHANGED",
                    "DIRECTORY_SNAPSHOT_LIMIT", "DIRECTORY_PAGE_LIMIT",
                    "observation_result_limit", "observation_invalid", "observation_revoked"})


class WorkspaceObservationError(ValueError):
    def __init__(self, code):
        self.code = code if code in ERRORS else "observation_invalid"
        super().__init__(self.code)


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def checked_workspace_read(value):
    if (type(value) is not dict or set(value) != {"action", "arguments", "owner_id", "worker_session_id"}
            or type(value["action"]) is not str or value["action"] not in ACTIONS
            or type(value["arguments"]) is not dict
            or any(type(value[key]) is not str or re.fullmatch("[a-f0-9]{32}", value[key]) is None
                   for key in ("owner_id", "worker_session_id"))):
        raise ValueError("Invalid workspace observation")
    arguments = WORKSPACE_MODELS[value["action"]].model_validate(value["arguments"]).model_dump()
    return {"action": value["action"], "arguments": arguments,
            "owner_id": value["owner_id"], "worker_session_id": value["worker_session_id"]}


def request_sha256(parameters):
    return hashlib.sha256(_encode(checked_workspace_read(parameters))).hexdigest()


def workspace_read_identity(capabilities):
    try:
        commands = [c for c in capabilities if c.get("executor_type") == "command"]
        if len(commands) != 1:
            return None, None
        owner = commands[0].get("execution_identity")
        if (type(owner) is not dict or set(owner) != {"version", "owner_id"}
                or type(owner["version"]) is not int or owner["version"] != 1
                or type(owner["owner_id"]) is not str
                or re.fullmatch("[a-f0-9]{32}", owner["owner_id"]) is None):
            return None, None
        return owner["owner_id"], worker_session_id(capabilities)
    except (ValueError, TypeError, AttributeError):
        return None, None


def workspace_read_allowed(capabilities, parameters, contacts, device):
    try:
        values = checked_workspace_read(parameters)
        rows = [c for c in capabilities if c.get("executor_type") == "workspace"]
        if len(rows) != 1:
            return False
        cap = rows[0]
        owner, session = workspace_read_identity(capabilities)
        return (cap.get("available") is True and cap.get("mode") in {"full", "read_only"}
                and valid_workspace_read_capability(cap.get("workspace_observation"))
                and values["action"] in cap.get("actions", [])
                and owner == values["owner_id"] and session == values["worker_session_id"]
                and type(contacts) is dict and contacts.get(device) == session)
    except (ValueError, TypeError, AttributeError):
        return False


class _ReadDeadline:
    """Cooperative deadline, not an OS I/O interrupt or a hard wall timer."""
    def __init__(self, stop, seconds):
        self.stop, self.deadline = stop, time.monotonic() + seconds

    def is_set(self):
        return self.stop.is_set() or time.monotonic() >= self.deadline


def perform_workspace_read(parameters, policy, stop, *, state_dir, owner_id, worker_session):
    from .project_evidence import valid_success_evidence
    from .workspace_executor import execute_workspace

    values = checked_workspace_read(parameters)
    if values["owner_id"] != owner_id or values["worker_session_id"] != worker_session:
        raise WorkspaceObservationError("observation_revoked")
    cancelled = _ReadDeadline(stop, MAX_SECONDS - 5)
    if cancelled.is_set():
        raise WorkspaceObservationError("CANCELLED")
    report = execute_workspace(values["action"], values["arguments"], policy, cancelled, state_dir=state_dir)
    if report.get("state") != "succeeded":
        error = report.get("error")
        raise WorkspaceObservationError(error.get("code") if isinstance(error, dict) else "observation_invalid")
    if cancelled.is_set():
        raise WorkspaceObservationError("CANCELLED")
    result = report.get("result")
    task = {"executor_type": "workspace", "action": values["action"], "parameters": values["arguments"]}
    if not valid_success_evidence(task, result):
        raise WorkspaceObservationError("observation_invalid")
    raw = _encode(result)
    if len(raw) > MAX_RESULT_BYTES:
        raise WorkspaceObservationError("observation_result_limit")
    header = {"kind": "workspace_read", "version": 1, "action": values["action"],
              "request_sha256": request_sha256(values)}
    return header, raw


def verified_workspace_read(header, raw, parameters):
    from .project_evidence import valid_success_evidence

    values = checked_workspace_read(parameters)
    if (type(header) is not dict or set(header) != {"kind", "version", "action", "request_sha256"}
            or header["kind"] != "workspace_read" or type(header["version"]) is not int or header["version"] != 1
            or header["action"] != values["action"] or header["request_sha256"] != request_sha256(values)
            or type(raw) is not bytes or len(raw) > MAX_RESULT_BYTES):
        raise ValueError("Invalid workspace observation evidence")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid workspace observation result") from None
    task = {"executor_type": "workspace", "action": values["action"], "parameters": values["arguments"]}
    if _encode(result) != raw or not valid_success_evidence(task, result):
        raise ValueError("Invalid workspace observation result")
    return result


def try_workspace_read(session, handle, operation, parameters):
    """None means no capability was advertised and no observation was attempted."""
    if type(operation) is not str or operation not in OPERATIONS:
        return None
    from .agent_operations import valid_operation_id
    from .desktop_session import DesktopError
    from .observation_session import _frames

    started = time.monotonic()
    with session._peer_operation_lock:
        if (not isinstance(handle, str) or handle != session._agent_connection_handle or session._closing.is_set()):
            raise DesktopError("agent_connection_changed")
        caps = [c for c in session._peer_capabilities if c.get("executor_type") == "workspace"]
        if not caps or "workspace_observation" not in caps[0]:
            return None
        if len(caps) != 1 or not valid_workspace_read_capability(caps[0]["workspace_observation"]):
            raise DesktopError("feature_unavailable")
        if type(parameters) is not dict or "owner_id" in parameters:
            raise DesktopError("invalid_agent_request")
        values = dict(parameters)
        key = values.pop("idempotency_key", None)
        if key is not None and not valid_operation_id(key):
            raise DesktopError("invalid_agent_request")
        session._agent_sync_peer_capabilities()
        if handle != session._agent_connection_handle or session.snapshot()["connection_state"] != "connected":
            raise DesktopError("agent_connection_changed")
        cap = next((c for c in session._peer_capabilities if c.get("executor_type") == "workspace"), {})
        action = OPERATIONS[operation]
        if operation == "list_directory":
            if "list_page" in cap.get("actions", []):
                action, values["owner_id"] = "list_page", handle
            elif values.pop("cursor", None) is not None:
                raise DesktopError("feature_unavailable")
        try:
            arguments = WORKSPACE_MODELS[action].model_validate(values).model_dump()
        except (ValueError, TypeError):
            raise DesktopError("invalid_agent_request") from None
        owner, worker = workspace_read_identity(session._peer_capabilities)
        if owner is None or worker is None:
            # A control-plane preflight is not an executing Worker. Do not
            # mislabel its missing session as invalid caller file arguments.
            raise DesktopError("observation_unavailable")
        request = checked_workspace_read({"action": action, "arguments": arguments,
                                          "owner_id": owner, "worker_session_id": worker})
        if (cap.get("available") is not True or cap.get("mode") not in {"full", "read_only"}
                or not valid_workspace_read_capability(cap.get("workspace_observation"))
                or action not in cap.get("actions", [])):
            raise DesktopError("feature_unavailable")
        binding = session._managed_observation_binding()
        if binding is None:
            raise DesktopError("agent_connection_changed")
        binding = copy.deepcopy(binding)
    stop = threading.Event()
    deadline_stop = _ReadDeadline(stop, max(0, MAX_SECONDS - (time.monotonic() - started)))
    iterator = _frames(session, handle, "workspace_read", request, deadline_stop)
    try:
        for checked, header, raw in iterator:
            if deadline_stop.is_set():
                raise DesktopError("observation_unavailable")
            result = verified_workspace_read(header, raw, checked)
            with session._peer_operation_lock:
                # Do not reuse a pre-observation 500ms managed status cache.
                session._discard_managed_observation()
                session._agent_sync_peer_capabilities()
                if (session._closing.is_set() or handle != session._agent_connection_handle
                        or binding != session._managed_observation_binding()
                        or session.snapshot()["connection_state"] != "connected"):
                    raise DesktopError("agent_connection_changed")
                if deadline_stop.is_set():
                    raise DesktopError("observation_unavailable")
            return {"state": "succeeded", "executor_type": "workspace", "action": checked["action"],
                    "parameters": checked["arguments"], "result": result,
                    "observation_only": True, "task_created": False}
        raise DesktopError("observation_unavailable")
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise DesktopError("observation_invalid") from None
    finally:
        stop.set()
        iterator.close()
