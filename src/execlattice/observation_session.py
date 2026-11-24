"""Current authenticated peer observations, without durable per-frame tasks."""

from __future__ import annotations

import base64
import hashlib
import re
import threading
import time

import httpx

from .client import APIError
from .live_observation import ObservationError, checked_parameters, valid_output_stream


def _pin(session, handle, kind, parameters):
    from .desktop_session import DesktopError

    with session._peer_operation_lock:
        if (not handle or handle != session._agent_connection_handle or session._closing.is_set()
                or session.snapshot()["connection_state"] != "connected"):
            raise DesktopError("agent_connection_changed")
        values = dict(parameters)
        if kind == "workspace_read":
            from .observation_capabilities import valid_workspace_read_capability
            from .workspace_observation import workspace_read_identity

            cap = next((cap for cap in session._peer_capabilities if cap.get("executor_type") == "workspace"), {})
            owner, worker = workspace_read_identity(session._peer_capabilities)
            if (cap.get("available") is not True or cap.get("mode") not in {"full", "read_only"}
                    or not valid_workspace_read_capability(cap.get("workspace_observation"))
                    or values.get("owner_id") != owner or values.get("worker_session_id") != worker):
                raise DesktopError("feature_unavailable")
        elif kind == "terminal":
            cap = next((cap for cap in session._peer_capabilities if cap.get("executor_type") == "terminal"), {})
            owner = session._agent_host_owner("terminal")
            if owner is None or not valid_output_stream(cap.get("output_stream")):
                raise DesktopError("terminal_stream_unsupported")
            if "owner_id" in values:
                raise DesktopError("invalid_agent_request")
            values["owner_id"] = owner
        elif kind in {"log", "command_output"}:
            marker = "log_follow_v1" if kind == "log" else "output_artifacts_v1"
            if not any(cap.get("executor_type") == "workspace" and cap.get("available") is True
                       and cap.get(marker) is True for cap in session._peer_capabilities):
                raise DesktopError("feature_unavailable")
            if kind == "command_output":
                _history, _scope, record = session._agent_owned_history(values.get("source_id"), handle)
                if record is None or record.get("operation") != "run_development_command":
                    raise DesktopError("agent_task_not_owned")
        else:
            if not any(cap.get("executor_type") == "computer" and cap.get("available") is True
                       and cap.get("capture_updates_v1") is True for cap in session._peer_capabilities):
                raise DesktopError("feature_unavailable")
        try:
            values = checked_parameters(kind, values)
        except (TypeError, ValueError):
            raise DesktopError("invalid_agent_request") from None
        # Stream-specific timeouts and a long-lived response must not alter or
        # occupy the pooled short-request transport used for task submission.
        client = session._remote_client(dedicated=True)
        client.http.timeout = httpx.Timeout(5, connect=2, write=2, pool=2)
        return session._peer_id, values, client


def _current(session, handle, peer):
    from .desktop_session import DesktopError

    with session._peer_operation_lock:
        if (session._closing.is_set() or handle != session._agent_connection_handle or peer != session._peer_id
                or session.snapshot()["connection_state"] != "connected"):
            raise DesktopError("agent_connection_changed")


def _frames(session, handle, kind, parameters, stop):
    from .desktop_session import DesktopError

    deadline = min(time.monotonic() + 30, getattr(stop, "deadline", float("inf"))) if kind == "workspace_read" else None
    peer, parameters, client = _pin(session, handle, kind, parameters)
    identifier = None
    try:
        if kind == "workspace_read":
            remaining = deadline - time.monotonic()
            if remaining <= 0 or stop.is_set():
                raise DesktopError("observation_unavailable")
            short = min(5, remaining)
            client.http.timeout = httpx.Timeout(short, connect=min(2, short), write=min(2, short), pool=min(2, short))
        value = client.request("POST", "/v1/observations", {"device_id": peer, "kind": kind, "parameters": parameters})
        if (type(value) is not dict or set(value) != {"observation_id", "kind", "max_duration_seconds"}
                or value["kind"] != kind or value["max_duration_seconds"] != 30
                or not isinstance(value["observation_id"], str) or re.fullmatch("[0-9a-f]{32}", value["observation_id"]) is None):
            raise ValueError("Invalid passive observation")
        identifier = value["observation_id"]
        stream_stop = stop
        if kind == "workspace_read":
            from .workspace_observation import _ReadDeadline

            remaining = deadline - time.monotonic()
            if remaining <= 0 or stop.is_set():
                raise DesktopError("observation_unavailable")
            client.http.timeout = httpx.Timeout(remaining, connect=min(2, remaining),
                                               write=min(2, remaining), pool=min(2, remaining))
            stream_stop = _ReadDeadline(stop, remaining)
        for envelope, raw in client.observation_frames(identifier, stream_stop):
            if kind == "workspace_read" and stream_stop.is_set():
                raise DesktopError("observation_unavailable")
            _current(session, handle, peer)
            if envelope["error"] is not None:
                code = envelope["error"]
                if kind == "workspace_read":
                    from .workspace_observation import ERRORS

                    if code in ERRORS:
                        raise DesktopError(code)
                if code in {"OUTPUT_NOT_FOUND", "OUTPUT_EXPIRED", "OUTPUT_CAPTURE_IO", "OUTPUT_IDENTITY_INVALID",
                            "OUTPUT_CURSOR_INVALID", "OUTPUT_DATA_INVALID",
                            "OUTPUT_STORE_FULL", "OUTPUT_STATE_UNAVAILABLE", "LOG_FOLLOW_CHANGED",
                            "LOG_FOLLOW_CURSOR_INVALID", "LOG_FOLLOW_INVALID", "FILE_TOO_LARGE"}:
                    raise DesktopError(code)
                if code == "terminal_stream_unsupported":
                    raise DesktopError(code)
                if code in {"HOST_REVOKED", "HOST_BINDING_CHANGED", "POLICY_DENIED", "TERMINAL_NOT_OWNED", "TERMINAL_NOT_FOUND"}:
                    raise DesktopError("observation_revoked")
                if code == "TERMINAL_OUTPUT_INVALID":
                    raise DesktopError("observation_invalid")
                raise DesktopError("observation_unavailable")
            yield parameters, envelope["result"], raw
    except APIError as error:
        if kind == "terminal" and error.code == "terminal_stream_unsupported":
            raise DesktopError("terminal_stream_unsupported") from None
        raise DesktopError("observation_unavailable") from None
    except (ObservationError, httpx.TransportError, OSError):
        if not stop.is_set():
            raise DesktopError("observation_unavailable") from None
    except (ValueError, TypeError, KeyError):
        raise DesktopError("observation_invalid") from None
    finally:
        if identifier is not None and (kind != "workspace_read" or time.monotonic() < deadline):
            try:
                if kind == "workspace_read":
                    remaining = max(.001, min(1, deadline - time.monotonic()))
                    client.http.timeout = httpx.Timeout(remaining)
                client.request("DELETE", "/v1/observations/" + identifier)
            except (APIError, httpx.TransportError, OSError, ValueError):
                pass
        client.close()


def stream_terminal(session, handle, session_id, cursor, stop):
    from .terminal_evidence import verified_terminal_stream_frame

    sequence = 0
    iterator = _frames(session, handle, "terminal", {"session_id": session_id, "cursor": cursor,
                                                    "limit": 32768, "wait_ms": 1000}, stop)
    try:
        for _parameters, header, raw in iterator:
            checked = verified_terminal_stream_frame(header, raw, expected_session=session_id,
                                                       sequence=sequence, cursor=cursor, limit=32768)
            if stop.is_set():
                return
            yield checked, raw
            cursor, sequence = checked["next_cursor"], sequence + 1
    finally:
        iterator.close()


def preview_desktop(session, handle, parameters):
    from .computer_evidence import valid_capture_update
    from .desktop_session import DesktopError

    stop = threading.Event()
    iterator = _frames(session, handle, "desktop", parameters, stop)
    try:
        for values, header, raw in iterator:
            result = dict(header)
            if raw:
                result["image_b64"] = base64.b64encode(raw).decode("ascii")
            if not valid_capture_update(result, values):
                raise DesktopError("observation_invalid")
            return result
        raise DesktopError("observation_unavailable")
    finally:
        stop.set()
        iterator.close()


def follow_terminal(session, handle, values):
    """One bounded MCP observation; the GUI consumes the same byte stream live."""
    from .desktop_session import DesktopError

    if type(values) is not dict or not {"session_id"} <= values.keys() or set(values) - {"session_id", "cursor", "wait_ms"}:
        raise DesktopError("invalid_agent_request")
    cursor, wait = values.get("cursor", 0), values.get("wait_ms", 1000)
    if type(cursor) is not int or not 0 <= cursor < 2**63 or type(wait) is not int or not 1 <= wait <= 2000:
        raise DesktopError("invalid_agent_request")
    stop = threading.Event()
    iterator = stream_terminal(session, handle, values["session_id"], cursor, stop)
    deadline, output, frames, last = time.monotonic() + wait / 1000, bytearray(), 0, None
    try:
        for header, raw in iterator:
            if len(output) + len(raw) > 32768:
                break  # This frame was not applied; the next call rereads it.
            if last is not None and header["gap"]:
                break  # Never concatenate text across a missing byte range.
            output.extend(raw)
            last, frames = header, frames + 1
            if (len(output) >= 32768 or time.monotonic() >= deadline or header["state"] == "unknown"
                    or header["output_complete"] and header["next_cursor"] == header["total_bytes"]):
                break
        if last is None:
            raise DesktopError("observation_unavailable")
        return {"session_id": values["session_id"], "cursor": cursor, "start_cursor": last["next_cursor"] - len(output),
                "next_cursor": last["next_cursor"], "oldest_cursor": last["oldest_cursor"], "total_bytes": last["total_bytes"],
                "output": output.decode("utf-8", errors="strict"), "size_bytes": len(output), "frames": frames,
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "gap": last["next_cursor"] - len(output) != cursor, "state": last["state"],
                "input_sequence": last["input_sequence"], "output_complete": last["output_complete"],
                "task_created": False, "observation_only": True}
    finally:
        stop.set()
        iterator.close()


def follow_log(session, handle, values):
    """Read one append-aware frame without creating or acknowledging a task."""
    from .desktop_session import DesktopError
    from .log_follow import readable_log_increment, valid_log_follow_frame

    stop = threading.Event()
    iterator = _frames(session, handle, "log", values, stop)
    try:
        for parameters, result, raw in iterator:
            if not valid_log_follow_frame(result, raw, parameters):
                raise DesktopError("observation_invalid")
            return readable_log_increment(result, raw)
        raise DesktopError("observation_unavailable")
    finally:
        stop.set()
        iterator.close()


def read_command_output(session, handle, values):
    from .desktop_session import DesktopError
    from .output_artifacts import valid_output_artifact_result

    stop = threading.Event()
    iterator = _frames(session, handle, "command_output", values, stop)
    try:
        for parameters, header, raw in iterator:
            result = {**header, "data_b64": base64.b64encode(raw).decode("ascii")}
            if not valid_output_artifact_result(result, parameters):
                raise DesktopError("observation_invalid")
            try:
                result["text_utf8"] = raw.decode("utf-8")
            except UnicodeError:
                result["text_utf8"] = None
            return {**result, "observation_only": True, "task_created": False}
        raise DesktopError("observation_unavailable")
    finally:
        stop.set()
        iterator.close()
