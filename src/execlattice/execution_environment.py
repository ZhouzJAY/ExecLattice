"""Public projection of an existing remote execution authority.

This creates neither an execution lease nor mutable cwd/environment state. The
durable environment identity is the original authenticated scope. A connection
handle refers only to the current device session. Actual user, system,
paths and desktop readiness still need a remote observation.
"""
from __future__ import annotations

import re
from uuid import UUID


def _hex(value, length):
    return value if isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) else None


def _device(value):
    try:
        return value if isinstance(value, str) and str(UUID(value)) == value else None
    except (ValueError, AttributeError):
        return None


def environment_reference(device_id, binding_id=None, execution_owner_id=None):
    """Project only an already verified scope; never resolve or contact a peer.

Callers must supply the ORIGINAL scope when describing an old operation. A
current connection is not evidence of that operation's execution authority.
Device-only and legacy references deliberately do not attest a Windows user.
"""
    device = _device(device_id)
    binding = _hex(binding_id, 64) if device is not None else None
    owner = _hex(execution_owner_id, 32) if device is not None else None
    identity = ("authenticated_execution_owner" if binding is not None and owner is not None else
                "legacy_device" if binding is not None else "device_only" if device is not None else "unavailable")
    return {"version": 1, "environment_id": binding, "device_id": device,
            "execution_owner_id": owner, "identity_scope": identity}


def execution_session(connection_handle, connection_state, access_mode, reference):
    """Describe current selection semantics without claiming discovery ran.

The existing connection checks remain authoritative for every operation. Ready
describes that execution channel only, not an unlocked interactive desktop.
"""
    reference = reference if isinstance(reference, dict) else {}
    public = environment_reference(reference.get("device_id"), reference.get("environment_id"),
                                   reference.get("execution_owner_id"))
    handle = _hex(connection_handle, 32)
    readiness = ("ready" if connection_state == "connected" and handle is not None
                 and public["device_id"] is not None else
                 "reconnecting" if connection_state == "reconnecting" else "unavailable")
    return {
        "version": 1, "reference": public, "connection_handle": handle,
        "handle_lifetime": "mother_device_view", "readiness": readiness,
        "access_mode": access_mode if isinstance(access_mode, str) and access_mode in {"full", "read_only"} else None,
        "environment_discovery": "not_observed", "desktop_readiness": "not_observed",
        "semantics": {
            "files": "remote_absolute_paths", "localhost": "remote_device",
            "commands": "explicit_cwd_per_command", "jobs": "explicit_cwd_per_job",
            "terminal": "persistent_cwd_per_terminal", "process_environment": "remote_current_user",
            "browser": "owned_isolated_profile", "desktop": "remote_interactive_user",
            "automatic_elevation": False, "local_fallback": False,
        },
    }


def describe_execution_environment(*, device_id, connection_handle, connection_state,
                                   access_mode, binding_id, execution_owner_id,
                                   environment_discovery_available, bundled_command_tools):
    """Add a session descriptor while retaining the original public fields."""
    return {
        "location": "remote", "device_id": device_id,
        "path_semantics": "remote_absolute", "network_semantics": "remote", "local_fallback": False,
        "environment_discovery_available": environment_discovery_available,
        "bundled_command_tools": bundled_command_tools,
        "version": 2,
        "session": execution_session(connection_handle, connection_state, access_mode,
                                     environment_reference(device_id, binding_id, execution_owner_id)),
    }
