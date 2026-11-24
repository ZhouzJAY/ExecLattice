"""One explicit registry for negotiated maintenance tools at every boundary.

No arbitrary capability metadata is forwarded. Descriptors, admission and
result validation use these same entries, including on read-only connections.
Imports stay lazy so protocol models do not form a computer-protocol cycle.
"""
from __future__ import annotations

from importlib import import_module

SYSTEM_TOOLS = {
    "resource_observe": ("inspect_resource", "resource_observation", "resource_protocol",
                         "ResourceObservationParameters", "resource_capability", "valid_resource_capability",
                         "resource_observation", "inspect_resource", "valid_resource_result"),
    "runtime_inspect": ("inspect_runtime", "runtime_inspection", "runtime_inspection_protocol",
                        "RuntimeInspectionParameters", "runtime_capability", "valid_runtime_capability",
                        "runtime_inspection", "inspect_runtime", "valid_runtime_result"),
    "system_change": ("change_system_state", "system_change", "system_change_protocol",
                      "SystemChangeParameters", "system_change_capability", "valid_system_change_capability",
                      "system_change", "execute_system_change", "valid_system_change_result"),
    "recovery_observation": ("observe_recovery", "recovery_observation", "recovery_observation_protocol",
                             "RecoveryObservationParameters", "recovery_observation_capability",
                             "valid_recovery_observation_capability", "recovery_observation",
                             "execute_recovery_observation", "valid_recovery_observation_result"),
}
SYSTEM_OPERATIONS = {value[0]: action for action, value in SYSTEM_TOOLS.items()}
SYSTEM_CAPABILITY_FIELDS = frozenset(value[1] for value in SYSTEM_TOOLS.values())
_READ_ACTIONS = {"system_change": {"inspect", "query"}, "recovery_observation": {"query", "sample"}}


def _member(module, name):
    return getattr(import_module("." + module, __package__), name)


def system_models():
    return {action: _member(row[2], row[3]) for action, row in SYSTEM_TOOLS.items()}


def system_capabilities():
    return {row[1]: _member(row[2], row[4])() for row in SYSTEM_TOOLS.values()}


def system_action_allowed(cap, action, parameters=None):
    row = SYSTEM_TOOLS.get(action)
    if row is None or type(cap) is not dict:
        return False
    if (cap.get("executor_type") != "computer" or cap.get("available") is not True
            or type(cap.get("actions")) is not list or action not in cap["actions"]
            or cap.get("mode") not in {"read_only", "full"}
            or not _member(row[2], row[5])(cap.get(row[1]))):
        return False
    if cap["mode"] == "read_only" and action in _READ_ACTIONS and parameters is not None:
        return type(parameters) is dict and parameters.get("action") in _READ_ACTIONS[action]
    return True


def base_capability(cap):
    """Validate the registered suffix, then let legacy validation check its base.

    A missing marker/action, wrong executor, duplicate or reordered suffix is
    rejected, rather than silently downgrading to a legacy generic action.
    """
    actions = cap.get("actions", [])
    present = [action for action, row in SYSTEM_TOOLS.items()
               if row[1] in cap or type(actions) is list and action in actions]
    if not present:
        return cap
    if (type(actions) is not list or cap.get("executor_type") != "computer"
            or actions[-len(present):] != present
            or any(actions.count(action) != 1 or not system_action_allowed(cap, action) for action in present)):
        raise ValueError("Invalid negotiated maintenance capability")
    return {key: (value[:-len(present)] if key == "actions" else value)
            for key, value in cap.items() if key not in SYSTEM_CAPABILITY_FIELDS}


def validate_system_result(action, result, parameters):
    row = SYSTEM_TOOLS[action]
    return _member(row[6], row[8])(result, parameters)


def execute_system_tool(action, parameters, policy, cancel, *, state_dir=None):
    row = SYSTEM_TOOLS[action]
    mode = policy.get("desktop_access", {}).get("mode")
    cap = {"executor_type": "computer", "available": True, "mode": mode,
           "actions": [action], row[1]: _member(row[2], row[4])()}
    if not system_action_allowed(cap, action, parameters):
        from .computer_executor import ComputerError

        raise ComputerError("POLICY_DENIED", "This system action requires editable mode")
    return _member(row[6], row[7])(parameters, policy, cancel, state_dir=state_dir)
