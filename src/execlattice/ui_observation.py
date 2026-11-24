"""Observe after one UIA mutation, or wait without performing any mutation.

An acknowledged action is distinct from a satisfied, explicitly requested UI
predicate. Failure to observe never causes an action to be submitted again.
"""

from __future__ import annotations

import re

from .computer_protocol import ComputerUICondition, validate_computer_parameters
from .ui_automation import AutomationError, valid_ui_action, valid_ui_tree


def condition_match(tree, condition):
    """Evaluate only exact, unique selectors on a complete bounded snapshot."""
    rows = [node for node in tree["nodes"] if not node["password"] and all(
        condition.get(key) is None or node[key] == condition[key]
        for key in ("automation_id", "name", "control_type"))]
    count = len(rows)
    protected_candidates = any(node["password"] and (
        condition.get("control_type") is None or node["control_type"] == condition["control_type"])
        for node in tree["nodes"])
    result = {"state": "not_matched", "matches": count,
              "index": rows[0]["index"] if count == 1 else None}
    if count > 1:
        result["state"] = "ambiguous"
    elif tree["truncated"]:
        # An unseen duplicate is possible, as is an unseen matching control.
        result["state"] = "incomplete"
    elif protected_candidates:
        # Password names/IDs are deliberately never read. A hidden identifier
        # may match this selector, so neither absence nor uniqueness is known.
        # A different explicit control type can exclude such protected nodes.
        result["state"] = "unsupported"
    elif condition["property"] == "exists":
        if (count == 1) is condition["expected"]:
            result["state"] = "matched"
    elif count == 1:
        actual = rows[0].get("pattern_states", {}).get(condition["property"])
        if actual is None:
            result["state"] = "unsupported"
        elif type(actual) is type(condition["expected"]) and actual == condition["expected"]:
            result["state"] = "matched"
    return result


def observe_controls(manager, parameters, *, window_id, expected_identity, action, cancel, started):
    """Retain the single original mutation receipt on every post-action path."""
    condition = parameters.get("condition")
    result = {"kind": "ui_action_observe" if action is not None else "ui_wait",
              "window_id": window_id, "state": "unavailable", "effect_verified": False,
              "action": action, "condition": condition, "match": None, "observation": None,
              "elapsed_ms": 0, "error": None}
    wait_deadline = manager._clock() + parameters["wait_ms"] / 1000
    try:
        if expected_identity is None:
            expected_identity = manager._observation_identity(
                int(window_id, 16), cancel=cancel, timeout_ms=parameters["timeout_ms"])
        while True:
            if cancel is not None and cancel.is_set():
                raise AutomationError("CANCELLED", "Control observation was cancelled", state="cancelled")
            remaining = wait_deadline - manager._clock()
            timeout_ms = parameters["timeout_ms"]
            if parameters["wait_ms"]:
                if remaining <= 0:
                    result["state"] = "timeout"
                    break
                timeout_ms = min(timeout_ms, max(100, int(remaining * 1000)))
            tree = manager.inspect(int(window_id, 16), window_id=window_id,
                                   owner_id=parameters["owner_id"], max_nodes=parameters["max_nodes"],
                                   max_depth=parameters["max_depth"], timeout_ms=timeout_ms,
                                   cancel=cancel, expected_identity=expected_identity)
            result["observation"] = tree
            result["match"] = condition_match(tree, condition) if condition else None
            if action is not None and action["state"] == "unknown":
                result["error"] = action["error"]
                break
            if condition is None:
                result["state"] = "observed"
                break
            if result["match"]["state"] == "matched":
                result["state"], result["effect_verified"] = "confirmed", True
                break
            remaining = wait_deadline - manager._clock()
            if remaining < .1:
                result["state"] = "timeout"
                break
            manager._waiter(min(parameters["interval_ms"] / 1000, remaining), cancel)
    except AutomationError as exc:
        result["state"] = "cancelled" if exc.state == "cancelled" else "unavailable"
        result["error"] = {"code": exc.code, "message": exc.message}
    except Exception:
        # COM/provider exceptions must neither erase the mutating call receipt
        # nor disclose provider exception text (which can contain input values).
        result["error"] = {"code": "UIA_UNAVAILABLE", "message": "Windows control observation is unavailable"}
    if action is not None and action["state"] == "unknown":
        result["state"], result["effect_verified"] = "unavailable", False
        result["error"] = action["error"]
    result["elapsed_ms"] = max(0, round((manager._clock() - started) * 1000))
    return result


def _error(value):
    return (isinstance(value, dict) and set(value) == {"code", "message"}
            and isinstance(value["code"], str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value["code"]) is not None
            and isinstance(value["message"], str) and 1 <= len(value["message"]) <= 256
            and all(ord(char) >= 32 and not 0xD800 <= ord(char) <= 0xDFFF for char in value["message"]))


def valid_ui_observation(result, action, parameters):
    try:
        return _valid_ui_observation(result, action, parameters)
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return False


def _valid_ui_observation(result, action, parameters):
    parameters = validate_computer_parameters(action, parameters)
    fields = {"kind", "window_id", "state", "effect_verified", "action", "condition", "match",
              "observation", "elapsed_ms", "error"}
    if (action not in {"ui_action_observe", "ui_wait"} or not isinstance(result, dict) or set(result) != fields
            or result["kind"] != action or not isinstance(result["window_id"], str)
            or re.fullmatch(r"0x[0-9a-f]{1,16}", result["window_id"]) is None or int(result["window_id"], 16) == 0
            or result["state"] not in {"observed", "confirmed", "timeout", "unavailable", "cancelled"}
            or type(result["effect_verified"]) is not bool
            or type(result["elapsed_ms"]) is not int or not 0 <= result["elapsed_ms"] <= 60000
            or result["condition"] != parameters.get("condition")
            or result["error"] is not None and not _error(result["error"])):
        return False
    receipt = result["action"]
    if action == "ui_wait":
        if receipt is not None or result["window_id"] != parameters["window_id"]:
            return False
    else:
        if (not isinstance(receipt, dict) or set(receipt) != {"state", "receipt", "error"}
                or receipt["state"] not in {"submitted", "unknown"}):
            return False
        if receipt["state"] == "submitted":
            if (receipt["error"] is not None or not valid_ui_action(receipt["receipt"])
                    or receipt["receipt"]["window_id"] != result["window_id"]
                    or receipt["receipt"]["operation"] != parameters["operation"]
                    or receipt["receipt"]["control_token"] != parameters["control_token"]):
                return False
        elif (receipt["receipt"] is not None or not _error(receipt["error"])
              or receipt["error"]["code"] != "UIA_OPERATION_UNCONFIRMED"
              or result["state"] != "unavailable" or result["error"] != receipt["error"]):
            return False
    tree = result["observation"]
    if tree is not None:
        if (not valid_ui_tree(tree) or tree["window_id"] != result["window_id"]
                or tree["node_count"] > parameters["max_nodes"]
                or any(node["depth"] > parameters["max_depth"] for node in tree["nodes"])):
            return False
    condition = parameters.get("condition")
    if result["condition"] is not None:
        if ComputerUICondition.model_validate(result["condition"]).model_dump() != condition:
            return False
    expected_match = condition_match(tree, condition) if tree is not None and condition else None
    match = result["match"]
    if match is not None and (not isinstance(match, dict) or set(match) != {"state", "matches", "index"}
                              or type(match["matches"]) is not int or not 0 <= match["matches"] <= 256
                              or match["index"] is not None and (type(match["index"]) is not int
                                                                  or not 0 <= match["index"] < 256)):
        return False
    if result["match"] != expected_match:
        return False
    if result["state"] == "confirmed":
        return (result["effect_verified"] is True and result["error"] is None
                and expected_match is not None and expected_match["state"] == "matched")
    if result["effect_verified"] is not False:
        return False
    if result["state"] == "observed":
        return condition is None and tree is not None and result["error"] is None
    if result["state"] == "timeout":
        return (condition is not None and result["error"] is None
                and (expected_match is None or expected_match["state"] != "matched"))
    return result["error"] is not None and (result["state"] != "cancelled" or result["error"]["code"] == "CANCELLED")
