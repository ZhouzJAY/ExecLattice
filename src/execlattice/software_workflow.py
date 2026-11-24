"""Explicit local UIA steps, never a planner, script runner or mutation retry.

Confirmation proves only caller-supplied UI predicates. In particular an exists
predicate cannot verify a ValuePattern value or successful business operation.
The ordinary Worker task journal remains the sole replay barrier. If the Worker
exits mid-task, that task becomes unknown, never a resumable sequence of inputs.
"""
from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy

from .computer_protocol import validate_computer_parameters
from .ui_automation import AutomationError, valid_ui_tree
from .ui_observation import condition_match, valid_ui_observation

MAX_STEPS = 8
MAX_TOTAL_MS = 60000
MAX_REQUEST_BYTES = MAX_RESULT_BYTES = 32768
_LEGACY_CAPABILITY = {"version": 1, "max_steps": MAX_STEPS, "max_total_ms": MAX_TOTAL_MS,
               "max_request_bytes": MAX_REQUEST_BYTES, "max_result_bytes": MAX_RESULT_BYTES,
               "exact_selectors": True, "stop_on_uncertain": True, "fresh_observation_per_step": True}
_CAPABILITY = {**_LEGACY_CAPABILITY, "version": 2, "focus_preparation": {
    "version": 1, "policy": "activate_once", "max_activation_requests": 1,
    "before_first_control_only": True, "pointer_or_keyboard_input": False,
    "fresh_identity_and_controls": True, "uncertain_activation_retries": False}}
_CONTEXT_KEYS = {"pid", "created", "session", "desktop", "title", "foreground", "focused_hwnd", "bounds"}
_STEP_KEYS = {"index", "operation", "selector_sha256", "condition_sha256", "state", "action_attempted",
              "action_submitted", "predicate_confirmed", "target_complete", "predicate_observation_complete", "match", "error"}


def software_workflow_capability():
    return deepcopy(_CAPABILITY)


def valid_software_workflow_capability(value):
    try:
        return (type(value) is dict and json.dumps(value, sort_keys=True, allow_nan=False) in {
                json.dumps(_CAPABILITY, sort_keys=True), json.dumps(_LEGACY_CAPABILITY, sort_keys=True)})
    except (TypeError, ValueError, OverflowError):
        return False


def software_workflow_focus_available(value):
    return valid_software_workflow_capability(value) and value.get("version") == 2


def software_workflow_target_capability():
    return {"version": 1, "action": "ui_workflow_target", "max_steps": MAX_STEPS,
            "max_total_ms": MAX_TOTAL_MS, "max_request_bytes": MAX_REQUEST_BYTES,
            "max_result_bytes": MAX_RESULT_BYTES, "expected_process_identity": True,
            "fresh_window_observation": True, "internal_observation_consumed": True,
            "focus_policy": ["require_foreground", "activate_once"], "stop_on_uncertain": True,
            "fresh_observation_per_step": True}


def valid_software_workflow_target_capability(value):
    try:
        return (type(value) is dict and json.dumps(value, sort_keys=True, allow_nan=False)
                == json.dumps(software_workflow_target_capability(), sort_keys=True, allow_nan=False))
    except (TypeError, ValueError, OverflowError):
        return False


def software_workflow_target_result(parameters, result):
    """Project a newly consumed observation without authorizing its reuse."""
    params = validate_computer_parameters("ui_workflow_target", parameters)
    projected = deepcopy(result)
    projected.update(kind="ui_workflow_target", expected_process=deepcopy(params["expected_process"]),
        request_sha256=_digest(redact_software_workflow_parameters(params)),
        target_preparation={"version": 1, "identity_verified": True,
                            "context_refreshed": True, "observation_consumed": True})
    return projected


def software_workflow_target_blocked(parameters, code, message, *, cancelled=False, elapsed_ms=0):
    """A rejected preparation has no observation and has attempted no input."""
    params = validate_computer_parameters("ui_workflow_target", parameters)
    rows = [{"index": i, "operation": step["operation"], "selector_sha256": _digest(step["selector"]),
             "condition_sha256": _digest(step["condition"]), "state": "not_attempted", "action_attempted": False,
             "action_submitted": False, "predicate_confirmed": False, "target_complete": False,
             "predicate_observation_complete": False, "match": None, "error": None}
            for i, step in enumerate(params["steps"])]
    return {"kind": "ui_workflow_target", "window_id": params["window_id"], "observation_id": None,
            "expected_process": deepcopy(params["expected_process"]),
            "request_sha256": _digest(redact_software_workflow_parameters(params)),
            "target_preparation": {"version": 1, "identity_verified": False,
                                   "context_refreshed": False, "observation_consumed": False},
            "state": "cancelled" if cancelled else "blocked", "confirmation_scope": "requested_ui_predicates_only",
            "business_success_verified": False, "steps": rows, "completed_steps": 0, "attempted_steps": 0,
            "stopped_at": None, "elapsed_ms": elapsed_ms, "requires_new_observation": True,
            "error": _error(code, message)}


def valid_software_workflow_target_result(task, result):
    try:
        if task.get("action") != "ui_workflow_target" or task.get("executor_type", "computer") != "computer":
            return False
        raw = deepcopy(task["parameters"])
        for step in raw.get("steps", []):
            if step.get("operation") == "set_value" and "value" not in step:
                step["value"] = ""
        params = validate_computer_parameters("ui_workflow_target", raw)
        if (type(result) is not dict or result.get("kind") != "ui_workflow_target"
                or json.dumps(result.get("expected_process"), sort_keys=True, allow_nan=False)
                    != json.dumps(params["expected_process"], sort_keys=True)
                or result.get("request_sha256") != _digest(redact_software_workflow_parameters(params))):
            return False
        if result.get("observation_id") is None:
            from .ui_observation import _error as valid_error

            error = result.get("error")
            if (result.get("state") not in {"blocked", "cancelled"} or not valid_error(error)
                    or type(result.get("elapsed_ms")) is not int or not 0 <= result["elapsed_ms"] <= MAX_TOTAL_MS + 20000):
                return False
            expected = software_workflow_target_blocked(params, error["code"], error["message"],
                cancelled=result["state"] == "cancelled", elapsed_ms=result["elapsed_ms"])
            return json.dumps(result, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)
        if (json.dumps(result.get("target_preparation"), sort_keys=True, allow_nan=False)
                != json.dumps({"version": 1, "identity_verified": True, "context_refreshed": True,
                               "observation_consumed": True}, sort_keys=True)):
            return False
        # Reuse every existing step/focus/uncertainty validator. The fresh
        # internal observation is a consumed audit reference, never caller input.
        legacy_params = {key: value for key, value in params.items() if key != "expected_process"}
        legacy_params["observation_id"] = result["observation_id"]
        legacy_params = validate_computer_parameters("ui_workflow", legacy_params)
        legacy = {key: value for key, value in result.items() if key not in {"expected_process", "target_preparation"}}
        legacy.update(kind="ui_workflow", request_sha256=_digest(redact_software_workflow_parameters(legacy_params)))
        return _valid_result({"action": "ui_workflow", "executor_type": "computer", "parameters": legacy_params}, legacy)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False


def focus_preparation_receipt(state="not_attempted", *, activation_requests=0, request_accepted=None,
                              target_verified=False, context_refreshed=False, error=None):
    return {"version": 1, "policy": "activate_once", "scope": "before_first_control_action", "state": state,
            "activation_requests": activation_requests, "request_accepted": request_accepted,
            "target_identity_verified": target_verified, "context_refreshed": context_refreshed,
            "control_input_attempted": False, "pointer_or_keyboard_input": False, "error": error}


def _valid_focus_preparation(value):
    from .ui_observation import _error as valid_error

    if (type(value) is not dict or set(value) != set(focus_preparation_receipt())
            or type(value["version"]) is not int or value["version"] != 1
            or value["policy"] != "activate_once" or value["scope"] != "before_first_control_action"
            or value["control_input_attempted"] is not False or value["pointer_or_keyboard_input"] is not False
            or type(value["activation_requests"]) is not int or value["activation_requests"] not in {0, 1}
            or type(value["target_identity_verified"]) is not bool or type(value["context_refreshed"]) is not bool):
        return False
    if value["activation_requests"] == 0:
        if value["request_accepted"] is not None:
            return False
    elif value["request_accepted"] is not None and type(value["request_accepted"]) is not bool:
        return False
    if value["activation_requests"] and not value["target_identity_verified"]:
        return False
    if value["state"] in {"not_needed", "confirmed"}:
        return (value["error"] is None and value["target_identity_verified"] and value["context_refreshed"]
                and value["activation_requests"] == (value["state"] == "confirmed"))
    if value["state"] in {"blocked", "unknown", "cancelled"}:
        return (valid_error(value["error"]) and not value["context_refreshed"]
                and value["activation_requests"] == (value["state"] == "unknown"))
    return False


def redact_software_workflow_parameters(parameters):
    public = deepcopy(parameters)
    if isinstance(public, dict) and isinstance(public.get("steps"), list):
        for step in public["steps"]:
            if isinstance(step, dict):
                step.pop("value", None)
    return public


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                                     allow_nan=False).encode("ascii")).hexdigest()


def _error(code, message):
    return {"code": code, "message": message}


def run_software_workflow(manager, parameters, *, context_guard, cancel, read_only=False, clock=time.monotonic,
                          prepare_focus=None):
    if read_only:
        raise AutomationError("READ_ONLY", "Read-only connections cannot change software controls")
    parameters = validate_computer_parameters("ui_workflow", parameters)
    started = clock()
    deadline = started + parameters["total_timeout_ms"] / 1000
    rows = [{"index": i, "operation": step["operation"], "selector_sha256": _digest(step["selector"]),
             "condition_sha256": _digest(step["condition"]), "state": "not_attempted", "action_attempted": False,
             "action_submitted": False, "predicate_confirmed": False, "target_complete": False,
             "predicate_observation_complete": False, "match": None, "error": None}
            for i, step in enumerate(parameters["steps"])]
    result = {"kind": "ui_workflow", "window_id": parameters["window_id"], "observation_id": parameters["observation_id"],
              "request_sha256": _digest(redact_software_workflow_parameters(parameters)), "state": "blocked",
              "confirmation_scope": "requested_ui_predicates_only", "business_success_verified": False,
              "steps": rows, "completed_steps": 0, "attempted_steps": 0, "stopped_at": 0, "elapsed_ms": 0,
              "requires_new_observation": True, "error": None}
    if parameters.get("focus_policy") == "activate_once":
        # This is a separate observed effect before UIA control admission. It
        # never reuses a previously issued control token or repeats a step.
        focus = (prepare_focus() if callable(prepare_focus) else focus_preparation_receipt("blocked", error=_error(
            "FOCUS_PREPARATION_UNAVAILABLE", "The explicit focus preparation capability is unavailable")))
        result["focus_preparation"] = focus
        if not _valid_focus_preparation(focus):
            raise AutomationError("UIA_OPERATION_UNCONFIRMED", "Focus preparation receipt did not verify", state="unknown")
        if focus["state"] not in {"confirmed", "not_needed"}:
            result.update(state=focus["state"], stopped_at=None, error=focus["error"],
                          elapsed_ms=max(0, round((clock() - started) * 1000)))
            return result
    anchor = stable = None
    current = None

    def check():
        if cancel is not None and cancel.is_set():
            raise AutomationError("CANCELLED", "Software workflow was cancelled", state="cancelled")
        if clock() >= deadline:
            raise AutomationError("WORKFLOW_BUDGET", "Software workflow reached its time budget")
        context = context_guard()
        if type(context) is not dict or set(context) != _CONTEXT_KEYS or not context["focused_hwnd"]:
            raise AutomationError("UIA_CONTEXT_CHANGED", "Software workflow context is unavailable")
        identity = {key: value for key, value in context.items() if key != "focused_hwnd"}
        if stable is not None and identity != stable:
            raise AutomationError("UIA_CONTEXT_CHANGED", "Software workflow window, identity or focus changed")
        return context

    try:
        anchor = check()
        stable = {key: value for key, value in anchor.items() if key != "focused_hwnd"}
        for index, step in enumerate(parameters["steps"]):
            current = rows[index]
            result["stopped_at"] = index
            before = check()
            if before != anchor:
                raise AutomationError("UIA_CONTEXT_CHANGED", "Software workflow focus changed between steps")
            # An admitted read has the existing helper's finite startup/provider
            # cutoff. Never start a mutation or another step after this budget.
            remaining_ms = int((deadline - clock()) * 1000)
            if remaining_ms < 250:
                raise AutomationError("WORKFLOW_BUDGET", "No time remains for another software observation")
            tree = manager.inspect(int(parameters["window_id"], 16), window_id=parameters["window_id"],
                owner_id=parameters["owner_id"], max_nodes=parameters["max_nodes"], max_depth=parameters["max_depth"],
                timeout_ms=min(parameters["timeout_ms"], remaining_ms), cancel=cancel)
            if check() != before:
                raise AutomationError("UIA_CONTEXT_CHANGED", "Software workflow focus changed during observation")
            if not valid_ui_tree(tree) or tree["window_id"] != parameters["window_id"]:
                raise AutomationError("UIA_UNAVAILABLE", "Software control observation did not verify")
            match = condition_match(tree, {**step["selector"], "property": "exists", "expected": True})
            if match["state"] != "matched":
                raise AutomationError("WORKFLOW_TARGET_UNAVAILABLE", "Software target is not unique, complete and available")
            target = tree["nodes"][match["index"]]
            if (target["pid"] != anchor["pid"] or not target["control_token"] or target["password"]
                    or not target["enabled"] or target["offscreen"] or step["operation"] not in target["actions"]):
                raise AutomationError("WORKFLOW_TARGET_UNAVAILABLE", "Software target is not currently actionable")
            current["target_complete"] = True
            # The existing action remains one-use, owner/focus/fingerprint bound.
            # Local waits call only inspect, never perform again.
            if (deadline - clock()) * 1000 < 6000 + parameters["timeout_ms"] + step["wait_ms"]:
                raise AutomationError("WORKFLOW_BUDGET", "Insufficient time to admit another bounded software operation")
            request = {"owner_id": parameters["owner_id"], "control_token": target["control_token"],
                       "operation": step["operation"], "value": step["value"], "condition": step["condition"],
                       "max_nodes": parameters["max_nodes"], "max_depth": parameters["max_depth"],
                       "timeout_ms": parameters["timeout_ms"], "wait_ms": step["wait_ms"],
                       "interval_ms": parameters["interval_ms"]}
            current["action_attempted"] = True
            observed = manager.perform_and_observe(request, read_only=False, cancel=cancel)
            if not valid_ui_observation(observed, "ui_action_observe", request):
                raise AutomationError("UIA_OPERATION_UNCONFIRMED", "Software operation response did not verify", state="unknown")
            action = observed["action"]
            current["action_submitted"] = action["state"] == "submitted"
            current["predicate_observation_complete"] = (observed["observation"] is not None
                                                         and not observed["observation"]["truncated"])
            current["match"] = observed["match"]
            if action["state"] == "unknown":
                raise AutomationError("UIA_OPERATION_UNCONFIRMED", "Software operation may have occurred; do not repeat it", state="unknown")
            anchor = check()
            if observed["state"] != "confirmed" or observed["effect_verified"] is not True:
                current.update(state="unconfirmed", error=observed["error"] or _error(
                    "WORKFLOW_PREDICATE_UNCONFIRMED", "The requested software predicate was not confirmed"))
                result.update(state="unconfirmed", error=current["error"])
                break
            current.update(state="confirmed", predicate_confirmed=True)
            result["completed_steps"] += 1
        else:
            result.update(state="confirmed", stopped_at=None)
    except AutomationError as error:
        attempted = current is not None and current["action_attempted"]
        # Entering the mutating RPC is the uncertainty boundary. An exception's
        # default state (including cancellation) cannot prove no input occurred.
        state = ("unknown" if attempted or error.state == "unknown" else
                 "cancelled" if error.state == "cancelled" else "blocked")
        safe = _error(error.code, error.message)
        if current is None:
            current = rows[0]
        current.update(state=state, error=safe)
        result.update(state=state, error=safe)
    except Exception:
        state = "unknown" if current is not None and current["action_attempted"] else "blocked"
        safe = _error("UIA_OPERATION_UNCONFIRMED" if state == "unknown" else "UIA_UNAVAILABLE",
                      "Software workflow context or provider is unavailable")
        if current is None:
            current = rows[0]
        current.update(state=state, error=safe)
        result.update(state=state, error=safe)
    result["attempted_steps"] = sum(row["action_attempted"] for row in rows)
    result["elapsed_ms"] = max(0, round((clock() - started) * 1000))
    return result


def valid_software_workflow_result(task, result):
    try:
        return _valid_result(task, result)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False


def _valid_result(task, result):
    if task.get("action") != "ui_workflow" or task.get("executor_type", "computer") != "computer":
        return False
    raw = deepcopy(task["parameters"])
    # Public task projections remove supplied text; no text is reconstructed.
    for step in raw.get("steps", []):
        if step.get("operation") == "set_value" and "value" not in step:
            step["value"] = ""
    params = validate_computer_parameters("ui_workflow", raw)
    keys = {"kind", "window_id", "observation_id", "request_sha256", "state", "confirmation_scope",
            "business_success_verified", "steps", "completed_steps", "attempted_steps", "stopped_at",
            "elapsed_ms", "requires_new_observation", "error"}
    if params.get("focus_policy") == "activate_once":
        keys.add("focus_preparation")
    if (type(result) is not dict or set(result) != keys or result["kind"] != "ui_workflow"
            or result["window_id"] != params["window_id"] or result["observation_id"] != params["observation_id"]
            or result["request_sha256"] != _digest(redact_software_workflow_parameters(params))
            or result["confirmation_scope"] != "requested_ui_predicates_only" or result["business_success_verified"] is not False
            or result["requires_new_observation"] is not True or type(result["elapsed_ms"]) is not int
            or not 0 <= result["elapsed_ms"] <= MAX_TOTAL_MS + 20000
            or type(result["steps"]) is not list or len(result["steps"]) != len(params["steps"])
            or len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_RESULT_BYTES):
        return False
    from .ui_observation import _error as valid_error
    if params.get("focus_policy") == "activate_once":
        focus = result["focus_preparation"]
        if not _valid_focus_preparation(focus):
            return False
        if focus["state"] in {"blocked", "unknown", "cancelled"}:
            expected = [{"index": i, "operation": step["operation"], "selector_sha256": _digest(step["selector"]),
                         "condition_sha256": _digest(step["condition"]), "state": "not_attempted", "action_attempted": False,
                         "action_submitted": False, "predicate_confirmed": False, "target_complete": False,
                         "predicate_observation_complete": False, "match": None, "error": None}
                        for i, step in enumerate(params["steps"])]
            return (result["state"] == focus["state"] and result["error"] == focus["error"]
                    and result["stopped_at"] is None and type(result["completed_steps"]) is int
                    and type(result["attempted_steps"]) is int and result["completed_steps"] == result["attempted_steps"] == 0
                    and json.dumps(result["steps"], sort_keys=True, allow_nan=False) ==
                        json.dumps(expected, sort_keys=True, allow_nan=False))
    stopped, completed, attempted = None, 0, 0
    for index, (row, step) in enumerate(zip(result["steps"], params["steps"], strict=True)):
        if (type(row) is not dict or set(row) != _STEP_KEYS or type(row["index"]) is not int or row["index"] != index
                or row["operation"] != step["operation"] or row["selector_sha256"] != _digest(step["selector"])
                or row["condition_sha256"] != _digest(step["condition"])
                or any(type(row[key]) is not bool for key in ("action_attempted", "action_submitted", "predicate_confirmed",
                                                            "target_complete", "predicate_observation_complete"))):
            return False
        attempted += row["action_attempted"]
        if row["action_submitted"] and not row["action_attempted"]:
            return False
        if row["action_attempted"] and not row["target_complete"]:
            return False
        match = row["match"]
        if match is not None and (type(match) is not dict or set(match) != {"state", "matches", "index"}
                or match["state"] not in {"matched", "not_matched", "ambiguous", "incomplete", "unsupported"}
                or type(match["matches"]) is not int or not 0 <= match["matches"] <= params["max_nodes"]
                or match["index"] is not None and (type(match["index"]) is not int or not 0 <= match["index"] < params["max_nodes"])):
            return False
        if row["state"] == "confirmed":
            if (stopped is not None or not row["action_attempted"] or not row["action_submitted"] or not row["predicate_confirmed"]
                    or not row["target_complete"] or not row["predicate_observation_complete"]
                    or row["error"] is not None or match is None or match["state"] != "matched"
                    or match["matches"] != (0 if step["condition"]["property"] == "exists" and step["condition"]["expected"] is False else 1)):
                return False
            if (match["matches"] == 1 and match["index"] is None) or (match["matches"] == 0 and match["index"] is not None):
                return False
            completed += 1
        elif row["state"] == "not_attempted":
            if stopped is None or any(row[k] for k in ("action_attempted", "action_submitted", "predicate_confirmed", "target_complete", "predicate_observation_complete")) or row["error"] is not None or match is not None:
                return False
        else:
            if (stopped is not None or row["state"] not in {"blocked", "unconfirmed", "unknown", "cancelled"}
                    or row["predicate_confirmed"] or not valid_error(row["error"])):
                return False
            if row["state"] in {"unknown", "unconfirmed"} and not row["action_attempted"]:
                return False
            if row["state"] == "unconfirmed" and not row["action_submitted"]:
                return False
            stopped = index
    if (type(result["completed_steps"]) is not int or result["completed_steps"] != completed
            or type(result["attempted_steps"]) is not int or result["attempted_steps"] != attempted):
        return False
    if stopped is None:
        return (result["state"] == "confirmed" and completed == len(params["steps"])
                and result["stopped_at"] is None and result["error"] is None)
    return (type(result["stopped_at"]) is int and result["stopped_at"] == stopped
            and result["state"] == result["steps"][stopped]["state"]
            and result["error"] == result["steps"][stopped]["error"])
