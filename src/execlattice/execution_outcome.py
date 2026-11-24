"""Additive Agent result projection; never changes durable task facts.

A successful wrapper is a received receipt, not necessarily a completed command
or a confirmed UI effect. This module performs no I/O and never borrows a
current connection to label an original task's execution environment.
"""

from __future__ import annotations

from uuid import UUID

_PENDING = {"queued", "authorized", "dispatched", "running", "cancelling"}
_TERMINAL = {"succeeded", "failed", "cancelled", "timed_out", "unknown"}
_RECEIPT_FIELDS = (
    "protocol_version", "task_id", "target_device_id", "executor_type", "action", "state",
    "created_at", "updated_at", "timeout_seconds", "result", "error", "progress", "recovery_evidence",
)


def _uuid(value):
    try:
        return value if isinstance(value, str) and str(UUID(value)) == value else None
    except ValueError:
        return None


def execution_outcome(value):
    """Project already checked public receipts, conservatively and without input.

Only explicit execution/predicate facts are lifted. Arbitrary result.state or a
generic succeeded task can never become overall business success. Legacy and
malformed receipts retain unknown dimensions instead of guessed authority.
"""
    state = value.get("state")
    state = state if isinstance(state, str) and state in _PENDING | _TERMINAL | {
        "result_unverified", "submission_unconfirmed"} else "unavailable"
    task_id = _uuid(value.get("task_id"))
    observed = value.get("observation_only") is True and value.get("task_created") is False
    result = value.get("result")
    result = result if type(result) is dict else {}
    verified = state == "succeeded"
    execution = {"scope": "task", "state": state, "exit_code": None}
    effect = {"state": "not_reported", "scope": "none", "business_success_verified": False}
    observation = {"state": "not_requested", "scope": "none"}
    executor, action = value.get("executor_type"), value.get("action")

    if observed:
        execution = {"scope": "observation", "state": "not_applicable", "exit_code": None}
        effect.update(state="not_applicable")
        observation.update(state="observed" if verified else "unverified", scope="requested_observation")
    elif state in {"unknown", "submission_unconfirmed", "result_unverified", "unavailable"}:
        effect.update(state="unknown")
        observation.update(state="unverified", scope="receipt")
    elif verified:
        observation.update(state="observed", scope="receipt")
        if executor == "job" and action in {"start", "describe", "cancel"}:
            job_state = result.get("job_state")
            execution.update(scope="persistent_job", state=job_state if isinstance(job_state, str) else "unconfirmed")
            output = result.get("result")
            if type(output) is dict and type(output.get("exit_code")) is int:
                execution["exit_code"] = output["exit_code"]
            effect.update(scope="job_receipt_only")
        elif (executor, action) in {("browser", "action_observe"), ("computer", "ui_action_observe"),
                                    ("computer", "ui_wait")}:
            confirmation = result.get("state") == "confirmed" and result.get("effect_verified") is True
            observation.update(state="confirmed" if confirmation else
                               "observed" if result.get("state") == "observed" else "unconfirmed",
                               scope="requested_predicate")
            if action == "ui_wait":
                effect.update(state="not_applicable")
            else:
                receipt = result.get("action")
                unknown = type(receipt) is dict and receipt.get("state") == "unknown"
                effect.update(state="unknown" if unknown else "confirmed" if confirmation else "unconfirmed",
                              scope="requested_predicate_only")
        elif (executor, action) in {("computer", "ui_workflow"), ("computer", "ui_workflow_target"), ("browser", "workflow")}:
            confirmation = result.get("state") == "confirmed"
            attempts = result.get("attempted_steps")
            effect.update(state="unknown" if result.get("state") == "unknown" else
                          "confirmed" if confirmation else "not_attempted" if type(attempts) is int and attempts == 0
                          else "unconfirmed",
                          scope="requested_predicates_only")
            observation.update(state="confirmed" if confirmation else "unconfirmed", scope="requested_predicates")
        elif (executor, action) == ("computer", "system_change"):
            phase = result.get("outcome")
            # The adapter receipt and the named setting are different facts.
            # A named-setting receipt does not establish broader outcomes.
            effect.update(state="confirmed" if phase in {"applied", "rolled_back"} else
                          "unknown" if phase == "unknown" else "not_attempted",
                          scope="named_setting_only")
            observation.update(state="confirmed" if phase in {"applied", "rolled_back"} else
                               "unconfirmed" if phase in {"unknown", "conflict"} else "observed",
                               scope="named_setting_state")
        elif executor == "computer" and action in {"diagnose", "resource_observe", "runtime_inspect", "recovery_observation"}:
            effect.update(state="not_applicable")
            observation.update(state="observed", scope="bounded_system_evidence")

    if executor in {"command", "development"} and action == "run" and state in {
        "succeeded", "failed", "timed_out", "cancelled",
    }:
        code = result.get("exit_code")
        execution.update(scope="command", state="completed" if type(code) is int else state,
                         exit_code=code if type(code) is int else None)
        effect.update(state="not_reported", scope="command_exit_only")

    original = value.get("original_task_receipt")
    origin = {"device_id": _uuid(value.get("target_device_id")), "current_connection_inferred": False,
              "authority": "original_task" if task_id else "fresh_observation" if observed else "unavailable"}
    if type(original) is dict:
        # Existence of an archived receipt is never current execution authority.
        origin["authority"] = "original_task_receipt"
    reference = value.get("execution_environment_ref")
    if type(reference) is dict:
        from .execution_environment import environment_reference

        public = environment_reference(reference.get("device_id"), reference.get("environment_id"),
                                       reference.get("execution_owner_id"))
        if (value.get("execution_location") == "local" and public["identity_scope"] == "authenticated_execution_owner"
                and reference.get("identity_scope") == "local_execution_owner"):
            # An explicit local backend has its own scope, never a Controller
            # authentication or a current remote device inferred from the GUI.
            public["identity_scope"] = "local_execution_owner"
        if public == reference and public["device_id"] == origin["device_id"]:
            origin["environment"] = public
    query = (None if observed else "get_task" if task_id else
             "get_operation" if value.get("operation_id") or value.get("idempotency_key") else None)
    return {"version": 1, "origin": origin, "task": {"task_id": task_id, "state": state},
            "execution": execution, "effect": effect, "observation": observation,
            "recovery": {"automatic_resubmit": False, "query_original": query}}


def with_execution_outcome(value):
    """Return a fresh projection, replacing any peer-supplied summary."""
    return {**value, "execution_outcome": execution_outcome(value)}


def public_task_receipt(value: dict) -> dict:
    """Preserve task identity and authorized evidence without repeating request data."""
    return with_execution_outcome({key: value[key] for key in _RECEIPT_FIELDS if key in value})
