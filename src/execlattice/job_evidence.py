"""Validate asynchronous acceptance separately from actual process completion."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

from .job_protocol import JOB_MODELS, JobStartParameters

JOB_STATES = frozenset({"running", "succeeded", "failed", "cancelled", "timed_out", "unknown"})


def _output(value, state):
    from .development_progress import valid_development_result, valid_progress

    if not isinstance(value, dict):
        return False
    observed = dict(value)
    duration = observed.get("duration_ms")
    if type(duration) is not int or not 0 <= duration <= 86460000:
        return False
    # A 24 h timeout can require a few seconds to confirm process-tree stop.
    observed["duration_ms"] = min(duration, 86400000)
    if state == "running" or state == "unknown" and observed.get("exit_code") is None:
        capture = observed.pop("output_capture", None)
        if capture is not None:
            from .output_artifacts import valid_capture_result

            if not valid_capture_result(capture, {name: observed.get(name + "_total_bytes")
                                                  for name in ("stdout", "stderr")}):
                return False
        return observed.pop("exit_code", "missing") is None and valid_progress(observed)
    return valid_development_result(observed)


def valid_job_metadata(value, owner_id, *, summary=False):
    try:
        if (not isinstance(value, dict) or value.get("owner_id") != owner_id
                or not isinstance(value.get("job_id"), str) or re.fullmatch(r"[0-9a-f]{32}", value["job_id"]) is None
                or value.get("job_state") not in JOB_STATES
                or not isinstance(value.get("command_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", value["command_sha256"]) is None
                or type(value.get("max_runtime_seconds")) is not int or not 1 <= value["max_runtime_seconds"] <= 86400):
            return False
        JobStartParameters.directory(value["cwd"])
        if datetime.fromisoformat(value["created_at"]).utcoffset() is None:
            return False
        state, result, error = value["job_state"], value.get("result"), value.get("error")
        if result is not None and (summary or not _output(result, state)):
            return False
        if isinstance(result, dict) and "output_capture" in result:
            capture = result["output_capture"]
            if capture["source_kind"] != "job" or capture["source_id"] != value["job_id"]:
                return False
        if state == "running":
            return error is None
        if state == "succeeded":
            return error is None and (summary or isinstance(result, dict) and result.get("exit_code") == 0)
        return (isinstance(error, dict) and set(error) == {"code", "message"}
                and isinstance(error["code"], str) and 1 <= len(error["code"]) <= 128
                and isinstance(error["message"], str) and 1 <= len(error["message"]) <= 1024)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def valid_job_evidence(task, result):
    try:
        parameters = JOB_MODELS[task["action"]].model_validate(task["parameters"]).model_dump()
        owner = parameters["owner_id"]
        if not isinstance(result, dict):
            return False
        if task["action"] == "list":
            jobs = result.get("jobs")
            return (isinstance(jobs, list) and len(jobs) <= 128 and type(result.get("count")) is int
                    and result["count"] == len(jobs) and type(result.get("max_jobs")) is int
                    and result["max_jobs"] == 4 and all(valid_job_metadata(row, owner, summary=True) for row in jobs)
                    and len({row["job_id"] for row in jobs}) == len(jobs))
        if not valid_job_metadata(result, owner):
            return False
        if task["action"] == "start":
            return (result.get("started") is True and result["command_sha256"]
                    == hashlib.sha256(parameters["command"].encode("utf-8")).hexdigest()
                    and result["max_runtime_seconds"] == parameters["max_runtime_seconds"])
        return (result["job_id"] == parameters["job_id"]
                and (task["action"] != "cancel" or result.get("cancel_requested") is True))
    except (KeyError, ValueError, TypeError):
        return False
