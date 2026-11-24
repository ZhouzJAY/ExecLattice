"""Ephemeral authenticated Worker identity, separate from persistent task ownership.

One run_worker invocation retains its ID across network reconnects. A new
invocation creates a new ID; it is never an execution permission or history key.
"""
from __future__ import annotations

import re
from uuid import uuid4


def valid_worker_session(value):
    return (type(value) is dict and set(value) == {"version", "instance_id"}
            and type(value["version"]) is int and value["version"] == 1
            and isinstance(value["instance_id"], str) and re.fullmatch("[a-f0-9]{32}", value["instance_id"]) is not None)


def new_worker_session():
    return {"version": 1, "instance_id": uuid4().hex}


def worker_session_id(capabilities):
    found = None
    for capability in capabilities:
        if "worker_session" not in capability:
            continue
        if capability.get("executor_type") != "command" or found is not None or not valid_worker_session(capability["worker_session"]):
            raise ValueError("Invalid Worker session")
        found = capability["worker_session"]["instance_id"]
    return found
