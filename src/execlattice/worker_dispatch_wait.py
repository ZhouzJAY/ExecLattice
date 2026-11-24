"""Exact opt-in to an idle, authenticated dispatch wait; never an execution ACK."""
from __future__ import annotations


def dispatch_wait_capability():
    return {"version": 1, "max_wait_ms": 5000, "idle_only": True}


def valid_dispatch_wait(value):
    return (type(value) is dict and set(value) == set(dispatch_wait_capability())
            and type(value.get("version")) is int and type(value.get("max_wait_ms")) is int
            and type(value.get("idle_only")) is bool and value == dispatch_wait_capability())


def supports_dispatch_wait(capabilities):
    from .worker_session import valid_worker_session

    commands = [cap for cap in capabilities if cap.get("executor_type") == "command"]
    return (len(commands) == 1 and valid_dispatch_wait(commands[0].get("worker_dispatch_wait"))
            and valid_worker_session(commands[0].get("worker_session")))
