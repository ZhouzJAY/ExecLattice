"""An exact claim restriction for locally active original tasks, including lost ACKs."""
from __future__ import annotations


def report_isolation_capability():
    return {"version": 1, "active_task_ids": True}


def valid_report_isolation(value):
    return (type(value) is dict and set(value) == set(report_isolation_capability())
            and type(value.get("version")) is int and type(value.get("active_task_ids")) is bool
            and value == report_isolation_capability())


def supports_report_isolation(capabilities):
    commands = [cap for cap in capabilities if cap.get("executor_type") == "command"]
    return len(commands) == 1 and valid_report_isolation(commands[0].get("worker_report_isolation"))
