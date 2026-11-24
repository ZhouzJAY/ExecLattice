"""Fixed, negotiated task scheduling shared by Controller and Worker.

These lanes isolate blocking tool operations, not filesystem or process access.
The legacy lane remains a barrier so older fixed-command workflows retain their
serial execution semantics. No task-supplied lane or concurrency hint is used.
"""

from __future__ import annotations

_V1_LANES = ("development", "files", "computer", "terminal_read", "terminal_control", "legacy")
_V2_LANES = (*_V1_LANES[:-1], "services", "legacy")
TASK_LANES = (*_V2_LANES[:-1], "browser", "legacy")
MAX_ACTIVE_TASKS = len(TASK_LANES)


def task_lane(task: dict) -> str:
    executor = task.get("executor_type")
    if executor == "development":
        return "development"
    if executor in {"workspace", "transfer"}:
        return "files"
    if executor == "computer":
        return "computer"
    if executor == "browser":
        return "browser"
    if executor in {"localhost", "job"}:
        return "services"
    if executor == "terminal":
        return "terminal_read" if task.get("action") == "read" else "terminal_control"
    return "legacy"


def concurrency_capability() -> dict:
    """Offer the current classifier; exact older descriptors remain valid."""
    return {"version": 3, "max_active": MAX_ACTIVE_TASKS, "lanes": list(TASK_LANES)}


def valid_task_concurrency(value) -> bool:
    # bool is an int subclass; equality alone would accept True as version 1.
    return (isinstance(value, dict) and set(value) == {"version", "max_active", "lanes"}
            and type(value.get("version")) is int and type(value.get("max_active")) is int
            and value in (concurrency_capability(), {"version": 2, "max_active": len(_V2_LANES),
                                                    "lanes": list(_V2_LANES)},
                          {"version": 1, "max_active": len(_V1_LANES), "lanes": list(_V1_LANES)}))


def supports_task_concurrency(capabilities: list[dict]) -> bool:
    commands = [cap for cap in capabilities if cap.get("executor_type") == "command"]
    return len(commands) == 1 and valid_task_concurrency(commands[0].get("task_concurrency"))


def negotiated_task_capacity(capabilities: list[dict]) -> int:
    """Use only an exact supported descriptor; malformed or absent means serial."""
    if not supports_task_concurrency(capabilities):
        return 1
    return next(cap["task_concurrency"]["max_active"] for cap in capabilities if cap.get("executor_type") == "command")
