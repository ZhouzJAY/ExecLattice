"""Bounded observational task notifications; never dispatch or replay work.

Waiting clients use ordinary authenticated HTTPS. The event loop sleeps while
idle; no request thread or database transaction is retained during a wait.
Notifications are process-local hints, so every wake is followed by an original
task/claim read. Durable task state remains the sole execution authority.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from uuid import uuid4


def notification_capability() -> dict:
    return {"version": 1, "wait_ms": 5000, "worker_notifications": True, "task_wait": True}


def valid_task_notifications(value) -> bool:
    return (isinstance(value, dict) and set(value) == set(notification_capability())
            and type(value.get("version")) is int and type(value.get("wait_ms")) is int
            and type(value.get("worker_notifications")) is bool and type(value.get("task_wait")) is bool
            and value == notification_capability())


def worker_action_notification_capability() -> dict:
    """Opt in to actionable Worker hints without changing legacy observers."""
    return {"version": 1, "wait_ms": 5000, "worker_notifications": True}


def valid_worker_action_notifications(value) -> bool:
    return (isinstance(value, dict) and set(value) == set(worker_action_notification_capability())
            and type(value.get("version")) is int and type(value.get("wait_ms")) is int
            and type(value.get("worker_notifications")) is bool
            and value == worker_action_notification_capability())


def supports_worker_action_notifications(capabilities: list[dict]) -> bool:
    commands = [cap for cap in capabilities if cap.get("executor_type") == "command"]
    return len(commands) == 1 and valid_worker_action_notifications(commands[0].get("worker_action_notifications"))


def worker_poll_capability() -> dict:
    """One authenticated heartbeat plus at most one original claim per request."""
    return {"version": 1, "claim": True}


def valid_worker_poll(value) -> bool:
    return (isinstance(value, dict) and set(value) == {"version", "claim"}
            and type(value.get("version")) is int and type(value.get("claim")) is bool
            and value == worker_poll_capability())


def supports_task_notifications(capabilities: list[dict]) -> bool:
    commands = [cap for cap in capabilities if cap.get("executor_type") == "command"]
    return len(commands) == 1 and valid_task_notifications(commands[0].get("task_notifications"))


class NotificationLimit(Exception):
    pass


class TaskNotifications:
    """At most 128 asynchronous waits, with no unbounded device/task history."""

    def __init__(self):
        self._lock = threading.RLock()
        self._epoch = uuid4().hex
        self._sequence = 0
        self._versions = OrderedDict()
        self._waiters = {}
        self._closed = False

    def cursor(self, key: str) -> str:
        with self._lock:
            # Register observed keys before any publication. Otherwise an
            # unrelated task update changes the global fallback sequence and
            # spuriously wakes a Worker whose actionable key has never fired.
            # Re-registering an evicted key gets a fresh sequence: eviction
            # remains a harmless extra wake, never a reused/missed cursor.
            if key not in self._versions:
                self._sequence += 1
                self._versions[key] = self._sequence
                self._trim_versions()
            return f"{self._epoch}.{self._versions[key]}"

    def _trim_versions(self):
        while len(self._versions) > 1024:
            self._versions.popitem(last=False)

    def publish(self, keys) -> None:
        callbacks = []
        with self._lock:
            self._sequence += 1
            for key in keys:
                self._versions[key] = self._sequence
                self._versions.move_to_end(key)
                callbacks.extend((value[1], value[2]) for value in self._waiters.values() if value[0] == key)
            self._trim_versions()
        for loop, event in callbacks:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                # A cancelled/disconnected event loop owns no task execution.
                pass

    async def wait(self, key: str, after: str, seconds: float, disconnected=None, *, per_key=8,
                   capacity_group=None) -> str:
        if capacity_group not in (None, "worker_dispatch"):
            raise ValueError("Invalid notification wait capacity group")
        loop, event, marker = asyncio.get_running_loop(), asyncio.Event(), object()
        with self._lock:
            if self._closed or self.cursor(key) != after:
                return self.cursor(key)
            # The Worker's passive action watcher and its idle dispatch poll
            # observe the same publication key, but each owns one bounded
            # admission slot. A second wait of either kind remains rejected.
            if (len(self._waiters) >= 128
                    or sum(value[0] == key and value[3] == capacity_group for value in self._waiters.values()) >= per_key):
                raise NotificationLimit
            self._waiters[marker] = (key, loop, event, capacity_group)
        deadline = time.monotonic() + min(5.0, max(0.0, seconds))
        try:
            while not event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or disconnected is not None and await disconnected():
                    break
                try:
                    await asyncio.wait_for(event.wait(), min(.25, remaining))
                except TimeoutError:
                    pass
            return self.cursor(key)
        finally:
            with self._lock:
                self._waiters.pop(marker, None)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            keys = {value[0] for value in self._waiters.values()}
        self.publish(keys)
