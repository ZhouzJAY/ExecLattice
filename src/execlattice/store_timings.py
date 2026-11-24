"""Bounded, in-memory timings; never SQL, identity, path or exception text."""
from __future__ import annotations

import threading
import time
from collections import deque

_KINDS = frozenset({"read_transaction", "write_transaction"})
_PHASES = frozenset({"lock_wait", "connect", "begin", "body", "commit", "rollback", "close", "notification"})
_LIMIT = 64


class _NullSpan:
    def phase(self, name):
        pass

    def finish(self, error=None):
        pass


_NULL = _NullSpan()


class _Span:
    def __init__(self, owner, kind):
        self.owner, self.kind = owner, kind
        self.started = self.checkpoint = owner._clock()
        self.current = "lock_wait"
        self.phases = {}
        self.finished = False
        self.enabled = True

    def phase(self, name):
        try:
            if not self.enabled or self.finished:
                return
            if name not in _PHASES:
                self.enabled = False
                return
            now = self.owner._clock()
            self.phases[self.current] = self.phases.get(self.current, 0) + max(0, now - self.checkpoint)
            self.current, self.checkpoint = name, now
        except Exception:
            self.enabled = False

    def finish(self, error=None):
        try:
            if not self.enabled or self.finished:
                return
            self.finished = True
            now = self.owner._clock()
            self.phases[self.current] = self.phases.get(self.current, 0) + max(0, now - self.checkpoint)
            outcome = "ok" if error is None else "error"
            if error is not None and getattr(error, "code", None) == "controller_storage_busy":
                outcome = "storage_busy"
            code = getattr(error, "sqlite_errorcode", None) if error is not None else None
            code = code if type(code) is int and 0 <= code < 2**32 else None
            self.owner._record({"kind": self.kind, "outcome": outcome, "sqlite_errorcode": code,
                                "elapsed_ns": max(0, now - self.started), "phases_ns": self.phases})
        except Exception:
            # Instrumentation must never replace a database/notification outcome.
            self.enabled = False


class StorageTimings:
    def __init__(self, *, clock=time.monotonic_ns):
        self._clock = clock
        self._lock = threading.Lock()
        self._recent = deque(maxlen=_LIMIT)
        self._summary = {}

    def start(self, kind):
        try:
            if kind not in _KINDS:
                return _NULL
            return _Span(self, kind)
        except Exception:
            return _NULL

    def _record(self, record):
        with self._lock:
            total = self._summary.setdefault(record["kind"], {"count": 0, "ok": 0, "error": 0,
                "storage_busy": 0, "total_ns": 0, "max_ns": 0, "phases": {}})
            total["count"] += 1
            total[record["outcome"]] += 1
            total["total_ns"] += record["elapsed_ns"]
            total["max_ns"] = max(total["max_ns"], record["elapsed_ns"])
            for name, duration in record["phases_ns"].items():
                phase = total["phases"].setdefault(name, {"count": 0, "total_ns": 0, "max_ns": 0})
                phase["count"] += 1
                phase["total_ns"] += duration
                phase["max_ns"] = max(phase["max_ns"], duration)
            self._recent.append(record)

    def snapshot(self):
        # No Store lock, database, file operation or caller-supplied string here.
        with self._lock:
            summary = {kind: {**value, "phases": {k: dict(v) for k, v in value["phases"].items()}}
                       for kind, value in self._summary.items()}
            recent = [{**value, "phases_ns": dict(value["phases_ns"])} for value in self._recent]
        return {"format": 1, "scope": "completed_store_transactions", "persistent": False,
                "includes_in_flight": False, "sample_limit": _LIMIT,
                "limitations": ["Nested outer Store lock acquisition and post-transaction work are not timed.",
                                "Counts are Store transactions, not RPCs, tasks or effects.",
                                "Administrative authentication may itself return storage busy."],
                "summary": summary, "recent": recent}
