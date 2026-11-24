"""Request-local diagnostic durations, never authorization or persistent state."""
from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

_CURRENT = ContextVar("execlattice_request_timings", default=None)
_NAMES = frozenset({"history", "controller_http", "controller_prepare"})


class RequestTimings:
    def __init__(self):
        self.started = time.perf_counter_ns()
        self.rows = {}

    def header(self):
        rows = [("mother", (time.perf_counter_ns() - self.started) / 1_000_000, 1)]
        rows += [(name, value[0] / 1_000_000, value[1]) for name, value in sorted(self.rows.items())]
        return ", ".join(f'{name};dur={elapsed:.3f};desc="n={count}"' for name, elapsed, count in rows)


@contextmanager
def collect_timings(timings):
    token = _CURRENT.set(timings)
    try:
        yield
    finally:
        _CURRENT.reset(token)


@contextmanager
def _stage(name):
    timings = _CURRENT.get()
    if timings is None:
        yield
        return
    started = time.perf_counter_ns()
    try:
        yield
    finally:
        previous, count = timings.rows.get(name, (0, 0))
        timings.rows[name] = previous + time.perf_counter_ns() - started, count + 1


def timed_function(name):
    if name not in _NAMES:
        raise ValueError("Unknown timing stage")

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if _CURRENT.get() is None:
                return function(*args, **kwargs)
            with _stage(name):
                return function(*args, **kwargs)
        return wrapped
    return decorate


def timed_context(name):
    if name not in _NAMES:
        raise ValueError("Unknown timing stage")

    def decorate(function):
        @contextmanager
        @wraps(function)
        def wrapped(*args, **kwargs):
            with _stage(name), function(*args, **kwargs) as value:
                yield value
        return wrapped
    return decorate
