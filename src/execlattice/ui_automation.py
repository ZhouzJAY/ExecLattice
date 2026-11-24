"""Bounded, explicitly requested Windows UI Automation observations and actions.

This token manager supports an injected typed UIA backend. Production computer
tasks use the isolated pywinauto helper in software_automation; the built-in COM
adapter remains available for compatibility and focused native tests. Creating
this object does not initialize COM or observe a window. Values and password
names are never queried. The compatibility adapter checks its traversal deadline
between provider calls; production additionally has a parent-side hard cutoff.

COM ABI: Microsoft's Windows SDK UIAutomationClient.h, IUIAutomation2,
IUIAutomationElement, IUIAutomationTreeWalker and the standard control patterns.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import threading
import time
from collections import OrderedDict
from ctypes import wintypes as wt
from uuid import UUID, uuid4

MAX_NODES = 256
MAX_DEPTH = 12
MAX_TIMEOUT_MS = 5000
MAX_TOKEN_AGE = 30
MAX_VALUE_BYTES = 8192
MAX_TREE_BYTES = 240000
_MAX_TOKENS = 1024
_ACTIONS = {"invoke", "focus", "set_value", "toggle", "select", "expand", "collapse", "scroll_into_view"}
# Microsoft win32metadata's generated UIAutomationClient.h. Each entry uses
# GetCurrentPatternAs, never a cast of an unverified IUnknown interface.
_PATTERNS = {
    "invoke": (10000, "fb377fbe-8ea6-46d5-9c73-6499642d3059"),
    "set_value": (10002, "a94cd8b1-0844-4cd6-9d2d-640537ab39e9"),
    "expand": (10005, "619be086-1f4e-4ee4-bafa-210128738730"),
    "collapse": (10005, "619be086-1f4e-4ee4-bafa-210128738730"),
    "select": (10010, "a8efa66a-0fda-421a-9194-38021f3578ea"),
    "toggle": (10015, "94cf8058-9b8d-4ab9-8bfd-4cd0a33c8c70"),
    "scroll_into_view": (10017, "b488300f-d015-4f19-9c29-bb595e3645ef"),
}
_CHECKED_STATES = ("off", "on", "indeterminate")
_EXPANDED_STATES = ("collapsed", "expanded", "partially_expanded", "leaf")
_OBSERVATION_FOCUS_KEYS = {"foreground", "focused_runtime_id"}


class AutomationError(Exception):
    def __init__(self, code, message, *, state="failed"):
        self.code, self.message, self.state = code, message, state
        super().__init__(message)


def _text(value, limit=256):
    return "".join(c for c in value if (ord(c) >= 32 or c in "\t\n")
                   and not 0xD800 <= ord(c) <= 0xDFFF)[:limit]


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _valid_observation_focus(context):
    return (type(context) is dict and _OBSERVATION_FOCUS_KEYS <= context.keys()
            and _integer(context["foreground"], 0, 2 ** 64 - 1)
            and type(context["focused_runtime_id"]) is tuple
            and len(context["focused_runtime_id"]) <= 64
            and all(_integer(value, -(2 ** 31), 2 ** 31 - 1)
                    for value in context["focused_runtime_id"]))


def _observation_target_context(context):
    # Only these two global focus fields may move between pure reads. Every
    # target property, including any future context field, remains pinned.
    return {key: value for key, value in context.items() if key not in _OBSERVATION_FOCUS_KEYS}


def _focus_only_observation_change(before, after):
    return (_valid_observation_focus(before) and _valid_observation_focus(after)
            and before.keys() == after.keys() and before != after
            and _observation_target_context(before) == _observation_target_context(after))


def _check(deadline, cancel, clock=time.monotonic):
    if cancel is not None and cancel.is_set():
        raise AutomationError("CANCELLED", "Control observation was cancelled", state="cancelled")
    if clock() >= deadline:
        raise AutomationError("UIA_TIMEOUT", "Control observation reached its time limit")


def _fingerprint(node):
    return tuple(node[key] if key != "bounds" else tuple(node[key].values()) for key in (
        "runtime_id", "pid", "control_type", "name", "automation_id", "enabled", "password",
        "offscreen", "keyboard_focusable", "has_keyboard_focus", "bounds", "actions")) + (
            tuple(sorted(node.get("pattern_state", {}).items())),)


def _public_node(node, index, parent, depth, token):
    states = node.get("pattern_state", {})
    return {"index": index, "parent": parent, "depth": depth,
            **{key: node[key] for key in ("pid", "control_type", "name", "automation_id", "enabled",
                                         "password", "offscreen", "keyboard_focusable", "bounds")},
            "actions": list(node["actions"]), "control_token": token,
            "pattern_states": {
                **({"checked": _CHECKED_STATES[states["toggle"]]} if "toggle" in states else {}),
                **({"selected": bool(states["selected"])} if "selected" in states else {}),
                **({"expanded": _EXPANDED_STATES[states["expanded"]]} if "expanded" in states else {}),
            }}


class UIAutomation:
    """Volatile owner-bound receipts; COM pointers never survive a request.

    inspect(hwnd, window_id=..., owner_id=...) returns flat preorder nodes with
    parent indexes. Tokens identify an observed control, not a selector. Any
    action consumes all observations for that owner/window, even on failure.
    An external policy must additionally reject writes in read-only mode.
    """

    def __init__(self, *, backend_factory=None, clock=time.monotonic, waiter=None):
        self._backend_factory = backend_factory or _NativeBackend
        self._clock = clock
        self._waiter = waiter or (lambda seconds, cancel: cancel.wait(seconds) if cancel else time.sleep(seconds))
        self._tokens = OrderedDict()
        self._lock = threading.RLock()

    def clear(self, owner_id=None):
        with self._lock:
            for token in list(self._tokens):
                if owner_id is None or self._tokens[token]["owner_id"] == owner_id:
                    self._tokens.pop(token)

    def _prune(self):
        now = self._clock()
        for token in list(self._tokens):
            if now - self._tokens[token]["created"] > MAX_TOKEN_AGE:
                self._tokens.pop(token)
        while len(self._tokens) > _MAX_TOKENS:
            self._tokens.popitem(last=False)

    @staticmethod
    def _owner(owner_id):
        if not isinstance(owner_id, str) or not 1 <= len(owner_id) <= 128:
            raise AutomationError("INVALID_PARAMETERS", "A current connection owner is required")

    def inspect(self, hwnd, *, window_id, owner_id, max_nodes=128, max_depth=6,
                timeout_ms=2500, cancel=None, expected_identity=None):
        self._owner(owner_id)
        if (not _integer(hwnd, 1, 2 ** 64 - 1) or not isinstance(window_id, str)
                or window_id != hex(hwnd) or not _integer(max_nodes, 1, MAX_NODES)
                or not _integer(max_depth, 0, MAX_DEPTH)
                or not _integer(timeout_ms, 100, MAX_TIMEOUT_MS)):
            raise AutomationError("INVALID_PARAMETERS", "Invalid bounded control-tree parameters")
        started = self._clock()
        deadline = started + timeout_ms / 1000
        target_context = None
        for attempt in range(2):
            _check(deadline, cancel, self._clock)
            rows, receipts, identities, truncated, reason = [], [], {}, False, None
            tree_bytes = 0
            with self._backend_factory(deadline=deadline, cancel=cancel, clock=self._clock) as native:
                before = native.context(hwnd)
                if expected_identity is not None and self._target_identity(before) != expected_identity:
                    raise AutomationError("UIA_CONTEXT_CHANGED", "The observed window process or session changed")
                current_target = _observation_target_context(before)
                if attempt == 0:
                    target_context = current_target
                elif current_target != target_context or not _valid_observation_focus(before):
                    raise AutomationError("UIA_CONTEXT_CHANGED", "The observed window context changed between reads")
                with contextlib.closing(native.walk(hwnd, max_depth=max_depth)) as walk:
                    try:
                        for node, element, parent, depth in walk:
                            _check(deadline, cancel, self._clock)
                            if len(rows) >= max_nodes:
                                truncated, reason = True, "node_limit"
                                break
                            if depth == max_depth:
                                truncated, reason = True, "depth_limit"
                            # An identityless element can still be completely
                            # observed. Never synthesize an action identity from
                            # its name, index, parent or HWND; real child IDs remain
                            # independently revalidated in the bound window.
                            if not node["runtime_id"]:
                                node = {**node, "actions": (), "pattern_state": {}}
                            pid = node["pid"]
                            if pid not in identities:
                                identities[pid] = native.process_identity(pid)
                            if identities[pid][1] != before["session"]:
                                raise AutomationError("SESSION_UNAVAILABLE", "Control belongs to another Windows session")
                            # A successful empty focused ID is observable, but it
                            # cannot prove stable focus across requests. Keep this
                            # snapshot readable without issuing mutation receipts.
                            token = (uuid4().hex if node["actions"] and not node["password"]
                                     and before["focused_runtime_id"] else None)
                            public = _public_node(node, len(rows), parent, depth, token)
                            row_bytes = len(json.dumps(public, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                            if tree_bytes + row_bytes + 1 > MAX_TREE_BYTES:
                                truncated, reason = True, "byte_limit"
                                break
                            tree_bytes += row_bytes + 1
                            rows.append(public)
                            if token:
                                receipts.append((token, {"owner_id": owner_id, "window_id": window_id,
                                    "hwnd": hwnd, "created": self._clock(), "context": before,
                                    "fingerprint": _fingerprint(node), "runtime_id": node["runtime_id"],
                                    "pid": pid, "process_identity": identities[pid],
                                    "actions": tuple(node["actions"]), "max_depth": max_depth}))
                    except AutomationError as exc:
                        if exc.code != "UIA_TIMEOUT":
                            raise
                        truncated, reason = True, "time_limit"
                if (expected_identity is not None
                        and self._current_target_identity(native, hwnd) != expected_identity):
                    raise AutomationError("UIA_CONTEXT_CHANGED", "The observed window process or session changed")
                # No token is valid without the final complete identity/focus
                # check. A single focus-only drift may discard this entire read
                # and take a fresh one within the ORIGINAL deadline. This never
                # retries provider failures, target changes or any action.
                if reason == "time_limit":
                    receipts = []
                    for row in rows:
                        row["control_token"] = None
                else:
                    after = native.context(hwnd)
                    if after != before:
                        if attempt == 0 and _focus_only_observation_change(before, after):
                            continue
                        raise AutomationError("UIA_CONTEXT_CHANGED", "Window or focus changed; observe controls again")
            break
        with self._lock:
            for token in list(self._tokens):
                old = self._tokens[token]
                if old["owner_id"] == owner_id and old["hwnd"] == hwnd:
                    self._tokens.pop(token)
            self._tokens.update(receipts)
            self._prune()
        return {"kind": "ui_tree", "window_id": window_id, "nodes": rows,
                "node_count": len(rows), "truncated": truncated, "limit_reason": reason,
                "elapsed_ms": max(0, round((self._clock() - started) * 1000)),
                "token_max_age_seconds": MAX_TOKEN_AGE, "values_included": False}

    @staticmethod
    def _target_identity(context):
        # Focus, placement and selection may change as the requested action's
        # result. A reused HWND/PID, another session or desktop is never a match.
        return tuple(context[key] for key in ("pid", "created", "session", "desktop"))

    @classmethod
    def _current_target_identity(cls, native, hwnd):
        # The native identity check uses Win32, without another UIA provider
        # transaction. It remains usable after a traversal hit its deadline.
        getter = getattr(native, "target_identity", native.context)
        return cls._target_identity(getter(hwnd))

    def _observation_identity(self, hwnd, *, cancel, timeout_ms):
        deadline = self._clock() + timeout_ms / 1000
        _check(deadline, cancel, self._clock)
        with self._backend_factory(deadline=deadline, cancel=cancel, clock=self._clock) as native:
            return self._current_target_identity(native, hwnd)

    def perform_and_observe(self, parameters, *, read_only=False, cancel=None):
        from .computer_protocol import validate_computer_parameters
        from .ui_observation import observe_controls

        parameters = validate_computer_parameters("ui_action_observe", parameters)
        if read_only:
            raise AutomationError("READ_ONLY", "Read-only connections cannot change software controls")
        started = self._clock()
        with self._lock:
            self._prune()
            saved = self._tokens.get(parameters["control_token"])
            if saved is None or saved["owner_id"] != parameters["owner_id"]:
                raise AutomationError("STALE_CONTROL", "Observe this control again before operating it")
            window_id = saved["window_id"]
            identity = self._target_identity(saved["context"])
        try:
            receipt = self.perform(parameters["control_token"], parameters["operation"],
                                   owner_id=parameters["owner_id"], value=parameters["value"],
                                   read_only=read_only, cancel=cancel)
            action = {"state": "submitted", "receipt": receipt, "error": None}
        except AutomationError as exc:
            if exc.code != "UIA_OPERATION_UNCONFIRMED" or exc.state != "unknown":
                raise
            action = {"state": "unknown", "receipt": None,
                      "error": {"code": exc.code, "message": exc.message}}
        # This path never calls perform again, including cancellation, timeout,
        # COM failure and an uncertain mutating call. Preserve its first receipt.
        return observe_controls(self, parameters, window_id=window_id, expected_identity=identity,
                                action=action, cancel=cancel, started=started)

    def wait_for_controls(self, parameters, *, cancel=None):
        from .computer_protocol import validate_computer_parameters
        from .ui_observation import observe_controls

        parameters = validate_computer_parameters("ui_wait", parameters)
        return observe_controls(self, parameters, window_id=parameters["window_id"],
                                expected_identity=None, action=None, cancel=cancel, started=self._clock())

    def perform(self, control_token, operation, *, owner_id, value=None, read_only=False, cancel=None):
        self._owner(owner_id)
        if read_only:
            raise AutomationError("READ_ONLY", "Read-only connections cannot change software controls")
        if (operation not in _ACTIONS or not isinstance(control_token, str) or len(control_token) != 32
                or operation == "set_value" and (not isinstance(value, str) or "\0" in value
                    or len(value.encode("utf-8")) > MAX_VALUE_BYTES)
                or operation != "set_value" and value is not None):
            raise AutomationError("INVALID_PARAMETERS", "Invalid control action")
        with self._lock:
            self._prune()
            saved = self._tokens.get(control_token)
            if saved is None or saved["owner_id"] != owner_id:
                raise AutomationError("STALE_CONTROL", "Observe this control again before operating it")
            for token in list(self._tokens):
                old = self._tokens[token]
                if old["owner_id"] == owner_id and old["hwnd"] == saved["hwnd"]:
                    self._tokens.pop(token)
        if operation not in saved["actions"]:
            raise AutomationError("UIA_UNSUPPORTED", "The observed control does not support this operation")
        deadline = self._clock() + MAX_TIMEOUT_MS / 1000
        _check(deadline, cancel, self._clock)
        attempted = False
        try:
            with self._backend_factory(deadline=deadline, cancel=cancel, clock=self._clock) as native:
                before = native.context(saved["hwnd"])
                if before != saved["context"] or before["foreground"] != saved["hwnd"]:
                    raise AutomationError("UIA_CONTEXT_CHANGED", "Window or focus changed; observe controls again")
                if native.process_identity(saved["pid"]) != saved["process_identity"]:
                    raise AutomationError("STALE_CONTROL", "The observed control process changed")
                finder = getattr(native, "find_control", None)
                if callable(finder):
                    found = finder(saved["hwnd"], runtime_id=saved["runtime_id"],
                                   max_depth=saved["max_depth"], max_nodes=MAX_NODES)
                    candidates = contextlib.nullcontext(() if found is None else (found,))
                else:
                    candidates = contextlib.closing(native.walk(saved["hwnd"], max_depth=saved["max_depth"]))
                with candidates as walk:
                    for count, (node, element, parent, depth) in enumerate(walk):
                        _check(deadline, cancel, self._clock)
                        if count >= MAX_NODES:
                            break
                        if node["runtime_id"] != saved["runtime_id"]:
                            continue
                        if (node["password"] or node["offscreen"] and operation != "scroll_into_view"
                                or not node["enabled"]
                                or _fingerprint(node) != saved["fingerprint"]):
                            raise AutomationError("STALE_CONTROL", "Control changed; observe controls again")
                        if native.context(saved["hwnd"]) != before:
                            raise AutomationError("UIA_CONTEXT_CHANGED", "Window or focus changed before operation")
                        _check(deadline, cancel, self._clock)
                        attempted = True
                        native.perform(element, operation, value)
                        return {"kind": "ui_action", "window_id": saved["window_id"],
                                "control_token": control_token,
                                "operation": operation, "submitted": True, "effect_verified": False,
                                "observation_consumed": True}
                raise AutomationError("STALE_CONTROL", "Observed control is no longer in this window")
        except Exception as exc:
            if attempted:
                raise AutomationError("UIA_OPERATION_UNCONFIRMED",
                                      "Control operation may have occurred; inspect before retrying",
                                      state="unknown") from None
            if isinstance(exc, AutomationError):
                raise
            raise AutomationError("UIA_UNAVAILABLE", "Windows control provider is unavailable") from None


def valid_ui_tree(result):
    try:
        return _valid_ui_tree(result)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _valid_ui_tree(result):
    if (not isinstance(result, dict) or set(result) != {
            "kind", "window_id", "nodes", "node_count", "truncated", "limit_reason", "elapsed_ms",
            "token_max_age_seconds", "values_included"} or result["kind"] != "ui_tree"
            or result["values_included"] is not False or type(result["truncated"]) is not bool
            or result["limit_reason"] not in {None, "node_limit", "depth_limit", "time_limit", "byte_limit"}
            or not isinstance(result["window_id"], str) or not result["window_id"].startswith("0x")
            or not _integer(result["node_count"], 0, MAX_NODES)
            or not isinstance(result["nodes"], list) or len(result["nodes"]) != result["node_count"]
            or not _integer(result["elapsed_ms"], 0, 60000)
            or result["token_max_age_seconds"] != MAX_TOKEN_AGE):
        return False
    fields = {"index", "parent", "depth", "pid", "control_type", "name", "automation_id", "enabled",
              "password", "offscreen", "keyboard_focusable", "bounds", "actions", "control_token"}
    for index, node in enumerate(result["nodes"]):
        if (not isinstance(node, dict) or set(node) not in (fields, fields | {"pattern_states"})
                or node["index"] != index
                or not (node["parent"] is None if index == 0 else _integer(node["parent"], 0, index - 1))
                or not _integer(node["depth"], 0, MAX_DEPTH) or not _integer(node["pid"], 1, 2 ** 32 - 1)
                or not _integer(node["control_type"], 50000, 59999)
                or any(type(node[key]) is not bool for key in ("enabled", "password", "offscreen", "keyboard_focusable"))
                or any(not isinstance(node[key], str) or len(node[key]) > 256 for key in ("name", "automation_id"))
                or not isinstance(node["actions"], list) or len(node["actions"]) != len(set(node["actions"]))
                or any(action not in _ACTIONS for action in node["actions"])
                or not isinstance(node["bounds"], dict) or set(node["bounds"]) != {"left", "top", "width", "height"}
                or any(not _integer(v, -131072, 131072) for v in node["bounds"].values())
                or node["bounds"]["width"] < 0 or node["bounds"]["height"] < 0
                or node["control_token"] is not None and (not isinstance(node["control_token"], str)
                    or len(node["control_token"]) != 32 or any(c not in "0123456789abcdef" for c in node["control_token"]))
                or node["password"] and (node["name"] or node["automation_id"] or node["actions"] or node["control_token"])):
            return False
        states = node.get("pattern_states", {})
        if (not isinstance(states, dict) or not set(states) <= {"checked", "selected", "expanded"}
                or "checked" in states and states["checked"] not in _CHECKED_STATES
                or "selected" in states and type(states["selected"]) is not bool
                or "expanded" in states and states["expanded"] not in _EXPANDED_STATES
                or node["password"] and states):
            return False
    return True


def valid_ui_action(result):
    try:
        return _valid_ui_action(result)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _valid_ui_action(result):
    return (isinstance(result, dict) and set(result) == {"kind", "window_id", "control_token", "operation", "submitted",
            "effect_verified", "observation_consumed"} and result["kind"] == "ui_action"
            and isinstance(result["window_id"], str) and result["window_id"].startswith("0x")
            and isinstance(result["control_token"], str) and len(result["control_token"]) == 32
            and all(c in "0123456789abcdef" for c in result["control_token"])
            and result["operation"] in _ACTIONS and result["submitted"] is True
            and result["effect_verified"] is False and result["observation_consumed"] is True)


class _GUID(ctypes.Structure):
    _fields_ = [("data1", ctypes.c_uint32), ("data2", ctypes.c_uint16), ("data3", ctypes.c_uint16),
                ("data4", ctypes.c_ubyte * 8)]


def _guid(value):
    return _GUID.from_buffer_copy(UUID(value).bytes_le)


class _NativeBackend:
    def __init__(self, *, deadline, cancel, clock):
        self.deadline, self.cancel, self.clock = deadline, cancel, clock
        self.automation = ctypes.c_void_p()
        self.walker = ctypes.c_void_p()
        self.initialized = False
        self.dpi = None

    def __enter__(self):
        if os.name != "nt":
            raise AutomationError("UNSUPPORTED_PLATFORM", "Windows UI Automation is unavailable")
        from .computer_executor import _Win
        self.win = _Win()
        self.ole = ctypes.WinDLL("ole32")
        self.aut = ctypes.WinDLL("oleaut32")
        self.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wt.DWORD]
        self.ole.CoInitializeEx.restype = ctypes.c_long
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None
        self.ole.CoCreateInstance.argtypes = [ctypes.POINTER(_GUID), ctypes.c_void_p, wt.DWORD,
                                            ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)]
        self.ole.CoCreateInstance.restype = ctypes.c_long
        self.aut.SysStringLen.argtypes, self.aut.SysStringLen.restype = [ctypes.c_void_p], wt.UINT
        self.aut.SysFreeString.argtypes, self.aut.SysFreeString.restype = [ctypes.c_void_p], None
        for name in ("SafeArrayGetLBound", "SafeArrayGetUBound"):
            fn = getattr(self.aut, name)
            fn.argtypes, fn.restype = [ctypes.c_void_p, wt.UINT, ctypes.POINTER(ctypes.c_long)], ctypes.c_long
        self.aut.SafeArrayGetDim.argtypes, self.aut.SafeArrayGetDim.restype = [ctypes.c_void_p], wt.UINT
        self.aut.SafeArrayAccessData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self.aut.SafeArrayAccessData.restype = ctypes.c_long
        self.aut.SafeArrayUnaccessData.argtypes = [ctypes.c_void_p]
        self.aut.SafeArrayUnaccessData.restype = ctypes.c_long
        self.aut.SafeArrayDestroy.argtypes, self.aut.SafeArrayDestroy.restype = [ctypes.c_void_p], ctypes.c_long
        if self.ole.CoInitializeEx(None, 0) < 0:  # COINIT_MULTITHREADED, request thread only.
            raise AutomationError("UIA_UNAVAILABLE", "Cannot initialize the Windows control client")
        self.initialized = True
        try:
            self.dpi = self.win.physical_coordinates()
            self.dpi.__enter__()
            clsid = _guid("e22ad333-b25f-460c-83d0-0581107395c9")
            iid = _guid("34723aff-0c9d-49d0-9896-7ab52df8cd8a")
            if self.ole.CoCreateInstance(ctypes.byref(clsid), None, 1, ctypes.byref(iid),
                                         ctypes.byref(self.automation)) < 0:
                raise AutomationError("UIA_UNAVAILABLE", "Windows UI Automation is unavailable")
            self._call(self.automation, 59, [wt.BOOL], False)  # Do not implicitly move focus.
            self._call(self.automation, 61, [wt.DWORD], 250)
            self._call(self.automation, 63, [wt.DWORD], 250)
            self._call(self.automation, 14, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(self.walker))
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        self._release(self.walker)
        self._release(self.automation)
        if self.dpi:
            self.dpi.__exit__(*exc)
            self.dpi = None
        if self.initialized:
            self.ole.CoUninitialize()
            self.initialized = False

    @staticmethod
    def _method(pointer, index, args, result=ctypes.c_long):
        table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        return ctypes.WINFUNCTYPE(result, ctypes.c_void_p, *args)(table[index])

    def _call(self, pointer, index, args, *values):
        _check(self.deadline, self.cancel, self.clock)
        result = self._method(pointer, index, args)(pointer, *values)
        if result < 0:
            raise AutomationError("UIA_UNAVAILABLE", "Windows control provider did not confirm the request")

    def _release(self, pointer):
        if pointer and pointer.value:
            self._method(pointer, 2, [], wt.ULONG)(pointer)
            pointer.value = None

    def _number(self, element, index):
        out = ctypes.c_int()
        self._call(element, index, [ctypes.POINTER(ctypes.c_int)], ctypes.byref(out))
        return out.value

    def _string(self, element, index):
        out = ctypes.c_void_p()
        self._call(element, index, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(out))
        try:
            return _text(ctypes.wstring_at(out, min(self.aut.SysStringLen(out), 256))) if out else ""
        finally:
            if out:
                self.aut.SysFreeString(out)

    def _runtime_id(self, element):
        out = ctypes.c_void_p()
        self._call(element, 4, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(out))
        try:
            lo, hi = ctypes.c_long(), ctypes.c_long()
            if (not out or self.aut.SafeArrayGetDim(out) != 1
                    or self.aut.SafeArrayGetLBound(out, 1, ctypes.byref(lo)) < 0
                    or self.aut.SafeArrayGetUBound(out, 1, ctypes.byref(hi)) < 0
                    or not 1 <= hi.value - lo.value + 1 <= 64):
                raise AutomationError("UIA_UNAVAILABLE", "Control runtime identity is unavailable")
            pointer = ctypes.c_void_p()
            if self.aut.SafeArrayAccessData(out, ctypes.byref(pointer)) < 0:
                raise AutomationError("UIA_UNAVAILABLE", "Cannot inspect control runtime identity")
            try:
                ints = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int))
                return tuple(ints[i] for i in range(hi.value - lo.value + 1))
            finally:
                self.aut.SafeArrayUnaccessData(out)
        finally:
            if out:
                self.aut.SafeArrayDestroy(out)

    def process_identity(self, pid):
        if not _integer(pid, 1, 2 ** 32 - 1):
            raise AutomationError("UIA_UNAVAILABLE", "Control process identity is unavailable")
        handle = self.win.kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise AutomationError("ACCESS_DENIED", "Windows denied access to this control process")
        try:
            created, exited, kernel, user = (wt.FILETIME() for _ in range(4))
            if not self.win.kernel.GetProcessTimes(handle, *(ctypes.byref(x) for x in (created, exited, kernel, user))):
                raise AutomationError("UIA_UNAVAILABLE", "Cannot verify the control process")
            return (created.dwHighDateTime << 32) | created.dwLowDateTime, self.win.session(pid)
        finally:
            self.win.kernel.CloseHandle(handle)

    def target_identity(self, hwnd):
        session, desktop = self.win.interactive()
        pid, created = self.win.identity(hwnd)
        return {"pid": pid, "created": created, "session": session, "desktop": desktop}

    def context(self, hwnd):
        identity = self.target_identity(hwnd)
        focus = ctypes.c_void_p()
        self._call(self.automation, 8, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(focus))
        try:
            focused = self._runtime_id(focus) if focus else ()
        finally:
            self._release(focus)
        return {**identity,
                "bounds": self.win.bounds(hwnd), "foreground": self.win.root(self.win.user.GetForegroundWindow()),
                "focused_runtime_id": focused}

    def _pattern(self, element, operation, *, required=False):
        pattern_id, iid = _PATTERNS[operation]
        out, interface = ctypes.c_void_p(), _guid(iid)
        _check(self.deadline, self.cancel, self.clock)
        result = self._method(element, 14, [ctypes.c_int, ctypes.POINTER(_GUID),
                                         ctypes.POINTER(ctypes.c_void_p)])(
            element, pattern_id, ctypes.byref(interface), ctypes.byref(out))
        if result < 0:
            self._release(out)
            if required:
                raise AutomationError("UIA_UNSUPPORTED", "The control no longer supports this pattern")
        elif required and not out:
            raise AutomationError("UIA_UNSUPPORTED", "The control no longer supports this pattern")
        return out

    def _snapshot(self, element):
        password = bool(self._number(element, 35))
        enabled, offscreen = bool(self._number(element, 28)), bool(self._number(element, 38))
        focusable = bool(self._number(element, 27))
        rect = wt.RECT()
        self._call(element, 43, [ctypes.POINTER(wt.RECT)], ctypes.byref(rect))
        actions, pattern_state = [], {}
        if not password and enabled:
            if focusable and not offscreen:
                actions.append("focus")
            # An offscreen item can only be brought into view. All other
            # operations require a fresh visible observation after scrolling.
            candidates = (("scroll_into_view",) if offscreen else
                          ("invoke", "set_value", "toggle", "select", "expand", "scroll_into_view"))
            for action in candidates:
                pattern = self._pattern(element, action)
                try:
                    if not pattern:
                        continue
                    if action == "set_value" and self._number(pattern, 5):
                        continue
                    if action == "expand":
                        state = self._number(pattern, 5)
                        if state not in (0, 1, 2, 3):
                            raise AutomationError("UIA_UNAVAILABLE", "Control expansion state is unavailable")
                        pattern_state["expanded"] = state
                        if state in (0, 2):
                            actions.append("expand")
                        if state in (1, 2):
                            actions.append("collapse")
                        continue
                    if action == "toggle":
                        state = self._number(pattern, 4)
                        if state not in (0, 1, 2):
                            raise AutomationError("UIA_UNAVAILABLE", "Control toggle state is unavailable")
                        pattern_state["toggle"] = state
                    if action == "select":
                        state = self._number(pattern, 6)
                        if state not in (0, 1):
                            raise AutomationError("UIA_UNAVAILABLE", "Control selection state is unavailable")
                        pattern_state["selected"] = state
                    actions.append(action)
                finally:
                    self._release(pattern)
        bounds = {"left": rect.left, "top": rect.top, "width": rect.right - rect.left,
                  "height": rect.bottom - rect.top}
        if any(abs(v) > 131072 for v in bounds.values()) or bounds["width"] < 0 or bounds["height"] < 0:
            raise AutomationError("UIA_UNAVAILABLE", "Control bounds are unavailable")
        return {"runtime_id": self._runtime_id(element), "pid": self._number(element, 20),
                "control_type": self._number(element, 21),
                "name": "" if password else self._string(element, 23),
                "automation_id": "" if password else self._string(element, 29),
                "enabled": enabled, "password": password, "offscreen": offscreen,
                "keyboard_focusable": focusable, "has_keyboard_focus": bool(self._number(element, 26)),
                "bounds": bounds, "actions": tuple(actions), "pattern_state": pattern_state}

    def walk(self, hwnd, *, max_depth):
        root = ctypes.c_void_p()
        self._call(self.automation, 6, [wt.HWND, ctypes.POINTER(ctypes.c_void_p)], hwnd, ctypes.byref(root))
        counter = [0]

        def visit(element, parent, depth):
            _check(self.deadline, self.cancel, self.clock)
            index = counter[0]
            counter[0] += 1
            snapshot = self._snapshot(element)
            yield snapshot, element, parent, depth
            if snapshot["password"] or depth >= max_depth:
                return
            child = ctypes.c_void_p()
            self._call(self.walker, 4, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], element, ctypes.byref(child))
            try:
                while child:
                    yield from visit(child, index, depth + 1)
                    following = ctypes.c_void_p()
                    self._call(self.walker, 6, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], child,
                               ctypes.byref(following))
                    self._release(child)
                    child = following
            finally:
                self._release(child)

        try:
            yield from visit(root, None, 0)
        finally:
            self._release(root)

    def perform(self, element, operation, value):
        # Recheck closest to the mutating COM call; no pattern is requested for
        # a control which has become a password box since observation.
        if (self._number(element, 35) or not self._number(element, 28)
                or self._number(element, 38) and operation != "scroll_into_view"):
            raise AutomationError("STALE_CONTROL", "Control is no longer safe to operate")
        if operation == "focus":
            self._call(element, 3, [])
            return
        pattern = self._pattern(element, operation, required=True)
        try:
            if operation == "set_value":
                if self._number(pattern, 5):
                    raise AutomationError("STALE_CONTROL", "Control became read-only")
                self._call(pattern, 3, [wt.LPCWSTR], value)
            else:
                if operation in {"expand", "collapse"}:
                    state = self._number(pattern, 5)
                    if state not in ((0, 2) if operation == "expand" else (1, 2)):
                        raise AutomationError("STALE_CONTROL", "Control expansion state changed")
                self._call(pattern, 4 if operation == "collapse" else 3, [])
        finally:
            self._release(pattern)
