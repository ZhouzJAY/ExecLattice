"""Transactional task state. Unconfirmed dispatches are never automatically retried."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from pathlib import Path

from .protocol import TERMINAL_STATES, new_id, utc_now, validate_transition
from .security import digest, new_secret
from .worker_identity import execution_owner_id
from .worker_session import worker_session_id

_STORE_INDEXES = (
    ("execlattice_tasks_state_device", "tasks", ("state", "device_id")),
    ("execlattice_audit_resource_seq", "audit", ("resource", "seq")),
)
_DISPATCH_GATE_SCHEMA = ("CREATE TABLE IF NOT EXISTS device_dispatch_gates "
                         "(device_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, allowed_task_id TEXT, "
                         "released INTEGER NOT NULL DEFAULT 0)")
_LAN_DATABASE_ID = 0x454C414E
_LAN_TABLES = {"credentials", "pairing", "devices", "tasks", "results",
               "recovery_evidence", "audit", "device_dispatch_gates"}
_LAN_BASE_TABLES = _LAN_TABLES - {"recovery_evidence", "device_dispatch_gates"}


class StoreError(Exception):
    def __init__(self, code: str, status: int = 409):
        self.code = code
        self.status = status
        super().__init__(code)


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        from .task_notifications import TaskNotifications

        self.notifications = TaskNotifications()
        self._transaction_changes = []
        self._worker_contacts = {}
        self._worker_fence_epoch = new_id()
        self._read_wait_seconds = 1.0  # Private read-pressure bound, never persisted policy.
        from .store_timings import StorageTimings

        self._storage_timings = StorageTimings()

    def storage_diagnostics(self):
        return self._storage_timings.snapshot()

    def begin_controller_session(self):
        """Cached database heartbeats cannot prove contact with a new server.

        Keep the existing 20 second execution lease, task records and ownership.
        Only readiness for managed Agent calls requires a heartbeat received by
        this Controller session; no task or effect is retried here.
        """
        with self.lock:
            self._worker_contacts.clear()
            self._worker_fence_epoch = new_id()

    def authenticated_worker_contacts(self):
        with self._read_guard():
            return dict(self._worker_contacts)

    @contextmanager
    def _read_guard(self):
        """A failed acquisition never grants cached authority or releases an owner."""
        deadline = time.monotonic() + self._read_wait_seconds
        if not self.lock.acquire(timeout=self._read_wait_seconds):
            raise StoreError("controller_storage_busy", 503)
        try:
            yield max(0.0, deadline - time.monotonic())
        finally:
            # RLock recursion is intentional: release only this acquisition,
            # preserving any caller's outer write/read fence.
            self.lock.release()

    @staticmethod
    def _raise_read_pressure(error):
        code = getattr(error, "sqlite_errorcode", None)
        if type(code) is int and code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise StoreError("controller_storage_busy", 503) from None

    @contextmanager
    def transaction(self):
        changed = set()
        span = self._storage_timings.start("write_transaction")
        failure = None
        try:
            with self.lock:
                span.phase("connect")
                conn = sqlite3.connect(self.path, timeout=10)
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute("PRAGMA foreign_keys=ON")
                    span.phase("begin")
                    conn.execute("BEGIN IMMEDIATE")
                    self._transaction_changes.append(changed)
                    span.phase("body")
                    yield conn
                    span.phase("commit")
                    conn.commit()
                except BaseException:
                    span.phase("rollback")
                    conn.rollback()
                    raise
                finally:
                    if self._transaction_changes and self._transaction_changes[-1] is changed:
                        self._transaction_changes.pop()
                    span.phase("close")
                    conn.close()
            # Publish only committed task changes, after releasing the DB lock.
            # Heartbeat/auth/GET transactions do not wake an otherwise idle Worker.
            span.phase("notification")
            if changed:
                self.notifications.publish(changed)
        except BaseException as error:
            failure = error
            raise
        finally:
            span.finish(failure)

    @contextmanager
    def _read_transaction(self):
        """Read one committed snapshot without reserving SQLite's writer lock.

        Local Store calls retain their ordering. query_only also makes an
        accidental write fail rather than silently turning a read into a
        deferred write transaction. State changes still use transaction().
        """
        span = self._storage_timings.start("read_transaction")
        failure = None
        try:
            with self._read_guard() as remaining:
                span.phase("connect")
                try:
                    conn = sqlite3.connect(self.path, timeout=remaining)
                except sqlite3.Error as error:
                    self._raise_read_pressure(error)
                    raise
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute("PRAGMA query_only=ON")
                    span.phase("begin")
                    conn.execute("BEGIN")
                    span.phase("body")
                    yield conn
                    span.phase("commit")
                    conn.commit()
                except sqlite3.Error as error:
                    span.phase("rollback")
                    conn.rollback()
                    self._raise_read_pressure(error)
                    raise
                except BaseException:
                    span.phase("rollback")
                    conn.rollback()
                    raise
                finally:
                    span.phase("close")
                    conn.close()
        except BaseException as error:
            failure = error
            raise
        finally:
            span.finish(failure)

    def _task_changed(self, device_id: str, task_id: str, *, worker_action: bool = False) -> None:
        self._transaction_changes[-1].update(("device:" + device_id, "task:" + task_id))
        if worker_action:
            self._transaction_changes[-1].add("worker:" + device_id)

    def initialize(self, admin_token: str, agent_token: str) -> None:
        if self.path.exists():
            raise ValueError("Controller database already exists")
        with self.transaction() as db:
            statements = [
                "CREATE TABLE credentials (hash TEXT PRIMARY KEY, role TEXT, identity TEXT, revoked INTEGER DEFAULT 0)",
                "CREATE TABLE pairing (hash TEXT PRIMARY KEY, device_id TEXT, expires REAL, used INTEGER DEFAULT 0)",
                "CREATE TABLE devices (id TEXT PRIMARY KEY, document TEXT, last_seen REAL, revoked INTEGER DEFAULT 0)",
                "CREATE TABLE tasks (id TEXT PRIMARY KEY, device_id TEXT, state TEXT, document TEXT, "
                "principal TEXT, idem_key TEXT, request_hash TEXT, deadline REAL, report_hash TEXT, "
                "UNIQUE(principal, idem_key))",
                "CREATE TABLE results (task_id TEXT PRIMARY KEY REFERENCES tasks(id), document TEXT)",
                "CREATE TABLE recovery_evidence (task_id TEXT PRIMARY KEY REFERENCES tasks(id), "
                "report_hash TEXT NOT NULL, document TEXT NOT NULL)",
                "CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, actor TEXT, event TEXT, "
                "resource TEXT, detail TEXT)",
                _DISPATCH_GATE_SCHEMA,
            ]
            for statement in statements:
                db.execute(statement)
            db.execute(f"PRAGMA application_id = {_LAN_DATABASE_ID}")
            self._create_indexes(db)
            db.execute(
                "INSERT INTO credentials(hash,role,identity) VALUES(?,?,?)",
                (digest(admin_token), "admin", "local-admin"),
            )
            db.execute(
                "INSERT INTO credentials(hash,role,identity) VALUES(?,?,?)",
                (digest(agent_token), "agent", "local-agent"),
            )
            self._audit(db, "local-admin", "controller_initialized", "controller")

    @staticmethod
    def _missing_indexes(db) -> list[tuple]:
        missing = []
        for name, table, columns in _STORE_INDEXES:
            row = db.execute("SELECT type,tbl_name FROM sqlite_master WHERE name=?", (name,)).fetchone()
            if row is None:
                missing.append((name, table, columns))
                continue
            if tuple(row) != ("index", table):
                raise ValueError("Controller index definition is incompatible: " + name)
            # Only the declared, non-partial BINARY ascending index satisfies
            # this schema. A colliding name must not silently hide corruption.
            index = next((row for row in db.execute(f"PRAGMA index_list('{table}')") if row[1] == name), None)
            keys = [tuple(row) for row in db.execute(f"PRAGMA index_xinfo('{name}')") if row[5]]
            if (index is None or index[2] or index[4] or tuple(row[2] for row in keys) != columns
                    or any(row[1] < 0 or row[3] or row[4] != "BINARY" for row in keys)):
                raise ValueError("Controller index definition is incompatible: " + name)
        return missing

    @classmethod
    def _create_indexes(cls, db) -> None:
        # Every identifier comes from this module's fixed schema, never input.
        for name, table, columns in cls._missing_indexes(db):
            db.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({','.join(columns)})")

    def migrate(self) -> None:
        """Add recovery storage and queue indexes without rewriting task records."""
        if not self.path.is_file():
            raise ValueError("Controller database does not exist")
        with self.lock:
            with closing(sqlite3.connect(self.path, timeout=10)) as source:
                database_id = source.execute("PRAGMA application_id").fetchone()[0]
                tables = {row[0] for row in source.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'"
                )}
                if database_id not in (0, _LAN_DATABASE_ID) or not _LAN_BASE_TABLES <= tables <= _LAN_TABLES:
                    raise ValueError("Initialize a new controller directory for the LAN preview.")
                recovery_exists = "recovery_evidence" in tables
                if database_id == _LAN_DATABASE_ID and tables == _LAN_TABLES and not self._missing_indexes(source):
                    return
                # SQLite's backup API includes a consistent committed snapshot, including
                # WAL pages. The parent is the owner's protected Controller state directory.
                # Never overwrite a previous backup or follow a pre-created destination link.
                if not recovery_exists:
                    backup_path = self.path.with_name(self.path.stem + ".pre-m2.sqlite3")
                    try:
                        descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    except FileExistsError:
                        if (
                            backup_path.is_symlink()
                            or getattr(backup_path.lstat(), "st_file_attributes", 0) & 0x400
                            or not backup_path.is_file()
                        ):
                            raise ValueError("Pre-M2 backup must be a regular database file") from None
                        try:
                            uri = backup_path.absolute().as_uri() + "?mode=ro"
                            with closing(sqlite3.connect(uri, uri=True)) as backup:
                                valid = backup.execute("PRAGMA quick_check").fetchone() == ("ok",)
                                tables = {r[0] for r in backup.execute("SELECT name FROM sqlite_master")}
                                if not valid or not {"tasks", "credentials", "devices"} <= tables:
                                    raise ValueError("Existing pre-M2 backup is incomplete; migration stopped")
                        except sqlite3.DatabaseError:
                            raise ValueError("Existing pre-M2 backup is incomplete; migration stopped") from None
                    else:
                        os.close(descriptor)
                        with closing(sqlite3.connect(backup_path)) as backup:
                            source.backup(backup)
                            if backup.execute("PRAGMA quick_check").fetchone() != ("ok",):
                                raise ValueError("Pre-M2 backup integrity check failed")
            with self.transaction() as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS recovery_evidence "
                    "(task_id TEXT PRIMARY KEY REFERENCES tasks(id), report_hash TEXT NOT NULL, "
                    "document TEXT NOT NULL)"
                )
                self._create_indexes(db)
                db.execute(_DISPATCH_GATE_SCHEMA)
                db.execute(f"PRAGMA application_id = {_LAN_DATABASE_ID}")

    @staticmethod
    def _audit(db, actor: str, event: str, resource: str, detail: str = "") -> None:
        db.execute(
            "INSERT INTO audit(at,actor,event,resource,detail) VALUES(?,?,?,?,?)",
            (utc_now(), actor, event, resource, detail),
        )

    def authenticate(self, token: str) -> dict:
        with self._read_transaction() as db:
            row = db.execute(
                "SELECT role,identity FROM credentials WHERE hash=? AND revoked=0", (digest(token),)
            ).fetchone()
            if not row:
                raise StoreError("unauthenticated", 401)
            return dict(row)

    def pairing_code(self, device_id: str) -> str:
        code = new_secret()
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                raise StoreError("device_identity_already_registered")
            db.execute("DELETE FROM pairing WHERE device_id=? OR expires<?", (device_id, time.time()))
            db.execute(
                "INSERT INTO pairing(hash,device_id,expires) VALUES(?,?,?)",
                (digest(code), device_id, time.time() + 300),
            )
            self._audit(db, "local-admin", "pairing_approved", device_id)
        return code

    def register(self, request: dict) -> dict:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM pairing WHERE hash=? AND used=0 AND expires>?",
                (digest(request["code"]), time.time()),
            ).fetchone()
            if not row or row["device_id"] != request["device_id"]:
                raise StoreError("invalid_or_expired_pairing", 403)
            if db.execute("SELECT 1 FROM devices WHERE id=?", (request["device_id"],)).fetchone():
                raise StoreError("device_identity_already_registered")
            doc = {k: v for k, v in request.items() if k not in ("code", "credential")}
            doc["status"] = "online"
            doc["last_seen"] = utc_now()
            db.execute(
                "INSERT INTO credentials(hash,role,identity) VALUES(?,?,?)",
                (digest(request["credential"]), "worker", request["device_id"]),
            )
            db.execute(
                "INSERT INTO devices(id,document,last_seen) VALUES(?,?,?)",
                (request["device_id"], json.dumps(doc), time.time()),
            )
            db.execute("UPDATE pairing SET used=1 WHERE hash=?", (digest(request["code"]),))
            self._audit(db, "worker:" + request["device_id"], "device_registered", request["device_id"])
            return doc

    def devices(self) -> list[dict]:
        with self.lock, self._read_transaction() as db:
            out = []
            for row in db.execute("SELECT * FROM devices ORDER BY id"):
                doc = json.loads(row["document"])
                doc["status"] = (
                    "revoked"
                    if row["revoked"]
                    else "online"
                    if 0 <= time.time() - row["last_seen"] < 20
                    else "offline"
                )
                doc["sdk_ready"] = bool(doc["status"] == "online" and execution_owner_id(doc["capabilities"])
                                        and self._has_worker_contact(doc))
                out.append(doc)
            return out

    def heartbeat(self, device_id: str, capabilities: list[dict], worker_version: str | None = None) -> dict:
        # Keep publication ordered with its DB commit, including overlapping
        # old/new Worker requests during an executor replacement.
        with self.lock:
            return self._heartbeat_committed(device_id, capabilities, worker_version)

    def _heartbeat_committed(self, device_id: str, capabilities: list[dict], worker_version: str | None = None) -> dict:
        session = worker_session_id(capabilities)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM devices WHERE id=? AND revoked=0", (device_id,)).fetchone()
            if not row:
                raise StoreError("device_revoked", 403)
            doc = json.loads(row["document"])
            paired_owner = execution_owner_id(doc["capabilities"])
            if paired_owner is not None and execution_owner_id(capabilities) != paired_owner:
                raise StoreError("worker_binding_changed", 403)
            if doc.get("capabilities") != capabilities:
                # Permission/session changes must interrupt passive old
                # subscriptions; ordinary unchanged heartbeats stay quiet.
                self._transaction_changes[-1].update(("device:" + device_id, "worker:" + device_id))
            doc.update(capabilities=capabilities, last_seen=utc_now(), status="online")
            if worker_version is not None:
                doc["worker_version"] = worker_version
            db.execute(
                "UPDATE devices SET document=?,last_seen=? WHERE id=?",
                (json.dumps(doc), time.time(), device_id),
            )
            active = db.execute(
                "SELECT id,state FROM tasks WHERE device_id=? AND state IN "
                "('dispatched','running','cancelling') ORDER BY rowid",
                (device_id,),
            ).fetchall()
            # M1 Workers use unknown to stop in-flight work. Keep that signal, but do not
            # return an ever-growing history on every heartbeat. M2 Workers also query
            # each durable pending journal entry by its exact task ID.
            unknown = db.execute(
                "SELECT id,state FROM tasks WHERE device_id=? AND state='unknown' "
                "ORDER BY rowid DESC LIMIT 128",
                (device_id,),
            ).fetchall()
            from .task_lanes import supports_task_concurrency

            result = {"tasks": [dict(row) for row in [*active, *unknown]]}
            if supports_task_concurrency(capabilities):
                # ACK the exact supported version offered by this Worker;
                # v1 peers retain their six-lane classifier and capacity.
                result["task_concurrency"] = next(cap["task_concurrency"] for cap in capabilities
                                                   if cap.get("executor_type") == "command")
            from .task_notifications import notification_capability, supports_task_notifications

            if supports_task_notifications(capabilities):
                result["task_notifications"] = notification_capability()
            from .task_notifications import (
                supports_worker_action_notifications,
                worker_action_notification_capability,
            )

            if supports_worker_action_notifications(capabilities):
                result["worker_action_notifications"] = worker_action_notification_capability()
            from .worker_dispatch_wait import dispatch_wait_capability, supports_dispatch_wait
            from .worker_report_isolation import report_isolation_capability, supports_report_isolation

            if supports_dispatch_wait(capabilities):
                result["worker_dispatch_wait"] = dispatch_wait_capability()
            if supports_report_isolation(capabilities):
                result["worker_report_isolation"] = report_isolation_capability()
        # This heartbeat already incorporates its own capability/session
        # update. Snapshot after that committed publication, while the outer
        # Store lock still orders external cancellation/new work after it.
        if "task_notifications" in result:
            result["notification_cursor"] = self.notifications.cursor("device:" + device_id)
        if "worker_action_notifications" in result:
            result["worker_action_cursor"] = self.notifications.cursor("worker:" + device_id)
        # Publish only after a committed, authenticated Worker heartbeat. Pair
        # registration, machine presence and watchdog diagnostics never do so.
        with self.lock:
            self._worker_contacts[device_id] = session
        return result

    def _has_worker_contact(self, device: dict) -> bool:
        session = worker_session_id(device.get("capabilities", []))
        return session is not None and self._worker_contacts.get(device["device_id"]) == session

    def _bound_problem(self, device: dict, task: dict) -> str | None:
        owner = task.get("expected_execution_owner_id")
        if owner is None:
            return None
        if execution_owner_id(device["capabilities"]) != owner:
            return "device_binding_changed"
        if not self._has_worker_contact(device):
            return "device_execution_unconfirmed"
        if not self._allows(device, task):
            return "capability_or_policy_denied"
        return None

    @staticmethod
    def _allows(device: dict, task: dict) -> bool:
        for cap in device.get("capabilities", []):
            if (
                cap.get("executor_type") == task["executor_type"]
                and cap.get("available") is True
                and task["action"] in cap.get("actions", [])
            ):
                params = task["parameters"]
                if task["executor_type"] == "command":
                    return params["profile"] in cap.get("profiles", [])
                if task["executor_type"] == "file":
                    return params["root"] in cap.get("roots", [])
                if task["executor_type"] == "workspace":
                    if task["action"] == "search_native_page":
                        from .ripgrep_backend import valid_capability

                        return cap.get("mode") in {"full", "read_only"} and valid_capability(cap.get("native_search"))
                    return cap.get("mode") == "full" or cap.get("mode") == "read_only" and task["action"] in {"list", "list_page", "search", "search_page", "read", "read_many", "read_range", "stat", "read_image", "patch_status", "log_read", "log_search"}
                if task["executor_type"] == "development":
                    return cap.get("mode") == "full"
                if task["executor_type"] == "localhost":
                    return (cap.get("mode") == "full" or cap.get("mode") == "read_only"
                            and params.get("method", "GET") in {"GET", "HEAD"})
                if task["executor_type"] == "browser":
                    from .browser_protocol import (
                        BROWSER_READ_ACTIONS,
                        valid_browser_capabilities,
                        valid_browser_text_capability,
                        valid_browser_workflow_capability,
                    )

                    return (valid_browser_capabilities(cap.get("browser_controls"))
                            and (task["action"] != "workflow" or
                                 valid_browser_workflow_capability(cap.get("browser_workflow"))
                                 and valid_browser_text_capability(cap.get("browser_controls")))
                            and (task["action"] != "action_observe" or params.get("text_semantics") != "visible_text_v1"
                                 or valid_browser_text_capability(cap.get("browser_controls")))
                            and (cap.get("mode") == "full" or cap.get("mode") == "read_only"
                                 and task["action"] in BROWSER_READ_ACTIONS))
                if task["executor_type"] in {"terminal", "job"}:
                    host = cap.get("execution_host")
                    return (cap.get("mode") == "full" and (not isinstance(host, dict)
                            or params.get("owner_id") == host.get("owner_id")))
                if task["executor_type"] == "transfer":
                    from .transfer_protocol import TRANSFER_READ_ACTIONS

                    return cap.get("mode") == "full" or cap.get("mode") == "read_only" and task["action"] in TRANSFER_READ_ACTIONS
                if task["executor_type"] == "computer":
                    from .system_tool_registry import SYSTEM_TOOLS, system_action_allowed

                    if task["action"] in SYSTEM_TOOLS:
                        return system_action_allowed(cap, task["action"], params)
                    if task["action"] == "diagnose":
                        from .system_diagnostics_protocol import valid_diagnostic_capability

                        return (cap.get("mode") in {"full", "read_only"}
                                and valid_diagnostic_capability(cap.get("system_diagnostics")))
                    if task["action"] == "ui_workflow_target":
                        from .software_workflow import valid_software_workflow_target_capability

                        operations, steps = cap.get("uia_operations"), params.get("steps")
                        return (cap.get("mode") == "full"
                                and valid_software_workflow_target_capability(cap.get("software_workflow_target"))
                                and isinstance(operations, list) and isinstance(steps, list) and 1 <= len(steps) <= 8
                                and all(isinstance(step, dict) and step.get("operation") in operations for step in steps))
                    if task["action"] == "ui_workflow":
                        from .software_workflow import (
                            software_workflow_focus_available,
                            valid_software_workflow_capability,
                        )

                        operations = cap.get("uia_operations")
                        steps = params.get("steps")
                        return (cap.get("mode") == "full" and valid_software_workflow_capability(cap.get("software_workflow"))
                                and (params.get("focus_policy", "require_foreground") == "require_foreground"
                                     or params.get("focus_policy") == "activate_once"
                                     and software_workflow_focus_available(cap.get("software_workflow")))
                                and isinstance(operations, list) and isinstance(steps, list) and 1 <= len(steps) <= 8
                                and all(isinstance(step, dict) and step.get("operation") in operations for step in steps))
                    if task["action"] in {"ui_action", "ui_action_observe"}:
                        operations = cap.get("uia_operations", ["invoke", "focus", "set_value"])
                        if not isinstance(operations, list) or params.get("operation") not in operations:
                            return False
                    if task["action"] == "input" and params.get("window_id") == "desktop" and cap.get("desktop_input") is not True:
                        return False
                    return cap.get("mode") == "full" or cap.get("mode") == "read_only" and task["action"] in {"info", "windows", "capture", "inspect", "environment", "ui_tree", "clipboard_read", "ui_wait"}
        return False

    def worker_notification_cursor(self, device_id: str, *, kind: str = "legacy") -> str:
        from .task_notifications import supports_task_notifications, supports_worker_action_notifications

        with self._read_transaction() as db:
            self._active_worker(db, device_id)
            device = json.loads(db.execute("SELECT document FROM devices WHERE id=?", (device_id,)).fetchone()[0])
            supported = (supports_task_notifications if kind == "legacy" else supports_worker_action_notifications
                         if kind == "action" else None)
            if supported is None or not supported(device.get("capabilities", [])):
                raise StoreError("task_notifications_not_negotiated", 409)
            return self.notifications.cursor(("device:" if kind == "legacy" else "worker:") + device_id)

    def submit(self, request: dict, principal: str) -> dict:
        request_hash = digest(json.dumps(request, sort_keys=True, separators=(",", ":")))
        with self.transaction() as db:
            idem_key = request.get("idempotency_key")
            if idem_key:
                previous = db.execute(
                    "SELECT * FROM tasks WHERE principal=? AND idem_key=?", (principal, idem_key)
                ).fetchone()
                if previous:
                    if previous["request_hash"] != request_hash:
                        raise StoreError("idempotency_key_conflict")
                    return self._task_document(previous)
            device_row = db.execute(
                "SELECT * FROM devices WHERE id=? AND revoked=0", (request["target_device_id"],)
            ).fetchone()
            if not device_row:
                raise StoreError("device_not_found", 404)
            if time.time() - device_row["last_seen"] >= 20:
                raise StoreError("device_offline")
            device = json.loads(device_row["document"])
            problem = self._bound_problem(device, request)
            if problem is not None:
                raise StoreError(problem, 403 if problem == "capability_or_policy_denied" else 409)
            if request.get("expected_execution_owner_id") is None and not self._allows(device, request):
                raise StoreError("capability_or_policy_denied", 403)
            task_id = new_id()
            doc = {
                **request,
                "task_id": task_id,
                "created_at": utc_now(),
                "requested_by": principal,
                "authorization_context": {"policy": "declared-capabilities-and-worker-local-policy"},
                "state": "authorized",
                "result_ref": None,
                "error": None,
                "audit_ref": task_id,
            }
            db.execute(
                "INSERT INTO tasks(id,device_id,state,document,principal,idem_key,request_hash) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    task_id,
                    request["target_device_id"],
                    "authorized",
                    json.dumps(doc),
                    principal,
                    idem_key,
                    request_hash,
                ),
            )
            self._audit(db, principal, "task_queued", task_id)
            self._audit(db, principal, "task_authorized", task_id)
            self._task_changed(request["target_device_id"], task_id, worker_action=True)
            return doc

    @staticmethod
    def _task_document(row) -> dict:
        doc = json.loads(row["document"])
        doc["state"] = row["state"]
        return doc

    def _transition(self, db, row, state: str, actor: str, error: dict | None = None,
                    *, worker_action: bool = True) -> dict:
        validate_transition(row["state"], state)
        doc = self._task_document(row)
        doc.update(state=state, updated_at=utc_now())
        if state in TERMINAL_STATES:
            doc.pop("progress", None)
        doc["error"] = error
        db.execute("UPDATE tasks SET state=?,document=? WHERE id=?", (state, json.dumps(doc), row["id"]))
        self._audit(db, actor, "task_" + state, row["id"])
        # Worker-owned claim/start/report merely acknowledge its own work.
        # Operators and recovery can change what it may execute, so those
        # transitions retain an immediate actionable wake.
        self._task_changed(row["device_id"], row["id"], worker_action=worker_action)
        return doc

    @staticmethod
    def _dispatch_job(job_id):
        if type(job_id) is not str or re.fullmatch(r"[0-9a-f]{32}", job_id) is None:
            raise StoreError("invalid_dispatch_maintenance")

    @staticmethod
    def _dispatch_gate(db, device_id):
        row = db.execute("SELECT job_id,allowed_task_id,released FROM device_dispatch_gates WHERE device_id=?",
                         (device_id,)).fetchone()
        if row is not None:
            Store._dispatch_job(row["job_id"])
            if row["released"] not in {0, 1}:
                raise StoreError("invalid_dispatch_maintenance")
        return row

    @classmethod
    def _dispatch_snapshot(cls, db, device_id):
        cls._active_worker(db, device_id)
        gate = cls._dispatch_gate(db, device_id)
        active = [row[0] for row in db.execute("SELECT id FROM tasks WHERE device_id=? AND state IN "
                  "('dispatched','running','cancelling') ORDER BY rowid", (device_id,))]
        allowed = [gate["allowed_task_id"]] if gate is not None and gate["allowed_task_id"] is not None else []
        blocking = [identity for identity in active if identity not in allowed]
        enabled = gate is not None and gate["released"] == 0
        drained = enabled and not blocking
        return {"format": 1, "device_id": device_id, "job_id": gate["job_id"] if gate is not None else None,
                "active": enabled, "released": gate is not None and gate["released"] == 1,
                "allowed_task_ids": allowed, "active_task_ids": active, "active_count": len(active),
                "blocking_task_ids": blocking, "blocking_count": len(blocking),
                "drained": drained, "ready": drained and len(allowed) == 1}

    def device_dispatch_maintenance(self, device_id):
        """Read the exact device's gate; no task, state transition or lease is created."""
        with self._read_transaction() as db:
            return self._dispatch_snapshot(db, device_id)

    def pause_device_dispatch(self, device_id, job_id):
        """Fence only new claims. Already-dispatched work finishes naturally."""
        self._dispatch_job(job_id)
        with self.transaction() as db:
            self._active_worker(db, device_id)
            gate = self._dispatch_gate(db, device_id)
            if gate is not None and gate["released"] == 0 and gate["job_id"] != job_id:
                raise StoreError("dispatch_maintenance_owned")
            if gate is None or gate["released"] == 1:
                db.execute("INSERT INTO device_dispatch_gates VALUES(?,?,NULL,0) ON CONFLICT(device_id) "
                           "DO UPDATE SET job_id=excluded.job_id,allowed_task_id=NULL,released=0", (device_id, job_id))
            return self._dispatch_snapshot(db, device_id)

    def allow_device_dispatch_task(self, device_id, job_id, task_id):
        """Allow one original Apply, without authorizing any other queued work."""
        from uuid import UUID

        self._dispatch_job(job_id)
        try:
            if type(task_id) is not str or str(UUID(task_id)) != task_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise StoreError("invalid_dispatch_maintenance") from None
        with self.transaction() as db:
            gate = self._dispatch_gate(db, device_id)
            if gate is None or gate["job_id"] != job_id:
                raise StoreError("dispatch_maintenance_owned")
            task = self._task_document(self._get(db, task_id, device_id))
            arguments = task.get("parameters", {}).get("arguments")
            if (task.get("executor_type") != "computer" or task.get("action") != "launch"
                    or type(arguments) is not list or len(arguments) != 7
                    or arguments[:4] != ["--child-update", "--action", "apply", "--folder"]
                    or type(arguments[4]) is not str or not arguments[4]
                    or arguments[5:] != ["--job-id", job_id]):
                raise StoreError("invalid_dispatch_maintenance")
            if gate["allowed_task_id"] not in {None, task_id}:
                raise StoreError("dispatch_maintenance_owned")
            if gate["released"] == 1:
                if gate["allowed_task_id"] != task_id:
                    raise StoreError("dispatch_maintenance_owned")
                return self._dispatch_snapshot(db, device_id)
            current = self._dispatch_snapshot(db, device_id)
            if current["blocking_task_ids"] and current["blocking_task_ids"] != [task_id]:
                raise StoreError("dispatch_maintenance_busy")
            db.execute("UPDATE device_dispatch_gates SET allowed_task_id=? WHERE device_id=? AND job_id=?",
                       (task_id, device_id, job_id))
            self._transaction_changes[-1].update(("device:" + device_id, "worker:" + device_id))
            return self._dispatch_snapshot(db, device_id)

    def release_device_dispatch(self, device_id, job_id):
        """A known original native-stop window releases its own persistent gate."""
        self._dispatch_job(job_id)
        with self.transaction() as db:
            self._active_worker(db, device_id)
            gate = self._dispatch_gate(db, device_id)
            if gate is None or gate["job_id"] != job_id:
                raise StoreError("dispatch_maintenance_owned")
            db.execute("UPDATE device_dispatch_gates SET released=1 WHERE device_id=? AND job_id=?", (device_id, job_id))
            self._transaction_changes[-1].update(("device:" + device_id, "worker:" + device_id))
            return {"format": 1, "device_id": device_id, "job_id": job_id, "released": True}

    def claim(self, device_id: str, *, expected_fence=None, active_task_ids=None) -> dict | None:
        from .task_lanes import negotiated_task_capacity, supports_task_concurrency, task_lane

        def candidate(db):
            self._active_worker(db, device_id)
            if expected_fence is not None:
                self._assert_worker_poll_fence(db, expected_fence)
            excluded = self._excluded_worker_lanes(db, device_id, active_task_ids)
            gate = self._dispatch_gate(db, device_id)
            allowed = gate["allowed_task_id"] if gate is not None and gate["released"] == 0 else None
            if gate is not None and gate["released"] == 0 and allowed is None:
                return None
            if not db.execute(
                "SELECT 1 FROM tasks WHERE device_id=? AND state='authorized' LIMIT 1", (device_id,)
            ).fetchone():
                return None
            active = db.execute(
                "SELECT document FROM tasks WHERE device_id=? AND state IN ('dispatched','running','cancelling')",
                (device_id,),
            ).fetchall()
            device = json.loads(db.execute("SELECT document FROM devices WHERE id=?", (device_id,)).fetchone()[0])
            parallel = supports_task_concurrency(device.get("capabilities", []))
            if ((active or excluded) and not parallel) or len(active) >= negotiated_task_capacity(device.get("capabilities", [])):
                return None
            busy = {task_lane(json.loads(row["document"])) for row in active} | excluded
            if "legacy" in busy or len(busy) >= negotiated_task_capacity(device.get("capabilities", [])):
                return None
            selected = None
            # Iterate without materializing command/file contents for the whole
            # queue. Each lane stays FIFO; an older legacy operation is a
            # barrier so a stream of newer work cannot starve it indefinitely.
            query = "SELECT * FROM tasks WHERE device_id=? AND state='authorized'"
            values = (device_id,)
            if gate is not None and gate["released"] == 0:
                query += " AND id=?"
                values += (allowed,)
            query += " ORDER BY rowid"
            if not parallel:
                query += " LIMIT 1"
            for candidate in db.execute(query, values):
                lane = task_lane(json.loads(candidate["document"]))
                if lane == "legacy" and busy:
                    break
                if lane not in busy:
                    selected = candidate
                    break
            if selected is None:
                return None

            return selected

        with self.lock:
            # Idle polls and fully occupied lanes do not need a write
            # reservation. A real claim is selected again under BEGIN
            # IMMEDIATE, including the device's revocation and lane policy.
            with self._read_transaction() as db:
                if candidate(db) is None:
                    return None
            with self.transaction() as db:
                selected = candidate(db)
                if selected is None:
                    return None
                task = self._task_document(selected)
                if task.get("expected_execution_owner_id") is not None:
                    device = json.loads(db.execute("SELECT document FROM devices WHERE id=?", (device_id,)).fetchone()[0])
                    problem = self._bound_problem(device, task)
                    if problem is not None:
                        self._transition(db, selected, "failed", "controller",
                                         {"code": problem, "message": "Device authorization changed before dispatch"})
                        return None
                doc = self._transition(db, selected, "dispatched", "worker:" + device_id, worker_action=False)
                db.execute(
                    "UPDATE tasks SET deadline=? WHERE id=?",
                    (time.time() + doc["timeout_seconds"] + 30, selected["id"]),
                )
                return doc

    @staticmethod
    def _excluded_worker_lanes(db, device_id, identities):
        """Client IDs can only remove lanes, never supply another task's authority."""
        from uuid import UUID

        from .task_lanes import task_lane

        if identities is None:
            return set()
        try:
            if (type(identities) is not list or len(identities) > 8 or len(set(identities)) != len(identities)
                    or any(type(value) is not str or str(UUID(value)) != value for value in identities)):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise StoreError("invalid_worker_state") from None
        lanes = set()
        for identity in identities:
            row = db.execute("SELECT document FROM tasks WHERE id=? AND device_id=?", (identity, device_id)).fetchone()
            if row is None:
                raise StoreError("invalid_worker_state")
            lanes.add(task_lane(json.loads(row["document"])))
        return lanes

    def worker_poll_fence(self, device_id, capabilities, credential_hash):
        """Capture exact post-heartbeat authority without retaining a raw credential."""
        from .worker_session import worker_session_id

        with self._read_transaction() as db:
            self._active_worker(db, device_id)
            doc = json.loads(db.execute("SELECT document FROM devices WHERE id=?", (device_id,)).fetchone()[0])
            if doc.get("capabilities") != capabilities:
                raise StoreError("worker_binding_changed")
            fence = {"device_id": device_id, "capabilities": json.dumps(capabilities, sort_keys=True, separators=(",", ":")),
                "credential_hash": credential_hash, "worker_session": worker_session_id(capabilities),
                "worker_version": doc.get("worker_version"), "controller_epoch": self._worker_fence_epoch}
            self._assert_worker_poll_fence(db, fence)
            return fence

    def _assert_worker_poll_fence(self, db, fence):
        from .worker_session import worker_session_id

        identity = fence["device_id"]
        self._active_worker(db, identity)
        credential = db.execute("SELECT role,identity FROM credentials WHERE hash=? AND revoked=0",
                                (fence["credential_hash"],)).fetchone()
        doc = json.loads(db.execute("SELECT document FROM devices WHERE id=?", (identity,)).fetchone()[0])
        if credential is None:
            raise StoreError("unauthenticated", 401)
        if credential["role"] != "worker" or credential["identity"] != identity:
            raise StoreError("forbidden_role", 403)
        if (fence["controller_epoch"] != self._worker_fence_epoch
                or json.dumps(doc.get("capabilities"), sort_keys=True, separators=(",", ":")) != fence["capabilities"]
                or worker_session_id(doc.get("capabilities", [])) != fence["worker_session"]
                or doc.get("worker_version") != fence["worker_version"]
                or self._worker_contacts.get(identity) != fence["worker_session"]):
            raise StoreError("worker_binding_changed")

    def worker_poll_state(self, fence, *, claim, active_task_ids=None):
        """Fresh state and an optional fenced claim; never replay an old heartbeat."""
        from .task_lanes import supports_task_concurrency
        from .task_notifications import (
            notification_capability,
            supports_task_notifications,
            supports_worker_action_notifications,
            worker_action_notification_capability,
        )
        from .worker_dispatch_wait import dispatch_wait_capability, supports_dispatch_wait
        from .worker_report_isolation import report_isolation_capability, supports_report_isolation

        identity = fence["device_id"]
        with self.lock:
            task = self.claim(identity, expected_fence=fence, active_task_ids=active_task_ids) if claim else None
            with self._read_transaction() as db:
                self._assert_worker_poll_fence(db, fence)
                self._excluded_worker_lanes(db, identity, active_task_ids)
                active = db.execute("SELECT id,state FROM tasks WHERE device_id=? AND state IN "
                                    "('dispatched','running','cancelling') ORDER BY rowid", (identity,)).fetchall()
                unknown = db.execute("SELECT id,state FROM tasks WHERE device_id=? AND state='unknown' "
                                     "ORDER BY rowid DESC LIMIT 128", (identity,)).fetchall()
                capabilities = json.loads(fence["capabilities"])
                result = {"tasks": [dict(row) for row in [*active, *unknown]], "task": task}
                if supports_task_concurrency(capabilities):
                    result["task_concurrency"] = next(cap["task_concurrency"] for cap in capabilities if cap.get("executor_type") == "command")
                if supports_task_notifications(capabilities):
                    result.update(task_notifications=notification_capability(), notification_cursor=self.notifications.cursor("device:" + identity))
                if supports_worker_action_notifications(capabilities):
                    result.update(worker_action_notifications=worker_action_notification_capability(), worker_action_cursor=self.notifications.cursor("worker:" + identity))
                if supports_dispatch_wait(capabilities):
                    result["worker_dispatch_wait"] = dispatch_wait_capability()
                if supports_report_isolation(capabilities):
                    result["worker_report_isolation"] = report_isolation_capability()
                return result, not active and not active_task_ids

    @staticmethod
    def _sdk_task_matches(row, scope: tuple[str, str, str]) -> bool:
        device_id, owner_id, principal = scope
        return (row["device_id"] == device_id and row["principal"] == principal
                and json.loads(row["document"]).get("expected_execution_owner_id") == owner_id)

    def _task_with_results(self, db, row) -> dict:
        task_id = row["id"]
        doc = self._task_document(row)
        result = db.execute("SELECT document FROM results WHERE task_id=?", (task_id,)).fetchone()
        doc["result"] = json.loads(result["document"]) if result else None
        recovery = db.execute("SELECT document FROM recovery_evidence WHERE task_id=?", (task_id,)).fetchone()
        doc["recovery_evidence"] = json.loads(recovery["document"]) if recovery else None
        return doc

    def get_task(self, task_id: str, device_id: str | None = None, *,
                 sdk_scope: tuple[str, str, str] | None = None) -> dict:
        with self._read_transaction() as db:
            if device_id is not None:
                self._active_worker(db, device_id)
            row = self._get(db, task_id, device_id)
            if sdk_scope is not None and not self._sdk_task_matches(row, sdk_scope):
                raise StoreError("task_not_found", 404)
            return self._task_with_results(db, row)

    def find_task_by_key(self, device_id: str, key: str, principal: str, *,
                         expected_owner: str | None = None) -> dict | None:
        """Only resolve an exact original submission belonging to this operator."""
        with self._read_transaction() as db:
            row = db.execute("SELECT * FROM tasks WHERE device_id=? AND principal=? AND idem_key=?",
                             (device_id, principal, key)).fetchone()
            if row is None or (expected_owner is not None
                               and not self._sdk_task_matches(row, (device_id, expected_owner, principal))):
                return None
            return self._task_with_results(db, row)

    @staticmethod
    def _active_worker(db, device_id: str) -> None:
        # Recheck inside the mutation transaction: revocation can race HTTP authentication.
        if not db.execute("SELECT 1 FROM devices WHERE id=? AND revoked=0", (device_id,)).fetchone():
            raise StoreError("device_revoked", 403)

    def progress(self, task_id: str, device_id: str, snapshot: dict) -> dict:
        """Replace bounded observational output; never change task execution state."""
        from .development_progress import valid_progress

        if not valid_progress(snapshot):
            raise StoreError("invalid_progress_evidence", 422)
        with self.transaction() as db:
            self._active_worker(db, device_id)
            row = self._get(db, task_id, device_id)
            doc = self._task_document(row)
            if doc["executor_type"] != "development" or row["state"] not in {"running", "cancelling"}:
                raise StoreError("task_progress_conflict")
            previous = doc.get("progress")
            if previous:
                if snapshot["sequence"] == previous["sequence"] and snapshot == previous:
                    return {"sequence": previous["sequence"], "accepted": True}
                if (snapshot["sequence"] <= previous["sequence"]
                        or snapshot["duration_ms"] < previous["duration_ms"]
                        or any(snapshot[channel + "_total_bytes"] < previous[channel + "_total_bytes"]
                               for channel in ("stdout", "stderr"))):
                    raise StoreError("task_progress_conflict")
            doc["progress"] = snapshot
            db.execute("UPDATE tasks SET document=? WHERE id=?", (json.dumps(doc), task_id))
            self._task_changed(device_id, task_id)
            return {"sequence": snapshot["sequence"], "accepted": True}

    @staticmethod
    def _get(db, task_id: str, device_id: str | None = None):
        row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row or (device_id is not None and row["device_id"] != device_id):
            raise StoreError("task_not_found", 404)
        return row

    def start(self, task_id: str, device_id: str) -> dict:
        with self.transaction() as db:
            self._active_worker(db, device_id)
            row = self._get(db, task_id, device_id)
            if row["state"] not in ("dispatched", "running"):
                raise StoreError("task_cannot_start")
            task = self._task_document(row)
            problem = None
            if task.get("expected_execution_owner_id") is not None:
                paired = db.execute("SELECT document, last_seen FROM devices WHERE id=?", (device_id,)).fetchone()
                if not 0 <= time.time() - paired["last_seen"] < 20:
                    raise StoreError("device_execution_unconfirmed")
                device = json.loads(paired["document"])
                problem = self._bound_problem(device, task)
            if row["state"] == "running":
                if problem is not None:
                    raise StoreError(problem)
                return task
            if problem is None:
                return self._transition(db, row, "running", "worker:" + device_id, worker_action=False)
            self._transition(db, row, "failed", "controller",
                             {"code": problem, "message": "Device authorization changed before execution"})
        # Commit the rejection before replying. A Worker must not begin on this response.
        raise StoreError(problem)

    @staticmethod
    def _validate_evidence(row, report: dict) -> None:
        """Apply the same success checks to initial reports and late recovery evidence."""
        if report["state"] != "succeeded":
            return
        result = report.get("result")
        doc = Store._task_document(row)
        if doc["executor_type"] == "browser":
            from .browser_evidence import valid_browser_evidence

            if not valid_browser_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "job":
            from .job_evidence import valid_job_evidence

            if not valid_job_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "localhost":
            from .localhost_evidence import valid_localhost_evidence

            if not valid_localhost_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "terminal":
            from .terminal_evidence import valid_terminal_evidence

            if not valid_terminal_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "transfer":
            from .transfer_evidence import valid_transfer_evidence

            if not valid_transfer_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "computer":
            from .computer_evidence import valid_computer_evidence

            if not valid_computer_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] in {"workspace", "development"}:
            from .project_evidence import valid_success_evidence

            if not valid_success_evidence(doc, result):
                raise StoreError("invalid_success_evidence", 422)
            return
        if doc["executor_type"] == "command":
            if (
                not isinstance(result, dict)
                or type(result.get("exit_code")) is not int
                or result["exit_code"] != 0
            ):
                raise StoreError("invalid_success_evidence", 422)
        else:
            import base64

            try:
                content = base64.b64decode(result["content_b64"], validate=True)
                valid = (
                    hashlib.sha256(content).hexdigest() == result["sha256"]
                    and type(result["size_bytes"]) is int
                    and len(content) == result["size_bytes"]
                    and len(content) <= 65536
                )
            except (KeyError, ValueError, TypeError):
                valid = False
            if not valid:
                raise StoreError("invalid_file_evidence", 422)

    def report(self, task_id: str, device_id: str, report: dict) -> dict:
        report_hash = digest(json.dumps(report, sort_keys=True))
        with self.transaction() as db:
            self._active_worker(db, device_id)
            row = self._get(db, task_id, device_id)
            if row["report_hash"] == report_hash:
                return self._task_document(row)
            if row["state"] not in ("running", "cancelling"):
                raise StoreError("task_report_conflict")
            self._validate_evidence(row, report)
            result = report.get("result")
            doc = self._transition(db, row, report["state"], "worker:" + device_id, report.get("error"),
                                   worker_action=False)
            doc["result_ref"] = "result:" + task_id
            if doc["executor_type"] == "transfer" and doc["action"] == "upload_chunk" and report["state"] == "succeeded":
                # The Worker has consumed and verified these request bytes.
                # Keep the original request hash and chunk digest for dedupe.
                doc["parameters"].pop("data_b64", None)
                doc["parameters"]["payload_expired"] = True
            db.execute("INSERT INTO results(task_id,document) VALUES(?,?)", (task_id, json.dumps(result)))
            db.execute(
                "UPDATE tasks SET document=?,report_hash=? WHERE id=?",
                (json.dumps(doc), report_hash, task_id),
            )
            if (doc["executor_type"], doc["action"]) in {("computer", "capture"), ("workspace", "read_image")}:
                self._expire_screen_images(db, device_id)
            return doc

    def consume_transfer_payload(self, task_id: str, actor: str) -> dict:
        """Remove chunk bytes only after their original authenticated receiver ACKs."""
        with self.transaction() as db:
            row = self._get(db, task_id)
            doc = self._task_document(row)
            if row["principal"] != actor:
                raise StoreError("transfer_task_not_owned", 403)
            if (row["state"] != "succeeded" or doc["executor_type"] != "transfer"
                    or doc["action"] not in {"upload_chunk", "download_chunk"}):
                raise StoreError("transfer_payload_not_consumable")
            result_row = db.execute("SELECT document FROM results WHERE task_id=?", (task_id,)).fetchone()
            if result_row is None:
                raise StoreError("transfer_payload_not_consumable")
            result = json.loads(result_row["document"])
            if doc["action"] == "download_chunk" and result.pop("data_b64", None) is not None:
                result["payload_expired"] = True
                db.execute("UPDATE results SET document=? WHERE task_id=?", (json.dumps(result), task_id))
                self._audit(db, actor, "transfer_payload_consumed", task_id)
            return {"task_id": task_id, "payload_consumed": True}

    @staticmethod
    def _expire_screen_images(db, device_id: str) -> None:
        """Keep bounded screen pixels while retaining immutable task/audit receipts.

        Only already accepted screenshot payloads are removed. Request hashes,
        report hashes, task states and image digests survive; querying an old
        task never captures the screen again.
        """
        for table, payload_path in (("results", "$.image_b64"),
                                    ("recovery_evidence", "$.result.image_b64")):
            rows = db.execute(
                f"SELECT r.task_id,r.document FROM {table} r JOIN tasks t ON t.id=r.task_id "
                "WHERE t.device_id=? AND ((json_extract(t.document,'$.executor_type')='computer' "
                "AND json_extract(t.document,'$.action')='capture') OR "
                "(json_extract(t.document,'$.executor_type')='workspace' "
                "AND json_extract(t.document,'$.action')='read_image')) "
                f"AND json_type(r.document,'{payload_path}')='text' ORDER BY r.rowid DESC LIMIT -1 OFFSET 32",
                (device_id,),
            ).fetchall()
            for row in rows:
                document = json.loads(row["document"])
                result = document if table == "results" else document["result"]
                result.pop("image_b64", None)
                result["image_expired"] = True
                db.execute(f"UPDATE {table} SET document=? WHERE task_id=?",
                           (json.dumps(document), row["task_id"]))

    def reconcile(self, task_id: str, device_id: str, report: dict) -> dict:
        """Retain late evidence without rewriting an uncertain terminal execution."""
        report_hash = digest(json.dumps(report, sort_keys=True))
        with self.transaction() as db:
            self._active_worker(db, device_id)
            row = self._get(db, task_id, device_id)
            if row["state"] != "unknown":
                raise StoreError("task_recovery_not_unknown")
            previous = db.execute(
                "SELECT report_hash FROM recovery_evidence WHERE task_id=?", (task_id,)
            ).fetchone()
            if previous:
                if previous["report_hash"] != report_hash:
                    raise StoreError("task_recovery_conflict")
                return self._task_document(row)
            self._validate_evidence(row, report)
            evidence = {**report, "received_at": utc_now()}
            db.execute(
                "INSERT INTO recovery_evidence(task_id,report_hash,document) VALUES(?,?,?)",
                (task_id, report_hash, json.dumps(evidence)),
            )
            self._audit(db, "worker:" + device_id, "task_recovery_evidence_recorded", task_id)
            self._task_changed(device_id, task_id)
            doc = self._task_document(row)
            if (doc["executor_type"], doc["action"]) in {("computer", "capture"), ("workspace", "read_image")}:
                self._expire_screen_images(db, device_id)
            return self._task_document(row)

    def cancel(self, task_id: str, actor: str, *, sdk_scope: tuple[str, str, str] | None = None) -> dict:
        with self.transaction() as db:
            row = self._get(db, task_id)
            if sdk_scope is not None and not self._sdk_task_matches(row, sdk_scope):
                raise StoreError("task_not_found", 404)
            if row["state"] in TERMINAL_STATES or row["state"] == "cancelling":
                return self._task_document(row)
            state = "cancelled" if row["state"] in ("queued", "authorized") else "cancelling"
            return self._transition(
                db, row, state, actor, {"code": "cancel_requested", "message": "Cancellation requested"}
            )

    def revoke(self, device_id: str) -> None:
        with self.transaction() as db:
            if not db.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                raise StoreError("device_not_found", 404)
            db.execute("UPDATE devices SET revoked=1 WHERE id=?", (device_id,))
            db.execute("UPDATE credentials SET revoked=1 WHERE role IN ('worker','presence') AND identity=?", (device_id,))
            for row in db.execute("SELECT * FROM tasks WHERE device_id=?", (device_id,)).fetchall():
                if row["state"] not in TERMINAL_STATES:
                    state = "cancelled" if row["state"] in ("queued", "authorized") else "unknown"
                    self._transition(
                        db,
                        row,
                        state,
                        "local-admin",
                        {"code": "device_revoked", "message": "Device access revoked"},
                    )
            self._audit(db, "local-admin", "device_revoked", device_id)
            self._transaction_changes[-1].update(("device:" + device_id, "worker:" + device_id))

    def recover(self, restart: bool = False) -> int:
        count = 0
        with self._read_transaction() as db:
            pending = db.execute(
                "SELECT tasks.deadline,devices.last_seen FROM tasks JOIN devices ON "
                "tasks.device_id=devices.id WHERE state IN ('dispatched','running','cancelling')"
            ).fetchall()
            if not any(restart or time.time() > row["deadline"] or time.time() - row["last_seen"] >= 20
                       for row in pending):
                return 0
        with self.transaction() as db:
            rows = db.execute(
                "SELECT tasks.*,devices.last_seen FROM tasks JOIN devices ON "
                "tasks.device_id=devices.id WHERE state IN ('dispatched','running','cancelling')"
            ).fetchall()
            for row in rows:
                if restart or time.time() > row["deadline"] or time.time() - row["last_seen"] >= 20:
                    self._transition(
                        db,
                        row,
                        "unknown",
                        "controller",
                        {
                            "code": "execution_unconfirmed",
                            "message": "No confirmed terminal evidence; do not retry automatically",
                        },
                    )
                    count += 1
        return count

    def audit(self, task_id: str | None = None) -> list[dict]:
        with self._read_transaction() as db:
            if task_id:
                return [
                    dict(r)
                    for r in db.execute("SELECT * FROM audit WHERE resource=? ORDER BY seq", (task_id,))
                ]
            return [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 500")]
