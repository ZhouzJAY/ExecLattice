"""Outbound-only Worker. Durable claimed-task journal prevents blind re-execution."""

from __future__ import annotations

import json
import platform
import re
import sqlite3
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

from . import __version__
from .client import APIError, ControllerClient
from .executors import execute_task, validate_policy
from .protocol import TERMINAL_STATES, CommandParameters, FileParameters, ReportRequest, TaskRequest
from .task_lanes import MAX_ACTIVE_TASKS, concurrency_capability, task_lane, valid_task_concurrency
from .task_notifications import (
    notification_capability,
    valid_task_notifications,
    valid_worker_action_notifications,
    valid_worker_poll,
    worker_action_notification_capability,
)
from .worker_dispatch_wait import dispatch_wait_capability, valid_dispatch_wait
from .worker_identity import worker_execution_identity
from .worker_report_isolation import report_isolation_capability, valid_report_isolation


class WorkerAccessEnded(RuntimeError):
    """The controller no longer accepts this worker's authority."""


def describe_capabilities(policy: dict) -> list[dict]:
    result = [
        {
            "executor_type": "command",
            "task_concurrency": concurrency_capability(),
            "task_notifications": notification_capability(),
            "worker_action_notifications": worker_action_notification_capability(),
            "worker_dispatch_wait": dispatch_wait_capability(),
            "worker_report_isolation": report_isolation_capability(),
            "actions": ["run"],
            "available": bool(policy["commands"]) and policy.get("desktop_access", {}).get("mode") != "read_only",
            "profiles": sorted(policy["commands"]) if policy.get("desktop_access", {}).get("mode") != "read_only" else [],
            "permission": "local fixed argv profiles; no caller arguments",
            "verification": "process exit code and bounded stdout/stderr",
            "parameters_schema": CommandParameters.model_json_schema(),
            "dependencies": ["locally configured executable"],
            "limitations": ["no interactive input", "no shell"],
        },
        {
            "executor_type": "file",
            "actions": ["read"],
            "available": bool(policy["roots"]),
            "roots": sorted(policy["roots"]),
            "permission": "read-only authorized root",
            "verification": "sha256 and size_bytes",
            "parameters_schema": FileParameters.model_json_schema(),
            "dependencies": ["local filesystem"],
            "limitations": ["max 64 KiB", "no symlinks/reparse points"],
        },
    ]
    mode = policy.get("desktop_access", {}).get("mode")
    if mode in {"full", "read_only"}:
        result.append({
            "executor_type": "workspace",
            "available": True,
            "mode": mode,
            "actions": ["list", "search", "read"] + (["write"] if mode == "full" else []),
        })
    if mode == "full":
        result.append({"executor_type": "development", "available": True, "mode": "full", "actions": ["run"]})
    return result


def runtime_capabilities(policy: dict, identity: dict) -> list[dict]:
    """Publish the stable binding and a separate marker for this process."""
    from .worker_session import new_worker_session

    caps = describe_capabilities(policy)
    caps[0]["execution_identity"] = identity
    caps[0]["worker_session"] = new_worker_session()
    return caps


def pairing_request(config: dict, code: str) -> dict:
    policy = validate_policy(config["policy"])
    capabilities = describe_capabilities(policy)
    capabilities[0]["execution_identity"] = worker_execution_identity(config)
    return {
        "device_id": config["device_id"],
        "display_name": config["display_name"],
        "os": platform.system(),
        "architecture": platform.machine(),
        "worker_version": __version__,
        "capabilities": capabilities,
        "policy_profile": "local-restricted",
        "code": code,
        "credential": config["token"],
    }


def send_heartbeat(client, capabilities: list[dict]) -> dict:
    """Report the version when supported, retaining M1 Controller compatibility."""
    body = {"capabilities": capabilities}
    if not getattr(client, "_legacy_worker_heartbeat", False):
        body["worker_version"] = __version__
    try:
        return client.request("POST", "/v1/worker/heartbeat", body)
    except APIError as exc:
        if "worker_version" not in body or exc.status != 422 or exc.code != "invalid_request_schema":
            raise
        # Only omit the optional diagnostic field. Authorization and local
        # policy/capability declarations are identical in both requests.
        result = client.request("POST", "/v1/worker/heartbeat", {"capabilities": capabilities})
        client._legacy_worker_heartbeat = True
        return result


class WorkerJournal:
    """An execution barrier and durable result outbox, never a retry queue.

    Rows without reports mean execution may have started.  On process restart
    they become unknown evidence rather than executable work.  Old M1 journals
    migrate in place; their existing reports receive an idempotent confirmation.
    """

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS executions(task_id TEXT PRIMARY KEY, report TEXT)")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(executions)")}
        if "acknowledged" not in columns:
            self.db.execute("ALTER TABLE executions ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0")
        if "delivery_error" not in columns:
            self.db.execute("ALTER TABLE executions ADD COLUMN delivery_error TEXT")
        self.db.commit()

    @staticmethod
    def unconfirmed() -> dict:
        return {
            "state": "unknown",
            "result": None,
            "error": {"code": "worker_restarted", "message": "Prior execution unconfirmed; not rerun"},
        }

    def recover_unfinished(self) -> None:
        self.db.execute(
            "UPDATE executions SET report=? WHERE report IS NULL",
            (json.dumps(self.unconfirmed()),),
        )
        self.db.commit()

    def contains(self, task_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM executions WHERE task_id=?", (task_id,)).fetchone() is not None

    def finished_report(self, task_id: str) -> dict | None:
        row = self.db.execute("SELECT report FROM executions WHERE task_id=?", (task_id,)).fetchone()
        return json.loads(row[0]) if row is not None and row[0] is not None else None

    def begin(self, task_id: str) -> dict | None:
        row = self.db.execute("SELECT report FROM executions WHERE task_id=?", (task_id,)).fetchone()
        if row:
            if row[0]:
                return json.loads(row[0])
            report = self.unconfirmed()
            self.finish(task_id, report)
            return report
        self.db.execute("INSERT INTO executions(task_id) VALUES(?)", (task_id,))
        self.db.commit()
        return None

    def finish(self, task_id: str, report: dict) -> None:
        report = ReportRequest.model_validate(report).model_dump()
        row = self.db.execute("SELECT report FROM executions WHERE task_id=?", (task_id,)).fetchone()
        if row and row[0] is not None:
            if json.loads(row[0]) != report:
                raise RuntimeError("Conflicting local execution evidence; original report retained")
            return
        self.db.execute(
            "INSERT INTO executions(task_id,report) VALUES(?,?) "
            "ON CONFLICT(task_id) DO UPDATE SET report=excluded.report,acknowledged=0,delivery_error=NULL",
            (task_id, json.dumps(report)),
        )
        self.db.commit()

    def pending(self, excluded: set[str] | None = None, limit: int = 32) -> list[tuple[str, dict]]:
        # Exclusions are session-local: an upgrade/restart retries reports that
        # an older Controller could not reconcile, while preserving their data.
        excluded = excluded or set()
        rows = self.db.execute(
            "SELECT task_id,report FROM executions WHERE acknowledged=0 AND report IS NOT NULL ORDER BY rowid"
        )
        result = []
        for task_id, report in rows:
            if task_id not in excluded:
                result.append((task_id, json.loads(report)))
                if len(result) >= limit:
                    break
        return result

    def acknowledge(self, task_id: str) -> None:
        row = self.db.execute("SELECT report FROM executions WHERE task_id=?", (task_id,)).fetchone()
        if row and row[0]:
            report = json.loads(row[0])
            result = report.get("result")
            if (isinstance(result, dict) and result.get("mime_type") == "image/jpeg"
                    and (isinstance(result.get("frame_id"), str) or result.get("artifact_type") == "image")
                    and "image_b64" in result):
                # The Controller has confirmed this exact report. Keep the
                # execution barrier and checksum, not a duplicate screen archive.
                result.pop("image_b64")
                result["image_expired"] = True
                self.db.execute("UPDATE executions SET report=? WHERE task_id=?", (json.dumps(report), task_id))
            if (isinstance(result, dict) and result.get("direction") == "download"
                    and isinstance(result.get("transfer_id"), str) and "chunk_sha256" in result and "data_b64" in result):
                # The Controller has the verified bytes; only its authenticated
                # receiver may subsequently ACK consumption of that copy.
                result.pop("data_b64")
                result["payload_expired"] = True
                self.db.execute("UPDATE executions SET report=? WHERE task_id=?", (json.dumps(report), task_id))
        self.db.execute(
            "UPDATE executions SET acknowledged=1,delivery_error=NULL WHERE task_id=?", (task_id,)
        )
        self.db.commit()

    def delivery_error(self, task_id: str, code: str) -> None:
        # Fixed local codes only: never persist arbitrary HTTP error content.
        self.db.execute("UPDATE executions SET delivery_error=? WHERE task_id=?", (code, task_id))
        self.db.commit()


def _validated_report(value) -> dict:
    try:
        return ReportRequest.model_validate(value).model_dump()
    except Exception:
        return {
            "state": "unknown",
            "result": None,
            "error": {
                "code": "executor_unconfirmed",
                "message": "Executor did not return valid terminal evidence",
            },
        }


def _observed_report(future) -> dict:
    try:
        return _validated_report(future.result())
    except Exception:
        return _validated_report(None)


def _execute_durably(task, policy, cancel, journal_path: Path, observation: dict) -> dict:
    # Use a separate SQLite connection on the executor thread so completion is
    # durable even while the polling thread is waiting on a broken connection.
    try:
        if task.get("executor_type") == "workspace":
            report = _validated_report(execute_task(task, policy, cancel, state_dir=journal_path.parent.parent))
        elif task.get("executor_type") == "development":
            # Assignment replaces the complete immutable snapshot. Only the
            # polling thread talks to the Controller; executor output cannot
            # trigger additional tasks or block on a failed network request.
            def progress(value):
                observation["progress"] = value

            report = _validated_report(execute_task(task, policy, cancel, progress=progress,
                                                   state_dir=journal_path.parent.parent))
        else:
            report = _validated_report(execute_task(task, policy, cancel))
    except Exception:
        report = _validated_report(None)
    remote_state = observation.get("state")
    if report["state"] == "cancelled" and remote_state != "cancelling":
        report["state"] = "failed"
        report["error"] = {
            "code": "connection_lost_safe_stop",
            "message": "Worker confirmed local stop without a confirmed controller cancellation",
        }
    output_journal = WorkerJournal(journal_path)
    try:
        output_journal.finish(task["task_id"], report)
    finally:
        output_journal.db.close()
    return report


def _task_owner_matches(task: dict, owner_id: str) -> bool:
    expected_owner = task.get("expected_execution_owner_id")
    return expected_owner is None or expected_owner == owner_id


def _deliver_report(client, journal: WorkerJournal, task_id: str, report: dict, owner_id: str) -> bool:
    """Confirm one durable report; preserve rejected or unsupported evidence."""
    path = f"/v1/worker/tasks/{task_id}"
    try:
        client.request("POST", path + "/report", report)
    except APIError as exc:
        if exc.status == 409:
            try:
                remote = client.request("GET", path)
                if not _task_owner_matches(remote, owner_id):
                    journal.delivery_error(task_id, "recovery_binding_changed")
                    return False
                if remote["state"] == "unknown":
                    client.request("POST", path + "/reconcile", report)
                elif remote["state"] == "dispatched" and report["state"] == "unknown":
                    # A claim response may have been lost before execution.
                    # Starting here records a protocol acknowledgement only;
                    # the unknown report is persisted and no executor is run.
                    client.request("POST", path + "/start")
                    client.request("POST", path + "/report", report)
                else:
                    journal.delivery_error(task_id, "report_conflict")
                    return False
            except APIError as recovery_error:
                if recovery_error.status in (404, 405):
                    journal.delivery_error(task_id, "reconciliation_unsupported_or_missing")
                    return False
                if recovery_error.status == 409:
                    journal.delivery_error(task_id, "recovery_conflict")
                    return False
                if recovery_error.status in (400, 413, 422):
                    journal.delivery_error(task_id, "recovery_rejected")
                    return False
                raise
        elif exc.status in (400, 404, 405, 413, 422):
            journal.delivery_error(task_id, "report_rejected_or_missing")
            return False
        else:
            raise
    journal.acknowledge(task_id)
    return True


def _deliver_progress(client, task_id: str, progress: dict) -> bool:
    """Send observational output, never execution; older Controllers can omit it."""
    try:
        client.request("POST", f"/v1/worker/tasks/{task_id}/progress", progress)
    except APIError as exc:
        if exc.status in (404, 405):
            return False
        if exc.status == 409:
            # Cancellation/completion can win after the last heartbeat. The
            # normal task state and durable terminal report resolve that race.
            return True
        raise
    return True


def _deliver_isolated(client, journal_path, task_id, report, admit, owner_id):
    """Send one already completed result; a lost ACK is returned to the owner."""
    if not admit():
        return None
    journal = WorkerJournal(journal_path)
    try:
        # The executor normally committed this exact evidence. This also keeps
        # an executor/journal exception from ever becoming an undurable report.
        journal.finish(task_id, report)
        if not admit():
            return None
        return _deliver_report(client, journal, task_id, report, owner_id)
    finally:
        journal.db.close()


@dataclass
class _ActiveTask:
    """Polling-thread ownership of one execution and its durable acknowledgement."""

    task: dict
    cancel: threading.Event = field(default_factory=threading.Event)
    observation: dict = field(default_factory=lambda: {"state": "dispatched"})
    future: Future | None = None
    pending: dict | None = None
    progress_sequence: int = 0
    progress_sent: float = 0.0
    delivery_future: Future | None = None
    delivery_decided: bool = True
    delivery_lock: threading.Lock = field(default_factory=threading.Lock)


class _NotificationWatcher:
    """One passive observer on its own connection, never a task dispatcher."""

    def __init__(self, client, cursor: str, wake: threading.Event, *, kind: str = "legacy"):
        if kind not in {"legacy", "action"}:
            raise ValueError("Unsupported Worker notification kind")
        self.client = client.notification_client()
        self.cursor = cursor
        self.kind = kind
        self.wake = wake
        self.stop = threading.Event()
        self.disabled = False
        self.thread = threading.Thread(target=self._run, name="worker-notifications", daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while not self.stop.is_set():
                try:
                    observed_at = time.monotonic()
                    query = "kind=action&" if self.kind == "action" else ""
                    response = self.client.request(
                        "GET", f"/v1/worker/notifications?{query}cursor={self.cursor}&wait_ms=1000"
                    )
                    if (not isinstance(response, dict) or set(response) != {"cursor", "changed"}
                            or type(response.get("changed")) is not bool):
                        self.disabled = True
                        break
                    cursor = response.get("cursor")
                    if not isinstance(cursor, str) or not re.fullmatch(r"[a-f0-9]{32}\.\d{1,20}", cursor):
                        self.disabled = True
                        break
                    if response.get("changed") is True or cursor != self.cursor:
                        self.wake.set()
                    self.cursor = cursor
                    # A closing or faulty server may return an unchanged hint
                    # immediately instead of waiting. Bound that loop as well.
                    self.stop.wait(max(0, .05 - (time.monotonic() - observed_at)))
                except APIError as exc:
                    self.wake.set()
                    if exc.status in (400, 401, 403, 404, 405, 409, 422):
                        self.disabled = True
                        break
                    self.stop.wait(.5)
                except httpx.TransportError:
                    self.wake.set()
                    self.stop.wait(.5)
                except (ValueError, TypeError, RuntimeError):
                    # Malformed observational JSON or a closed notification
                    # transport never changes execution state. Restore the
                    # original authenticated polling path without a hot loop.
                    self.disabled = True
                    break
        finally:
            self.client.close()
            self.wake.set()

    def close(self):
        self.stop.set()
        # A healthy wait returns in <= 1 s. Closing the independent transport
        # also interrupts ordinary blocking reads without closing task I/O.
        self.client.close()
        self.thread.join(timeout=1.5)


def _notification_binding(heartbeat: dict) -> tuple[str, str] | None:
    """Prefer only explicitly negotiated actionable hints, with legacy fallback.

    A Worker's own acknowledged start is already known locally. Its generic
    device cursor change must not cause a new synchronous poll to get ahead of
    a fast executor's durable completion. Only a Controller advertising the
    exact separate protocol may omit those own-state hints; cancellation,
    revocation and new work remain actionable on that channel.
    """
    for kind, validator, capability, cursor_key in (
        ("action", valid_worker_action_notifications, "worker_action_notifications", "worker_action_cursor"),
        ("legacy", valid_task_notifications, "task_notifications", "notification_cursor"),
    ):
        cursor = heartbeat.get(cursor_key)
        if (validator(heartbeat.get(capability)) and isinstance(cursor, str)
                and re.fullmatch(r"[a-f0-9]{32}\.\d{1,20}", cursor)):
            return cursor, kind
    return None


def run_worker(
    config: dict,
    state_dir: Path,
    stop: threading.Event | None = None,
    poll_interval: float = 0.5,
    on_status: Callable[[str], None] | None = None,
) -> None:
    def status(value: str) -> None:
        if on_status is not None:
            try:
                on_status(value)
            except Exception:
                # Display/reporting callbacks must never interrupt task execution.
                pass

    stop = stop or threading.Event()
    policy = validate_policy(config["policy"])
    for root in policy["roots"].values():
        if state_dir.resolve().is_relative_to(Path(root).resolve()):
            raise ValueError("Worker state must be outside every authorized file root")
    identity = worker_execution_identity(config, state_dir)
    owner_id = identity["owner_id"]
    caps = runtime_capabilities(policy, identity)
    client = ControllerClient(config)
    journal = WorkerJournal(state_dir / "worker-journal.sqlite3")
    journal.recover_unfinished()
    pool = ThreadPoolExecutor(max_workers=MAX_ACTIVE_TASKS, thread_name_prefix="executor")
    active: dict[str, _ActiveTask] = {}
    last_contact = time.monotonic()
    progress_supported = True
    deferred_reports: set[str] = set()
    wake = threading.Event()
    notifications = None
    report_client = None
    report_pool = ThreadPoolExecutor(max_workers=MAX_ACTIVE_TASKS, thread_name_prefix="worker-report")
    report_isolation = False
    dispatch_wait = False
    report_stop = threading.Event()
    report_admission = threading.Lock()
    poll_supported = False
    capacity = 1

    def accept_claim(task) -> None:
        if not isinstance(task, dict) or task.get("target_device_id") != config["device_id"]:
            raise RuntimeError("Controller routed a task to the wrong device; worker stopped")
        lane = task_lane(task)
        lanes = {task_lane(item.task) for item in active.values()}
        if task["task_id"] in active or lane in lanes or lane == "legacy" and active or len(active) >= capacity:
            # A faulty/newer Controller cannot make local lanes overlap. The
            # claim is retained as unknown; it never becomes executable work.
            if task["task_id"] not in active and not journal.contains(task["task_id"]):
                journal.finish(task["task_id"], WorkerJournal.unconfirmed())
            raise RuntimeError("Controller dispatched an occupied task lane; worker stopped")
        active[task["task_id"]] = _ActiveTask(task)

    def cancel_active() -> None:
        for execution in active.values():
            execution.cancel.set()

    def collect_completed(task_id: str, execution: _ActiveTask) -> bool:
        if execution.future is None or not execution.future.done():
            return False
        # The executor thread's committed result is authoritative. A dedicated
        # report may already have ACKed and removed only an image/chunk copy;
        # never overwrite that same original evidence with the Future payload.
        execution.pending = journal.finished_report(task_id)
        if execution.pending is None:
            execution.pending = _observed_report(execution.future)
            journal.finish(task_id, execution.pending)
        execution.future = None
        return True

    def completed(task_id, execution, future):
        try:
            with report_admission, execution.delivery_lock:
                if (report_isolation and report_client is not None and not stop.is_set() and not report_stop.is_set()
                        and time.monotonic() - last_contact < 10):
                    execution.delivery_future = report_pool.submit(_deliver_isolated, report_client,
                        state_dir / "worker-journal.sqlite3", task_id, _observed_report(future),
                        lambda: not stop.is_set() and not report_stop.is_set() and time.monotonic() - last_contact < 10,
                        owner_id)
                    execution.delivery_future.add_done_callback(lambda _delivery: wake.set())
        except RuntimeError:
            # Shutdown can reject a pending callback's report submission. The
            # committed original evidence remains in the normal durable outbox.
            pass
        finally:
            with execution.delivery_lock:
                execution.delivery_decided = True
            wake.set()

    def set_report_isolation(value):
        nonlocal report_isolation
        # A rollback must observe every callback admitted under the old ACK
        # before a legacy /claim can run without active_task_ids protection.
        with report_admission:
            report_isolation = value

    def deliver_pending(task_id, execution):
        with execution.delivery_lock:
            if not execution.delivery_decided:
                return False
            delivery = execution.delivery_future
            if delivery is not None:
                if not delivery.done():
                    return False
                execution.delivery_future = None
        # Observe the sole attempt. On transport/ACK error, the caller keeps
        # its local lane and enters the ordinary authenticated poll path before
        # confirming this same report again. No executor is resubmitted.
        delivered = delivery.result() if delivery is not None else None
        if delivered is None:
            delivered = _deliver_report(client, journal, task_id, execution.pending, owner_id)
        if not delivered:
            deferred_reports.add(task_id)
            status("recovery_pending")
        return True

    try:
        while not stop.is_set():
            wake.clear()
            immediate = False
            using_poll = poll_supported
            poll_inflight, poll_isolation_sent = False, False
            waited_idle = False
            try:
                # Completion is already durable on the executor thread. Send
                # that original evidence before an unrelated heartbeat RTT;
                # its authenticated report transaction rechecks the Worker.
                # Only newly completed futures take this path. A lost report
                # ACK retains the local lane and goes through normal heartbeat
                # observation before another attempt with the same evidence.
                if time.monotonic() - last_contact < 10:
                    for task_id, execution in list(active.items()):
                        if stop.is_set() or time.monotonic() - last_contact >= 10:
                            break
                        if (not collect_completed(task_id, execution)
                                and not (execution.pending is not None and execution.delivery_future is not None)):
                            continue
                        if deliver_pending(task_id, execution):
                            del active[task_id]
                if stop.is_set():
                    break
                claimed = None
                if using_poll:
                    want_claim = (len(active) < capacity and not any(
                        task_lane(item.task) == "legacy" or item.pending is not None
                        or not report_isolation and item.delivery_future is not None
                        for item in active.values()
                    ))
                    # A report may already be committed while its ACK is lost.
                    # Keep the local lane until its original report is confirmed,
                    # before the Controller can offer new work in that lane.
                    poll_body = {
                        "capabilities": caps, "worker_version": __version__, "claim": want_claim,
                    }
                    if report_isolation:
                        poll_body["active_task_ids"] = list(active)
                        poll_isolation_sent = True
                    idle = want_claim and not active and not deferred_reports and not journal.pending()
                    wait_ms = 5000 if dispatch_wait and idle else 0
                    poll_path = client.worker_poll_path(wait_ms) if wait_ms else "/v1/worker/poll"
                    poll_inflight = True
                    poll_started = time.monotonic()
                    heartbeat = client.request("POST", poll_path, poll_body)
                    poll_inflight = False
                    waited_idle = bool(wait_ms and time.monotonic() - poll_started >= wait_ms / 1000 - .5)
                    if not isinstance(heartbeat, dict) or "task" not in heartbeat:
                        raise RuntimeError("Controller returned an invalid Worker poll response")
                    claimed = heartbeat["task"]
                    if claimed is not None and (not want_claim or not isinstance(claimed, dict)
                                                or claimed.get("state") != "dispatched"):
                        raise RuntimeError("Controller returned an invalid original task claim")
                else:
                    heartbeat = send_heartbeat(client, caps)
                last_contact = time.monotonic()
                poll_supported = (not getattr(client, "_legacy_worker_poll", False)
                                  and valid_worker_poll(heartbeat.get("worker_poll")))
                supported_report = (poll_supported and not getattr(client, "_legacy_worker_report_isolation", False)
                                    and valid_report_isolation(heartbeat.get("worker_report_isolation")))
                if supported_report and report_client is None:
                    create = getattr(client, "reporting_client", None)
                    if callable(create):
                        report_client = create()
                set_report_isolation(supported_report and report_client is not None)
                dispatch_wait = (not getattr(client, "_legacy_worker_dispatch_wait", False)
                                 and valid_dispatch_wait(heartbeat.get("worker_dispatch_wait"))
                                 and callable(getattr(client, "worker_poll_path", None)))
                if stop.is_set():
                    break
                # Both peers must explicitly agree on this fixed classifier.
                # An older Controller simply omits the ACK and remains serial.
                capacity = heartbeat["task_concurrency"]["max_active"] if valid_task_concurrency(heartbeat.get("task_concurrency")) else 1
                if notifications is None and callable(getattr(client, "notification_client", None)):
                    binding = _notification_binding(heartbeat)
                    if binding is not None:
                        cursor, kind = binding
                        notifications = _NotificationWatcher(client, cursor, wake, kind=kind)
                status("executing" if any(item.future for item in active.values()) else "connected")
                states = {t["id"]: t["state"] for t in heartbeat["tasks"]}
                if claimed is not None:
                    accept_claim(claimed)
                    # The claim committed after this heartbeat snapshot. /start
                    # still rechecks revocation/cancellation in its transaction;
                    # execution still needs its ACK then durable journal.begin.
                    states[claimed["task_id"]] = "dispatched"
                for task_id, execution in list(active.items()):
                    if stop.is_set():
                        break
                    remote_state = states.get(task_id)
                    if remote_state is None:
                        # Heartbeat history is bounded.  Never infer permission
                        # to continue execution from a missing heartbeat row.
                        remote_state = client.request(
                            "GET", f"/v1/worker/tasks/{task_id}"
                        )["state"]
                    if remote_state == "cancelling" or remote_state in TERMINAL_STATES:
                        execution.cancel.set()
                    execution.observation["state"] = remote_state
                    if execution.future is None and execution.pending is None:
                        if remote_state in TERMINAL_STATES:
                            execution.pending = journal.begin(task_id) or WorkerJournal.unconfirmed()
                            journal.finish(task_id, execution.pending)
                        elif remote_state == "cancelling":
                            execution.pending = {
                                "state": "cancelled",
                                "result": None,
                                "error": {
                                    "code": "cancelled_before_start",
                                    "message": "Cancelled before execution",
                                },
                            }
                            journal.finish(task_id, execution.pending)
                        else:
                            # start is idempotent; execution begins only after a confirmed response.
                            if execution.task.get("target_device_id") != config["device_id"]:
                                raise RuntimeError(
                                    "Controller routed a task to the wrong device; worker stopped"
                                )
                            if not _task_owner_matches(execution.task, owner_id):
                                raise RuntimeError("Controller routed a task outside this worker binding.")
                            started = client.request("POST", f"/v1/worker/tasks/{task_id}/start")
                            if execution.task.get("expected_execution_owner_id") is not None and (
                                not isinstance(started, dict)
                                or started.get("task_id") != task_id
                                or started.get("target_device_id") != config["device_id"]
                                or started.get("expected_execution_owner_id") != owner_id
                                or started.get("state") != "running"
                            ):
                                raise RuntimeError("Controller did not confirm the original worker binding.")
                            old_report = journal.begin(task_id)
                            if old_report:
                                execution.pending = old_report
                            else:
                                allowed_fields = {
                                    k: execution.task[k] for k in TaskRequest.model_fields if k in execution.task
                                }
                                validated = TaskRequest.model_validate(allowed_fields).model_dump()
                                validated["task_id"] = task_id
                                execution.cancel.clear()
                                execution.delivery_decided = False
                                execution.future = pool.submit(
                                    _execute_durably,
                                    validated,
                                    policy,
                                    execution.cancel,
                                    state_dir / "worker-journal.sqlite3",
                                    execution.observation,
                                )
                                execution.future.add_done_callback(lambda future, task_id=task_id, execution=execution:
                                    completed(task_id, execution, future))
                                status("executing")
                    collect_completed(task_id, execution)
                    if execution.future is not None and progress_supported and remote_state == "running":
                        progress = execution.observation.get("progress")
                        if (isinstance(progress, dict) and progress.get("sequence", 0) > execution.progress_sequence
                                and time.monotonic() - execution.progress_sent >= 1):
                            progress_supported = _deliver_progress(client, task_id, progress)
                            execution.progress_sequence = progress["sequence"]
                            execution.progress_sent = time.monotonic()
                    if execution.pending is not None:
                        if not deliver_pending(task_id, execution):
                            continue
                        del active[task_id]
                        # One completed reconciliation can free a lane. Observe
                        # a new authenticated poll promptly, without idle spins
                        # or replaying the execution whose report was just sent.
                        immediate = using_poll
                # A prior process (or a lost claim ACK) can leave work on the
                # Controller without a local execution. This scan must exclude
                # all currently owned tasks, even those not yet started.
                for task_id, remote_state in states.items():
                    if (task_id not in active and remote_state in ("dispatched", "running", "cancelling")
                            and not journal.contains(task_id)):
                        remote = client.request("GET", f"/v1/worker/tasks/{task_id}")
                        if remote.get("target_device_id") != config["device_id"]:
                            raise RuntimeError("Controller routed a task to the wrong device; worker stopped")
                        journal.finish(task_id, WorkerJournal.unconfirmed())
                outbox = journal.pending(deferred_reports | set(active), limit=1)
                if outbox:
                    task_id, report = outbox[0]
                    if not _deliver_report(client, journal, task_id, report, owner_id):
                        deferred_reports.add(task_id)
                        status("recovery_pending")
                lanes = {task_lane(item.task) for item in active.values()}
                if (not using_poll and len(active) < capacity and "legacy" not in lanes and not stop.is_set()
                        and not any(item.pending is not None or item.delivery_future is not None
                                    for item in active.values())):
                    task = client.request("POST", "/v1/worker/claim")["task"]
                    if task:
                        accept_claim(task)
                        immediate = notifications is not None and not notifications.disabled
                if (waited_idle and dispatch_wait and claimed is None and not active
                        and not deferred_reports and not journal.pending()):
                    # A completed idle wait already provided the pacing. Arm
                    # the next one without an extra idle gap. Only a response
                    # near the requested deadline qualifies; early/closing
                    # empty responses still fall through to the watchdog.
                    immediate = True
            except APIError as exc:
                status("reconnecting")
                if (using_poll and poll_inflight and poll_isolation_sent and exc.status == 422
                        and exc.code == "invalid_request_schema"):
                    # An older/rolled-back Controller rejected the new body
                    # before dispatch. Disable the extra field and async path;
                    # any already attempted report retains its original lane.
                    client._legacy_worker_report_isolation = True
                    set_report_isolation(False)
                    continue
                if using_poll and exc.status in (404, 405):
                    # A rolled-back Controller may no longer implement /poll.
                    # Observe its next heartbeat before a separate legacy claim;
                    # never immediately retry a possibly accepted dispatch.
                    client._legacy_worker_poll = True
                    poll_supported = False
                    set_report_isolation(False)
                    continue
                if exc.status in (401, 403):
                    cancel_active()
                    raise WorkerAccessEnded() from None
                if exc.status not in (409, 429, 500, 502, 503, 504):
                    cancel_active()
                    raise RuntimeError(f"Worker protocol rejected: {exc.code}") from None
            except httpx.TransportError:
                status("reconnecting")
                # A lost acknowledgement never causes a second execution. Reconnect/lease recovery resolves it.
                if time.monotonic() - last_contact >= 10:
                    cancel_active()
            if time.monotonic() - last_contact >= 10:
                # Current-user commands cannot outlive the authenticated contact lease.
                cancel_active()
            if immediate:
                continue
            if notifications is not None and not notifications.disabled:
                # Server task changes and durable executor completion wake
                # immediately. A 1 s watchdog retains heartbeat/lease/progress
                # and missed-hint recovery; no mutation is retried by a hint.
                deadline = time.monotonic() + 1
                while not stop.is_set() and not wake.is_set() and time.monotonic() < deadline:
                    wake.wait(min(.05, max(0, deadline - time.monotonic())))
            else:
                stop.wait(poll_interval)
    finally:
        status("stopping")
        report_stop.set()
        if notifications is not None:
            notifications.close()
        cancel_active()
        pool.shutdown(wait=True, cancel_futures=True)
        report_pool.shutdown(wait=True, cancel_futures=True)
        if report_client is not None:
            report_client.close()
        for task_id, execution in active.items():
            if execution.future is not None:
                # Every lane retains independent evidence even if another lane
                # failed, the polling thread lost contact or the GUI closed.
                if journal.finished_report(task_id) is None:
                    journal.finish(task_id, _observed_report(execution.future))
            elif not journal.contains(task_id):
                # A normal close may win after claim but before confirmed
                # start. Retain this claim as an execution barrier as well.
                journal.finish(task_id, WorkerJournal.unconfirmed())
        journal.db.close()
        client.close()
        status("stopped")
