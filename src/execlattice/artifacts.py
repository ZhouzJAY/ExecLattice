"""Explicit local result export and offline content retention; never retries execution."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from .protocol import TERMINAL_STATES, utc_now
from .security import _reject_link_ancestors, protect_directory, write_private_json


def _bytes(value: dict, key: str, digest_key: str, limit: int = 65536) -> bytes:
    try:
        data = base64.b64decode(value[key], validate=True)
        if len(data) > limit or hashlib.sha256(data).hexdigest() != value[digest_key]:
            raise ValueError()
        return data
    except (KeyError, TypeError, ValueError):
        raise ValueError("Result content failed integrity verification") from None


def export_result(task: dict, directory: Path, *, recovery: bool = False) -> dict:
    """Create a new private directory only after all content has been checked."""
    task_id = str(UUID(task["task_id"]))
    evidence = task.get("recovery_evidence") if recovery else task
    if not evidence or not isinstance(evidence.get("result"), dict):
        raise ValueError("No retained result content for the selected evidence")
    result = evidence["result"]
    files: dict[str, bytes] = {}
    if task["executor_type"] == "file":
        content = _bytes(result, "content_b64", "sha256")
        if type(result.get("size_bytes")) is not int or len(content) != result["size_bytes"]:
            raise ValueError("Result content failed integrity verification")
        files["content.bin"] = content
    else:
        for stream in ("stdout", "stderr"):
            # M1 default executor has raw bytes; legacy reports may contain text only.
            if stream + "_b64" in result:
                files[stream + ".bin"] = _bytes(result, stream + "_b64", stream + "_sha256")
            else:
                value = result.get(stream)
                if not isinstance(value, str):
                    raise ValueError("Result content failed integrity verification")
                files[stream + ".bin"] = value.encode("utf-8")
        if sum(map(len, files.values())) > 65536:
            raise ValueError("Result content exceeds the export limit")
    directory = Path(os.path.abspath(directory))
    _reject_link_ancestors(directory)
    if directory.exists():
        raise ValueError("Export directory must be new; existing files are never overwritten")
    directory = protect_directory(directory)
    metadata = []
    for name, content in files.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)
        metadata.append({"name": name, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    manifest = {
        "task_id": task_id,
        "task_state": task["state"],
        "evidence": "recovery" if recovery else "terminal_report",
        "reported_state": evidence["state"],
        "exported_at": utc_now(),
        "files": metadata,
    }
    write_private_json(directory / "manifest.json", manifest)
    return {"directory": str(directory), **manifest}


def _cutoff(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment > datetime.now(timezone.utc):
            raise ValueError()
        return moment.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        raise ValueError("Retention cutoff must be a past ISO timestamp with timezone") from None


def prune_results(state: Path, before: str, *, apply: bool = False) -> dict:
    """Caller must hold controller.lock; no directories or credentials are deleted.

    Clear logical result bodies only. SQLite free pages, backups, exports and the
    independent Worker journal require their own retention; this is not secure erasure.
    """
    state = Path(os.path.abspath(state))
    _reject_link_ancestors(state)
    path = state / "controller.sqlite3"
    _reject_link_ancestors(path)
    if not path.is_file():
        raise ValueError("Initialize this controller first")
    cutoff = _cutoff(before)
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        recovery_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='recovery_evidence'"
        ).fetchone()
        selected = []
        total_bytes = 0
        for row in db.execute(
            "SELECT * FROM tasks WHERE NOT EXISTS "
            "(SELECT 1 FROM audit WHERE resource=tasks.id AND at>=?) ORDER BY rowid", (cutoff,)
        ).fetchall():
            doc = json.loads(row["document"])
            if row["state"] not in TERMINAL_STATES or doc["created_at"] >= cutoff:
                continue
            stored = db.execute("SELECT document FROM results WHERE task_id=?", (row["id"],)).fetchone()
            normal = json.loads(stored["document"]) if stored else None
            saved = db.execute(
                "SELECT document FROM recovery_evidence WHERE task_id=?", (row["id"],)
            ).fetchone() if recovery_table else None
            late = json.loads(saved["document"]) if saved else None
            if normal is None and (not late or late.get("result") is None):
                continue
            selected.append(row["id"])
            # Only hashes and storage length enter the retention manifest, never content.
            bodies = {"terminal_report": normal, "recovery": late.get("result") if late else None}
            fingerprints = {}
            for source, body in bodies.items():
                if body is not None:
                    encoded = json.dumps(body, sort_keys=True).encode("utf-8")
                    total_bytes += len(encoded)
                    fingerprints[source] = {"sha256": hashlib.sha256(encoded).hexdigest(), "json_bytes": len(encoded)}
            if apply:
                now = utc_now()
                db.execute("UPDATE results SET document='null' WHERE task_id=?", (row["id"],))
                if late and late.get("result") is not None:
                    late.update(result=None, content_removed_at=now)
                    db.execute(
                        "UPDATE recovery_evidence SET document=? WHERE task_id=?",
                        (json.dumps(late), row["id"]),
                    )
                doc["result_retention"] = {"content_removed_at": now, "bodies": fingerprints}
                db.execute("UPDATE tasks SET document=? WHERE id=?", (json.dumps(doc), row["id"]))
                db.execute(
                    "INSERT INTO audit(at,actor,event,resource,detail) VALUES(?,?,?,?,?)",
                    (now, "local-admin", "result_content_removed", row["id"], "Explicit offline retention"),
                )
    return {"applied": apply, "before": cutoff, "task_ids": selected, "task_count": len(selected), "json_bytes": total_bytes}
