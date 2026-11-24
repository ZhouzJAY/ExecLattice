"""Reproducible real-process HTTPS/MCP demonstration; no other device is simulated."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from execlattice.lan_sdk import LanSdkError, LanSession

from execlattice.cli import init_controller, init_worker
from execlattice.client import APIError, ControllerClient
from execlattice.protocol import TaskRequest, utc_now
from execlattice.security import read_json, tls_context
from execlattice.store import Store
from execlattice.worker import pairing_request

PROJECT = Path(__file__).resolve().parents[1]
PREVIEW_SOURCE = (PROJECT / "src").resolve()


def isolated_env():
    return {**os.environ, "PYTHONPATH": str(PREVIEW_SOURCE), "PYTHONDONTWRITEBYTECODE": "1"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_process(*args: str, log):
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    return subprocess.Popen(
        [sys.executable, "-m", "execlattice", *args],
        cwd=PROJECT,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        env=isolated_env(),
        **options,
    )


async def mcp_check(config: Path, device_id: str, workspace: Path) -> dict:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "execlattice", "mcp", "--config", str(config)], cwd=PROJECT,
        env={"PYTHONPATH": str(PREVIEW_SOURCE), "PYTHONDONTWRITEBYTECODE": "1"},
    )

    async def receipt(client, name, arguments):
        reply = await client.call_tool(name, arguments)
        assert not reply.is_error, f"MCP request failed for {name}"
        payload = reply.structured_content
        if not payload or "task_id" not in payload:
            payload = json.loads(next(item.text for item in reply.content if hasattr(item, "text")))
        assert not ({"parameters", "idempotency_key", "requested_by", "audit_ref", "authorization_context"}
                    & payload.keys()), "MCP receipt repeated internal request data"
        assert payload["execution_outcome"]["recovery"]["automatic_resubmit"] is False
        return payload

    async with Client(params) as client:
        tools = await client.list_tools()
        result = await client.call_tool("list_devices", {})
        assert not result.is_error, "MCP list_devices failed"
        assert device_id in result.model_dump_json(), "MCP result omitted actual worker"
        task_id = (await receipt(
            client,
            "submit_command",
            {"device_id": device_id, "profile": "python-version", "idempotency_key": "demo-mcp-command"},
        ))["task_id"]
        output = workspace / "mcp-result.txt"
        content = "Sample approved write\n"
        write_id = (await receipt(client, "write_project_file", {
            "device_id": device_id,
            "path": str(output),
            "content": content,
            "idempotency_key": "demo-mcp-write",
        }))["task_id"]
        # Close the submitting MCP connection. The original task ID is sufficient
        # to recover the result from a new authenticated client.
    operator = ControllerClient.from_file(config)
    try:
        task = await asyncio.to_thread(operator.wait, task_id, 15)
        write = await asyncio.to_thread(operator.wait, write_id, 15)
        assert task["state"] == "succeeded", (task["state"], task.get("error", {}).get("code"))
        assert write["state"] == "succeeded", (write["state"], write.get("error", {}).get("code"))
        assert output.read_bytes() == content.encode()
        assert write["result"]["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    finally:
        operator.close()
    async with Client(params) as client:
        reproduced = await receipt(client, "get_task", {"task_id": write_id})
        assert reproduced["task_id"] == write_id and reproduced["result"]["sha256"] == write["result"]["sha256"]
        command = await receipt(client, "get_task", {"task_id": task_id})
        assert command["execution_outcome"]["execution"]["exit_code"] == 0
    return {
        "transport": "official-sdk-stdio",
        "tools": sorted(tool.name for tool in tools.tools),
        "task_id": task_id,
        "state": task["state"],
        "exit_code": task["result"]["exit_code"],
        "write_original_recovered": True,
        "write_sha256_verified": True,
        "receipt_projection_verified": True,
    }


def sdk_check(config: Path, device_id: str, workspace: Path, admin: ControllerClient) -> dict:
    operation = "sdk-demo-operation"
    with LanSession.open(config, device_id) as original:
        owner = original.execution_owner_id
        task = original.submit(operation, "command", "run", {"profile": "demo-sdk"})
        task_id = task["task_id"]
        deadline = time.monotonic() + 10
        while original.get_task(task_id)["state"] != "running":
            assert time.monotonic() < deadline, "SDK task did not start"
            time.sleep(0.05)
    wrong_owner = "1" * 32 if owner == "0" * 32 else "0" * 32
    try:
        with LanSession.open(config, device_id, expected_execution_owner_id=wrong_owner):
            raise AssertionError("SDK accepted an incorrect device owner")
    except LanSdkError as exc:
        assert exc.code == "device_binding_changed"
    with LanSession.open(config, device_id, expected_execution_owner_id=owner) as resumed:
        observed = resumed.query_original(operation)
        assert observed["task_id"] == task_id and observed["state"] == "running"
        (workspace / "sdk-release.txt").touch()
        receipt = resumed.wait(operation, timeout_seconds=15)
        assert receipt["state"] == "succeeded" and receipt["task_id"] == task_id
        assert receipt["result"]["exit_code"] == 0
        assert "Original SDK operation finished" in receipt["result"]["stdout"]
        assert (workspace / "sdk-executions.txt").read_text(encoding="utf-8").splitlines() == ["one"]
        audit = admin.request("GET", "/v1/audit")
        events = [event["event"] for event in audit if event["resource"] == task_id]
        assert events.count("task_queued") == events.count("task_running") == 1
        admin.request("POST", f"/v1/devices/{device_id}/revoke")
        assert resumed.query_original(operation) == receipt
        assert resumed.get_task(task_id) == receipt
        try:
            resumed.submit("sdk-revoked-operation", "file", "read", {"root": "workspace", "path": "sample.txt"})
            raise AssertionError("SDK accepted new work after revocation")
        except LanSdkError as exc:
            assert (exc.code, exc.status) == ("device_not_found", 404)
    return {
        "reconnected_while_running": True,
        "queried_same_task": True,
        "execution_count": 1,
        "wrong_owner_rejected": True,
        "read_receipt_after_revocation": True,
        "new_task_rejected_after_revocation": True,
    }


def run_demo(run_dir: Path | None = None) -> dict:
    if run_dir is None:
        demo_root = PROJECT / ".demo"
        demo_root.mkdir(exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=demo_root))
    else:
        run_dir.mkdir(parents=True, exist_ok=True)
    run_dir = run_dir.resolve()
    runtime = run_dir / "runtime"
    controller_state = runtime / "controller"
    worker_state = runtime / "worker"
    workspace = run_dir / "workspace"
    workspace.mkdir()
    content = "ExecLattice actual HTTPS file evidence / 文件校验\n".encode()
    (workspace / "sample.txt").write_bytes(content)
    for filename, code in {
        "ok.py": "print('actual worker output')\n",
        "fail.py": "import sys\nprint('diagnostic', file=sys.stderr)\nsys.exit(7)\n",
        "slow.py": "import time\ntime.sleep(20)\n",
        "sdk.py": (
            "from pathlib import Path\nimport time\n"
            "while not Path('sdk-release.txt').exists():\n    time.sleep(0.05)\n"
            "with Path('sdk-executions.txt').open('a', encoding='utf-8') as count:\n"
            "    count.write('one\\n')\n"
            "print('Original SDK operation finished')\n"
        ),
    }.items():
        (workspace / filename).write_text(code, encoding="utf-8")
    port = free_port()
    url = f"https://127.0.0.1:{port}"
    init_controller(controller_state, url, [])
    initialized = init_worker(
        worker_state, url, controller_state / "server-cert.pem", workspace, "local-demo-worker",
        access_mode="full",
    )
    config_path = worker_state / "worker.json"
    config = read_json(config_path)
    for profile, filename in [
        ("demo-ok", "ok.py"), ("demo-fail", "fail.py"), ("demo-slow", "slow.py"), ("demo-sdk", "sdk.py"),
    ]:
        config["policy"]["commands"][profile] = {
            "argv": [sys.executable, str(workspace / filename)],
            "cwd": "workspace",
        }
    # This file was created in the current run and remains under the protected Worker ACL.
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    store = Store(controller_state / "controller.sqlite3")
    log = (run_dir / "process.log").open("wb")
    processes = []
    operator = admin = worker_client = None
    try:
        processes.append(
            start_process("controller", "--state", str(controller_state), "--port", str(port), log=log)
        )
        operator = ControllerClient.from_file(controller_state / "client.json")
        admin = ControllerClient.from_file(controller_state / "admin.json")
        for _ in range(100):
            if processes[0].poll() is not None:
                raise RuntimeError("Demo controller exited; see private process log")
            try:
                operator.request("GET", "/health")
                break
            except httpx.TransportError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Demo controller did not become ready")
        code = store.pairing_code(config["device_id"])
        worker_client = ControllerClient(config)
        device = worker_client.request("POST", "/v1/pair", pairing_request(config, code))
        assert device["device_id"] == initialized["device_id"]
        try:
            worker_client.request("POST", "/v1/pair", pairing_request(config, code))
            raise AssertionError("Pairing code was reused")
        except APIError as exc:
            assert exc.status == 403
        processes.append(start_process("worker", "--config", str(config_path), log=log))

        def submit(executor: str, params: dict, timeout: int = 10, idem: str | None = None):
            return operator.request(
                "POST",
                "/v1/tasks",
                TaskRequest(
                    target_device_id=config["device_id"],
                    executor_type=executor,
                    action="run" if executor == "command" else "read",
                    parameters=params,
                    timeout_seconds=timeout,
                    idempotency_key=idem,
                ).model_dump(),
            )

        tasks = {}
        command = submit("command", {"profile": "demo-ok"}, idem="demo-command-unique")
        repeated = submit("command", {"profile": "demo-ok"}, idem="demo-command-unique")
        assert repeated["task_id"] == command["task_id"]
        command = operator.wait(command["task_id"], 15)
        assert command["state"] == "succeeded", command
        assert command["result"]["exit_code"] == 0 and "actual worker output" in command["result"]["stdout"]
        tasks["command"] = {
            "task_id": command["task_id"],
            "state": command["state"],
            "exit_code": command["result"]["exit_code"],
            "stdout": command["result"]["stdout"],
        }
        file_task = submit("file", {"root": "workspace", "path": "sample.txt"})
        file_task = operator.wait(file_task["task_id"], 15)
        assert file_task["state"] == "succeeded", file_task
        assert base64.b64decode(file_task["result"]["content_b64"]) == content
        assert file_task["result"]["sha256"] == hashlib.sha256(content).hexdigest()
        tasks["file"] = {
            "task_id": file_task["task_id"],
            "state": file_task["state"],
            "sha256": file_task["result"]["sha256"],
            "size_bytes": len(content),
        }
        for label, profile, timeout, expected in [
            ("nonzero_exit", "demo-fail", 10, "failed"),
            ("timeout", "demo-slow", 1, "timed_out"),
        ]:
            task = submit("command", {"profile": profile}, timeout)
            task = operator.wait(task["task_id"], timeout + 15)
            assert task["state"] == expected, task
            if label == "nonzero_exit":
                assert task["result"]["exit_code"] == 7
            tasks[label] = {"task_id": task["task_id"], "state": task["state"], "error": task["error"]}
        # Cancellation while a real process is running.
        task = submit("command", {"profile": "demo-slow"}, 20)
        for _ in range(100):
            observed = operator.request("GET", f"/v1/tasks/{task['task_id']}")
            if observed["state"] == "running":
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Worker did not start cancellable process")
        operator.request("POST", f"/v1/tasks/{task['task_id']}/cancel")
        task = operator.wait(task["task_id"], 15)
        assert task["state"] == "cancelled", task
        tasks["cancel"] = {"task_id": task["task_id"], "state": task["state"]}
        denied = submit("file", {"root": "workspace", "path": "../controller/admin.json"})
        denied = operator.wait(denied["task_id"], 15)
        assert denied["state"] == "failed" and denied["error"]["code"] == "POLICY_DENIED"
        tasks["path_escape"] = {
            "task_id": denied["task_id"],
            "state": denied["state"],
            "error": denied["error"],
        }
        try:
            submit("command", {"profile": "powershell-arbitrary"})
            raise AssertionError("Unauthorized profile accepted")
        except APIError as exc:
            assert exc.status == 403
        private_read = operator.request("POST", "/v1/tasks", TaskRequest(
            target_device_id=config["device_id"],
            executor_type="workspace",
            action="read",
            parameters={"path": str(controller_state / "admin.json")},
        ).model_dump())
        private_read = operator.wait(private_read["task_id"], 15)
        assert private_read["state"] == "failed" and private_read["error"]["code"] == "POLICY_DENIED"
        with httpx.Client(
            verify=tls_context(str(controller_state / "server-cert.pem")), trust_env=False
        ) as raw:
            assert raw.get(url + "/v1/devices").status_code == 401
        untrusted_tls_rejected = False
        try:
            with httpx.Client(trust_env=False) as untrusted:
                untrusted.get(url + "/health")
        except httpx.ConnectError:
            untrusted_tls_rejected = True
        assert untrusted_tls_rejected
        mcp = asyncio.run(mcp_check(controller_state / "client.json", config["device_id"], workspace))
        sdk = sdk_check(controller_state / "client.json", config["device_id"], workspace, admin)
        audit = admin.request("GET", "/v1/audit")
        audit_text = json.dumps(audit)
        for secret in (code, config["token"], read_json(controller_state / "admin.json")["token"]):
            assert secret not in audit_text
        try:
            worker_client.request("POST", "/v1/worker/heartbeat", {"capabilities": device["capabilities"]})
            raise AssertionError("Revoked worker authenticated")
        except APIError as exc:
            assert exc.status == 401
        assert processes[1].wait(timeout=15) == 1
        worker_log = (run_dir / "process.log").read_bytes()
        assert b"Worker credential rejected or revoked; execution stopped" in worker_log
        assert b"ModuleNotFoundError" not in worker_log and b"Traceback" not in worker_log
        report = {
            "recorded_at": utc_now(),
            "scope": "one Windows host; independent Controller, Worker and MCP processes",
            "host_os": platform.system(),
            "python": platform.python_version(),
            "controller_url": url,
            "tls_verified": True,
            "untrusted_tls_rejected": True,
            "pairing_single_use": True,
            "idempotency_verified": True,
            "unauthenticated_rejected": True,
            "unauthorized_profile_rejected": True,
            "runtime_file_rejected": True,
            "revocation_verified": True,
            "worker_stopped_cleanly_after_revocation": True,
            "audit_secret_scan_passed": True,
            "audit_events": len(audit),
            "tasks": tasks,
            "mcp": mcp,
            "sdk": sdk,
            "limitations": [
                "No second Windows device connected",
                "No cross-network or Linux/macOS validation",
            ],
        }
        (run_dir / "evidence.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return report
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for client in (operator, admin, worker_client):
            if client:
                client.close()
        log.close()


if __name__ == "__main__":
    import argparse

    import execlattice

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-root", type=Path, required=True)
    args = parser.parse_args()
    if not Path(execlattice.__file__).resolve().is_relative_to(PREVIEW_SOURCE):
        parser.error("Start with PYTHONPATH set to this preview's src directory")
    with tempfile.TemporaryDirectory(prefix="execlattice-lan-", dir=args.scratch_root) as folder:
        report = run_demo(Path(folder))
    output = {
        "scope": report["scope"],
        "pair_once": report["pairing_single_use"],
        "strict_tls": report["tls_verified"] and report["untrusted_tls_rejected"],
        "tasks": {name: task["state"] for name, task in report["tasks"].items()},
        "mcp_command": report["mcp"]["state"],
        "mcp_write_original_recovered": report["mcp"]["write_original_recovered"],
        "mcp_write_sha256_verified": report["mcp"]["write_sha256_verified"],
        "mcp_receipt_projection_verified": report["mcp"]["receipt_projection_verified"],
        "sdk": report["sdk"],
        "runtime_file_rejected": report["runtime_file_rejected"],
        "revocation_verified": report["revocation_verified"],
        "worker_stopped_cleanly_after_revocation": report["worker_stopped_cleanly_after_revocation"],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
