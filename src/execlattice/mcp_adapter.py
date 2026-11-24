"""Official MCP SDK stdio adapter, with the same authenticated task API as CLI."""

import base64
from pathlib import Path
from uuid import UUID

from . import __version__
from .client import ControllerClient
from .execution_outcome import public_task_receipt
from .protocol import TaskRequest


def create_mcp(client: ControllerClient):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        "ExecLattice",
        version=__version__,
        log_level="WARNING",
        instructions="Use list_devices to check the file and command capabilities of paired workers. "
        "Full access runs with the current Windows user's permissions. "
        "unknown means execution is unconfirmed; never blindly resubmit a task.",
    )

    def submit(body: TaskRequest) -> dict:
        return public_task_receipt(client.request("POST", "/v1/tasks", body.model_dump()))

    @server.tool()
    def list_devices() -> list[dict]:
        """List authorized devices and their actual declared capabilities."""
        return client.request("GET", "/v1/devices")

    @server.tool()
    def submit_command(
        device_id: str, profile: str, timeout_seconds: int = 30, idempotency_key: str | None = None
    ) -> dict:
        """Queue a locally approved fixed command profile. Caller arguments are forbidden."""
        body = TaskRequest(
            target_device_id=device_id,
            executor_type="command",
            action="run",
            parameters={"profile": profile},
            timeout_seconds=timeout_seconds,
            idempotency_key=idempotency_key,
        )
        return submit(body)

    @server.tool()
    def read_file(device_id: str, root: str, path: str, idempotency_key: str | None = None) -> dict:
        """Queue a bounded read of a relative path inside an authorized root alias."""
        body = TaskRequest(
            target_device_id=device_id,
            executor_type="file",
            action="read",
            parameters={"root": root, "path": path},
            idempotency_key=idempotency_key,
        )
        return submit(body)

    def project_task(device_id, action, parameters, idempotency_key=None):
        body = TaskRequest(target_device_id=device_id, executor_type="workspace", action=action,
                           parameters=parameters, idempotency_key=idempotency_key)
        return submit(body)

    @server.tool()
    def list_directory(device_id: str, path: str = "", limit: int = 300, idempotency_key: str | None = None) -> dict:
        """List an absolute remote local directory; empty path lists available drives. Returns a task ID."""
        return project_task(device_id, "list", {"path": path, "limit": limit}, idempotency_key)

    @server.tool()
    def search_files(device_id: str, path: str, query: str, glob: str = "*", case_sensitive: bool = False,
                     max_results: int = 100, idempotency_key: str | None = None) -> dict:
        """Search remote UTF-8 project text with bounded literal matches. Query the returned task ID."""
        return project_task(device_id, "search", {"path": path, "query": query, "glob": glob,
                            "case_sensitive": case_sensitive, "max_results": max_results}, idempotency_key)

    @server.tool()
    def read_project_file(device_id: str, path: str, idempotency_key: str | None = None) -> dict:
        """Read a remote UTF-8 text file up to 64 KiB; get_task returns exact bytes and SHA-256."""
        return project_task(device_id, "read", {"path": path}, idempotency_key)

    @server.tool()
    def write_project_file(device_id: str, path: str, content: str, expected_sha256: str | None = None,
                           idempotency_key: str | None = None) -> dict:
        """Write UTF-8 text in full mode. Null expected_sha256 creates only; existing files require the read hash."""
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return project_task(device_id, "write", {"path": path, "content_b64": encoded,
                            "expected_sha256": expected_sha256}, idempotency_key)

    @server.tool()
    def run_development_command(device_id: str, command: str, cwd: str, timeout_seconds: int = 30,
                                idempotency_key: str | None = None) -> dict:
        """Run a command as the remote current user in full mode; get_task gives real exit code/output. No elevation."""
        body = TaskRequest(target_device_id=device_id, executor_type="development", action="run",
                           parameters={"command": command, "cwd": cwd}, timeout_seconds=timeout_seconds,
                           idempotency_key=idempotency_key)
        return submit(body)

    @server.tool()
    def get_task(task_id: str) -> dict:
        """Get the original task state, command exit code, output, and file evidence."""
        return public_task_receipt(client.request("GET", f"/v1/tasks/{UUID(task_id)}"))

    @server.tool()
    def cancel_task(task_id: str) -> dict:
        """Request cancellation and return the task's current state."""
        return public_task_receipt(client.request("POST", f"/v1/tasks/{UUID(task_id)}/cancel"))

    return server


def run_mcp(config_path: Path) -> None:
    client = ControllerClient.from_file(config_path)
    try:
        create_mcp(client).run(transport="stdio")
    finally:
        client.close()
