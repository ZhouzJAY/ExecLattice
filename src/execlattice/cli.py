"""Local administrative bootstrap and authenticated operator CLI."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import shutil
import socket
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

import httpx

from .client import APIError, ControllerClient
from .protocol import TERMINAL_STATES, new_id
from .security import (
    cert_fingerprint,
    create_certificate,
    new_secret,
    protect_directory,
    read_json,
    validate_url,
    write_private_json,
)
from .store import Store, StoreError

_CONTROLLER_STATE = Path(".execlattice-lan/controller")
_WORKER_STATE = Path(".execlattice-lan/worker")


class CliInputError(ValueError):
    """An error with a fixed message safe to show in the console."""


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Run the command with --help for available options.\n")


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def init_controller(state: Path, url: str, hosts: list[str]) -> dict:
    url = validate_url(url)
    if state.exists() and any(state.iterdir()):
        raise CliInputError("Choose a new or empty controller directory.")
    state = protect_directory(state)
    from urllib.parse import urlsplit

    create_certificate(state, [urlsplit(url).hostname, *hosts])
    admin, agent = new_secret(), new_secret()
    Store(state / "controller.sqlite3").initialize(admin, agent)
    for filename, token in [("admin.json", admin), ("client.json", agent)]:
        write_private_json(
            state / filename,
            {"controller_url": url, "token": token, "ca_file": str(state / "server-cert.pem"),
             "lan_preview": 1},
        )
    return {
        "state_dir": str(state),
        "client_config": str(state / "client.json"),
        "admin_config": str(state / "admin.json"),
        "certificate_sha256": cert_fingerprint(state / "server-cert.pem"),
    }


def init_worker(
    state: Path, url: str, cert: Path, root: Path, name: str, *, device_id: str | None = None,
    access_mode: str | None = None,
) -> dict:
    from .executors import validate_policy

    url = validate_url(url)
    if device_id is not None and str(UUID(device_id)) != device_id:
        raise CliInputError("Use the device ID shown by init-worker.")
    if state.exists() and any(state.iterdir()):
        raise CliInputError("Choose a new or empty worker directory.")
    if not cert.is_file() or not root.is_dir():
        raise CliInputError("Choose a trusted controller certificate and an existing sample directory.")
    if state.resolve().is_relative_to(root.resolve()):
        raise CliInputError("Choose a worker state directory outside the sample directory.")
    profiles = {} if getattr(sys, "frozen", False) else {
        "python-version": {"argv": [sys.executable, "--version"], "cwd": "workspace"}
    }
    policy = {
        "roots": {"workspace": str(root.resolve())},
        "commands": profiles,
        "max_file_bytes": 65536,
        "max_output_bytes": 16384,
    }
    if access_mode is not None:
        policy["desktop_access"] = {"mode": access_mode}
    policy = validate_policy(policy)

    state = protect_directory(state)
    cert_target = state / "controller-cert.pem"
    shutil.copyfile(cert, cert_target)
    config = {
        "device_id": device_id if device_id is not None else new_id(),
        "display_name": name,
        "controller_url": url,
        "token": new_secret(),
        "ca_file": str(cert_target),
        "policy": policy,
        "lan_preview": 1,
    }
    write_private_json(state / "worker.json", config)
    return {
        "device_id": config["device_id"],
        "worker_config": str(state / "worker.json"),
        "certificate_sha256": cert_fingerprint(cert_target),
        "profiles": [] if access_mode == "read_only" else sorted(profiles),
        "root_alias": "workspace",
    }


@contextmanager
def exclusive_state(state: Path, filename: str):
    """OS locks prevent two controllers/workers sharing one state directory."""
    stream = (state / filename).open("a+b")
    try:
        # A Windows byte-range lock can reject the initial read as well as the
        # subsequent locking call. Keep both in the same contention handler;
        # an actual directory/file open permission failure still propagates.
        stream.seek(0)
        if not stream.read(1):
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        stream.close()
        raise CliInputError("The state directory is already in use.") from None
    try:
        yield
    finally:
        stream.close()


def serve_controller(state: Path, host: str, port: int, *, include_loopback: bool = False) -> None:
    import uvicorn

    from .controller import create_app

    # Bind an explicit loopback/private/overlay IP. No wildcard or public exposure in this MVP.
    address = ipaddress.ip_address(host)
    overlay = address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10")
    if (
        address.is_unspecified
        or address.is_multicast
        or not (address.is_loopback or address.is_private or overlay)
    ):
        raise CliInputError("Use a specific loopback or private network address.")
    if not (state / "controller.sqlite3").is_file():
        raise CliInputError("Run init-controller before starting the controller.")
    if read_json(state / "client.json").get("lan_preview") != 1:
        raise CliInputError("Initialize a separate controller for this preview.")
    with exclusive_state(state, "controller.lock"):
        options = dict(
            host=host,
            port=port,
            ssl_certfile=str(state / "server-cert.pem"),
            ssl_keyfile=str(state / "server-key.pem"),
            ssl_version=__import__("ssl").PROTOCOL_TLS_SERVER,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            limit_concurrency=32,
            timeout_keep_alive=3,
        )
        application = create_app(Store(state / "controller.sqlite3"))
        if not include_loopback or address == ipaddress.ip_address("127.0.0.1"):
            uvicorn.run(application, **options)
            return
        # Serve can forward raw TCP to the IPv4 loopback listener while LAN
        # clients continue using the existing address and certificate.  Bind
        # every socket before Uvicorn starts listening, so a conflict cannot
        # leave an unexpectedly partial service running.
        sockets = []
        try:
            listen_port = port
            for bind_host in (str(address), "127.0.0.1"):
                family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
                listener = socket.socket(family, socket.SOCK_STREAM)
                sockets.append(listener)
                if os.name == "nt":
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((bind_host, listen_port))
                if listen_port == 0:
                    listen_port = listener.getsockname()[1]
                listener.set_inheritable(False)
            options["port"] = listen_port
            server = uvicorn.Server(uvicorn.Config(application, **options))
            server.run(sockets=sockets)
            if not server.started:
                raise CliInputError("The controller could not start.")
        finally:
            for listener in sockets:
                listener.close()


def build_parser() -> argparse.ArgumentParser:
    parser = PrivateArgumentParser(prog="execlattice", description="Run authorized tasks on another computer.")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-controller", help="Create protected controller state and TLS certificate")
    init.add_argument("--state", type=Path, default=_CONTROLLER_STATE)
    init.add_argument("--url", default="https://127.0.0.1:8765")
    init.add_argument("--cert-host", action="append", default=[])
    serve = sub.add_parser("controller")
    serve.add_argument("--state", type=Path, default=_CONTROLLER_STATE)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--include-loopback", action="store_true", help="Also bind 127.0.0.1 for a private TCP gateway")
    initw = sub.add_parser("init-worker")
    initw.add_argument("--state", type=Path, default=_WORKER_STATE)
    initw.add_argument("--url", required=True)
    initw.add_argument("--ca-file", type=Path, required=True)
    initw.add_argument("--root", type=Path, required=True)
    initw.add_argument("--name", default="LAN worker", help="Label shown on the controller")
    initw.add_argument(
        "--access-mode", choices=("read-only", "full"),
        help="Grant inspection or full access using the worker's existing Windows user permissions. "
        "Both apply to paths accessible to that user. Omit to keep access to the root and fixed command profile.",
    )
    paircode = sub.add_parser("pair-code", help="Create a one-time code for one device")
    paircode.add_argument("--state", type=Path, default=_CONTROLLER_STATE)
    paircode.add_argument("--device-id", required=True)
    paircode.add_argument(
        "--out", type=Path, required=True, help="Create a secret file inside protected state"
    )
    pair = sub.add_parser("pair")
    pair.add_argument("--config", type=Path, default=_WORKER_STATE / "worker.json")
    pair.add_argument("--code-file", type=Path)
    run = sub.add_parser("worker")
    run.add_argument("--config", type=Path, default=_WORKER_STATE / "worker.json")
    export = sub.add_parser("export-task", help="Verify and save retained output to a new private directory")
    export.add_argument("task_id")
    export.add_argument("--config", type=Path, default=_CONTROLLER_STATE / "client.json")
    export.add_argument("--out", required=True, type=Path)
    export.add_argument("--recovery", action="store_true", help="Export late evidence; task remains unknown")
    prune = sub.add_parser("prune-results", help="Offline result retention; previews unless --apply")
    prune.add_argument("--state", type=Path, default=_CONTROLLER_STATE)
    prune.add_argument("--before", required=True, help="Past ISO timestamp including timezone")
    prune.add_argument("--apply", action="store_true")
    for name in ("devices", "submit", "task", "cancel", "revoke", "audit", "mcp"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, default=_CONTROLLER_STATE / "client.json")
        if name == "submit":
            command.add_argument("--device-id", required=True)
            mode = command.add_mutually_exclusive_group(required=True)
            mode.add_argument("--profile")
            mode.add_argument("--path")
            command.add_argument("--root", default="workspace")
            command.add_argument("--timeout", type=int, default=30)
            command.add_argument("--idempotency-key")
            command.add_argument("--wait", action="store_true")
        if name in ("task", "cancel"):
            command.add_argument("task_id")
        if name == "revoke":
            command.add_argument("device_id")
        if name == "audit":
            command.add_argument("--task-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init-controller":
            print_json(init_controller(args.state.absolute(), args.url, args.cert_host))
        elif args.command == "controller":
            serve_controller(args.state.absolute(), args.host, args.port, include_loopback=args.include_loopback)
        elif args.command == "init-worker":
            access_mode = "read_only" if args.access_mode == "read-only" else args.access_mode
            print_json(init_worker(args.state.absolute(), args.url, args.ca_file, args.root, args.name,
                                   access_mode=access_mode))
        elif args.command == "pair-code":
            device_id = str(UUID(args.device_id))
            state = args.state.resolve(strict=True)
            if read_json(state / "client.json").get("lan_preview") != 1:
                raise CliInputError("Initialize a separate controller for this preview.")
            out = args.out.absolute()
            if out.parent.resolve(strict=True) != state:
                raise CliInputError("Save the pairing code directly in the protected controller directory.")
            if out.exists():
                raise CliInputError("Choose an unused pairing-code filename.")
            code = Store(state / "controller.sqlite3").pairing_code(device_id)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(code)
            print_json({"code_file": str(out), "device_id": device_id, "expires_in_seconds": 300})
        elif args.command == "pair":
            from .worker import pairing_request

            config = read_json(args.config)
            code = (
                args.code_file.read_text(encoding="utf-8").strip()
                if args.code_file
                else getpass.getpass("Pairing code: ")
            )
            client = ControllerClient(config)
            try:
                print_json(client.request("POST", "/v1/pair", pairing_request(config, code)))
            finally:
                client.close()
        elif args.command == "worker":
            from .worker import WorkerAccessEnded, run_worker

            try:
                with exclusive_state(args.config.absolute().parent, "worker.lock"):
                    run_worker(read_json(args.config), args.config.absolute().parent)
            except WorkerAccessEnded:
                print_json({"error": {"code": "worker_access_ended",
                                      "message": "Worker credential rejected or revoked; execution stopped"}})
                return 1
        elif args.command == "mcp":
            from .mcp_adapter import run_mcp

            run_mcp(args.config)
        elif args.command == "prune-results":
            from .artifacts import prune_results

            state = args.state.absolute()
            if not (state / "controller.sqlite3").is_file():
                raise CliInputError("Run init-controller before managing results.")
            if read_json(state / "client.json").get("lan_preview") != 1:
                raise CliInputError("Initialize a separate controller for this preview.")
            from .security import _reject_link_ancestors

            _reject_link_ancestors(state)
            with exclusive_state(state, "controller.lock"):
                print_json(prune_results(state, args.before, apply=args.apply))
        else:
            client = ControllerClient.from_file(args.config)
            try:
                result = operator_command(client, args)
                if args.command in {"submit", "task", "cancel"}:
                    from .execution_outcome import public_task_receipt

                    result = public_task_receipt(result)
                print_json(result)
                if isinstance(result, dict) and result.get("state") in TERMINAL_STATES - {"succeeded"}:
                    return 2
            finally:
                client.close()
    except KeyboardInterrupt:
        return 130
    except (APIError, StoreError) as exc:
        print_json({"error": {"code": exc.code}})
        return 1
    except httpx.TransportError:
        print_json(
            {
                "error": {
                    "code": "transport_failed",
                    "message": "Check controller availability, address and trusted certificate",
                }
            }
        )
        return 1
    except CliInputError as exc:
        print_json({"error": {"code": "local_configuration_error", "message": str(exc)}})
        return 1
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, sqlite3.Error):
        print_json({"error": {"code": "local_configuration_error",
                              "message": "Check the selected configuration, paths, and permissions."}})
        return 1
    return 0


def operator_command(client: ControllerClient, args):
    if args.command == "export-task":
        from .artifacts import export_result

        task = client.request("GET", f"/v1/tasks/{UUID(args.task_id)}")
        return export_result(task, args.out, recovery=args.recovery)
    if args.command == "devices":
        return client.request("GET", "/v1/devices")
    if args.command == "submit":
        from .protocol import TaskRequest

        body = TaskRequest(
            target_device_id=args.device_id,
            executor_type="command" if args.profile else "file",
            action="run" if args.profile else "read",
            parameters={"profile": args.profile} if args.profile else {"root": args.root, "path": args.path},
            timeout_seconds=args.timeout,
            idempotency_key=args.idempotency_key,
        ).model_dump()
        task = client.request("POST", "/v1/tasks", body)
        return client.wait(task["task_id"], args.timeout + 35) if args.wait else task
    if args.command == "task":
        return client.request("GET", f"/v1/tasks/{UUID(args.task_id)}")
    if args.command == "cancel":
        return client.request("POST", f"/v1/tasks/{UUID(args.task_id)}/cancel")
    if args.command == "revoke":
        return client.request("POST", f"/v1/devices/{args.device_id}/revoke")
    if args.command == "audit":
        path = "/v1/audit" + ("?task_id=" + str(UUID(args.task_id)) if args.task_id else "")
        return client.request("GET", path)
    raise ValueError("Unknown operator command")


if __name__ == "__main__":
    sys.exit(main())
