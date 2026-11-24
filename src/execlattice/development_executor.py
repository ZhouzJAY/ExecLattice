"""Authenticated development commands run with the current user's authority.

The full desktop mode permits shell code deliberately; it is not a sandbox.
Read-only mode never runs development commands. Process ownership, bounded
output, cancellation and uncertain-stop evidence follow the existing runner.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .command_toolchain import build_development_environment
from .development_progress import CommandOutput
from .executors import ExecutionDenied, _failure, _stop_process, _WindowsJob

MAX_COMMAND_CHARACTERS = 12000


def _arguments() -> list[str]:
    if os.name == "nt":
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        # PowerShell -Command otherwise folds native exit codes other than 0/1
        # into 1. Capture $? before evaluating anything else, and preserve the
        # native exit code explicitly. Console encoding is fixed for both
        # PowerShell output and normal child processes.
        script = (
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);\n"
            "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false);\n"
            "$OutputEncoding = [Console]::OutputEncoding;\n"
            "$ErrorActionPreference = 'Stop';\n"
            # No user code is present in this command line. ReadToEnd blocks
            # until the parent has assigned this process to its owned job and
            # has sent and closed the private input pipe. Even parse-time code
            # such as a `using module` cannot run before job assignment.
            "$elDevelopmentSource = [Console]::In.ReadToEnd();\n"
            "& ([ScriptBlock]::Create($elDevelopmentSource));\n"
            "$elDevelopmentSucceeded = $?;\n"
            "if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE };\n"
            "if (-not $elDevelopmentSucceeded) { exit 1 };\n"
            "exit 0"
        )
        # This runner is admitted only in full mode. The native process policy
        # also reaches ordinary child PowerShell sessions through the engine's
        # PSExecutionPolicyPreference environment variable; it never writes the
        # user/machine policy or overrides enterprise Group Policy. User source
        # still enters only through the private pipe after job assignment.
        return [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script]
    # This fallback is useful for isolated unit testing; shipped desktop and
    # physical acceptance still cover Windows only.
    return ["/bin/sh", "-s"]


def _validated(parameters: dict, policy: dict, timeout: int, *, maximum_timeout=3600) -> tuple[str, Path, int]:
    access = policy.get("desktop_access") if isinstance(policy, dict) else None
    if not isinstance(access, dict) or access.get("mode") != "full":
        raise ExecutionDenied("Development commands require editable mode")
    if not isinstance(parameters, dict) or set(parameters) != {"command", "cwd"}:
        raise ExecutionDenied("Development commands require exactly command and cwd")
    command, directory = parameters["command"], parameters["cwd"]
    if (not isinstance(command, str) or not command.strip()
            or len(command) > MAX_COMMAND_CHARACTERS or "\x00" in command):
        raise ExecutionDenied("Development command text is invalid")
    if (not isinstance(directory, str) or not directory or len(directory) > 4096
            or "\x00" in directory or directory.startswith(("\\\\", "//"))):
        raise ExecutionDenied("Working directory must be an absolute local directory")
    cwd = Path(directory)
    if not cwd.is_absolute():
        raise ExecutionDenied("Working directory must be an absolute local directory")
    cwd = cwd.resolve(strict=True)
    if not cwd.is_dir():
        raise ExecutionDenied("Working directory must be a directory")
    if type(timeout) is not int or not 1 <= timeout <= maximum_timeout:
        raise ExecutionDenied(f"Execution timeout must be between 1 and {maximum_timeout} seconds")
    limit = policy.get("max_output_bytes", 65536)
    if type(limit) is not int or not 1 <= limit <= 65536:
        raise ExecutionDenied("Output byte limit is invalid")
    return command, cwd, limit


def execute_development(parameters: dict, policy: dict, timeout: int, cancel: threading.Event,
                        *, progress: Callable[[dict], None] | None = None,
                        state_dir=None, source_id=None) -> dict:
    """Run one explicitly editable command and return exact bounded evidence."""
    try:
        command, cwd, limit = _validated(parameters, policy, timeout)
        if cancel.is_set():
            return _failure("CANCELLED", "Task was cancelled before execution", state="cancelled")
        return _run_captured(command, cwd, limit, timeout, cancel, progress=progress,
                             state_dir=state_dir, source_kind="task", source_id=source_id)
    except ExecutionDenied as exc:
        return _failure("POLICY_DENIED", str(exc))
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "Working directory or command shell was not found")
    except PermissionError:
        return _failure("ACCESS_DENIED", "Operating system denied access")
    except (ValueError, TypeError):
        return _failure("INVALID_CONFIGURATION", "Development command configuration is invalid")
    except OSError:
        return _failure("IO_ERROR", "Development command could not be started")


def execute_host_development(parameters: dict, policy: dict, timeout: int, cancel: threading.Event,
                             *, progress: Callable[[dict], None] | None = None,
                             state_dir=None, source_id=None) -> dict:
    """Private execution-host runner; wrapper task completion is not job completion."""
    try:
        command, cwd, limit = _validated(parameters, policy, timeout, maximum_timeout=86400)
        if cancel.is_set():
            return _failure("CANCELLED", "Job was cancelled before execution", state="cancelled")
        return _run_captured(command, cwd, limit, timeout, cancel, progress=progress,
                             state_dir=state_dir, source_kind="job", source_id=source_id)
    except ExecutionDenied as exc:
        return _failure("POLICY_DENIED", str(exc))
    except FileNotFoundError:
        return _failure("FILE_NOT_FOUND", "Working directory or command shell was not found")
    except PermissionError:
        return _failure("ACCESS_DENIED", "Operating system denied access")
    except (ValueError, TypeError):
        return _failure("INVALID_CONFIGURATION", "Job configuration is invalid")
    except OSError:
        return _failure("IO_ERROR", "Job could not be started")


def _run_captured(command, cwd, limit, timeout, cancel, *, progress, state_dir, source_kind, source_id):
    artifact = None
    capture_reason = None
    capture_requested = state_dir is not None and source_id is not None
    if capture_requested:
        from .output_artifacts import OutputArtifactError, OutputArtifactWriter, capture_result

        try:
            artifact = OutputArtifactWriter(state_dir, source_kind, source_id)
        except OutputArtifactError as error:
            if error.code in {"OUTPUT_ALREADY_EXISTS", "OUTPUT_ID_INVALID"}:
                return _failure(error.code, "Original output already exists; the command was not restarted")
            capture_reason = error.code
        except OSError:
            capture_reason = "OUTPUT_CAPTURE_IO"
        except ValueError:
            capture_reason = "OUTPUT_METADATA_INVALID"
    try:
        if artifact is None:
            report = _run(command, cwd, limit, timeout, cancel, progress=progress)
        else:
            report = _run(command, cwd, limit, timeout, cancel, progress=progress, artifact=artifact)
        if capture_requested and isinstance(report.get("result"), dict):
            # This does not change the command state or authorize its retry.
            # Even a successful exit can have unavailable/partial output.
            report["result"]["output_capture"] = capture_result(source_kind, source_id,
                                                               writer=artifact, reason=capture_reason)
        return report
    finally:
        if artifact is not None and not artifact.closed:
            artifact.finish("unknown", None, output_complete=False)


def _run(command: str, cwd: Path, limit: int, timeout: int, cancel: threading.Event,
         *, progress: Callable[[dict], None] | None = None, artifact=None) -> dict:
    started = time.monotonic()
    creation = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    # Inherit the user's toolchain, package caches and locale, adding verified
    # bundled command tools only to this owned process's PATH. This
    # is deliberately distinct from legacy fixed-profile execution. A remote
    # caller cannot supply an environment mapping or elevate the process.
    process = subprocess.Popen(
        _arguments(), cwd=cwd, env=build_development_environment(windows_powershell=os.name == "nt"), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True,
        creationflags=creation, start_new_session=os.name != "nt",
    )
    job = None
    if os.name == "nt":
        try:
            job = _WindowsJob(process)
        except OSError:
            stopped = _stop_process(process, None)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
            return _failure("PROCESS_CONTAINMENT_FAILED", "Cannot manage the development process tree",
                            state="failed" if stopped else "unknown")
    outputs = CommandOutput(limit, started)
    read_error, input_error = threading.Event(), threading.Event()

    def supply_command():
        # Start only after successful job assignment. A separate writer keeps
        # the one task timeout effective even if a child stops reading input.
        try:
            process.stdin.write(command.encode("utf-8"))
            process.stdin.flush()
        except (OSError, UnicodeError):
            input_error.set()
        finally:
            process.stdin.close()

    def consume(stream, index):
        try:
            while chunk := os.read(stream.fileno(), 4096):
                outputs.append(index, chunk)
                if artifact is not None:
                    artifact.append(index, chunk)
        except OSError:
            read_error.set()
        finally:
            stream.close()

    readers = [threading.Thread(target=consume, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    writer = threading.Thread(target=supply_command, daemon=True)
    state, error = "succeeded", None
    next_progress = started
    try:
        for reader in readers:
            reader.start()
        writer.start()
        while True:
            if cancel.is_set():
                state, error = "cancelled", {"code": "CANCELLED", "message": "Task cancellation was confirmed"}
                break
            if time.monotonic() - started >= timeout:
                state, error = "timed_out", {"code": "TIMEOUT", "message": "Command exceeded its execution timeout"}
                break
            if process.poll() is not None and not any(reader.is_alive() for reader in readers):
                break
            if (progress is not None or artifact is not None) and time.monotonic() >= next_progress:
                # This callback only hands an immutable snapshot to the Worker;
                # network delivery runs on its polling thread. A diagnostic
                # consumer must not interrupt or replay the executing command.
                try:
                    if artifact is not None:
                        artifact.checkpoint()
                    if progress is not None:
                        progress(outputs.snapshot())
                except Exception:
                    pass
                next_progress = time.monotonic() + 1
            time.sleep(.02)
        settle_until = time.monotonic() + .2
        if state == "succeeded" and job is not None:
            while job.active() and time.monotonic() < settle_until:
                time.sleep(.01)
        descendants_alive = job is not None and job.active() > 0
        if state != "succeeded" or descendants_alive:
            if not _stop_process(process, job):
                state, error = "unknown", {"code": "STOP_UNCONFIRMED", "message": "Process-tree termination could not be verified"}
            elif state == "succeeded":
                state, error = "failed", {"code": "CHILD_PROCESSES_REMAIN", "message": "Command left child processes running"}
        for reader in readers:
            reader.join(timeout=1)
        writer.join(timeout=1)
        if writer.is_alive() or input_error.is_set() and state == "succeeded":
            state, error = "unknown", {"code": "INPUT_INCOMPLETE", "message": "Command input could not be delivered completely"}
        elif any(reader.is_alive() for reader in readers):
            state, error = "unknown", {"code": "OUTPUT_INCOMPLETE", "message": "Command output pipes did not close"}
        elif read_error.is_set() and state == "succeeded":
            state, error = "unknown", {"code": "OUTPUT_INCOMPLETE", "message": "Command output could not be read completely"}
        elif state == "succeeded" and process.returncode != 0:
            state, error = "failed", {"code": "COMMAND_EXIT", "message": "Development command returned a nonzero exit code"}
        if artifact is not None:
            artifact.finish(state, process.poll(), output_complete=not read_error.is_set()
                            and not any(reader.is_alive() for reader in readers))
        return {
            "state": state,
            "result": {**outputs.snapshot(), "exit_code": process.poll()},
            "error": error,
        }
    finally:
        if process.poll() is None:
            _stop_process(process, job)
        if job is not None:
            job.close()
        if writer.ident is not None:
            writer.join(timeout=1)
        if not writer.is_alive():
            process.stdin.close()
