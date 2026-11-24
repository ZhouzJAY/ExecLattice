# ExecLattice LAN preview

ExecLattice gives an agent explicit access to a computer's files and command execution. This developer preview includes a Windows worker, an HTTPS controller, and a local MCP server for use with Codex or another compatible client.

## Supported in this preview

- Pair a worker to a controller with a one-time code and an explicitly trusted controller certificate.
- List, search, and read files. With the worker owner's full-access choice, also write text files and run commands as that Windows user.
- Keep a task ID and use it to query, wait for, or cancel the original task. Revoking a worker blocks new tasks for that device.

Use two Windows x64 computers on the same trusted local network. Install Python 3.13 or later on both computers. Run the worker in a standard Windows user account. That account's file and process permissions apply to every task.

## Install and pair

### Check Python on both computers

Run this version check in PowerShell on both computers.

```powershell
py -3.13 --version
```

The examples use Python 3.13, so this should print `Python 3.13.x`. If you have a later supported version, substitute its version number in the check and the `py` commands below. If `py` is unavailable, try `python --version`. When it reports Python 3.13 or later, use `python` in place of `py -3.13` below.

If neither command reports a supported version, or the only result is a Microsoft Store prompt, install 64-bit Python for Windows, open a new PowerShell window, and check again. [Python for Windows](https://www.python.org/downloads/windows/)

Create the virtual environment and install the package from a folder you own, using the same Windows account that will run ExecLattice.

### Set up the controller and worker

On the controller, open PowerShell in the preview source folder. Create a virtual environment and install the controller with the optional MCP adapter.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[mcp]"
```

You can install the wheel by passing its file path to pip. Append `[mcp]` to the wheel path to install the controller's MCP adapter. Use the preview source folder for the example files below.

Enter the controller's LAN IPv4 address. Keep the controller running in its own terminal.

```powershell
$controllerAddress = Read-Host "Controller LAN IPv4 address"
$controllerUrl = "https://${controllerAddress}:8765"
.\.venv\Scripts\execlattice.exe init-controller --url $controllerUrl
.\.venv\Scripts\execlattice.exe controller --host $controllerAddress --port 8765
```

If Windows Firewall blocks the connection, ask the controller's administrator to allow inbound TCP 8765 on the private network profile for the intended worker address. The worker initiates the connection. Keep the controller on the trusted network and leave router port forwarding disabled.

On the worker, open PowerShell in a copy of the preview source folder that you own. Transfer only `.execlattice-lan/controller/server-cert.pem` from the controller and save it as `server-cert.pem` in this folder. Keep the controller key and configuration files on the controller. Use the same worker folder for the remaining commands.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
$worker = ".\.venv\Scripts\execlattice.exe"
New-Item -ItemType Directory -Path .\sample-workspace
Copy-Item .\examples\hello.txt .\sample-workspace\hello.txt
$controllerUrl = Read-Host "Controller HTTPS address"
& $worker init-worker --url $controllerUrl --ca-file .\server-cert.pem --root .\sample-workspace --name "Demo worker"
```

Compare the certificate SHA-256 printed by both initialization commands before pairing. The worker also prints its device ID. Choose the access mode at initialization with the worker owner's approval.

| Mode | What the controller can request |
| --- | --- |
| Default in the example | Read the sample root and run a fixed Python version-check command. |
| `--access-mode read-only` | Read the sample root and inspect files that the Windows account can read, including paths outside the sample root. |
| `--access-mode full` | Inspect and modify files and run commands using the Windows account's access. Commands run without automatic elevation. |

In a second controller terminal, generate a one-time code for that UUID. Read the value locally and provide it to the intended worker operator through a trusted channel. It expires in five minutes.

```powershell
$workerId = Read-Host "Device ID shown on the worker"
$codeName = "pair-" + [guid]::NewGuid().ToString("N") + ".txt"
$codePath = Join-Path .\.execlattice-lan\controller $codeName
.\.venv\Scripts\execlattice.exe pair-code --device-id $workerId --out $codePath
```

Read the code from that file in a private session and enter it at the worker's hidden prompt. Start the worker in the same terminal.

```powershell
& $worker pair
& $worker worker
```

## Run a sample

On the controller, list devices and read the sample. The result includes the original task ID and SHA-256.

```powershell
.\.venv\Scripts\execlattice.exe devices
$workerId = Read-Host "Device ID"
.\.venv\Scripts\execlattice.exe submit --device-id $workerId --path hello.txt --wait
$taskId = Read-Host "Original task ID"
.\.venv\Scripts\execlattice.exe task $taskId
```

For Codex, add a local stdio MCP server using the full paths on the controller. Replace the example paths in this configuration.

```toml
[mcp_servers.execlattice]
command = 'C:\ExecLatticeDemo\.venv\Scripts\execlattice.exe'
args = ['mcp', '--config', 'C:\ExecLatticeDemo\.execlattice-lan\controller\client.json']
```

Use `list_devices` to find the worker, then call `read_file` with `root="workspace"` and `path="hello.txt"`. With a full-access worker, `write_project_file` can create `result.txt` using its absolute path on the worker. Use `get_task` to retrieve the original result. Keep that ID when reconnecting. A receipt records the task state and available execution evidence. If a result is missing or unknown, query the original before requesting any further write.

The worker operator can stop the worker with Ctrl+C. To revoke the device credential, run this on the controller, using the original device ID. The revoked worker can no longer accept tasks from this controller.

```powershell
.\.venv\Scripts\execlattice.exe revoke $workerId --config .\.execlattice-lan\controller\admin.json
```

## Verify a source installation

The single-machine check uses separate controller, worker and MCP processes over HTTPS. It exercises actual files and commands, SDK reconnect and device revocation. Run it on the controller from the preview source tree with the MCP extra installed and an existing scratch directory.

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
.\.venv\Scripts\python.exe .\scripts\verify-lan.py --scratch-root $env:TEMP
```

## Two-computer validation for v0.54.0.dev8

On 2026-11-25, a maintainer installed the [published v0.54.0.dev8 wheel](https://github.com/ZhouzJAY/ExecLattice/releases/tag/v0.54.0.dev8) on two Windows x64 computers and verified its SHA-256 on both. The controller and worker ran under standard Windows accounts on a trusted LAN. The interruption tests cut only the test HTTPS connection.

| Scenario | Observed result |
| --- | --- |
| Pair and read a file | One-time HTTPS pairing succeeded. The controller read the 130-byte public sample from the worker and verified its SHA-256 against `examples/hello.txt`. |
| Connection interrupted for about 12 seconds | The task finished during the interruption. After reconnecting, the controller retrieved the original successful result with exit code 0. The task ran once. |
| Connection interrupted for about 25 seconds | The worker stopped safely. The original result remained unconfirmed, and the controller retrieved evidence of the stop after reconnecting. The task ran once. |
| Revoke the worker | An existing receipt remained readable, and a new task request returned HTTP 404. |

## Use the Python SDK

The SDK binds a session to one paired device. Start the worker and wait for its authenticated heartbeat before opening a session. Pass the chosen device ID explicitly.

```python
from pathlib import Path

from execlattice.lan_sdk import LanSession

config = Path(".execlattice-lan/controller/client.json")
device_id = input("Device ID shown on the controller: ").strip()
operation_id = "demo-read-hello-v1"

with LanSession.open(config, device_id) as session:
    submitted = session.submit(operation_id, "file", "read", {
        "root": "workspace",
        "path": "hello.txt",
    })
    print(submitted["task_id"])
    receipt = session.wait(operation_id, timeout_seconds=15)
    print(receipt["state"] if receipt else "Original submission unconfirmed")
```

Choose and save an operation ID and `session.execution_owner_id` before submitting. If the connection breaks, query that same operation with `query_original(operation_id)`. When opening a replacement session, pass the saved owner ID as `expected_execution_owner_id` to verify the binding. The SDK checks both the device and owner before accepting a receipt and leaves unconfirmed work in its original state. It never automatically resubmits a task.

`get_task(task_id)` reads an original task for the current device binding. `cancel(task_id)` returns the task's current cancellation state. A cancellation request can remain pending while the worker stops. A retained session can read its earlier receipts after the device is revoked, while new tasks require a current grant and heartbeat.

## Credentials and retained data

`client.json` grants operator access across the controller's paired devices and task records. Use it only with agents and client applications you trust. The SDK's device binding checks task routing and recovery. The controller's operator credential remains controller-wide. Keep `admin.json` for local administration only.

The protected controller directory stores device and task records, submitted parameters, audit history and available results. Results can contain file bytes or command output. Revocation invalidates the device credential. Existing records remain available to the authorized controller client. Keep both machines' runtime state directories and any backups or exports private.

## Share a report

For a public issue, reproduce the problem with the sample workspace and a synthetic device label. Share the preview version, the command or tool name, and its error code. Capture screenshots from that demo only. Review the entire frame, including window titles, tabs, console prompts and paths. Keep pairing codes, device IDs, network addresses, account names, task contents and logs private.

The development preview exposes the CLI, basic MCP tools, and a device-bound SDK for the listed LAN file and command operations. Desktop and graphical tools have a separate release scope.

## Build from reviewed files

Run `python scripts/release_source.py --out <new-directory>` from the source tree to stage the files listed in `release-files.txt`. Build the wheel with `python -m pip wheel --no-deps <staged-directory>` and check it with `python scripts/release_artifacts.py --wheel <wheel-path>`.

For a local standalone worker build, install the `build` extra on Windows x64, then run `python scripts/package-worker.py --scratch-root <existing-directory>`. Review the licenses for the components bundled in any standalone build before distributing it.

Each release script accepts an optional `--deny-term-file` stored outside the source tree. Keep the review terms and the original test environment private.

## License

ExecLattice is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
