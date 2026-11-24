from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from execlattice.controller import create_app
from execlattice.store import Store

ADMIN = {"Authorization": "Bearer " + "a" * 40}
AGENT = {"Authorization": "Bearer " + "b" * 40}
OWNER = "c" * 32
OTHER_OWNER = "d" * 32
SESSION = {"version": 1, "instance_id": "e" * 32}
OPERATION_KEY = "agent-" + "f" * 64


def capabilities(owner=OWNER, *, mode="full"):
    command = {
        "executor_type": "command",
        "available": True,
        "actions": ["run"],
        "profiles": ["proof"],
        "worker_session": SESSION,
    }
    if owner is not None:
        command["execution_identity"] = {"version": 1, "owner_id": owner}
    actions = ["list", "search", "read"]
    if mode == "full":
        actions.append("write")
    return [command, {
        "executor_type": "workspace",
        "available": True,
        "actions": actions,
        "mode": mode,
    }]


@pytest.fixture
def paired(tmp_path):
    store = Store(tmp_path / "controller.sqlite3")
    store.initialize(ADMIN["Authorization"].split()[1], AGENT["Authorization"].split()[1])
    device_id = str(uuid4())
    worker_credential = uuid4().hex
    worker_headers = {"Authorization": "Bearer " + worker_credential}
    with TestClient(create_app(store)) as client:
        response = client.post("/v1/pair", json={
            "device_id": device_id,
            "display_name": "Synthetic worker",
            "os": "windows",
            "architecture": "x64",
            "worker_version": "0.1",
            "code": store.pairing_code(device_id),
            "credential": worker_credential,
            "capabilities": capabilities(),
        })
        assert response.status_code == 200, response.text
        yield store, client, device_id, worker_headers


def scope(device_id, owner=OWNER):
    return {"target_device_id": device_id, "expected_execution_owner_id": owner}


def request_body(device_id):
    return {
        **scope(device_id),
        "idempotency_key": OPERATION_KEY,
        "executor_type": "workspace",
        "action": "write",
        "parameters": {"path": "result.txt", "content_b64": "YQ=="},
    }


def heartbeat(client, worker_headers, **changes):
    return client.post("/v1/worker/heartbeat", headers=worker_headers,
                       json={"capabilities": capabilities(**changes)})


def submit(client, body):
    return client.post("/v1/tasks", headers=AGENT, json=body)


def lookup(client, device_id, *, owner=OWNER, headers=AGENT):
    response = client.get("/v1/task-lookup", headers=headers,
                          params={**scope(device_id, owner), "idempotency_key": OPERATION_KEY})
    assert response.status_code == 200, response.text
    return response.json()["task"]


def assert_error(response, status, code):
    assert response.status_code == status, response.text
    assert response.json() == {"error": {"code": code}}


def test_pairing_and_previous_session_do_not_confirm_live_execution(paired):
    store, client, device_id, worker_headers = paired
    body = request_body(device_id)
    assert client.get("/v1/devices", headers=AGENT).json()[0]["sdk_ready"] is False
    assert_error(submit(client, body), 409, "device_execution_unconfirmed")

    assert heartbeat(client, worker_headers).status_code == 200
    assert client.get("/v1/devices", headers=AGENT).json()[0]["sdk_ready"] is True

    store.begin_controller_session()
    assert_error(submit(client, body), 409, "device_execution_unconfirmed")
    assert lookup(client, device_id) is None


@pytest.mark.parametrize("other_owner", [OTHER_OWNER, None])
def test_heartbeat_can_only_confirm_original_paired_owner(paired, other_owner):
    _, client, device_id, worker_headers = paired
    assert_error(heartbeat(client, worker_headers, owner=other_owner), 403, "worker_binding_changed")
    assert_error(submit(client, request_body(device_id)), 409, "device_execution_unconfirmed")

    assert heartbeat(client, worker_headers).status_code == 200
    created = submit(client, request_body(device_id))
    assert created.status_code == 200, created.text
    assert created.json()["expected_execution_owner_id"] == OWNER


def test_bound_submit_rejects_invalid_key_owner_and_changed_replay(paired):
    _, client, device_id, worker_headers = paired
    assert heartbeat(client, worker_headers).status_code == 200
    body = request_body(device_id)
    for invalid_key in (None, "manual-operation"):
        assert_error(submit(client, {**body, "idempotency_key": invalid_key}),
                     422, "invalid_request_schema")
    assert_error(submit(client, {**body, **scope(device_id, OTHER_OWNER)}), 409, "device_binding_changed")
    assert lookup(client, device_id) is None

    first = submit(client, body)
    assert first.status_code == 200, first.text
    assert_error(submit(client, {**body, "timeout_seconds": 31}), 409, "idempotency_key_conflict")
    assert_error(submit(client, {**body, **scope(device_id, OTHER_OWNER)}), 409, "idempotency_key_conflict")
    assert lookup(client, device_id)["task_id"] == first.json()["task_id"]


@pytest.mark.parametrize("claim_before_downgrade", [False, True])
def test_write_denied_and_terminal_when_permissions_downgrade(paired, claim_before_downgrade):
    _, client, device_id, worker_headers = paired
    assert heartbeat(client, worker_headers).status_code == 200
    created = submit(client, request_body(device_id))
    assert created.status_code == 200, created.text
    task_id = created.json()["task_id"]
    if claim_before_downgrade:
        claimed = client.post("/v1/worker/claim", headers=worker_headers)
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["task"]["task_id"] == task_id
        assert claimed.json()["task"]["state"] == "dispatched"

    assert heartbeat(client, worker_headers, mode="read_only").status_code == 200
    if claim_before_downgrade:
        assert_error(client.post(f"/v1/worker/tasks/{task_id}/start", headers=worker_headers),
                     409, "capability_or_policy_denied")
    else:
        claim = client.post("/v1/worker/claim", headers=worker_headers)
        assert claim.status_code == 200, claim.text
        assert claim.json()["task"] is None

    failed = lookup(client, device_id)
    assert failed["task_id"] == task_id
    assert failed["state"] == "failed"
    assert failed["error"]["code"] == "capability_or_policy_denied"
    assert failed["result"] is None
    assert_error(client.post(f"/v1/worker/tasks/{task_id}/start", headers=worker_headers),
                 409, "task_cannot_start")


def test_running_start_retry_rechecks_binding_without_rewriting_receipt(paired):
    _, client, device_id, worker_headers = paired
    assert heartbeat(client, worker_headers).status_code == 200
    created = submit(client, request_body(device_id))
    assert created.status_code == 200, created.text
    task_id = created.json()["task_id"]
    start_path = f"/v1/worker/tasks/{task_id}/start"
    claim = client.post("/v1/worker/claim", headers=worker_headers)
    assert claim.json()["task"]["task_id"] == task_id
    assert client.post(start_path, headers=worker_headers).status_code == 200
    assert heartbeat(client, worker_headers, mode="read_only").status_code == 200
    assert_error(client.post(start_path, headers=worker_headers), 409, "capability_or_policy_denied")
    assert lookup(client, device_id)["state"] == "running"


def test_original_receipt_is_scoped_and_survives_revocation(paired):
    _, client, device_id, worker_headers = paired
    assert heartbeat(client, worker_headers).status_code == 200
    body = {**request_body(device_id), "executor_type": "command", "action": "run",
            "parameters": {"profile": "proof"}}
    created = submit(client, body)
    assert created.status_code == 200, created.text
    task_id = created.json()["task_id"]
    resource = f"/v1/tasks/{task_id}"
    worker_resource = f"/v1/worker/tasks/{task_id}"
    other_device = str(uuid4())

    for headers, params in ((ADMIN, scope(device_id)), (AGENT, scope(other_device)),
                            (AGENT, scope(device_id, OTHER_OWNER))):
        assert_error(client.post(resource + "/cancel", headers=headers, params=params), 404, "task_not_found")
    assert lookup(client, device_id)["state"] == "authorized"

    claimed = client.post("/v1/worker/claim", headers=worker_headers)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["task"]["task_id"] == task_id
    started = client.post(worker_resource + "/start", headers=worker_headers)
    assert started.status_code == 200, started.text
    result = {"exit_code": 0, "stdout": "synthetic receipt"}
    reported = client.post(worker_resource + "/report", headers=worker_headers,
                           json={"state": "succeeded", "result": result})
    assert reported.status_code == 200, reported.text
    assert client.post(f"/v1/devices/{device_id}/revoke", headers=ADMIN).status_code == 200

    receipt = lookup(client, device_id)
    assert (receipt["task_id"], receipt["state"], receipt["result"]) == (task_id, "succeeded", result)
    scoped = client.get(resource, headers=AGENT, params=scope(device_id))
    assert scoped.status_code == 200, scoped.text
    assert scoped.json() == receipt
    exact_replay = submit(client, body)
    assert exact_replay.status_code == 200, exact_replay.text
    assert exact_replay.json()["task_id"] == task_id
    assert_error(submit(client, {**body, "idempotency_key": "agent-" + "1" * 64}), 404, "device_not_found")

    assert lookup(client, other_device) is None
    assert lookup(client, device_id, owner=OTHER_OWNER) is None
    assert lookup(client, device_id, headers=ADMIN) is None
    for headers, params in ((ADMIN, scope(device_id)), (AGENT, scope(other_device)),
                            (AGENT, scope(device_id, OTHER_OWNER))):
        assert_error(client.get(resource, headers=headers, params=params), 404, "task_not_found")
