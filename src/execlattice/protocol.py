"""Transport-independent, strictly validated ExecLattice task protocol.

Credentials appear only on the ephemeral pairing request.  Task callers cannot
set provenance, authorization, state, results, or audit fields: the controller
owns those fields.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .development_protocol import (
    WORKSPACE_MODELS,
    DevelopmentRunParameters,
)

PROTOCOL_VERSION = "0.1"
TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "timed_out", "unknown"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"authorized", "failed", "cancelled"}),
    "authorized": frozenset({"dispatched", "failed", "cancelled"}),
    "dispatched": frozenset({"running", "cancelling", "failed", "unknown"}),
    "running": frozenset({"cancelling", "succeeded", "failed", "timed_out", "unknown"}),
    # A cancellation request does not prove that the process was stopped.  A
    # completion that won the race is allowed to report its observed result.
    "cancelling": frozenset({"cancelled", "succeeded", "failed", "timed_out", "unknown"}),
    **{state: frozenset() for state in TERMINAL_STATES},
}
TASK_STATES = frozenset(TRANSITIONS)


def validate_transition(old: str, new: str) -> None:
    """Reject unknown states, terminal rewrites, and skipped transitions."""
    if old not in TRANSITIONS or new not in TRANSITIONS[old]:
        raise ValueError(f"Illegal task state transition: {old} -> {new}")


def utc_now() -> str:
    """Return an unambiguous, timezone-aware ISO 8601 timestamp."""
    return datetime.now(UTC).isoformat()


def new_id() -> str:
    return str(uuid4())


def _json_size(value: Any, limit: int) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Value must contain finite, UTF-8 JSON data") from exc
    if len(encoded) > limit:
        raise ValueError(f"JSON value exceeds {limit} bytes")


class ProtocolModel(BaseModel):
    # Prevent a formatted ValidationError from printing credential-bearing
    # input. API error handlers must also omit errors()[*]["input"].
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class CommandParameters(ProtocolModel):
    # The remote caller selects an existing local profile, never argv or code.
    profile: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")


class FileParameters(ProtocolModel):
    root: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("path")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        # Canonicalization and platform-specific containment belong to the
        # worker, where the filesystem actually exists.
        if any(ord(character) < 32 for character in value):
            raise ValueError("File path must not contain control characters")
        return value

class TaskRequest(ProtocolModel):
    protocol_version: Literal["0.1"] = PROTOCOL_VERSION
    target_device_id: str
    executor_type: Literal["command", "file", "workspace", "development"]
    action: Literal["run", "list", "search", "read", "write"]
    parameters: dict[str, Any]
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    expected_execution_owner_id: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{32}$", exclude_if=lambda value: value is None
    )

    @field_validator("target_device_id")
    @classmethod
    def canonical_device_id(cls, value: str) -> str:
        try:
            parsed = UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ValueError("Device ID must be a UUID") from exc
        if str(parsed) != value:
            raise ValueError("Device ID must use canonical lowercase UUID format")
        return value

    @model_validator(mode="after")
    def validate_executor_parameters(self) -> TaskRequest:
        if self.expected_execution_owner_id is not None:
            key = self.idempotency_key
            if key is None or re.fullmatch(r"agent-[0-9a-f]{64}", key) is None:
                raise ValueError("Device-bound tasks require an original operation key")
        if self.executor_type != "development" and self.timeout_seconds > 300:
            raise ValueError("Only development commands support timeouts above 300 seconds")
        if self.executor_type == "command":
            if self.action != "run":
                raise ValueError("The command executor only supports run")
            self.parameters = CommandParameters.model_validate(self.parameters).model_dump()
        elif self.executor_type == "file":
            if self.action != "read":
                raise ValueError("The file executor only supports read")
            self.parameters = FileParameters.model_validate(self.parameters).model_dump()
        elif self.executor_type == "development":
            if self.action != "run":
                raise ValueError("The development executor only supports run")
            self.parameters = DevelopmentRunParameters.model_validate(self.parameters).model_dump()
        else:
            models = WORKSPACE_MODELS
            if self.action not in {"list", "search", "read", "write"}:
                raise ValueError("Unsupported workspace action")
            self.parameters = models[self.action].model_validate(self.parameters).model_dump()
        _json_size(self.parameters, 120000)
        return self


class CapabilityRequest(ProtocolModel):
    capabilities: list[dict[str, Any]] = Field(max_length=16)

    @field_validator("capabilities")
    @classmethod
    def bounded_capabilities(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        _json_size(value, 65536)
        return value


class PairRequest(CapabilityRequest):
    device_id: str
    display_name: str = Field(min_length=1, max_length=80)
    os: str = Field(min_length=1, max_length=40)
    architecture: str = Field(min_length=1, max_length=40)
    worker_version: str = Field(min_length=1, max_length=40)
    policy_profile: str = Field(default="local-restricted", min_length=1, max_length=80)
    code: str = Field(min_length=32, max_length=256, repr=False)
    credential: str = Field(min_length=32, max_length=256, repr=False)

    @field_validator("device_id")
    @classmethod
    def canonical_device_id(cls, value: str) -> str:
        return TaskRequest.canonical_device_id(value)


class Heartbeat(CapabilityRequest):
    worker_version: str | None = Field(default=None, min_length=1, max_length=40)


class ReportRequest(ProtocolModel):
    state: Literal["succeeded", "failed", "timed_out", "cancelled", "unknown"]
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_report(self) -> ReportRequest:
        if self.state == "succeeded":
            if self.result is None or self.error is not None:
                raise ValueError("Success requires a result and no error")
        else:
            if self.error is None:
                raise ValueError("An unsuccessful report requires a structured error")
            if set(self.error) - {"code", "message"}:
                raise ValueError("Error only supports code and message")
            code = self.error.get("code")
            message = self.error.get("message")
            if not isinstance(code, str) or not 1 <= len(code) <= 128:
                raise ValueError("Error code must contain 1 to 128 characters")
            if not isinstance(message, str) or not 1 <= len(message) <= 1024:
                raise ValueError("Error message must contain 1 to 1024 characters")
        _json_size(self.model_dump(), 300000)
        return self
