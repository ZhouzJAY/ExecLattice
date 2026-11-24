"""Strict, current-connection parameters for native Windows terminals."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

TERMINAL_BACKENDS = frozenset({"windows-conpty", "pywinpty-3.1.0-winpty"})
DEFAULT_TERMINAL_BACKEND = "windows-conpty"
WINPTY_COMPATIBILITY = {"backend": "pywinpty-3.1.0-winpty", "component": "pywinpty", "version": "3.1.0",
                       "output_semantics": "screen-redraw-vt", "exact_output_bytes": False}


def valid_winpty_compatibility(value):
    return (type(value) is dict and set(value) == set(WINPTY_COMPATIBILITY)
            and all(type(value[k]) is type(v) and value[k] == v for k, v in WINPTY_COMPATIBILITY.items()))


class TerminalParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    # The desktop injects its pinned connection handle; MCP callers cannot
    # choose another owner's sessions. It also travels in the durable task.
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class TerminalOpenParameters(TerminalParameters):
    cwd: str = Field(default="", max_length=4096)
    shell: Literal["powershell", "cmd"] = "powershell"
    backend: Literal["native", "winpty"] = "native"
    columns: int = Field(default=120, ge=20, le=300)
    rows: int = Field(default=30, ge=5, le=150)

    @model_serializer(mode="wrap")
    def legacy_native_wire(self, handler):
        value = handler(self)
        if self.backend == "native":
            value.pop("backend", None)
        return value

    @field_validator("cwd")
    @classmethod
    def ordinary_path(cls, value):
        from .development_protocol import DevelopmentRunParameters

        return DevelopmentRunParameters.absolute_directory(value) if value else value


class TerminalSessionParameters(TerminalParameters):
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class TerminalListParameters(TerminalParameters):
    pass


class TerminalDescribeParameters(TerminalSessionParameters):
    pass


class TerminalReadParameters(TerminalSessionParameters):
    cursor: int = Field(default=0, ge=0, le=2**63 - 1)
    limit: int = Field(default=16384, ge=4, le=32768)
    wait_ms: int = Field(default=0, ge=0, le=10000)


class TerminalStreamParameters(TerminalSessionParameters):
    """A read-only subscription; it is never submitted as a durable task."""

    cursor: int = Field(default=0, ge=0, le=2**63 - 1)
    limit: int = Field(default=32768, ge=4, le=32768)
    wait_ms: int = Field(default=1000, ge=0, le=1000)


class TerminalWriteParameters(TerminalSessionParameters):
    text: str = Field(min_length=1, max_length=8192, repr=False)
    expected_input_sequence: int = Field(ge=0, le=2**63 - 1)

    @field_validator("text")
    @classmethod
    def bounded_utf8(cls, value):
        if "\x00" in value or len(value.encode("utf-8")) > 8192:
            raise ValueError("Terminal input must be at most 8192 UTF-8 bytes and contain no NUL")
        return value


class TerminalResizeParameters(TerminalSessionParameters):
    columns: int = Field(ge=20, le=300)
    rows: int = Field(ge=5, le=150)


class TerminalCloseParameters(TerminalSessionParameters):
    pass


TERMINAL_MODELS = {
    "open": TerminalOpenParameters,
    "list": TerminalListParameters,
    "describe": TerminalDescribeParameters,
    "read": TerminalReadParameters,
    "write": TerminalWriteParameters,
    "resize": TerminalResizeParameters,
    "close": TerminalCloseParameters,
}


def validate_terminal_parameters(action: str, parameters: dict) -> dict:
    model = TERMINAL_MODELS.get(action)
    if model is None:
        raise ValueError("Unknown terminal action")
    return model.model_validate(parameters).model_dump()
