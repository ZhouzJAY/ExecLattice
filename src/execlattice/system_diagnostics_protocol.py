"""Strict target-only requests for fixed current-user Windows diagnostics."""

from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_DIAGNOSTIC_ITEMS = 32
MAX_DIAGNOSTIC_BYTES = 120000


def diagnostic_text(value, limit=512):
    return (type(value) is str and len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def ordinary_path(value):
    if not diagnostic_text(value, 2048) or value.startswith(("\\\\", "//")):
        return False
    path = PureWindowsPath(value)
    return (bool(re.fullmatch(r"[A-Za-z]:", path.drive)) and path.is_absolute()
            and not any(c in value[2:] for c in ':<>"|?*')
            and all(p not in {".", ".."} and not p.endswith((" ", ".")) for p in path.parts[1:]))


class SystemDiagnosticParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    target_type: Literal["process", "service", "port", "executable"]
    target: int | str
    limit: int = Field(default=16, ge=1, le=MAX_DIAGNOSTIC_ITEMS)
    include_events: bool = False
    event_minutes: int = Field(default=60, ge=1, le=1440)
    expected_process_created: str | None = None

    @model_validator(mode="after")
    def target_shape(self):
        if self.target_type in {"process", "port"}:
            maximum = 2**32 - 1 if self.target_type == "process" else 65535
            if type(self.target) is not int or not 1 <= self.target <= maximum:
                raise ValueError("A numeric process ID or port is required")
        elif self.target_type == "service":
            if not diagnostic_text(self.target, 256) or not self.target:
                raise ValueError("A literal nonempty service name is required")
        elif not ordinary_path(self.target):
            raise ValueError("An ordinary absolute Windows file path is required")
        if self.expected_process_created is not None:
            value = self.expected_process_created
            if (self.target_type != "process" or type(value) is not str
                    or not re.fullmatch(r"[1-9][0-9]{0,19}", value) or int(value) > 2**64 - 1):
                raise ValueError("A process creation FILETIME is required")
        return self


def validate_diagnostic_parameters(parameters):
    return SystemDiagnosticParameters.model_validate(parameters).model_dump()


def diagnostic_capability():
    return {"version": 1, "target_types": ["process", "service", "port", "executable"],
            "max_items": MAX_DIAGNOSTIC_ITEMS, "max_result_bytes": MAX_DIAGNOSTIC_BYTES,
            "max_event_minutes": 1440, "events_default": False, "read_only": True,
            "automatic_elevation": False, "process_identity": "pid-and-creation-filetime",
            "event_projection": "metadata-only-exact-target-data-match"}


def valid_diagnostic_capability(value):
    expected = diagnostic_capability()
    return (type(value) is dict and set(value) == set(expected)
            and all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))
