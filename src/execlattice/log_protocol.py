"""Bounded, byte-addressed observations of an existing large text log."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_LOG_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_LOG_READ_BYTES = 65536
MAX_LOG_SCAN_BYTES = 4 * 1024 * 1024
MAX_LOG_MATCHES = 100
MAX_LOG_SCAN_SECONDS = 5
MAX_LOG_RESPONSE_BYTES = 180000
MAX_LOG_TEXT_JSON_BYTES = 128 * 1024
LogEncoding = Literal["auto", "utf-8", "utf-16-le", "utf-16-be", "gb18030"]
ResolvedLogEncoding = Literal["utf-8", "utf-16-le", "utf-16-be", "gb18030"]


class _Parameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class LogPathParameters(_Parameters):
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def ordinary_path(cls, value):
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Path must not contain control characters")
        return value


class LogReadParameters(LogPathParameters):
    offset: int = Field(default=0, ge=0, le=MAX_LOG_FILE_BYTES)
    limit: int = Field(default=MAX_LOG_READ_BYTES, ge=4, le=MAX_LOG_READ_BYTES)
    tail_bytes: int | None = Field(default=None, ge=4, le=MAX_LOG_READ_BYTES)
    encoding: LogEncoding = "auto"
    expected_version: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def range_or_tail(self):
        if self.tail_bytes is not None and self.offset:
            raise ValueError("Tail and a nonzero offset cannot be combined")
        return self


class LogSearchCursor(_Parameters):
    offset: int = Field(ge=0, le=MAX_LOG_FILE_BYTES)
    version: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoding: ResolvedLogEncoding


class LogSearchParameters(LogPathParameters):
    query: str = Field(min_length=1, max_length=128, repr=False)
    case_sensitive: bool = True
    encoding: LogEncoding = "auto"
    max_matches: int = Field(default=50, ge=1, le=MAX_LOG_MATCHES)
    scan_bytes: int = Field(default=1048576, ge=65536, le=MAX_LOG_SCAN_BYTES)
    cursor: LogSearchCursor | None = None

    @field_validator("query")
    @classmethod
    def literal_query(cls, value):
        if any(ord(char) < 32 or ord(char) == 127 for char in value) or len(value.encode("utf-8")) > 512:
            raise ValueError("Query must be one printable text line of at most 512 UTF-8 bytes")
        return value


LOG_MODELS = {"log_read": LogReadParameters, "log_search": LogSearchParameters}


def query_digest(parameters, encoding):
    """Bind an explicit continuation to the same path, literal, mode and codec.

    This is a consistency token, not authentication of a caller's scan history.
    """
    value = {key: parameters[key] for key in ("path", "query", "case_sensitive")}
    value["encoding"] = encoding
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(",", ":")).encode("ascii")).hexdigest()
