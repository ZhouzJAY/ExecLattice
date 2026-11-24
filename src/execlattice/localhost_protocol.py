"""Bounded HTTP requests to literal loopback services on the selected computer."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_HTTP_BODY_BYTES = 65536
MAX_HTTP_HEADER_BYTES = 16384
MAX_HTTP_HEADERS = 80
READ_METHODS = frozenset({"GET", "HEAD"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MANAGED_HEADERS = frozenset({"host", "connection", "content-length", "transfer-encoding", "expect",
                              "upgrade", "proxy-authorization", "proxy-connection", "accept-encoding",
                              "trailer", "te"})


def request_body(value):
    """Return canonical bounded bytes without accepting whitespace or aliases."""
    if not isinstance(value, str) or len(value) > 4 * ((MAX_HTTP_BODY_BYTES + 2) // 3):
        raise ValueError("HTTP body exceeds 64 KiB")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("HTTP body must use canonical base64") from None
    if len(raw) > MAX_HTTP_BODY_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("HTTP body must use canonical base64 and fit in 64 KiB")
    return raw


class LocalhostRequestParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    scheme: Literal["http", "https"] = "http"
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: int = Field(ge=1, le=65535)
    path: str = Field(default="/", min_length=1, max_length=8192, repr=False)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict, repr=False)
    body_b64: str = Field(default="", repr=False)
    max_response_bytes: int = Field(default=MAX_HTTP_BODY_BYTES, ge=1, le=MAX_HTTP_BODY_BYTES)

    @field_validator("path")
    @classmethod
    def origin_form(cls, value):
        if (not value.startswith("/") or value.startswith("//") or "\\" in value or "#" in value
                or any(not 33 <= ord(char) <= 126 for char in value)
                or re.search(r"%(?![0-9a-fA-F]{2})", value)):
            raise ValueError("HTTP path must be an ASCII origin-form path; URL-encode non-ASCII text")
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ValueError("HTTP path must not contain another origin, userinfo, or fragment")
        decoded = parsed.path
        # Reject encoded private application names as well as ordinary names.
        # This is accidental-state protection, not a sandbox for full commands.
        for _ in range(4):
            current = unquote(decoded)
            if any(ord(char) < 32 or ord(char) == 127 for char in current) or "\\" in current:
                raise ValueError("HTTP path contains unsafe encoded characters")
            if any(part.split(":", 1)[0].rstrip(" .").casefold() in {".execlattice", ".omniagent"}
                   for part in current.split("/")):
                raise ValueError("Application private state is not a project HTTP resource")
            if current == decoded:
                break
            decoded = current
        else:
            raise ValueError("HTTP path is excessively encoded")
        return value

    @field_validator("headers")
    @classmethod
    def bounded_headers(cls, value):
        if len(value) > MAX_HTTP_HEADERS:
            raise ValueError("Too many HTTP headers")
        names, size = set(), 0
        for name, text in value.items():
            lower = name.casefold()
            if (not HEADER_NAME.fullmatch(name) or lower in names or lower in _MANAGED_HEADERS
                    or any(not 32 <= ord(char) <= 126 for char in text)):
                raise ValueError("HTTP headers must be ordinary ASCII fields without transport overrides")
            names.add(lower)
            size += len(name) + len(text) + 4
        if size > MAX_HTTP_HEADER_BYTES:
            raise ValueError("HTTP headers exceed 16 KiB")
        return value

    @field_validator("body_b64")
    @classmethod
    def bounded_body(cls, value):
        request_body(value)
        return value

    @model_validator(mode="after")
    def safe_method_body(self):
        if self.method in READ_METHODS and self.body_b64:
            raise ValueError("GET and HEAD requests do not accept a request body")
        return self


LOCALHOST_MODELS = {"request": LocalhostRequestParameters}


def validate_localhost_parameters(action, parameters):
    model = LOCALHOST_MODELS.get(action)
    if model is None:
        raise ValueError("Unknown localhost operation")
    return model.model_validate(parameters).model_dump()


def localhost_capabilities():
    return {"http_request": 1, "schemes": ["http", "https"], "hosts": ["127.0.0.1", "::1"],
            "read_methods": ["GET", "HEAD"], "write_methods": ["POST", "PUT", "PATCH", "DELETE"],
            "max_request_bytes": MAX_HTTP_BODY_BYTES, "max_response_bytes": MAX_HTTP_BODY_BYTES,
            "redirects": False, "retries": False, "tls_verification": "system"}
