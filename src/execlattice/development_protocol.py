"""Strict parameter schemas for authenticated desktop development tasks."""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .log_protocol import LOG_MODELS

MAX_TEXT_BYTES = 65536
MAX_READ_MANY_FILES = 16
MAX_READ_MANY_PATH_BYTES = 8192
MAX_READ_MANY_BYTES = 65536
MAX_READ_MANY_RESULT_BYTES = 160000
MAX_READ_MANY_RESPONSE_BYTES = 180000
MAX_EDIT_FILE_BYTES = 8 * 1024 * 1024
MAX_FILE_OPERATION_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE_IMAGE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_IMAGE_PIXELS = 16 * 1024 * 1024
MAX_WORKSPACE_IMAGE_BYTES = 96000
TextEncoding = Literal["auto", "utf-8", "utf-16-le", "utf-16-be", "gb18030"]


class DevelopmentParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class WorkspacePathParameters(DevelopmentParameters):
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def printable_path(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Path must not contain control characters")
        return value


class WorkspaceListParameters(DevelopmentParameters):
    path: str = Field(default="", max_length=4096)
    limit: int = Field(default=300, ge=1, le=500)

    @field_validator("path")
    @classmethod
    def printable_path(cls, value: str) -> str:
        return WorkspacePathParameters.printable_path(value)


class WorkspaceListPageParameters(WorkspaceListParameters):
    cursor: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}:[0-9]{1,5}$")
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class WorkspaceSearchParameters(WorkspacePathParameters):
    query: str = Field(min_length=1, max_length=1024)
    glob: str = Field(default="*", min_length=1, max_length=128)
    case_sensitive: bool = False
    max_results: int = Field(default=100, ge=1, le=200)

    @field_validator("query")
    @classmethod
    def text_query(cls, value: str) -> str:
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("Search query must be a single text line")
        return value

    @field_validator("glob")
    @classmethod
    def filename_pattern(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value) or "/" in value or "\\" in value or ":" in value:
            raise ValueError("Glob must be a filename pattern")
        return value


class WorkspaceSearchPageParameters(WorkspaceSearchParameters):
    cursor: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}:[0-9]{1,5}$")
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class WorkspaceNativeSearchPageParameters(WorkspaceSearchPageParameters):
    pattern_type: Literal["literal", "regex"] = "literal"


class WorkspaceReadParameters(WorkspacePathParameters):
    pass


class WorkspaceReadManyFile(WorkspacePathParameters):
    encoding: TextEncoding = "auto"


class WorkspaceReadManyParameters(DevelopmentParameters):
    files: list[WorkspaceReadManyFile] = Field(min_length=1, max_length=MAX_READ_MANY_FILES)

    @field_validator("files")
    @classmethod
    def bounded_paths(cls, value):
        if sum(len(item.path.encode("utf-8")) for item in value) > MAX_READ_MANY_PATH_BYTES:
            raise ValueError("Combined file paths exceed the batch limit")
        return value


class WorkspaceStatParameters(WorkspacePathParameters):
    pass


class WorkspaceMkdirParameters(WorkspacePathParameters):
    exist_ok: bool = False


class WorkspaceMoveParameters(WorkspacePathParameters):
    destination: str = Field(min_length=1, max_length=4096)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("destination")
    @classmethod
    def printable_destination(cls, value: str) -> str:
        return WorkspacePathParameters.printable_path(value)


class WorkspaceCopyParameters(WorkspaceMoveParameters):
    expected_target_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class WorkspaceDeleteParameters(WorkspacePathParameters):
    expected_version: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkspaceRenameParameters(WorkspaceDeleteParameters):
    destination: str = Field(min_length=1, max_length=4096)

    @field_validator("destination")
    @classmethod
    def printable_destination(cls, value):
        return WorkspacePathParameters.printable_path(value)


class WorkspaceReadImageParameters(WorkspacePathParameters):
    max_width: int = Field(default=1280, ge=64, le=1280)
    max_height: int = Field(default=1280, ge=64, le=1280)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class WorkspaceReadRangeParameters(WorkspacePathParameters):
    offset: int = Field(default=0, ge=0, le=MAX_EDIT_FILE_BYTES)
    limit: int = Field(default=MAX_TEXT_BYTES, ge=4, le=MAX_TEXT_BYTES)
    encoding: Literal["auto", "utf-8", "utf-16-le", "utf-16-be", "gb18030", "binary"] = "auto"
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class WorkspaceEditParameters(WorkspacePathParameters):
    old_text: str = Field(min_length=1, max_length=32768, repr=False)
    new_text: str = Field(max_length=32768, repr=False)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoding: TextEncoding = "auto"

    @field_validator("old_text", "new_text")
    @classmethod
    def bounded_text(cls, value: str) -> str:
        if "\x00" in value or len(value.encode("utf-8")) > 32768:
            raise ValueError("Edit text must contain no NUL and fit in 32 KiB of UTF-8")
        return value


class WorkspacePatchHunk(DevelopmentParameters):
    old_text: str = Field(min_length=1, max_length=32768, repr=False)
    new_text: str = Field(max_length=32768, repr=False)

    @field_validator("old_text", "new_text")
    @classmethod
    def bounded_text(cls, value: str) -> str:
        return WorkspaceEditParameters.bounded_text(value)


class WorkspacePatchFile(WorkspacePathParameters):
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoding: TextEncoding = "auto"
    edits: list[WorkspacePatchHunk] = Field(min_length=1, max_length=16)


class WorkspaceApplyPatchParameters(DevelopmentParameters):
    patch_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    files: list[WorkspacePatchFile] = Field(min_length=1, max_length=8)

    @field_validator("files")
    @classmethod
    def bounded_patch(cls, value):
        if len({item.path for item in value}) != len(value):
            raise ValueError("A patch must name each file only once")
        if sum(len(item.path.encode("utf-8")) for item in value) > 8192:
            raise ValueError("Combined file paths exceed the patch limit")
        if sum(len(item.edits) for item in value) > 64:
            raise ValueError("A patch supports at most 64 hunks")
        if sum(len(text.encode("utf-8")) for item in value for edit in item.edits
               for text in (edit.old_text, edit.new_text)) > 65536:
            raise ValueError("Combined patch text exceeds 64 KiB of UTF-8")
        return value


class WorkspacePatchStatusParameters(DevelopmentParameters):
    patch_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class WorkspaceWriteParameters(WorkspacePathParameters):
    content_b64: str = Field(max_length=4 * ((MAX_TEXT_BYTES + 2) // 3), repr=False)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("content_b64")
    @classmethod
    def bounded_utf8(cls, value: str) -> str:
        try:
            content = base64.b64decode(value, validate=True)
            if len(content) > MAX_TEXT_BYTES or base64.b64encode(content).decode("ascii") != value:
                raise ValueError("File content exceeds the limit or is not canonical base64")
            if b"\x00" in content:
                raise ValueError("Text files must not contain NUL bytes")
            content.decode("utf-8-sig")
        except (binascii.Error, UnicodeError) as exc:
            raise ValueError("Content must be base64-encoded UTF-8 text") from exc
        return value


class DevelopmentRunParameters(DevelopmentParameters):
    command: str = Field(min_length=1, max_length=12000, repr=False)
    cwd: str = Field(min_length=1, max_length=4096)

    @field_validator("command")
    @classmethod
    def valid_command(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("Development command must contain text and no NUL")
        return value

    @field_validator("cwd")
    @classmethod
    def absolute_directory(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Working directory must not contain control characters")
        windows = PureWindowsPath(value)
        if value.startswith(("\\\\", "//")) or not (windows.is_absolute() or os.path.isabs(value)):
            raise ValueError("Working directory must be an absolute local path")
        return value


WORKSPACE_MODELS = {
    "list": WorkspaceListParameters,
    "list_page": WorkspaceListPageParameters,
    "search": WorkspaceSearchParameters,
    "search_page": WorkspaceSearchPageParameters,
    "search_native_page": WorkspaceNativeSearchPageParameters,
    "read": WorkspaceReadParameters,
    "read_many": WorkspaceReadManyParameters,
    "write": WorkspaceWriteParameters,
    "read_range": WorkspaceReadRangeParameters,
    "edit": WorkspaceEditParameters,
    "apply_patch": WorkspaceApplyPatchParameters,
    "patch_status": WorkspacePatchStatusParameters,
    "stat": WorkspaceStatParameters,
    "mkdir": WorkspaceMkdirParameters,
    "copy": WorkspaceCopyParameters,
    "move": WorkspaceMoveParameters,
    "read_image": WorkspaceReadImageParameters,
    "delete": WorkspaceDeleteParameters,
    "rename": WorkspaceRenameParameters,
    **LOG_MODELS,
}


def validate_workspace_parameters(action: str, parameters: dict) -> dict:
    model = WORKSPACE_MODELS.get(action)
    if model is None:
        raise ValueError("Unknown workspace action")
    return model.model_validate(parameters).model_dump()
