"""Binary file transport over the authenticated task channel."""

from __future__ import annotations

import base64
import binascii
import hashlib

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CHUNK_BYTES = 65536
MAX_TRANSFER_BYTES = 2 * 1024 ** 3
TRANSFER_ID = r"^[0-9a-f]{32}$"
SHA256 = r"^[0-9a-f]{64}$"


class TransferParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class TransferIdParameters(TransferParameters):
    transfer_id: str = Field(pattern=TRANSFER_ID)


class TransferPathParameters(TransferParameters):
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def ordinary_text(cls, value):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Paths cannot contain control characters")
        return value


class UploadBeginParameters(TransferPathParameters, TransferIdParameters):
    size_bytes: int = Field(ge=0, le=MAX_TRANSFER_BYTES)
    sha256: str = Field(pattern=SHA256)
    expected_sha256: str | None = Field(default=None, pattern=SHA256)


class UploadChunkParameters(TransferIdParameters):
    offset: int = Field(ge=0, le=MAX_TRANSFER_BYTES)
    data_b64: str = Field(max_length=4 * ((CHUNK_BYTES + 2) // 3), repr=False)
    chunk_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def exact_chunk(self):
        try:
            raw = base64.b64decode(self.data_b64, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid binary chunk") from None
        if (not 1 <= len(raw) <= CHUNK_BYTES or base64.b64encode(raw).decode("ascii") != self.data_b64
                or hashlib.sha256(raw).hexdigest() != self.chunk_sha256
                or self.offset + len(raw) > MAX_TRANSFER_BYTES):
            raise ValueError("Invalid binary chunk receipt")
        return self


class DownloadBeginParameters(TransferPathParameters, TransferIdParameters):
    expected_sha256: str | None = Field(default=None, pattern=SHA256)


class DownloadChunkParameters(TransferIdParameters):
    offset: int = Field(default=0, ge=0, le=MAX_TRANSFER_BYTES)
    limit: int = Field(default=CHUNK_BYTES, ge=1, le=CHUNK_BYTES)


TRANSFER_MODELS = {
    "upload_begin": UploadBeginParameters,
    "upload_chunk": UploadChunkParameters,
    "upload_status": TransferIdParameters,
    "upload_commit": TransferIdParameters,
    "upload_abort": TransferIdParameters,
    "download_begin": DownloadBeginParameters,
    "download_chunk": DownloadChunkParameters,
    "download_status": TransferIdParameters,
    "download_abort": TransferIdParameters,
}
TRANSFER_READ_ACTIONS = frozenset({"download_begin", "download_chunk", "download_status", "download_abort"})


def validate_transfer_parameters(action, parameters):
    model = TRANSFER_MODELS.get(action)
    if model is None:
        raise ValueError("Unsupported transfer action")
    return model.model_validate(parameters).model_dump()
