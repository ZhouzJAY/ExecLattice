"""Short authenticated operations on independently owned long-running jobs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class JobParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class JobStartParameters(JobParameters):
    command: str = Field(min_length=1, max_length=12000, repr=False)
    cwd: str = Field(min_length=1, max_length=4096)
    max_runtime_seconds: int = Field(default=86400, ge=1, le=86400)

    @field_validator("command")
    @classmethod
    def command_text(cls, value):
        if not value.strip() or "\x00" in value:
            raise ValueError("Invalid job command")
        return value

    @field_validator("cwd")
    @classmethod
    def directory(cls, value):
        from .development_protocol import DevelopmentRunParameters

        return DevelopmentRunParameters.absolute_directory(value)


class JobListParameters(JobParameters):
    pass


class JobIdentityParameters(JobParameters):
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$")


JOB_MODELS = {"start": JobStartParameters, "list": JobListParameters,
              "describe": JobIdentityParameters, "cancel": JobIdentityParameters}


def valid_execution_host(value):
    import re

    return (isinstance(value, dict) and set(value) == {
        "version", "owner_id", "persistent_sessions", "persistent_jobs"}
        and type(value.get("version")) is int and value["version"] == 1
        and value.get("persistent_sessions") is True and value.get("persistent_jobs") is True
        and isinstance(value.get("owner_id"), str) and re.fullmatch(r"[0-9a-f]{32}", value["owner_id"]) is not None)
