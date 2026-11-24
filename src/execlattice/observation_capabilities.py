"""Strict versioned declarations for software observations and log access."""


def uia_observation_capability() -> dict:
    return {"version": 1, "max_wait_ms": 5000, "min_interval_ms": 100,
            "max_nodes": 256, "max_depth": 12, "action_retries": False,
            "explicit_condition_confirmation": True, "values_included": False}


def log_access_capability() -> dict:
    return {"version": 1, "max_file_bytes": 2147483648, "max_read_bytes": 65536,
            "max_scan_bytes": 4194304, "max_matches": 100, "max_scan_seconds": 5,
            "whole_file_sha256": False, "versioned_cursors": True}


def software_backend_capability() -> dict:
    return {"version": 1, "component": "pywinauto", "component_version": "0.6.9", "backend": "uia",
            "isolated_process": True, "persistent_helper": True, "apartment": "MTA",
            "provider_deadline": True, "uncertain_action_retries": False, "password_fields": False}


def _valid(value, expected):
    return (isinstance(value, dict) and set(value) == set(expected)
            and all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))


def valid_uia_observation_capability(value) -> bool:
    return _valid(value, uia_observation_capability())


def valid_log_access_capability(value) -> bool:
    return _valid(value, log_access_capability())


def valid_software_backend_capability(value) -> bool:
    return _valid(value, software_backend_capability())


def workspace_read_capability() -> dict:
    return {"version": 1, "actions": ["list", "list_page", "read", "read_many"],
            "max_duration_seconds": 30, "max_result_bytes": 160000,
            "taskless": True, "binding": "worker-session-and-execution-owner"}


def valid_workspace_read_capability(value) -> bool:
    return _valid(value, workspace_read_capability())
