"""Exact, versioned declaration for durable project patch receipts."""


def project_patch_capability() -> dict:
    return {"version": 1, "max_files": 8, "max_hunks": 64,
            "max_text_bytes": 65536, "max_preflight_bytes": 16 * 1024 * 1024,
            "durable_receipts": True, "automatic_replay": False}


def valid_project_patch_capability(value) -> bool:
    expected = project_patch_capability()
    return (isinstance(value, dict) and set(value) == set(expected)
            and all(type(value[key]) is type(item) and value[key] == item for key, item in expected.items()))
