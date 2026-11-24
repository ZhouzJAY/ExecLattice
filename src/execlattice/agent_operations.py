"""Shared task operation models; this registry never admits or executes work."""
from __future__ import annotations


def task_operation_models():
    """A fresh map preserves the caller's negotiated paging overrides."""
    from .browser_protocol import BROWSER_MODELS
    from .computer_protocol import COMPUTER_MODELS
    from .development_protocol import WORKSPACE_MODELS, DevelopmentRunParameters
    from .job_protocol import JOB_MODELS
    from .localhost_protocol import LOCALHOST_MODELS
    from .terminal_protocol import TERMINAL_MODELS
    from .transfer_protocol import TRANSFER_MODELS

    models = {"run_development_command": ("development", "run", DevelopmentRunParameters)}
    models.update({operation: ("workspace", action, WORKSPACE_MODELS[action])
                   for operation, action in {
                       "list_directory": "list", "search_files": "search", "read_project_file": "read",
                       "read_project_files": "read_many", "read_log": "log_read", "search_log": "log_search",
                       "apply_project_patch": "apply_patch", "get_project_patch": "patch_status",
                       "write_project_file": "write", "read_file_range": "read_range", "edit_file": "edit",
                       "stat_path": "stat", "create_directory": "mkdir", "copy_file": "copy",
                       "move_file": "move", "view_image": "read_image", "delete_path": "delete",
                       "rename_path": "rename",
                   }.items()})
    models.update({operation: ("computer", action, COMPUTER_MODELS[action])
                   for operation, action in {
                       "get_system_info": "info", "list_windows": "windows", "capture_screen": "capture",
                       "control_computer": "input", "launch_application": "launch",
                       "inspect_system": "inspect", "diagnose_system": "diagnose", "manage_window": "window", "get_environment": "environment",
                       "inspect_controls": "ui_tree", "operate_control": "ui_action",
                       "operate_control_and_observe": "ui_action_observe", "wait_for_controls": "ui_wait",
                       "run_software_workflow": "ui_workflow", "run_software_workflow_target": "ui_workflow_target",
                       "read_clipboard": "clipboard_read",
                       "write_clipboard": "clipboard_write",
                   }.items()})
    models.update({"terminal_" + action: ("terminal", action, model)
                   for action, model in TERMINAL_MODELS.items()})
    models.update({"transfer_" + action: ("transfer", action, model)
                   for action, model in TRANSFER_MODELS.items()})
    models["request_localhost"] = ("localhost", "request", LOCALHOST_MODELS["request"])
    models.update({operation: ("browser", action, BROWSER_MODELS[action])
                   for operation, action in {
                       "open_browser": "start", "list_browser_tabs": "tabs", "navigate_browser": "navigate",
                       "inspect_browser_page": "snapshot", "operate_browser_page": "action",
                       "operate_browser_page_and_observe": "action_observe", "close_browser": "close",
                       "run_browser_workflow": "workflow",
                   }.items()})
    models.update({"job_" + action: ("job", action, model) for action, model in JOB_MODELS.items()})
    from .system_tool_registry import SYSTEM_TOOLS

    models.update({row[0]: ("computer", action, COMPUTER_MODELS[action]) for action, row in SYSTEM_TOOLS.items()})
    return models


def valid_operation_id(value):
    """Operation IDs are the existing caller-supplied external idempotency keys."""
    try:
        return (isinstance(value, str) and 8 <= len(value) <= 128
                and not any(ord(character) < 32 for character in value)
                and bool(value.encode("utf-8")))
    except UnicodeError:
        return False
