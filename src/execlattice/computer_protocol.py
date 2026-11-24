"""Bounded requests for the connected user's Windows desktop."""

from __future__ import annotations

import json
import re
from pathlib import PureWindowsPath
from typing import Annotated, Literal, get_args

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from .system_diagnostics_protocol import SystemDiagnosticParameters
from .system_tool_registry import system_models

MAX_IMAGE_BYTES = 160000
MAX_FRAME_AGE = 60
MAX_CLIPBOARD_BYTES = 65536

# UIAutomationClient.h control type IDs, in their stable numeric order.
# https://learn.microsoft.com/windows/win32/winauto/uiauto-controltype-ids
UIAControlTypeName = Literal[
    "Button", "Calendar", "CheckBox", "ComboBox", "Edit", "Hyperlink", "Image", "ListItem",
    "List", "Menu", "MenuBar", "MenuItem", "ProgressBar", "RadioButton", "ScrollBar", "Slider",
    "Spinner", "StatusBar", "Tab", "TabItem", "Text", "ToolBar", "ToolTip", "Tree", "TreeItem",
    "Custom", "Group", "Thumb", "DataGrid", "DataItem", "Document", "SplitButton", "Window",
    "Pane", "Header", "HeaderItem", "Table", "TitleBar", "Separator", "SemanticZoom", "AppBar",
]
_UIA_CONTROL_TYPE_IDS = {name: 50000 + index for index, name in enumerate(get_args(UIAControlTypeName))}
_UIAControlTypeId = Annotated[int, Field(strict=True, ge=50000, le=59999)]


def _uia_control_type(value):
    # Canonicalize before any request is hashed or submitted. Unknown names,
    # numeric strings, bools and floats retain the strict integer rejection.
    return _UIA_CONTROL_TYPE_IDS.get(value, value) if type(value) is str else value


UIAControlType = Annotated[
    _UIAControlTypeId,
    BeforeValidator(_uia_control_type, json_schema_input_type=_UIAControlTypeId | UIAControlTypeName),
]


class ComputerParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class ComputerInfoParameters(ComputerParameters):
    pass


class ComputerEnvironmentParameters(ComputerParameters):
    pass


class ComputerWindowsParameters(ComputerParameters):
    pass


def clipboard_text(value: str) -> str:
    if ("\x00" in value or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
            or len(value.encode("utf-8")) > MAX_CLIPBOARD_BYTES):
        raise ValueError("Clipboard requires at most 64 KiB of Unicode text")
    return value


class ComputerClipboardReadParameters(ComputerParameters):
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class ComputerClipboardWriteParameters(ComputerClipboardReadParameters):
    observation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    expected_sequence: int = Field(ge=0, le=2**32 - 1)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    text: str = Field(max_length=MAX_CLIPBOARD_BYTES, repr=False)

    @field_validator("text")
    @classmethod
    def bounded_unicode(cls, value):
        return clipboard_text(value)


class ComputerUITreeParameters(ComputerParameters):
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    window_id: str
    max_nodes: int = Field(default=128, ge=1, le=256)
    max_depth: int = Field(default=6, ge=0, le=12)
    timeout_ms: int = Field(default=2000, ge=250, le=5000)

    @field_validator("window_id")
    @classmethod
    def specific_window(cls, value):
        return _window_id(value, desktop=False)


class ComputerUIActionParameters(ComputerParameters):
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    control_token: str = Field(pattern=r"^[0-9a-f]{32}$")
    operation: Literal["invoke", "focus", "set_value", "toggle", "select", "expand", "collapse", "scroll_into_view"]
    value: str | None = Field(default=None, max_length=4096, repr=False)

    @model_validator(mode="after")
    def bounded_value(self):
        if self.operation == "set_value":
            if (self.value is None or "\x00" in self.value
                    or any(0xD800 <= ord(char) <= 0xDFFF for char in self.value)
                    or len(self.value.encode("utf-8")) > 8192):
                raise ValueError("Set-value requires bounded Unicode text")
        elif self.value is not None:
            raise ValueError("Only set_value accepts text")
        return self


class ComputerUICondition(ComputerParameters):
    automation_id: str | None = Field(default=None, min_length=1, max_length=256)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    control_type: UIAControlType | None = Field(
        default=None, description="Exact Windows UIA name (e.g. Edit, CheckBox, ComboBox, Button) or numeric ID; names become the existing integer wire ID",
        examples=["CheckBox", 50002])
    property: Literal["exists", "checked", "selected", "expanded"]
    expected: bool | str

    @model_validator(mode="after")
    def exact_predicate(self):
        if self.automation_id is None and self.name is None:
            raise ValueError("A condition requires an exact automation ID or name")
        if any(value is not None and ("\x00" in value or any(0xD800 <= ord(c) <= 0xDFFF for c in value))
               for value in (self.automation_id, self.name)):
            raise ValueError("A condition requires ordinary Unicode identifiers")
        if self.property in {"exists", "selected"}:
            valid = type(self.expected) is bool
        elif self.property == "checked":
            valid = type(self.expected) is str and self.expected in {"off", "on", "indeterminate"}
        else:
            valid = type(self.expected) is str and self.expected in {
                "collapsed", "expanded", "partially_expanded", "leaf"}
        if not valid:
            raise ValueError("Condition expected value must match the selected property")
        return self


# Keep the common validator for stored receipts and exact selectors. Public
# requests use the tagged variants so MCP exposes each property's actual type.
class ComputerUIExistsCondition(ComputerUICondition):
    property: Literal["exists"]
    expected: bool = Field(description="Whether the uniquely identified Windows control exists", examples=[True])


class ComputerUICheckedCondition(ComputerUICondition):
    property: Literal["checked"]
    expected: Literal["off", "on", "indeterminate"] = Field(
        description="Windows UIA ToggleState, not a browser checkbox boolean", examples=["on"])


class ComputerUISelectedCondition(ComputerUICondition):
    property: Literal["selected"]
    expected: bool = Field(description="Windows UIA SelectionItem selected state", examples=[True])


class ComputerUIExpandedCondition(ComputerUICondition):
    property: Literal["expanded"]
    expected: Literal["collapsed", "expanded", "partially_expanded", "leaf"] = Field(
        description="Windows UIA ExpandCollapseState", examples=["expanded"])


ComputerUIConditionRequest = Annotated[
    ComputerUIExistsCondition | ComputerUICheckedCondition | ComputerUISelectedCondition | ComputerUIExpandedCondition,
    Field(discriminator="property"),
]


class UIObservationBounds(ComputerParameters):
    max_nodes: int = Field(default=128, ge=1, le=256)
    max_depth: int = Field(default=6, ge=0, le=12)
    timeout_ms: int = Field(default=2000, ge=250, le=5000)
    wait_ms: int = Field(default=0, ge=0, le=5000)
    interval_ms: int = Field(default=100, ge=100, le=1000)


class ComputerUIActionObserveParameters(ComputerUIActionParameters, UIObservationBounds):
    condition: ComputerUIConditionRequest | None = None


class ComputerUIWaitParameters(ComputerUITreeParameters, UIObservationBounds):
    condition: ComputerUIConditionRequest


class ComputerUIWorkflowSelector(ComputerParameters):
    automation_id: str | None = Field(default=None, min_length=1, max_length=256)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    control_type: UIAControlType | None = Field(
        default=None, description="Exact Windows UIA name (e.g. Edit, CheckBox, ComboBox, Button) or numeric ID; names become the existing integer wire ID",
        examples=["Edit", 50004])

    @model_validator(mode="after")
    def exact_selector(self):
        ComputerUICondition(**self.model_dump(), property="exists", expected=True)
        return self


class ComputerUIWorkflowStep(ComputerParameters):
    selector: ComputerUIWorkflowSelector
    operation: Literal["set_value", "toggle", "select", "invoke", "expand", "collapse"]
    value: str | None = Field(default=None, max_length=4096, repr=False)
    condition: ComputerUIConditionRequest = Field(description="Confirms only this UI predicate; exists never verifies an entered value or business success")
    wait_ms: int = Field(default=1000, ge=0, le=5000)

    @model_validator(mode="after")
    def bounded_action(self):
        ComputerUIActionParameters(owner_id="0" * 32, control_token="0" * 32, operation=self.operation, value=self.value)
        return self


class ComputerUIWorkflowParameters(ComputerParameters):
    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    window_id: str
    observation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    steps: list[ComputerUIWorkflowStep] = Field(min_length=1, max_length=8)
    total_timeout_ms: int = Field(default=60000, ge=1000, le=60000)
    max_nodes: int = Field(default=128, ge=1, le=256)
    max_depth: int = Field(default=6, ge=0, le=12)
    timeout_ms: int = Field(default=1000, ge=250, le=5000)
    interval_ms: int = Field(default=100, ge=100, le=1000)
    focus_policy: Literal["require_foreground", "activate_once"] = "require_foreground"

    @model_serializer(mode="wrap")
    def legacy_focus_shape(self, handler):
        value = handler(self)
        if value.get("focus_policy") == "require_foreground":
            value.pop("focus_policy", None)
        return value

    @field_validator("window_id")
    @classmethod
    def specific_window(cls, value):
        return _window_id(value, desktop=False)

    @model_validator(mode="after")
    def bounded_workflow(self):
        if len(json.dumps(self.model_dump(), ensure_ascii=False).encode("utf-8")) > 32768:
            raise ValueError("Software workflow exceeds its request byte limit")
        return self


class ComputerExpectedProcessIdentity(ComputerParameters):
    pid: int = Field(ge=1, le=2**32 - 1)
    created: int = Field(ge=1, le=2**64 - 1)


class ComputerUIWorkflowTargetStepBase(ComputerParameters):
    selector: ComputerUIWorkflowSelector
    condition: ComputerUIConditionRequest = Field(description="Confirms only this UI predicate; exists never verifies an entered value or business success")
    wait_ms: int = Field(default=1000, ge=0, le=5000)

    @model_validator(mode="after")
    def bounded_legacy_action(self):
        ComputerUIWorkflowStep.model_validate(self.model_dump())
        return self


class ComputerUIWorkflowTargetSetValueStep(ComputerUIWorkflowTargetStepBase):
    operation: Literal["set_value"]
    value: str = Field(max_length=4096, repr=False)


class ComputerUIWorkflowTargetActionStep(ComputerUIWorkflowTargetStepBase):
    operation: Literal["toggle", "select", "invoke", "expand", "collapse"]


ComputerUIWorkflowTargetStep = Annotated[
    ComputerUIWorkflowTargetSetValueStep | ComputerUIWorkflowTargetActionStep,
    Field(discriminator="operation"),
]


class ComputerUIWorkflowTargetParameters(ComputerParameters):
    """A selected process/window, not a capability to reuse an old observation."""

    owner_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    window_id: str
    expected_process: ComputerExpectedProcessIdentity
    steps: list[ComputerUIWorkflowTargetStep] = Field(min_length=1, max_length=8)
    total_timeout_ms: int = Field(default=60000, ge=1000, le=60000)
    max_nodes: int = Field(default=128, ge=1, le=256)
    max_depth: int = Field(default=6, ge=0, le=12)
    timeout_ms: int = Field(default=1000, ge=250, le=5000)
    interval_ms: int = Field(default=100, ge=100, le=1000)
    focus_policy: Literal["require_foreground", "activate_once"] = "require_foreground"

    @model_serializer(mode="wrap")
    def legacy_focus_shape(self, handler):
        value = handler(self)
        if value.get("focus_policy") == "require_foreground":
            value.pop("focus_policy", None)
        return value

    @field_validator("window_id")
    @classmethod
    def specific_window(cls, value):
        return _window_id(value, desktop=False)

    @model_validator(mode="after")
    def bounded_workflow(self):
        if len(json.dumps(self.model_dump(), ensure_ascii=False).encode("utf-8")) > 32768:
            raise ValueError("Software workflow exceeds its request byte limit")
        return self


class ComputerInspectParameters(ComputerParameters):
    topic: Literal["processes", "services", "applications", "network", "environment"]
    query: str = Field(default="", max_length=256)
    limit: int = Field(default=100, ge=1, le=200)

    @field_validator("query")
    @classmethod
    def printable_query(cls, value):
        if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("Inspection query must be printable text")
        return value


def _window_id(value: str, *, desktop: bool) -> str:
    if desktop and value == "desktop":
        return value
    if not re.fullmatch(r"0x[0-9a-f]{1,16}", value) or int(value, 16) == 0:
        raise ValueError("Use a window_id returned by list_windows")
    return value


class ComputerWindowParameters(ComputerParameters):
    window_id: str
    observation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    operation: Literal["restore", "minimize", "maximize", "close"]

    @field_validator("window_id")
    @classmethod
    def observed_window(cls, value):
        return _window_id(value, desktop=False)


class ComputerCaptureParameters(ComputerParameters):
    window_id: str = "desktop"
    max_width: int = Field(default=1280, ge=320, le=1280)
    max_height: int = Field(default=960, ge=240, le=1280)
    known_image_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("window_id")
    @classmethod
    def observed_window(cls, value):
        return _window_id(value, desktop=True)

    @model_serializer(mode="wrap")
    def legacy_default_shape(self, handler):
        value = handler(self)
        if value.get("known_image_sha256") is None:
            value.pop("known_image_sha256", None)
        return value


class ComputerInputParameters(ComputerParameters):
    frame_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    window_id: str
    kind: Literal["activate", "click", "double_click", "right_click", "move", "scroll", "key", "text", "drag"]
    x: int | None = Field(default=None, ge=0, le=1279)
    y: int | None = Field(default=None, ge=0, le=1279)
    to_x: int | None = Field(default=None, ge=0, le=1279)
    to_y: int | None = Field(default=None, ge=0, le=1279)
    scroll_y: int | None = Field(default=None, ge=-1200, le=1200)
    scroll_x: int | None = Field(default=None, ge=-1200, le=1200)
    key: str | None = Field(default=None, min_length=1, max_length=80)
    text: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)

    @field_validator("window_id")
    @classmethod
    def observed_window(cls, value):
        return _window_id(value, desktop=True)

    @model_validator(mode="after")
    def exact_fields(self):
        needed = {
            "activate": set(),
            "click": {"x", "y"}, "double_click": {"x", "y"}, "right_click": {"x", "y"},
            "move": {"x", "y"}, "scroll": {"x", "y", "scroll_x" if self.scroll_x is not None else "scroll_y"},
            "drag": {"x", "y", "to_x", "to_y"}, "key": {"key"}, "text": {"text"},
        }[self.kind]
        present = {name for name in ("x", "y", "to_x", "to_y", "scroll_y", "scroll_x", "key", "text")
                   if getattr(self, name) is not None}
        if present != needed or self.scroll_y == 0 or self.scroll_x == 0:
            raise ValueError("Input fields must match the selected kind")
        if self.window_id == "desktop" and self.kind == "activate":
            raise ValueError("Desktop input uses the current desktop; activate a specific window instead")
        if self.text is not None and ("\x00" in self.text or any(0xD800 <= ord(c) <= 0xDFFF for c in self.text)):
            raise ValueError("Text contains an unsupported Unicode character")
        if self.key is not None and any(ord(c) < 32 for c in self.key):
            raise ValueError("Key contains control characters")
        return self


class ComputerLaunchParameters(ComputerParameters):
    executable: str = Field(min_length=1, max_length=4096)
    arguments: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("executable")
    @classmethod
    def ordinary_executable(cls, value):
        path = PureWindowsPath(value)
        if (not path.is_absolute() or not re.fullmatch(r"[a-zA-Z]:", path.drive)
                or path.suffix.lower() != ".exe" or any(ord(c) < 32 for c in value)
                or any(part in {".", ".."} for part in path.parts)
                or any(c in value[2:] for c in ':<>"|?*')):
            raise ValueError("Use an absolute local .exe path")
        return value

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value):
        if (sum(len(v) for v in value) > 12000
                or any(len(v) > 4096 or "\x00" in v or any(0xD800 <= ord(c) <= 0xDFFF for c in v) for v in value)):
            raise ValueError("Application arguments exceed the supported bounds")
        return value


COMPUTER_MODELS = {
    "info": ComputerInfoParameters,
    "environment": ComputerEnvironmentParameters,
    "windows": ComputerWindowsParameters,
    "capture": ComputerCaptureParameters,
    "input": ComputerInputParameters,
    "launch": ComputerLaunchParameters,
    "inspect": ComputerInspectParameters,
    "diagnose": SystemDiagnosticParameters,
    "window": ComputerWindowParameters,
    "ui_tree": ComputerUITreeParameters,
    "ui_action": ComputerUIActionParameters,
    "ui_action_observe": ComputerUIActionObserveParameters,
    "ui_wait": ComputerUIWaitParameters,
    "ui_workflow": ComputerUIWorkflowParameters,
    "ui_workflow_target": ComputerUIWorkflowTargetParameters,
    "clipboard_read": ComputerClipboardReadParameters,
    "clipboard_write": ComputerClipboardWriteParameters,
    **system_models(),
}


def validate_computer_parameters(action: str, parameters: dict) -> dict:
    model = COMPUTER_MODELS.get(action)
    if model is None:
        raise ValueError("Unknown computer action")
    return model.model_validate(parameters).model_dump()
