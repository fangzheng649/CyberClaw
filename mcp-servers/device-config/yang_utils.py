"""YANG path parsing and validation utilities for the gNMI MCP Server.

Provides path validation, parsing of key-value selectors, and conversion
between gNMI path elements and human-readable YANG path strings.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_yang_path(path: str) -> tuple[bool, str | None]:
    """Validate a YANG path string.

    Returns (True, None) if valid, or (False, error_message) if invalid.
    """
    if not path:
        return False, "Path must not be empty"

    if not path.startswith("/"):
        return False, "Path must start with '/'"

    if "//" in path:
        return False, "Path must not contain consecutive slashes"

    # Validate key-value selectors
    bracket_re = re.compile(r"\[([^\]]*)\]")
    for match in bracket_re.finditer(path):
        content = match.group(1)
        if "=" not in content:
            return False, f"Key-value selector must use [key=value] syntax, got '[{content}]'"

    # Check for unmatched brackets
    open_count = path.count("[")
    close_count = path.count("]")
    if open_count != close_count:
        return False, "Unmatched brackets in path"

    return True, None


def validate_yang_paths(paths: list[str]) -> tuple[bool, str | None]:
    """Validate a list of YANG paths.

    Returns (True, None) if all valid, or (False, error_message) for the
    first invalid path.
    """
    if not paths:
        return False, "At least one YANG path is required"

    for path in paths:
        valid, error = validate_yang_path(path)
        if not valid:
            return False, f"Invalid path '{path}': {error}"

    return True, None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_path_elements(path: str) -> list[dict[str, Any]]:
    """Parse a YANG path into gNMI-style path elements.

    Example::

        /interfaces/interface[name=Ethernet1]/state/oper-status
        ->
        [
            {"name": "interfaces"},
            {"name": "interface", "key": {"name": "Ethernet1"}},
            {"name": "state"},
            {"name": "oper-status"},
        ]
    """
    elements: list[dict[str, Any]] = []
    # Strip leading slash, split on '/' but keep bracket content intact
    stripped = path.lstrip("/")
    if not stripped:
        return elements

    # Split respecting brackets
    parts = _split_path(stripped)
    for part in parts:
        element: dict[str, Any] = {}
        bracket_match = re.match(r"^([^\[]+)((?:\[[^\]]*\])*)$", part)
        if bracket_match:
            element["name"] = bracket_match.group(1)
            keys_str = bracket_match.group(2)
            if keys_str:
                keys: dict[str, str] = {}
                for km in re.finditer(r"\[([^=]+)=([^\]]*)\]", keys_str):
                    keys[km.group(1)] = km.group(2)
                if keys:
                    element["key"] = keys
        else:
            element["name"] = part
        elements.append(element)

    return elements


def path_elements_to_string(elements: list[dict[str, Any]]) -> str:
    """Convert gNMI-style path elements back to a YANG path string."""
    parts: list[str] = []
    for elem in elements:
        part = elem.get("name", "")
        keys = elem.get("key", {})
        for k, v in keys.items():
            part += f"[{k}={v}]"
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def extract_module_name(path: str) -> str | None:
    """Extract the top-level module name from a YANG path.

    Example: ``/openconfig-interfaces:interfaces/...`` -> ``openconfig-interfaces``
    """
    stripped = path.lstrip("/")
    first_segment = stripped.split("/")[0] if stripped else ""
    if ":" in first_segment:
        return first_segment.split(":")[0]
    return first_segment or None


def build_path_with_prefix(path: str, origin: str | None) -> str:
    """Prepend a YANG origin prefix if not already present.

    If the path already contains a module prefix (colon notation), return as-is.
    """
    if origin is None:
        return path
    stripped = path.lstrip("/")
    if ":" in stripped.split("/")[0]:
        return path  # Already prefixed
    return f"/{origin}:{stripped}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _split_path(path: str) -> list[str]:
    """Split a YANG path on '/' while respecting bracket contents."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0

    for ch in path:
        if ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "/" and depth == 0:
            if current:
                parts.append("".join(current))
            current = []
        else:
            current.append(ch)

    if current:
        parts.append("".join(current))

    return parts
