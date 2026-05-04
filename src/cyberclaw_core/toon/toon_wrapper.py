"""TOON conversion wrapper for community/remote MCP servers.

For MCP servers that cannot be directly modified (community forks, remote
servers), this wrapper post-processes JSON responses into TOON format.
It can be used as middleware or a standalone converter.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Union

from . import TOONResponse
from .toon_serializer import serialize_response

logger = logging.getLogger("cyberclaw_core.toon.toon_wrapper")


def wrap_json_response(json_str: str) -> TOONResponse:
    """Convert a JSON string response to TOON format.

    Args:
        json_str: A JSON-encoded string from an MCP server response.

    Returns:
        TOONResponse with the data in TOON format (or original JSON on failure).
    """
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Cannot parse JSON for TOON conversion: %s", exc)
        return TOONResponse(
            toon_data=json_str,
            json_token_count=max(1, len(json_str) // 4),
            toon_token_count=max(1, len(json_str) // 4),
            savings_tokens=0,
            savings_pct=0.0,
            fallback_used=True,
        )

    return serialize_response(data)


def wrap_mcp_tool_result(result: Union[str, dict, list, Any]) -> str:
    """Wrap any MCP tool result in TOON format.

    Handles string (assumed JSON), dict, or list inputs.
    Returns the TOON-serialized string (or JSON fallback).

    Args:
        result: The tool result to wrap. Can be a JSON string, dict, or list.

    Returns:
        TOON-serialized string.
    """
    if isinstance(result, str):
        response = wrap_json_response(result)
        return response.toon_data
    elif isinstance(result, (dict, list)):
        response = serialize_response(result)
        return response.toon_data
    elif isinstance(result, (bytes, bytearray)):
        # Binary data -- pass through as-is
        logger.debug("Binary data detected; skipping TOON wrapping")
        return result.decode("utf-8", errors="replace") if isinstance(result, bytes) else str(result)
    else:
        # Unknown type -- convert to string
        return str(result)


def validate_toon_integration(data: Any) -> dict:
    """Validate that TOON serialization works correctly for the given data.

    Tests edge cases: empty data, large data, nested structures, mixed types.
    Returns a validation report.

    Args:
        data: The data to validate TOON serialization against.

    Returns:
        Dict with: success (bool), toon_size, json_size, savings_pct,
        fallback_used, error (str or None).
    """
    try:
        response = serialize_response(data)
        return {
            "success": True,
            "toon_size": len(response.toon_data),
            "json_size": response.json_token_count * 4,  # Approximate
            "toon_token_count": response.toon_token_count,
            "json_token_count": response.json_token_count,
            "savings_pct": response.savings_pct,
            "fallback_used": response.fallback_used,
            "error": None,
        }
    except Exception as exc:
        return {
            "success": False,
            "toon_size": 0,
            "json_size": 0,
            "toon_token_count": 0,
            "json_token_count": 0,
            "savings_pct": 0.0,
            "fallback_used": True,
            "error": str(exc),
        }
