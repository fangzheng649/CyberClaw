"""TOON serialization utility for MCP server responses.

Uses the toon-format package to serialize structured data into TOON format,
which achieves 40-60% token savings on tabular network data. Falls back to
JSON on any error, never failing the operation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from . import TOONResponse

logger = logging.getLogger("cyberclaw_core.toon.toon_serializer")


def _estimate_token_count(text: str) -> int:
    """Quick token estimation using len/4 heuristic."""
    return max(1, len(text) // 4)


def _is_binary_data(data: Any) -> bool:
    """Check if data is binary (bytes or contains non-UTF-8 content)."""
    if isinstance(data, (bytes, bytearray)):
        return True
    if isinstance(data, str):
        try:
            data.encode("utf-8")
            return False
        except (UnicodeEncodeError, UnicodeDecodeError):
            return True
    return False


def serialize_response(data: Any) -> TOONResponse:
    """Serialize data to TOON format with JSON fallback.

    Args:
        data: Any JSON-serializable data structure.

    Returns:
        TOONResponse with toon_data (TOON string or JSON string),
        token counts for both formats, savings calculation,
        and fallback_used flag.

    Behavior:
        - If data is bytes or non-UTF-8: returns JSON, fallback_used=True
        - If toon.dumps() fails: returns JSON, fallback_used=True, logs warning
        - Otherwise: returns TOON, fallback_used=False
    """
    # Generate JSON representation for comparison
    try:
        json_str = json.dumps(data, indent=2, default=str)
    except (TypeError, ValueError):
        json_str = str(data)

    json_token_count = _estimate_token_count(json_str)

    # Skip TOON for binary data
    if _is_binary_data(data):
        logger.debug("Binary data detected; skipping TOON, using JSON")
        return TOONResponse(
            toon_data=json_str,
            json_token_count=json_token_count,
            toon_token_count=json_token_count,
            savings_tokens=0,
            savings_pct=0.0,
            fallback_used=True,
        )

    # Attempt TOON serialization
    try:
        import toon

        toon_str = toon.dumps(data)
        toon_token_count = _estimate_token_count(toon_str)
        savings_tokens = max(0, json_token_count - toon_token_count)
        savings_pct = (savings_tokens / json_token_count * 100.0) if json_token_count > 0 else 0.0

        return TOONResponse(
            toon_data=toon_str,
            json_token_count=json_token_count,
            toon_token_count=toon_token_count,
            savings_tokens=savings_tokens,
            savings_pct=round(savings_pct, 1),
            fallback_used=False,
        )
    except Exception as exc:
        logger.warning(
            "TOON serialization failed (%s: %s); falling back to JSON",
            type(exc).__name__,
            exc,
        )
        return TOONResponse(
            toon_data=json_str,
            json_token_count=json_token_count,
            toon_token_count=json_token_count,
            savings_tokens=0,
            savings_pct=0.0,
            fallback_used=True,
        )
