"""Token counting via Anthropic API with local estimation fallback.

Uses anthropic.Anthropic().messages.count_tokens() for exact counts.
Falls back to len(text) / 4 approximation when the API is unavailable,
marking the result with estimated=True.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from . import TokenCount

logger = logging.getLogger("cyberclaw_core.toon.counter")


def _estimate_tokens(text: str) -> int:
    """Approximate token count using the len/4 heuristic."""
    return max(1, len(text) // 4)


def count_tokens(text: str, model: str = "claude-opus-4-6") -> TokenCount:
    """Count tokens for a text string using Anthropic API with local fallback.

    Args:
        text: The text to count tokens for.
        model: The model identifier for tokenizer selection.

    Returns:
        TokenCount with input_tokens populated.
        If API unavailable, estimated=True and uses len(text)/4.

    Never raises -- always returns a result (exact or estimated).
    """
    try:
        import anthropic

        client = anthropic.Anthropic()
        response = client.messages.count_tokens(
            model=model,
            messages=[{"role": "user", "content": text}],
        )
        return TokenCount(
            input_tokens=response.input_tokens,
            output_tokens=0,
            model=model,
            timestamp=datetime.now(timezone.utc),
            estimated=False,
        )
    except Exception as exc:
        logger.warning(
            "Anthropic count_tokens API unavailable (%s); using local estimation",
            type(exc).__name__,
        )
        return TokenCount(
            input_tokens=_estimate_tokens(text),
            output_tokens=0,
            model=model,
            timestamp=datetime.now(timezone.utc),
            estimated=True,
        )


def count_message_tokens(
    messages: list[dict],
    model: str = "claude-opus-4-6",
    system: Optional[str] = None,
) -> TokenCount:
    """Count tokens for a full message array (input context).

    Args:
        messages: List of message dicts with role/content.
        model: Model identifier.
        system: Optional system prompt.

    Returns:
        TokenCount with input_tokens from API or estimation.
    """
    try:
        import anthropic

        client = anthropic.Anthropic()
        kwargs: dict = {
            "model": model,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = client.messages.count_tokens(**kwargs)
        return TokenCount(
            input_tokens=response.input_tokens,
            output_tokens=0,
            model=model,
            timestamp=datetime.now(timezone.utc),
            estimated=False,
        )
    except Exception as exc:
        logger.warning(
            "Anthropic count_tokens API unavailable (%s); using local estimation",
            type(exc).__name__,
        )
        # Estimate from concatenated message content
        total_text = ""
        if system:
            total_text += system
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total_text += content
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and "text" in block:
                        total_text += block["text"]

        return TokenCount(
            input_tokens=_estimate_tokens(total_text),
            output_tokens=0,
            model=model,
            timestamp=datetime.now(timezone.utc),
            estimated=True,
        )
