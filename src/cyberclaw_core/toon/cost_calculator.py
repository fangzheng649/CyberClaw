"""Model-aware token cost calculator for NetClaw.

Supports Opus 4.6, Sonnet 4.6, and Haiku 4.5 pricing with prompt caching
discounts and optional environment variable overrides.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict

from . import CostEstimate, ModelPricing

logger = logging.getLogger("cyberclaw_core.toon.cost_calculator")

# ---------------------------------------------------------------------------
# Default pricing (per 1M tokens, USD)
# ---------------------------------------------------------------------------
DEFAULT_PRICING: Dict[str, ModelPricing] = {
    "claude-opus-4-6": ModelPricing(
        model_name="claude-opus-4-6",
        input_price_per_1m=5.00,
        output_price_per_1m=25.00,
        cache_discount_pct=90.0,
    ),
    "claude-sonnet-4-6": ModelPricing(
        model_name="claude-sonnet-4-6",
        input_price_per_1m=3.00,
        output_price_per_1m=15.00,
        cache_discount_pct=90.0,
    ),
    "claude-haiku-4-5": ModelPricing(
        model_name="claude-haiku-4-5",
        input_price_per_1m=1.00,
        output_price_per_1m=5.00,
        cache_discount_pct=90.0,
    ),
}

# Aliases for common model name variations
MODEL_ALIASES: Dict[str, str] = {
    "opus": "claude-opus-4-6",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5",
    "claude-opus-4-6": "claude-opus-4-6",
    "claude-sonnet-4-6": "claude-sonnet-4-6",
    "claude-haiku-4-5": "claude-haiku-4-5",
    "anthropic/claude-opus-4-6": "claude-opus-4-6",
    "anthropic/claude-sonnet-4-6": "claude-sonnet-4-6",
    "anthropic/claude-haiku-4-5": "claude-haiku-4-5",
}


def _resolve_model(model: str) -> str:
    """Resolve a model name (or alias) to a canonical model identifier."""
    return MODEL_ALIASES.get(model.lower(), model.lower())


def _load_pricing_overrides() -> Dict[str, ModelPricing]:
    """Load pricing overrides from NETCLAW_TOKEN_PRICING_OVERRIDE env var.

    Expected format: JSON string like:
      {"claude-opus-4-6": {"input": 6.0, "output": 30.0}}
    """
    raw = os.environ.get("NETCLAW_TOKEN_PRICING_OVERRIDE", "")
    if not raw:
        return {}

    try:
        overrides_data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.warning(
            "NETCLAW_TOKEN_PRICING_OVERRIDE is not valid JSON; ignoring overrides"
        )
        return {}

    overrides: Dict[str, ModelPricing] = {}
    for model_name, prices in overrides_data.items():
        canonical = _resolve_model(model_name)
        base = DEFAULT_PRICING.get(canonical)
        overrides[canonical] = ModelPricing(
            model_name=canonical,
            input_price_per_1m=prices.get("input", base.input_price_per_1m if base else 5.0),
            output_price_per_1m=prices.get("output", base.output_price_per_1m if base else 25.0),
            cache_discount_pct=prices.get("cache_discount", base.cache_discount_pct if base else 90.0),
        )

    return overrides


def get_pricing(model: str = "claude-opus-4-6") -> ModelPricing:
    """Return pricing for the given model, with env var override support.

    Falls back to Opus pricing if the model is unknown.
    """
    canonical = _resolve_model(model)

    # Check overrides first
    overrides = _load_pricing_overrides()
    if canonical in overrides:
        return overrides[canonical]

    # Check defaults
    if canonical in DEFAULT_PRICING:
        return DEFAULT_PRICING[canonical]

    # Unknown model — use Opus pricing as fallback and warn
    logger.warning("Unknown model '%s'; using Opus pricing as fallback", model)
    return DEFAULT_PRICING["claude-opus-4-6"]


def calculate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "claude-opus-4-6",
    cache_creation_tokens: int = 0,
    cache_read_tokens: int = 0,
) -> CostEstimate:
    """Calculate USD cost for token usage.

    Args:
        input_tokens: Number of input tokens (non-cached).
        output_tokens: Number of output tokens.
        model: Model identifier for pricing lookup.
        cache_creation_tokens: Tokens used to create cache entry.
        cache_read_tokens: Tokens read from cache (discounted).

    Returns:
        CostEstimate with itemized costs.
    """
    pricing = get_pricing(model)

    # Input cost: regular input tokens + cache creation tokens at full price
    regular_input = input_tokens + cache_creation_tokens
    input_cost = (regular_input / 1_000_000) * pricing.input_price_per_1m

    # Output cost
    output_cost = (output_tokens / 1_000_000) * pricing.output_price_per_1m

    # Cache discount: cached read tokens get discount
    discount_rate = pricing.cache_discount_pct / 100.0
    cache_read_cost_full = (cache_read_tokens / 1_000_000) * pricing.input_price_per_1m
    cache_discount = cache_read_cost_full * discount_rate

    # Cached reads still cost something (1 - discount_rate), so add the reduced cost
    # and subtract the discount from what would have been full price
    input_cost += cache_read_cost_full  # Add full cost first
    # Then the discount is applied

    total_cost = input_cost + output_cost - cache_discount

    return CostEstimate(
        input_cost=round(input_cost, 6),
        output_cost=round(output_cost, 6),
        cache_discount=round(cache_discount, 6),
        total_cost=round(total_cost, 6),
        model=_resolve_model(model),
    )
