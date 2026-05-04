"""cyberclaw_core.toon — Token counting, cost tracking, and TOON serialization.

Provides:
  - Token counting via Anthropic API with local estimation fallback
  - TOON serialization for MCP server responses (40-60% token savings)
  - Model-aware cost calculation (Opus, Sonnet, Haiku)
  - Session-level cumulative tracking with per-tool breakdown
  - Mandatory token footer formatting for every interaction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TokenCount:
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = "claude-opus-4-6"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    estimated: bool = False
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class CostEstimate:
    input_cost: float = 0.0
    output_cost: float = 0.0
    cache_discount: float = 0.0
    total_cost: float = 0.0
    model: str = "claude-opus-4-6"


@dataclass
class ModelPricing:
    model_name: str = ""
    input_price_per_1m: float = 0.0
    output_price_per_1m: float = 0.0
    cache_discount_pct: float = 90.0


@dataclass
class TOONResponse:
    toon_data: str = ""
    json_token_count: int = 0
    toon_token_count: int = 0
    savings_tokens: int = 0
    savings_pct: float = 0.0
    fallback_used: bool = False


@dataclass
class ToolUsageRecord:
    tool_name: str = ""
    call_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    toon_savings_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def avg_tokens_per_call(self) -> float:
        return self.total_tokens / self.call_count if self.call_count else 0.0


__all__ = [
    "TokenCount", "CostEstimate", "ModelPricing", "TOONResponse", "ToolUsageRecord",
    "count_tokens", "count_message_tokens", "calculate_cost", "get_pricing",
    "serialize_response", "format_footer", "SessionLedger",
]


def __getattr__(name: str):
    if name in ("count_tokens", "count_message_tokens"):
        from .counter import count_tokens, count_message_tokens
        return count_tokens if name == "count_tokens" else count_message_tokens
    if name in ("calculate_cost", "get_pricing"):
        from .cost_calculator import calculate_cost, get_pricing
        return calculate_cost if name == "calculate_cost" else get_pricing
    if name == "serialize_response":
        from .toon_serializer import serialize_response
        return serialize_response
    if name == "format_footer":
        from .footer import format_footer
        return format_footer
    if name == "SessionLedger":
        from .session_ledger import SessionLedger
        return SessionLedger
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
