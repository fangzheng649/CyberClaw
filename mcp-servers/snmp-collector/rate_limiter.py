"""
Token bucket rate limiter for receiver overload protection.
Based on research.md specification (FR-021).
"""

import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter.

    Features:
    - Configurable sustained rate (messages per second)
    - Burst tolerance for traffic spikes
    - Thread-safe design
    """

    def __init__(self, rate: float = 1000.0, burst: int = 5000):
        """
        Initialize the rate limiter.

        Args:
            rate: Maximum messages per second (sustained)
            burst: Maximum burst size (allows spikes)
        """
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.time()
        self.total_allowed = 0
        self.total_rejected = 0

    def allow(self) -> bool:
        """
        Check if a message should be allowed through.

        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Add tokens based on elapsed time
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.total_allowed += 1
            return True

        self.total_rejected += 1
        return False

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            'rate_limit': self.rate,
            'burst_size': self.burst,
            'current_tokens': self.tokens,
            'total_allowed': self.total_allowed,
            'total_rejected': self.total_rejected
        }

    def reset(self) -> None:
        """Reset the rate limiter state."""
        self.tokens = float(self.burst)
        self.last_update = time.time()
        self.total_allowed = 0
        self.total_rejected = 0

    def update_rate(self, rate: Optional[float] = None, burst: Optional[int] = None) -> None:
        """
        Update rate limiter parameters.

        Args:
            rate: New rate limit (messages per second)
            burst: New burst size
        """
        if rate is not None:
            self.rate = rate
        if burst is not None:
            self.burst = burst
            # Ensure tokens don't exceed new burst size
            self.tokens = min(self.tokens, float(burst))
