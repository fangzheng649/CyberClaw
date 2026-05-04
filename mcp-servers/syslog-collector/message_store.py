"""
In-memory message store with deduplication and retention management.
Based on research.md specifications:
- 24-hour retention period (configurable)
- 5-second deduplication window (configurable)
- Content hash-based deduplication
"""

import hashlib
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar('T', bound=BaseModel)


class MessageStore(Generic[T]):
    """
    In-memory message store with deduplication and TTL-based expiration.

    Features:
    - Hash-based deduplication within configurable time window
    - Automatic cleanup of expired messages
    - Query support with filtering
    - Statistics tracking
    """

    def __init__(
        self,
        retention_hours: int = 24,
        dedup_window_sec: int = 5,
        max_messages: int = 100000
    ):
        """
        Initialize the message store.

        Args:
            retention_hours: Hours to retain messages (default 24)
            dedup_window_sec: Seconds for deduplication window (default 5)
            max_messages: Maximum messages to store before forced cleanup
        """
        self.messages: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self.dedup_cache: Dict[str, float] = {}
        self.retention_sec = retention_hours * 3600
        self.dedup_window = dedup_window_sec
        self.max_messages = max_messages

        # Statistics
        self.total_received = 0
        self.total_deduplicated = 0
        self.total_expired = 0

    def _compute_hash(self, message: T, hash_fields: Optional[List[str]] = None) -> str:
        """
        Compute a hash for deduplication.

        Args:
            message: The message to hash
            hash_fields: Optional list of fields to include in hash.
                        If None, uses the full message dict.
        """
        if hash_fields:
            data = {k: getattr(message, k, None) for k in hash_fields}
        else:
            data = message.model_dump(exclude={'id', 'received_at'})

        return hashlib.sha256(str(data).encode()).hexdigest()[:16]

    def add(
        self,
        message: T,
        hash_fields: Optional[List[str]] = None
    ) -> bool:
        """
        Add a message to the store with deduplication.

        Args:
            message: The message to store
            hash_fields: Optional list of fields to use for dedup hash

        Returns:
            True if message was stored, False if duplicate
        """
        self.total_received += 1
        now = time.time()

        # Compute dedup hash
        msg_hash = self._compute_hash(message, hash_fields)

        # Check for duplicate within window
        if msg_hash in self.dedup_cache:
            if now - self.dedup_cache[msg_hash] < self.dedup_window:
                self.total_deduplicated += 1
                return False

        # Update dedup cache
        self.dedup_cache[msg_hash] = now

        # Store message with timestamp
        msg_id = getattr(message, 'id', str(id(message)))
        self.messages[msg_id] = (now, message)

        # Cleanup if needed
        self._cleanup()

        return True

    def get(self, message_id: str) -> Optional[T]:
        """Get a specific message by ID."""
        entry = self.messages.get(message_id)
        return entry[1] if entry else None

    def query(
        self,
        filter_func: Optional[Callable[[T], bool]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> tuple[int, List[T]]:
        """
        Query messages with optional filtering.

        Args:
            filter_func: Optional function to filter messages
            start_time: Optional start of time range
            end_time: Optional end of time range
            limit: Maximum results to return
            offset: Number of results to skip

        Returns:
            Tuple of (total_matching, list_of_messages)
        """
        results = []

        for msg_id, (ts, message) in self.messages.items():
            # Time range filter
            msg_time = getattr(message, 'received_at', datetime.fromtimestamp(ts))

            if start_time and msg_time < start_time:
                continue
            if end_time and msg_time > end_time:
                continue

            # Custom filter
            if filter_func and not filter_func(message):
                continue

            results.append(message)

        # Sort by received_at descending (newest first)
        results.sort(
            key=lambda m: getattr(m, 'received_at', datetime.min),
            reverse=True
        )

        total = len(results)
        return total, results[offset:offset + limit]

    def count(self, filter_func: Optional[Callable[[T], bool]] = None) -> int:
        """Count messages matching optional filter."""
        if not filter_func:
            return len(self.messages)

        return sum(1 for _, msg in self.messages.values() if filter_func(msg))

    def _cleanup(self) -> None:
        """Remove expired messages and old dedup cache entries."""
        now = time.time()
        cutoff = now - self.retention_sec

        # Remove expired messages
        expired_keys = []
        for msg_id, (ts, _) in self.messages.items():
            if ts < cutoff:
                expired_keys.append(msg_id)
            else:
                break  # OrderedDict is ordered by insertion time

        for key in expired_keys:
            del self.messages[key]
            self.total_expired += 1

        # Clean dedup cache
        self.dedup_cache = {
            k: v for k, v in self.dedup_cache.items()
            if now - v < self.dedup_window
        }

        # Force cleanup if over max
        while len(self.messages) > self.max_messages:
            self.messages.popitem(last=False)
            self.total_expired += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            'stored_messages': len(self.messages),
            'total_received': self.total_received,
            'total_deduplicated': self.total_deduplicated,
            'total_expired': self.total_expired,
            'dedup_cache_size': len(self.dedup_cache),
            'retention_hours': self.retention_sec / 3600,
            'dedup_window_sec': self.dedup_window
        }

    def clear(self) -> None:
        """Clear all messages and reset statistics."""
        self.messages.clear()
        self.dedup_cache.clear()
        self.total_received = 0
        self.total_deduplicated = 0
        self.total_expired = 0
