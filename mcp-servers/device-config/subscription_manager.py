"""Subscription manager for gNMI streaming telemetry.

Manages in-memory tracking of active subscriptions, enforces the
configurable concurrent subscription limit (default 50), and handles
subscription lifecycle (create, cancel, list, get updates).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from models import (
    Subscription,
    SubscriptionMode,
    SubscriptionStatus,
    SubscriptionUpdate,
)

logger = logging.getLogger("gnmi-mcp.subscriptions")

# Maximum number of updates to keep per subscription (ring buffer)
_UPDATE_BUFFER_SIZE = 1000


class SubscriptionManager:
    """Manages gNMI streaming telemetry subscriptions.

    Thread-safe.  Each subscription runs in a background thread that
    reads from the gRPC stream and stores updates in a per-subscription
    ring buffer.
    """

    def __init__(
        self,
        client: Any,  # GnmiClientWrapper (avoid circular import)
        max_subscriptions: int = 50,
    ) -> None:
        self._client = client
        self._max_subscriptions = max_subscriptions
        self._lock = threading.Lock()
        # subscription_id -> Subscription
        self._subscriptions: dict[str, Subscription] = {}
        # subscription_id -> deque of SubscriptionUpdate
        self._updates: dict[str, deque[SubscriptionUpdate]] = {}
        # subscription_id -> background thread
        self._threads: dict[str, threading.Thread] = {}
        # subscription_id -> stop event
        self._stop_events: dict[str, threading.Event] = {}
        # subscription_id -> pygnmi client (to close on cancel)
        self._clients: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_subscription(
        self,
        target: str,
        paths: list[str],
        mode: str,
        sample_interval_seconds: int = 10,
    ) -> Subscription:
        """Create a new streaming telemetry subscription.

        Raises:
            ValueError: If the concurrent subscription limit is reached or
                        the subscription mode is invalid.
        """
        with self._lock:
            active = sum(
                1 for s in self._subscriptions.values()
                if s.status == SubscriptionStatus.ACTIVE
            )
            if active >= self._max_subscriptions:
                raise ValueError(
                    f"Subscription limit reached ({self._max_subscriptions}). "
                    "Cancel an existing subscription before creating a new one."
                )

        sub_mode = SubscriptionMode(mode.upper())
        sub = Subscription(
            target=target,
            paths=paths,
            mode=sub_mode,
            sample_interval_seconds=sample_interval_seconds if sub_mode == SubscriptionMode.SAMPLE else None,
        )

        stop_event = threading.Event()

        with self._lock:
            self._subscriptions[sub.id] = sub
            self._updates[sub.id] = deque(maxlen=_UPDATE_BUFFER_SIZE)
            self._stop_events[sub.id] = stop_event

        # Start background reader thread
        thread = threading.Thread(
            target=self._subscription_reader,
            args=(sub.id, target, paths, mode, sample_interval_seconds, stop_event),
            daemon=True,
            name=f"gnmi-sub-{sub.id[:8]}",
        )
        with self._lock:
            self._threads[sub.id] = thread
        thread.start()

        logger.info("Subscription %s created for %s (mode=%s)", sub.id, target, mode)
        return sub

    def cancel_subscription(self, subscription_id: str) -> None:
        """Cancel an active subscription and clean up resources.

        Raises:
            ValueError: If the subscription does not exist.
        """
        with self._lock:
            sub = self._subscriptions.get(subscription_id)
            if sub is None:
                raise ValueError(f"Subscription '{subscription_id}' not found")

            sub.status = SubscriptionStatus.CANCELLED

            # Signal the background thread to stop
            stop_event = self._stop_events.get(subscription_id)
            if stop_event:
                stop_event.set()

            # Close the pygnmi client to terminate the gRPC stream
            client = self._clients.pop(subscription_id, None)
            if client:
                try:
                    client.close()
                except Exception:
                    pass

        logger.info("Subscription %s cancelled", subscription_id)

    def list_subscriptions(self) -> list[Subscription]:
        """Return all subscriptions (active, error, cancelled)."""
        with self._lock:
            return list(self._subscriptions.values())

    def get_updates(
        self,
        subscription_id: str,
        limit: int = 10,
    ) -> list[SubscriptionUpdate]:
        """Return the latest *limit* updates for a subscription.

        Raises:
            ValueError: If the subscription does not exist.
        """
        with self._lock:
            if subscription_id not in self._subscriptions:
                raise ValueError(f"Subscription '{subscription_id}' not found")
            buf = self._updates.get(subscription_id, deque())
            # Return the most recent *limit* entries
            items = list(buf)
            return items[-limit:] if len(items) > limit else items

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(
                1 for s in self._subscriptions.values()
                if s.status == SubscriptionStatus.ACTIVE
            )

    # ------------------------------------------------------------------
    # Background reader (T024 — error handling)
    # ------------------------------------------------------------------

    def _subscription_reader(
        self,
        subscription_id: str,
        target: str,
        paths: list[str],
        mode: str,
        sample_interval: int,
        stop_event: threading.Event,
    ) -> None:
        """Background thread: read from the gNMI subscribe stream."""
        try:
            client, telemetry = self._client.subscribe(
                target_name=target,
                paths=paths,
                mode=mode,
                sample_interval=sample_interval,
            )
            with self._lock:
                self._clients[subscription_id] = client

            for response in telemetry:
                if stop_event.is_set():
                    break

                # Parse telemetry response into updates
                try:
                    self._process_telemetry_response(subscription_id, target, response)
                except Exception as parse_err:
                    logger.warning(
                        "Error parsing telemetry for %s: %s",
                        subscription_id, parse_err,
                    )

        except Exception as exc:
            # T024: report subscription loss with device identity and reason
            error_msg = f"Subscription lost for '{target}': {self._sanitize_error(str(exc))}"
            logger.error(error_msg)
            with self._lock:
                sub = self._subscriptions.get(subscription_id)
                if sub and sub.status == SubscriptionStatus.ACTIVE:
                    sub.status = SubscriptionStatus.ERROR
                    sub.error_message = error_msg
        finally:
            # Ensure the client is closed
            with self._lock:
                client = self._clients.pop(subscription_id, None)
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    def _process_telemetry_response(
        self,
        subscription_id: str,
        target: str,
        response: Any,
    ) -> None:
        """Parse a raw telemetry response and store as SubscriptionUpdate(s)."""
        now = datetime.now(timezone.utc).isoformat()

        if isinstance(response, dict):
            updates_list = response.get("update", {}).get("update", [])
            for update_entry in updates_list:
                path = update_entry.get("path", "/")
                val = update_entry.get("val")
                su = SubscriptionUpdate(
                    subscription_id=subscription_id,
                    target=target,
                    path=path,
                    value=val,
                    timestamp=now,
                )
                with self._lock:
                    buf = self._updates.get(subscription_id)
                    if buf is not None:
                        buf.append(su)
                    sub = self._subscriptions.get(subscription_id)
                    if sub:
                        sub.last_update = now
        else:
            # Try to handle as a generic value
            su = SubscriptionUpdate(
                subscription_id=subscription_id,
                target=target,
                path="/",
                value=str(response),
                timestamp=now,
            )
            with self._lock:
                buf = self._updates.get(subscription_id)
                if buf is not None:
                    buf.append(su)
                sub = self._subscriptions.get(subscription_id)
                if sub:
                    sub.last_update = now

    @staticmethod
    def _sanitize_error(msg: str) -> str:
        """Remove credentials from error messages."""
        import re
        msg = re.sub(r"(password|secret|token|key)\s*[:=]\s*\S+", r"\1=[REDACTED]", msg, flags=re.IGNORECASE)
        if len(msg) > 300:
            msg = msg[:300] + "..."
        return msg
