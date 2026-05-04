"""gNMI client wrapper for the gNMI MCP Server.

Provides connection management, TLS configuration, encoding negotiation,
target loading from environment, response formatting, size handling,
and structured error handling using pygnmi.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from pygnmi.client import gNMIclient, telemetryParser

from models import (
    GnmiEncoding,
    GnmiError,
    GnmiErrorCode,
    GnmiGetResponse,
    GnmiTarget,
    PathResult,
    YangCapability,
)
from vendor_dialects import get_default_encoding, get_default_port, get_path_origin
from yang_utils import validate_yang_path

logger = logging.getLogger("gnmi-mcp")

# Default response size threshold (1 MB)
DEFAULT_MAX_RESPONSE_SIZE = 1_048_576


# ---------------------------------------------------------------------------
# Target configuration loader (T008)
# ---------------------------------------------------------------------------

def load_targets_from_env() -> dict[str, GnmiTarget]:
    """Load gNMI targets from the GNMI_TARGETS environment variable.

    GNMI_TARGETS must be a JSON array of target objects.  Each object
    requires at minimum: name, host, username, password.

    Global TLS settings are read from:
      - GNMI_TLS_CA_CERT
      - GNMI_TLS_CLIENT_CERT
      - GNMI_TLS_CLIENT_KEY
      - GNMI_TLS_SKIP_VERIFY
      - GNMI_DEFAULT_PORT

    Per-target fields override the global defaults.
    """
    raw = os.environ.get("GNMI_TARGETS", "")
    if not raw:
        logger.warning("GNMI_TARGETS environment variable is not set")
        return {}

    try:
        targets_json = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse GNMI_TARGETS JSON: %s", exc)
        return {}

    if not isinstance(targets_json, list):
        logger.error("GNMI_TARGETS must be a JSON array")
        return {}

    # Global TLS env vars
    global_ca = os.environ.get("GNMI_TLS_CA_CERT") or os.environ.get("GNMI_TLS_CA")
    global_cert = os.environ.get("GNMI_TLS_CLIENT_CERT") or os.environ.get("GNMI_TLS_CERT")
    global_key = os.environ.get("GNMI_TLS_CLIENT_KEY") or os.environ.get("GNMI_TLS_KEY")
    global_skip = os.environ.get("GNMI_TLS_SKIP_VERIFY", "false").lower() in ("true", "1", "yes")
    global_port_str = os.environ.get("GNMI_DEFAULT_PORT", "")

    targets: dict[str, GnmiTarget] = {}
    for entry in targets_json:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-dict target entry: %s", entry)
            continue

        name = entry.get("name")
        if not name:
            logger.warning("Skipping target without a 'name' field")
            continue

        vendor = entry.get("vendor")
        default_port = get_default_port(vendor)
        if global_port_str:
            try:
                default_port = int(global_port_str)
            except ValueError:
                pass

        try:
            target = GnmiTarget(
                name=name,
                host=entry.get("host", ""),
                port=entry.get("port", default_port),
                username=entry.get("username", ""),
                password=entry.get("password", ""),
                tls_ca_cert=entry.get("tls_ca_cert", global_ca),
                tls_client_cert=entry.get("tls_client_cert", global_cert),
                tls_client_key=entry.get("tls_client_key", global_key),
                tls_skip_verify=entry.get("tls_skip_verify", global_skip),
                vendor=vendor,
                encoding=entry.get("encoding"),
            )
            targets[name] = target
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping invalid target '%s': %s", name, exc)

    logger.info("Loaded %d gNMI target(s) from GNMI_TARGETS", len(targets))
    return targets


# ---------------------------------------------------------------------------
# Response size handling (T010)
# ---------------------------------------------------------------------------

def get_max_response_size() -> int:
    """Return the maximum response size from GNMI_MAX_RESPONSE_SIZE or default 1 MB."""
    raw = os.environ.get("GNMI_MAX_RESPONSE_SIZE", "")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return DEFAULT_MAX_RESPONSE_SIZE


def truncate_response(data: str, max_size: int | None = None) -> tuple[str, bool, int]:
    """Truncate *data* if it exceeds *max_size*.

    Returns (possibly_truncated_data, was_truncated, original_size_bytes).
    """
    if max_size is None:
        max_size = get_max_response_size()
    original_size = len(data.encode("utf-8"))
    if original_size <= max_size:
        return data, False, original_size
    truncated = data.encode("utf-8")[:max_size].decode("utf-8", errors="ignore")
    return truncated, True, original_size


# ---------------------------------------------------------------------------
# Structured error handling (T011)
# ---------------------------------------------------------------------------

def classify_gnmi_error(exc: Exception, target_name: str | None = None) -> GnmiError:
    """Map a pygnmi / gRPC exception to a structured ``GnmiError``.

    Credential data and certificate contents are NEVER included in messages.
    """
    exc_str = str(exc).lower()

    # Sanitize: strip anything that looks like a credential or cert block
    safe_msg = _sanitize_error_message(str(exc))

    if "ssl" in exc_str or "tls" in exc_str or "certificate" in exc_str or "handshake" in exc_str:
        return GnmiError(
            code=GnmiErrorCode.TLS_ERROR,
            message="TLS handshake or certificate verification failed",
            target=target_name,
            details=safe_msg,
        )
    if "authentication" in exc_str or "unauthenticated" in exc_str or "401" in exc_str:
        return GnmiError(
            code=GnmiErrorCode.AUTH_ERROR,
            message="Authentication failed — check credentials",
            target=target_name,
        )
    if "not found" in exc_str or "invalid path" in exc_str or "unknown element" in exc_str:
        return GnmiError(
            code=GnmiErrorCode.PATH_ERROR,
            message="Invalid or unsupported YANG path on target device",
            target=target_name,
            details=safe_msg,
        )
    if "encoding" in exc_str or "unsupported encoding" in exc_str:
        return GnmiError(
            code=GnmiErrorCode.ENCODING_ERROR,
            message="Requested encoding not supported by the device",
            target=target_name,
            details=safe_msg,
        )
    if "unavailable" in exc_str or "deadline" in exc_str or "connect" in exc_str or "refused" in exc_str:
        return GnmiError(
            code=GnmiErrorCode.CONNECTION_ERROR,
            message="Device unreachable, timeout, or connection refused",
            target=target_name,
            details=safe_msg,
        )
    # Generic gRPC / RPC error
    return GnmiError(
        code=GnmiErrorCode.RPC_ERROR,
        message="gNMI RPC error",
        target=target_name,
        details=safe_msg,
    )


def _sanitize_error_message(msg: str) -> str:
    """Strip credentials, certificate PEM blocks, and connection strings."""
    import re as _re

    # Remove PEM certificate blocks
    msg = _re.sub(r"-----BEGIN[^-]*-----[\s\S]*?-----END[^-]*-----", "[REDACTED_CERT]", msg)
    # Remove password-like patterns
    msg = _re.sub(r"(password|passwd|secret|token|key)\s*[:=]\s*\S+", r"\1=[REDACTED]", msg, flags=_re.IGNORECASE)
    # Truncate long messages
    if len(msg) > 500:
        msg = msg[:500] + "... [truncated]"
    return msg


# ---------------------------------------------------------------------------
# gNMI client wrapper (T007)
# ---------------------------------------------------------------------------

class GnmiClientWrapper:
    """High-level wrapper around pygnmi for gNMI operations.

    Manages TLS configuration, vendor dialect handling, and connection
    lifecycle.
    """

    def __init__(self, targets: dict[str, GnmiTarget]) -> None:
        self._targets = targets

    # -- helpers --

    def _get_target(self, name: str) -> GnmiTarget:
        target = self._targets.get(name)
        if target is None:
            raise ValueError(f"Target '{name}' is not configured")
        return target

    def _build_client_kwargs(self, target: GnmiTarget) -> dict[str, Any]:
        """Build pygnmi gNMIclient kwargs from a target."""
        kwargs: dict[str, Any] = {
            "target": (target.host, target.port),
            "username": target.username,
            "password": target.password,
            "insecure": False,  # TLS is mandatory
        }

        if target.tls_skip_verify:
            kwargs["skip_verify"] = True
        else:
            kwargs["skip_verify"] = False

        # Path to CA cert for server verification
        if target.tls_ca_cert:
            kwargs["path_cert"] = target.tls_ca_cert

        # mTLS client certificate/key
        if target.tls_client_cert and target.tls_client_key:
            kwargs["path_key"] = target.tls_client_key
            kwargs["path_cert"] = target.tls_client_cert
            if target.tls_ca_cert:
                kwargs["path_root"] = target.tls_ca_cert

        # Encoding
        encoding = target.encoding or get_default_encoding(target.vendor)
        kwargs["encoding"] = encoding

        return kwargs

    def _connect(self, target: GnmiTarget) -> gNMIclient:
        """Create a connected gNMIclient for the given target."""
        kwargs = self._build_client_kwargs(target)
        client = gNMIclient(**kwargs)
        client.connect()
        return client

    # -- Response formatting (T015) --

    @staticmethod
    def format_get_response(
        raw_response: dict[str, Any],
        target_name: str,
    ) -> GnmiGetResponse:
        """Convert a raw pygnmi get response into a structured GnmiGetResponse."""
        results: list[PathResult] = []

        notifications = raw_response.get("notification", [])
        for notification in notifications:
            ts = notification.get("timestamp", 0)
            updates = notification.get("update", [])
            for update in updates:
                path = update.get("path", "/")
                val = update.get("val")
                results.append(PathResult(path=path, value=val, timestamp=ts))

        return GnmiGetResponse(
            target=target_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            results=results,
        )

    # -- Public API --

    def get(
        self,
        target_name: str,
        paths: list[str],
        encoding: str | None = None,
        data_type: str = "ALL",
    ) -> GnmiGetResponse:
        """Execute a gNMI Get RPC."""
        target = self._get_target(target_name)
        try:
            client = self._connect(target)
            try:
                result = client.get(path=paths, encoding=encoding or target.encoding or get_default_encoding(target.vendor))
                return self.format_get_response(result, target_name)
            finally:
                client.close()
        except Exception as exc:
            raise exc

    def set(
        self,
        target_name: str,
        updates: list[tuple[str, Any]] | None = None,
        replaces: list[tuple[str, Any]] | None = None,
        deletes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute a gNMI Set RPC."""
        target = self._get_target(target_name)
        client = self._connect(target)
        try:
            result = client.set(
                update=updates or [],
                replace=replaces or [],
                delete=deletes or [],
            )
            return result
        finally:
            client.close()

    def capabilities(self, target_name: str) -> tuple[list[YangCapability], list[str]]:
        """Execute a gNMI Capabilities RPC.

        Returns (yang_models, supported_encodings).
        """
        target = self._get_target(target_name)
        client = self._connect(target)
        try:
            result = client.capabilities()
            models: list[YangCapability] = []
            for model in result.get("supported_models", []):
                models.append(
                    YangCapability(
                        name=model.get("name", ""),
                        organization=model.get("organization"),
                        version=model.get("version"),
                    )
                )
            encodings = [str(e) for e in result.get("supported_encodings", [])]
            return models, encodings
        finally:
            client.close()

    def subscribe(
        self,
        target_name: str,
        paths: list[str],
        mode: str = "SAMPLE",
        sample_interval: int = 10,
    ) -> Any:
        """Create a gNMI Subscribe RPC and return the client + telemetry iterator.

        The caller is responsible for managing the stream lifecycle.
        Returns (client, subscribe_iterator).
        """
        target = self._get_target(target_name)
        client = self._connect(target)

        subscribe_config: dict[str, Any] = {
            "subscription": [],
            "mode": "stream",
            "encoding": target.encoding or get_default_encoding(target.vendor),
        }

        for path in paths:
            sub_entry: dict[str, Any] = {"path": path}
            if mode.upper() == "SAMPLE":
                sub_entry["mode"] = "sample"
                sub_entry["sample_interval"] = sample_interval * 1_000_000_000  # nanoseconds
            else:
                sub_entry["mode"] = "on_change"
            subscribe_config["subscription"].append(sub_entry)

        telemetry = client.subscribe(subscribe=subscribe_config)
        return client, telemetry

    def check_reachability(self, target_name: str) -> bool:
        """Check whether a target device is reachable via gNMI."""
        target = self._get_target(target_name)
        try:
            client = self._connect(target)
            client.capabilities()
            client.close()
            return True
        except Exception:
            return False

    def get_targets(self) -> dict[str, GnmiTarget]:
        """Return all configured targets."""
        return dict(self._targets)

    def browse_yang_paths(
        self,
        target_name: str,
        module: str,
        depth: int = 3,
    ) -> list[str]:
        """Browse YANG paths under a module by attempting a gNMI Get with prefix.

        Returns a list of discovered sub-paths.
        """
        target = self._get_target(target_name)
        prefix_path = f"/{module}:/"
        # Try a shallow get to discover paths
        try:
            client = self._connect(target)
            try:
                result = client.get(path=[f"/{module}:/"], encoding="JSON_IETF")
                paths: list[str] = []
                for notif in result.get("notification", []):
                    for update in notif.get("update", []):
                        p = update.get("path", "")
                        if p:
                            paths.append(p)
                # Limit depth
                filtered = _filter_by_depth(paths, depth)
                return filtered
            finally:
                client.close()
        except Exception:
            # Fall back: return the module root
            return [f"/{module}:/"]


def _filter_by_depth(paths: list[str], max_depth: int) -> list[str]:
    """Filter YANG paths to those within *max_depth* levels."""
    result: list[str] = []
    for path in paths:
        segments = [s for s in path.strip("/").split("/") if s]
        if len(segments) <= max_depth:
            result.append(path)
    return result
