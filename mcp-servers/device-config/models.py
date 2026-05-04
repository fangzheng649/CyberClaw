"""Pydantic data models for the gNMI MCP Server.

Defines request/response models, target configuration, subscription tracking,
YANG capabilities, and vendor dialect configuration.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class GnmiEncoding(str, Enum):
    JSON_IETF = "JSON_IETF"
    JSON = "JSON"
    PROTO = "PROTO"
    ASCII = "ASCII"


class GnmiDataType(str, Enum):
    ALL = "ALL"
    CONFIG = "CONFIG"
    STATE = "STATE"
    OPERATIONAL = "OPERATIONAL"


class SubscriptionMode(str, Enum):
    SAMPLE = "SAMPLE"
    ON_CHANGE = "ON_CHANGE"


class SubscriptionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class GnmiErrorCode(str, Enum):
    CONNECTION_ERROR = "CONNECTION_ERROR"
    TLS_ERROR = "TLS_ERROR"
    AUTH_ERROR = "AUTH_ERROR"
    PATH_ERROR = "PATH_ERROR"
    ENCODING_ERROR = "ENCODING_ERROR"
    ITSM_ERROR = "ITSM_ERROR"
    SUBSCRIPTION_LIMIT = "SUBSCRIPTION_LIMIT"
    SUBSCRIPTION_NOT_FOUND = "SUBSCRIPTION_NOT_FOUND"
    RPC_ERROR = "RPC_ERROR"
    TRUNCATED = "TRUNCATED"


# ---------------------------------------------------------------------------
# Target & Vendor
# ---------------------------------------------------------------------------

class GnmiTarget(BaseModel):
    """A network device reachable via gNMI."""

    name: str = Field(..., description="Logical device name")
    host: str = Field(..., description="IP address or hostname")
    port: int = Field(default=6030, ge=1, le=65535, description="gNMI/gRPC port")
    username: str = Field(..., description="Authentication username")
    password: str = Field(..., description="Authentication password")
    tls_ca_cert: Optional[str] = Field(default=None, description="Path to CA certificate")
    tls_client_cert: Optional[str] = Field(default=None, description="Path to client cert (mTLS)")
    tls_client_key: Optional[str] = Field(default=None, description="Path to client key (mTLS)")
    tls_skip_verify: bool = Field(default=False, description="Skip TLS verification (lab only)")
    vendor: Optional[str] = Field(default=None, description="Vendor: cisco-iosxr, juniper, arista, nokia")
    encoding: Optional[str] = Field(default=None, description="Preferred encoding")

    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"cisco-iosxr", "juniper", "arista", "nokia"}
            if v not in allowed:
                raise ValueError(f"vendor must be one of {allowed}, got '{v}'")
        return v

    @field_validator("encoding")
    @classmethod
    def validate_encoding(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {e.value for e in GnmiEncoding}
            if v not in allowed:
                raise ValueError(f"encoding must be one of {allowed}, got '{v}'")
        return v

    @model_validator(mode="after")
    def validate_mtls_pair(self) -> "GnmiTarget":
        cert = self.tls_client_cert
        key = self.tls_client_key
        if (cert and not key) or (key and not cert):
            raise ValueError("tls_client_cert and tls_client_key must both be set for mTLS")
        return self


class VendorDialect(BaseModel):
    """Vendor-specific gNMI behaviour configuration."""

    vendor_id: str
    default_port: int
    default_encoding: str
    path_prefix: Optional[str] = None
    supports_on_change: bool = True


# ---------------------------------------------------------------------------
# YANG Path
# ---------------------------------------------------------------------------

class YangPath(BaseModel):
    """A YANG model path used in gNMI operations."""

    path: str = Field(..., description="YANG path string")
    origin: Optional[str] = Field(default=None, description="YANG model origin")

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("YANG path must start with '/'")
        if "//" in v:
            raise ValueError("YANG path must not contain consecutive slashes")
        # Validate key-value selectors
        bracket_re = re.compile(r"\[([^\]]*)\]")
        for match in bracket_re.finditer(v):
            content = match.group(1)
            if "=" not in content:
                raise ValueError(
                    f"Key-value selector must use [key=value] syntax, got '[{content}]'"
                )
        return v


# ---------------------------------------------------------------------------
# gNMI Get
# ---------------------------------------------------------------------------

class GnmiGetRequest(BaseModel):
    """Input model for gNMI Get tool calls."""

    target: str
    paths: list[str]
    encoding: Optional[str] = None
    data_type: GnmiDataType = GnmiDataType.ALL


class PathResult(BaseModel):
    """A single path-value pair from a gNMI response."""

    path: str
    value: Any
    timestamp: Optional[int] = None


class GnmiGetResponse(BaseModel):
    """Output model for gNMI Get results."""

    target: str
    timestamp: str
    results: list[PathResult]
    truncated: bool = False
    total_size_bytes: Optional[int] = None


# ---------------------------------------------------------------------------
# gNMI Set
# ---------------------------------------------------------------------------

class SetOperation(BaseModel):
    """A single update or replace operation for gNMI Set."""

    path: str
    value: Any


class GnmiSetRequest(BaseModel):
    """Input model for gNMI Set tool calls."""

    target: str
    change_request_number: str
    updates: Optional[list[SetOperation]] = None
    replaces: Optional[list[SetOperation]] = None
    deletes: Optional[list[str]] = None

    @field_validator("change_request_number")
    @classmethod
    def validate_cr(cls, v: str) -> str:
        if not re.match(r"^CHG\d+$", v):
            raise ValueError("change_request_number must match pattern CHG followed by digits")
        return v

    @model_validator(mode="after")
    def at_least_one_operation(self) -> "GnmiSetRequest":
        if not self.updates and not self.replaces and not self.deletes:
            raise ValueError("At least one of updates, replaces, or deletes must be provided")
        return self


class GnmiSetResponse(BaseModel):
    """Output model for gNMI Set results."""

    target: str
    timestamp: str
    change_request_number: str
    operations_applied: list[str]
    success: bool
    errors: Optional[list[str]] = None


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------

class SubscriptionRequest(BaseModel):
    """Input model for gNMI Subscribe tool calls."""

    target: str
    paths: list[str]
    mode: SubscriptionMode
    sample_interval_seconds: int = Field(default=10, ge=1)


class Subscription(BaseModel):
    """An active telemetry subscription."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    paths: list[str]
    mode: SubscriptionMode
    sample_interval_seconds: Optional[int] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    last_update: Optional[str] = None
    error_message: Optional[str] = None


class SubscriptionUpdate(BaseModel):
    """A telemetry update received from a subscription."""

    subscription_id: str
    target: str
    path: str
    value: Any
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

class YangCapability(BaseModel):
    """A YANG module advertised by a device via gNMI Capabilities."""

    name: str
    organization: Optional[str] = None
    version: Optional[str] = None


# ---------------------------------------------------------------------------
# Error envelope
# ---------------------------------------------------------------------------

class GnmiError(BaseModel):
    """Structured error response."""

    code: GnmiErrorCode
    message: str
    target: Optional[str] = None
    details: Optional[str] = None
