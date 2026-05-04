"""Vendor dialect abstraction for gNMI MCP Server.

Handles vendor-specific gNMI behaviour: default ports, encodings,
path prefixes, origin handling, and ON_CHANGE support for
Cisco IOS-XR, Juniper, Arista, and Nokia SR OS.
"""

from __future__ import annotations

from models import VendorDialect


# ---------------------------------------------------------------------------
# Vendor dialect registry
# ---------------------------------------------------------------------------

VENDOR_DIALECTS: dict[str, VendorDialect] = {
    "cisco-iosxr": VendorDialect(
        vendor_id="cisco-iosxr",
        default_port=57400,
        default_encoding="JSON_IETF",
        path_prefix="Cisco-IOS-XR",
        supports_on_change=True,
    ),
    "juniper": VendorDialect(
        vendor_id="juniper",
        default_port=32767,
        default_encoding="JSON_IETF",
        path_prefix="openconfig",
        supports_on_change=True,
    ),
    "arista": VendorDialect(
        vendor_id="arista",
        default_port=6030,
        default_encoding="JSON",
        path_prefix="openconfig",
        supports_on_change=True,
    ),
    "nokia": VendorDialect(
        vendor_id="nokia",
        default_port=57400,
        default_encoding="JSON_IETF",
        path_prefix="srl_nokia",
        supports_on_change=True,
    ),
}


def get_dialect(vendor: str | None) -> VendorDialect | None:
    """Return the dialect for *vendor*, or ``None`` if unknown / not set."""
    if vendor is None:
        return None
    return VENDOR_DIALECTS.get(vendor)


def get_default_port(vendor: str | None) -> int:
    """Return the default gNMI port for *vendor*, falling back to 6030."""
    dialect = get_dialect(vendor)
    return dialect.default_port if dialect else 6030


def get_default_encoding(vendor: str | None) -> str:
    """Return the preferred encoding for *vendor*, falling back to JSON_IETF."""
    dialect = get_dialect(vendor)
    return dialect.default_encoding if dialect else "JSON_IETF"


def get_path_origin(vendor: str | None) -> str | None:
    """Return the default YANG origin/prefix for the vendor."""
    dialect = get_dialect(vendor)
    return dialect.path_prefix if dialect else None


def supports_on_change(vendor: str | None) -> bool:
    """Return whether ON_CHANGE subscriptions are supported."""
    dialect = get_dialect(vendor)
    return dialect.supports_on_change if dialect else True


def list_supported_vendors() -> list[str]:
    """Return all supported vendor identifiers."""
    return list(VENDOR_DIALECTS.keys())
