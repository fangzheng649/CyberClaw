"""Tests for OUI vendor resolution (pillar 2: device vendor identification).

Root cause being fixed: ``scan_service._sync_scan`` only fell back to the IEEE
OUI database when the scanner returned an *empty* vendor string. nmap -sn
returns the literal string ``"Unknown"`` (truthy), so the fallback was skipped
and every device whose OUI nmap couldn't resolve locally was stuck at vendor
"Unknown" forever — even though the project ships a valid 38k-entry OUI DB
that DOES know e.g. 60:a3:e3 -> TP-LINK. ``_resolve_vendor`` treats any null-
equivalent vendor (Unknown/unknown/(unknown)/""/...) as "no vendor" and consults
the OUI DB; an honest empty string is returned when neither source knows.
"""
from server.services.scan_service import _lookup_vendor_oui, _resolve_vendor


def test_lookup_vendor_oui_resolves_known_prefixes():
    assert "TP-LINK" in _lookup_vendor_oui("60:a3:e3:61:81:0f")
    assert "Hikvision" in _lookup_vendor_oui("44:19:b6:3a:4c:10")


def test_lookup_vendor_oui_empty_for_unknown_prefix():
    # 8c:22:d2 is genuinely absent from the shipped IEEE OUI snapshot.
    assert _lookup_vendor_oui("8c:22:d2:41:0b:ca") == ""


def test_lookup_vendor_oui_case_insensitive():
    assert _lookup_vendor_oui("60:A3:E3:61:81:0F") == _lookup_vendor_oui("60:a3:e3:61:81:0f")


def test_resolve_vendor_falls_back_to_oui_for_placeholder():
    for placeholder in ("Unknown", "unknown", "(unknown)", "UNKNOWN", ""):
        assert "TP-LINK" in _resolve_vendor(placeholder, "60:a3:e3:61:81:0f")


def test_resolve_vendor_preserves_real_vendor():
    # A real vendor string is never overwritten by the OUI lookup.
    assert _resolve_vendor("Cisco Systems", "60:a3:e3:61:81:0f") == "Cisco Systems"


def test_resolve_vendor_empty_when_both_miss():
    # Placeholder input + OUI miss -> honest empty (not the "Unknown" lie).
    assert _resolve_vendor("Unknown", "8c:22:d2:41:0b:ca") == ""
