"""Tests for device position resolution (pillar 1: fix device overlap).

Root cause: dynamically-discovered devices have devPos="[]" (empty), which the
frontend treats as truthy and slips past `pos || [0,0,0]`, so every such device
stacks at the origin. ``_resolved_pos`` returns a real 3-number coordinate
derived from the MAC (deterministic, stable, collision-spread) whenever the
stored pos is missing/invalid, while passing valid coordinates through
unchanged — so the mock/config topology layout is never disturbed.
"""
from server.services.topology_service import (
    _is_valid_pos,
    _layout_pos,
    _resolved_pos,
)


def test_is_valid_pos_truthy():
    assert _is_valid_pos([0, 0, 0]) is True       # [0,0,0] is a legal coord (Docker hub)
    assert _is_valid_pos([1.0, 2.0, 3.0]) is True
    assert _is_valid_pos((-1, 0, 5)) is True       # tuples accepted


def test_is_valid_pos_falsy():
    for bad in (None, [], [1, 2], [1, 2, 3, 4], [1, "a", 3], "abc", True):
        assert _is_valid_pos(bad) is False


def test_layout_pos_deterministic_and_not_origin():
    p = _layout_pos("8c:22:d2:41:0b:ca")
    assert _layout_pos("8c:22:d2:41:0b:ca") == p   # deterministic / stable
    assert isinstance(p, list) and len(p) == 3
    assert p[1] == 0.0                             # on the ground plane
    assert p != [0, 0, 0]                          # off the origin


def test_layout_pos_distinct_macs_do_not_overlap():
    macs = ["8c:22:d2:41:0b:c%X" % i for i in range(8)]
    positions = {tuple(_layout_pos(m)) for m in macs}
    assert len(positions) == 8                      # 8 macs -> 8 distinct spots


def test_layout_pos_case_insensitive():
    assert _layout_pos("AA:BB:CC:DD:EE:FF") == _layout_pos("aa:bb:cc:dd:ee:ff")


def test_resolved_pos_passes_through_valid():
    # valid coordinates (incl. mock devices) are NEVER re-laid-out
    assert _resolved_pos("[-10, 0, 0]", "00:18:82:e4:f5:01") == [-10.0, 0.0, 0.0]
    assert _resolved_pos([4, 0, -5], "x") == [4.0, 0.0, -5.0]


def test_resolved_pos_falls_back_on_invalid():
    for bad in ("[]", None, "not-json", [1, 2]):
        p = _resolved_pos(bad, "8c:22:d2:41:0b:ca")
        assert isinstance(p, list) and len(p) == 3
        assert p == _layout_pos("8c:22:d2:41:0b:ca")


def test_resolved_pos_no_mac_returns_none():
    assert _resolved_pos("[]", "") is None
    assert _resolved_pos(None, None) is None
