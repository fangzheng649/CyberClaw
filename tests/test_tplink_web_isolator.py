"""Tests for TPLinkWebIsolator — 端口标签解析（selenium 操作靠端到端验证）。

通过 web 界面 shutdown 交换机端口实现真物理隔离：端口 disable → 下挂设备断网。
HTTP API 登录被设备反自动化拒绝，只能用真浏览器（selenium）驱动。
"""
import pytest

from server.services.tplink_web_isolator import _parse_port_number


def test_parse_port_number_from_label():
    assert _parse_port_number("Port 1") == 1
    assert _parse_port_number("Port 12") == 12


def test_parse_port_number_plain_int_string():
    assert _parse_port_number("3") == 3


def test_parse_port_number_none_when_no_digit():
    assert _parse_port_number("") is None
    assert _parse_port_number(None) is None
    assert _parse_port_number("local") is None


def test_parse_port_number_takes_first_digit_group():
    # "Port 2 (PoE)" → 2
    assert _parse_port_number("Port 2 (PoE)") == 2
