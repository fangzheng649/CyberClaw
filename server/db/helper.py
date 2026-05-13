"""
CyberClaw DB 工具函数
保留被持久化模块引用的通用函数
"""
from .compat import get_setting_value, mylog, is_random_mac, normalize_mac
import ipaddress
import re


def check_IP_format(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def format_ip_long(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def sanitize_SQL_input(input_str):
    if input_str is None:
        return ""
    return str(input_str).replace("'", "''").replace(";", "").replace("--", "")


def list_to_where(column, values):
    if not values:
        return "1=0"
    return f"{column} IN ({','.join(repr(str(v)) for v in values)})"


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default
