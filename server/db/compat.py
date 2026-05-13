"""
CyberClaw DB 兼容层
为持久化代码提供统一的 logger / settings / DB 连接 / 时间 / MAC 工具
"""
import os
import re
import json
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

# ── 路径 ──────────────────────────────────────────────────────────
DB_ROOT = Path(__file__).parent                   # server/db/
DATA_DIR = Path(os.environ.get("CYBERCLAW_DATA", "data"))
DB_PATH = DATA_DIR / "cyberclaw.db"
CONF_DIR = Path("config")
LOG_DIR = DATA_DIR / "logs"
VENDORS_DIR = DB_ROOT / "vendors"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Logger ────────────────────────────────────────────────────────
_logger = logging.getLogger("cyberclaw.db")


def mylog(level, *messages):
    msg = " ".join(str(m) for m in messages)
    _logger.log(getattr(logging, level.upper(), logging.INFO), msg)


class Logger:
    """兼容原始代码中的 Logger 类"""
    def __init__(self, log_path=None, level="info"):
        pass


def logResult(log_path, message):
    _logger.info(message)


# ── Settings ──────────────────────────────────────────────────────
_settings: dict = {}


def load_settings(path: str | None = None):
    global _settings
    p = Path(path) if path else CONF_DIR / "db_settings.json"
    if p.exists():
        _settings = json.loads(p.read_text(encoding="utf-8"))


def get_setting_value(key, default=""):
    return _settings.get(key, default)


# ── DB 连接 ───────────────────────────────────────────────────────
_db_connection: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    """获取持久连接（主循环用）"""
    global _db_connection
    if _db_connection is None:
        _db_connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _db_connection.row_factory = sqlite3.Row
        _db_connection.execute("PRAGMA journal_mode=WAL")
        _db_connection.execute("PRAGMA busy_timeout=5000")
        _db_connection.execute("PRAGMA foreign_keys=ON")
    return _db_connection


def get_temp_db_connection() -> sqlite3.Connection:
    """获取临时连接（短生命周期操作用）"""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def close_db():
    global _db_connection
    if _db_connection:
        _db_connection.close()
        _db_connection = None


# ── 时间工具 ──────────────────────────────────────────────────────
def timeNowUTC():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def timeNowTZ():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── 常用常量 ──────────────────────────────────────────────────────
NULL_EQUIVALENTS = [
    "", " ", "None", "none", "N/A", "n/a", "null", "NULL",
    "(unknown)", "Unknown", "unknown",
]

NULL_EQUIVALENTS_SQL = (
    """COALESCE(COL, "") IN ("", "None", "(unknown)", "N/A", "unknown")"""
)


# ── MAC 工具 ──────────────────────────────────────────────────────
def normalize_mac(mac) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", str(mac)).lower()


def is_mac(input_str) -> bool:
    cleaned = normalize_mac(input_str)
    return len(cleaned) == 12


def is_random_mac(mac) -> bool:
    mac_clean = normalize_mac(mac)
    if len(mac_clean) < 2:
        return False
    return bool(int(mac_clean[:2], 16) & 0x02)


# ── 通用工具 ──────────────────────────────────────────────────────
def if_byte_then_to_str(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
