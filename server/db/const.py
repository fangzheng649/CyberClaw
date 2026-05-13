"""
CyberClaw DB 常量
"""
from pathlib import Path
from .compat import DB_ROOT, DATA_DIR, DB_PATH, CONF_DIR, NULL_EQUIVALENTS, NULL_EQUIVALENTS_SQL

fullDbPath = str(DB_PATH)
fullConfFolder = str(CONF_DIR)
fullConfPath = str(CONF_DIR)
vendorsPath = str(DB_ROOT / "vendors")
logPath = str(DATA_DIR / "logs")
default_tz = "UTC"
applicationPath = str(DB_ROOT.parent.parent)

sql_generateGuid = (
    "lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) "
    "|| '-4' || substr(lower(hex(randomblob(2))),2) "
    "|| '-' || substr('89ab',abs(random()) % 4 + 1, 1) "
    "|| substr(lower(hex(randomblob(2))),2) "
    "|| '-' || lower(hex(randomblob(6)))"
)

sql_devices_stats = "SELECT COUNT(*) FROM Devices"
sql_devices_all = "SELECT * FROM Devices WHERE devIsArchived = 0"
