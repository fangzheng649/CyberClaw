"""数据库管理 — 适配自开源网络发现项目"""

import sqlite3

from server.db.const import fullDbPath, sql_devices_stats, sql_devices_all
from server.db.compat import mylog
from server.db.db.db_upgrade import (
    ensure_column,
    ensure_CurrentScan,
    ensure_plugins_tables,
    ensure_Parameters,
    ensure_Settings,
    ensure_Indexes,
    ensure_mac_lowercase_triggers,
    migrate_to_camelcase,
    migrate_timestamps_to_utc,
    ensure_cyberclaw_tables,
)


class DB:
    """SQLite 数据库管理类"""

    def __init__(self):
        self.sql = None
        self.sql_connection = None

    def open(self):
        if self.sql_connection is not None:
            mylog("debug", "[Database] DB already open")
            return

        mylog("verbose", "[Database] Opening DB")
        try:
            self.sql_connection = sqlite3.connect(fullDbPath, isolation_level=None)
            self.sql_connection.execute("pragma journal_mode=WAL;")
            self.sql_connection.execute("PRAGMA synchronous=NORMAL;")
            self.sql_connection.execute("PRAGMA temp_store=MEMORY;")
            try:
                from server.db.compat import get_setting_value
                wal_limit_mb = int(get_setting_value("PRAGMA_JOURNAL_SIZE_LIMIT", "50"))
                wal_limit_bytes = wal_limit_mb * 1_000_000
            except Exception:
                wal_limit_bytes = 50_000_000
            self.sql_connection.execute(f"PRAGMA journal_size_limit={wal_limit_bytes};")
            self.sql_connection.text_factory = str
            self.sql_connection.row_factory = sqlite3.Row
            self.sql = self.sql_connection.cursor()
        except sqlite3.Error as e:
            mylog("error", f"[Database] Open DB Error: {e}")

    def commitDB(self):
        if self.sql_connection is None:
            return False
        self.sql_connection.commit()
        return True

    def rollbackDB(self):
        if self.sql_connection:
            self.sql_connection.rollback()

    def get_sql_array(self, query):
        if self.sql_connection is None:
            return None
        self.sql.execute(query)
        rows = self.sql.fetchall()
        return [list(row) for row in rows]

    def _ensure_base_tables(self):
        """创建核心基础表（首次启动时 Devices/Events/Sessions 不存在）"""
        # Devices 表
        self.sql.execute("""CREATE TABLE IF NOT EXISTS Devices (
            devMac TEXT PRIMARY KEY,
            devName TEXT DEFAULT '',
            devOwner TEXT DEFAULT '',
            devType TEXT DEFAULT '',
            devVendor TEXT DEFAULT '',
            devFavorite TEXT DEFAULT '',
            devGroup TEXT DEFAULT '',
            devComments TEXT DEFAULT '',
            devFirstConnection TEXT DEFAULT '',
            devLastConnection TEXT DEFAULT '',
            devLastIP TEXT DEFAULT '',
            devPresentLastScan INTEGER DEFAULT 0,
            devIsNew TEXT DEFAULT '',
            devLocation TEXT DEFAULT '',
            devIsArchived TEXT DEFAULT '',
            devParentMAC TEXT DEFAULT '',
            devParentPort TEXT DEFAULT '',
            devIcon TEXT DEFAULT '',
            devGUID TEXT DEFAULT '',
            devSite TEXT DEFAULT '',
            devSSID TEXT DEFAULT '',
            devSyncHubNode TEXT DEFAULT '',
            devSourcePlugin TEXT DEFAULT '',
            devCustomProps TEXT DEFAULT '',
            devAlertDown INTEGER DEFAULT 1,
            devLogEvents TEXT DEFAULT '',
            devAlertEvents TEXT DEFAULT '',
            devScan TEXT DEFAULT '',
            devStaticIP TEXT DEFAULT '',
            devSkipRepeated TEXT DEFAULT '',
            devLastNotification TEXT DEFAULT '',
            devModel TEXT DEFAULT '',
            devNotes TEXT DEFAULT ''
        )""")

        # Events 表
        self.sql.execute("""CREATE TABLE IF NOT EXISTS Events (
            RowID INTEGER PRIMARY KEY AUTOINCREMENT,
            eveMac TEXT NOT NULL DEFAULT '',
            eveIp TEXT DEFAULT '',
            eveDateTime TEXT DEFAULT '',
            eveEventType TEXT DEFAULT '',
            eveAdditionalInfo TEXT DEFAULT '',
            evePendingAlertEmail INTEGER DEFAULT 0,
            evePairEventRowid INTEGER DEFAULT 0
        )""")

        # Sessions 表
        self.sql.execute("""CREATE TABLE IF NOT EXISTS Sessions (
            RowID INTEGER PRIMARY KEY AUTOINCREMENT,
            sesMac TEXT DEFAULT '',
            sesIp TEXT DEFAULT '',
            sesEventTypeConnection TEXT DEFAULT '',
            sesDateTimeConnection TEXT DEFAULT '',
            sesEventTypeDisconnection TEXT DEFAULT '',
            sesDateTimeDisconnection TEXT DEFAULT '',
            sesStillConnected INTEGER DEFAULT 1,
            sesAdditionalInfo TEXT DEFAULT ''
        )""")

        # Online_History 表
        self.sql.execute("""CREATE TABLE IF NOT EXISTS Online_History (
            scanDate TEXT, onlineDevices INTEGER, downDevices INTEGER,
            allDevices INTEGER, archivedDevices INTEGER, offlineDevices INTEGER
        )""")

        # AppEvents 表（工作流引擎使用）
        self.sql.execute("""CREATE TABLE IF NOT EXISTS AppEvents (
            "index" INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT DEFAULT '',
            appEventProcessed INTEGER DEFAULT 0,
            dateTimeCreated TEXT DEFAULT (datetime('now')),
            objectType TEXT DEFAULT '',
            objectGuid TEXT DEFAULT '',
            objectPlugin TEXT DEFAULT '',
            objectPrimaryId TEXT DEFAULT '',
            objectSecondaryId TEXT DEFAULT '',
            objectForeignKey TEXT DEFAULT '',
            objectIndex TEXT DEFAULT '',
            objectIsNew TEXT DEFAULT '',
            objectIsArchived TEXT DEFAULT '',
            objectStatusColumn TEXT DEFAULT '',
            objectStatus TEXT DEFAULT '',
            appEventType TEXT DEFAULT '',
            helper1 TEXT DEFAULT '',
            helper2 TEXT DEFAULT '',
            helper3 TEXT DEFAULT '',
            extra TEXT DEFAULT ''
        )""")

    def initDB(self):
        try:
            self.sql_connection.execute("BEGIN IMMEDIATE;")

            # 首次启动：创建基础表（db_upgrade 只做增量升级，不创建基础表）
            self._ensure_base_tables()

            # Devices 表字段补充
            columns_to_ensure = [
                ("devFQDN", "TEXT"), ("devPrimaryIPv4", "TEXT"),
                ("devPrimaryIPv6", "TEXT"), ("devVlan", "TEXT"),
                ("devForceStatus", "TEXT"), ("devParentRelType", "TEXT"),
                ("devReqNicsOnline", "INTEGER"), ("devMacSource", "TEXT"),
                ("devNameSource", "TEXT"), ("devFQDNSource", "TEXT"),
                ("devLastIPSource", "TEXT"), ("devVendorSource", "TEXT"),
                ("devSSIDSource", "TEXT"), ("devParentMACSource", "TEXT"),
                ("devParentPortSource", "TEXT"), ("devParentRelTypeSource", "TEXT"),
                ("devVlanSource", "TEXT"), ("devCanSleep", "INTEGER"),
                ("devIconSource", "TEXT"), ("devTypeSource", "TEXT"),
            ]
            for col_name, col_type in columns_to_ensure:
                ensure_column(self.sql, "Devices", col_name, col_type)

            migrate_to_camelcase(self.sql)
            ensure_Settings(self.sql)
            ensure_Parameters(self.sql)
            migrate_timestamps_to_utc(self.sql)
            ensure_plugins_tables(self.sql)
            ensure_CurrentScan(self.sql)
            ensure_Indexes(self.sql)
            ensure_mac_lowercase_triggers(self.sql)

            # CyberClaw 扩展表
            ensure_cyberclaw_tables(self.sql)

            self.commitDB()
        except Exception as e:
            mylog("error", f"[Database] initDB ERROR: {e}")
            self.rollbackDB()
            raise

    def db_reconnect(self):
        if self.sql_connection:
            self.sql_connection.close()
        self.sql_connection = None
        self.open()
        self.initDB()

    def read(self, query, *args):
        try:
            assert query.count("?") == len(args)
            assert query.upper().strip().startswith("SELECT")
            self.sql.execute(query, args)
            return self.sql.fetchall()
        except Exception as e:
            mylog("error", f"[Database] SQL ERROR: {e}")
        return None

    def read_one(self, query, *args):
        rows = self.read(query, *args)
        if not rows:
            return None
        return rows[0]


def get_temp_db_connection():
    """线程安全的临时数据库连接"""
    conn = sqlite3.connect(fullDbPath, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.row_factory = sqlite3.Row
    return conn


def get_array_from_sql_rows(rows):
    return [
        list(row) if isinstance(row, (sqlite3.Row, tuple, list)) else [row]
        for row in rows
    ]
