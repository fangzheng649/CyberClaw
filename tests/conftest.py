import os
import sys
import pytest
import asyncio
from pathlib import Path

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# 设置测试环境变量（必须在 import app 之前）
os.environ["SCAN_SUBNET"] = ""  # 禁用自动扫描
os.environ["GLM_API_KEY"] = ""  # 禁用 LLM 调用
os.environ["ISOLATION_METHOD"] = "record_only"  # 隔离操作仅记录

import sqlite3
from httpx import AsyncClient, ASGITransport
from server.main import app

# 强制清空 GLM_API_KEY 模块级变量（如果模块已经加载）
try:
    import server.api.chat as _chat_mod
    _chat_mod.GLM_API_KEY = ""
except Exception:
    pass


@pytest.fixture
def db_conn():
    """提供测试用的数据库连接"""
    db_path = PROJECT_ROOT / "data" / "cyberclaw.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@pytest.fixture
async def client():
    """提供异步 HTTP 测试客户端"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", timeout=30.0) as ac:
        yield ac


@pytest.fixture(autouse=True)
def setup_test_data(db_conn):
    """每个测试前清理并准备测试数据"""
    # 清理测试数据
    db_conn.execute("DELETE FROM security_events")
    db_conn.execute("DELETE FROM Events")

    # 确保有测试设备（网段与 topology.json 一致）
    db_conn.execute("""
        INSERT OR IGNORE INTO Devices (devMac, devName, devType, devVendor, devModel, devLastIP, devStatus, devPresentLastScan, devIsArchived, devIsNew, devAlertDown)
        VALUES ('aa:bb:cc:dd:ee:01', 'Test-Camera-1', 'camera', 'Hikvision', 'DS-2CD2142', '192.168.10.101', 'secure', 1, '0', '0', 1)
    """)
    db_conn.execute("""
        INSERT OR IGNORE INTO Devices (devMac, devName, devType, devVendor, devModel, devLastIP, devStatus, devPresentLastScan, devIsArchived, devIsNew, devAlertDown, devParentMAC)
        VALUES ('aa:bb:cc:dd:ee:02', 'Test-Sensor-1', 'sensor', 'Siemens', 'SITRANS TH400', '192.168.10.102', 'secure', 1, '0', '0', 1, 'aa:bb:cc:dd:ee:01')
    """)
    db_conn.execute("""
        INSERT OR IGNORE INTO Devices (devMac, devName, devType, devVendor, devModel, devLastIP, devStatus, devPresentLastScan, devIsArchived, devIsNew, devAlertDown)
        VALUES ('aa:bb:cc:dd:ee:03', 'Test-Gateway', 'gateway', 'Advantech', 'UNO-2484G', '192.168.10.3', 'secure', 1, '0', '0', 1)
    """)
    db_conn.commit()
    yield
    # 测试后清理
    db_conn.execute("DELETE FROM security_events")
    db_conn.execute("DELETE FROM Events")
    db_conn.commit()
