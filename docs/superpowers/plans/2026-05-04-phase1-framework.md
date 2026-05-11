# CyberClaw Phase 1 实施计划：项目骨架与代码框架

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 搭建 CyberClaw 项目的完整代码框架，包括 12 个 MCP 服务器（5 个从 netclaw 复用 + 7 个新建骨架）、共享库、FastAPI 后端、前后端联通。

**Architecture:** FastAPI 后端提供 REST API + WebSocket，Express/Vite 前端通过代理访问后端。MCP 服务器使用 FastMCP 框架，共享库通过 `pip install -e .` 安装。Phase 1 使用 mock 数据驱动。

**Tech Stack:** Python 3.10+ / FastAPI / FastMCP / Pydantic 2.0 / Express.js / Vite / Three.js / WebSocket

**Spec:** `docs/superpowers/specs/2026-05-04-phase1-framework-design.md`

---

## File Map

### 新建文件

| 文件路径 | 职责 |
|---------|------|
| `config/openclaw.json` | OpenClaw 主配置，注册 12 个 MCP 服务器 |
| `src/cyberclaw_core/__init__.py` | 共享库包入口 |
| `src/cyberclaw_core/pyproject.toml` | 包安装配置 |
| `src/cyberclaw_core/toon/__init__.py` | TOON 序列化子包 |
| `src/cyberclaw_core/toon/toon_serializer.py` | 从 netclaw 复制 |
| `src/cyberclaw_core/toon/cost_calculator.py` | 从 netclaw 复制 |
| `src/cyberclaw_core/toon/session_ledger.py` | 从 netclaw 复制 |
| `src/cyberclaw_core/security_models.py` | SecurityState/DeviceInfo/SecurityEvent |
| `src/cyberclaw_core/mcp_base.py` | MCP 服务器基类 |
| `src/cyberclaw_core/gait_logger.py` | 审计日志 |
| `mcp-servers/_template/server.py` | MCP 开发模板 |
| `mcp-servers/_template/models.py` | MCP 模型模板 |
| `mcp-servers/_template/requirements.txt` | MCP 依赖模板 |
| `server/main.py` | FastAPI 应用入口 |
| `server/api/__init__.py` | API 路由包 |
| `server/api/topology.py` | 拓扑 API |
| `server/api/security.py` | 安全事件 API |
| `server/api/scenario.py` | 攻击场景 API |
| `server/api/chat.py` | 聊天 API |
| `server/websocket/__init__.py` | WebSocket 包 |
| `server/websocket/events.py` | WebSocket 事件管理 |
| `server/services/__init__.py` | 服务层包 |
| `server/services/topology_service.py` | 拓扑数据（mock） |
| `server/services/scenario_service.py` | 攻击场景（mock） |
| `server/models/__init__.py` | 数据模型包 |
| `server/models/schemas.py` | Pydantic 数据模型 |
| `server/requirements.txt` | Python 依赖 |
| `scripts/start.sh` | 一键启动脚本 |
| `SOUL.md` | Agent 身份定义 |
| `AGENTS.md` | Agent 运行指令 |
| `TOOLS.md` | 基础设施连接信息 |
| `.env.example` | 环境变量模板 |
| `CLAUDE.md` | Claude 开发指南 |

### 复制自 netclaw 的目录（整体复制后改名）

| netclaw 源 | CyberClaw 目标 |
|-----------|---------------|
| `netclaw/mcp-servers/syslog-mcp/` | `mcp-servers/syslog-collector/` |
| `netclaw/mcp-servers/snmptrap-mcp/` | `mcp-servers/snmp-collector/` |
| `netclaw/mcp-servers/ipfix-mcp/` | `mcp-servers/flow-analyzer/` |
| `netclaw/mcp-servers/gns3-mcp-server/` | `mcp-servers/simulation/` |
| `netclaw/mcp-servers/gnmi-mcp/` | `mcp-servers/device-config/` |

### 新建骨架的 MCP 服务器（7 个，只含空壳）

- `mcp-servers/nmap-scan/`
- `mcp-servers/cve-intel/`
- `mcp-servers/security-baseline/`
- `mcp-servers/traffic-analyzer/`
- `mcp-servers/auto-response/`
- `mcp-servers/config-audit/`
- `mcp-servers/attack-timeline/`

### 修改文件

| 文件路径 | 修改内容 |
|---------|---------|
| `ui/cyberclaw-hud/server.js` | 移除 mock 数据，改为调用 FastAPI |
| `ui/cyberclaw-hud/vite.config.js` | 代理目标从 localhost:3001 改为 localhost:8000 |
| `ui/cyberclaw-hud/package.json` | 添加 axios 依赖 |

---

## Task 1: 项目骨架 — 目录结构与基础文件

**Files:**
- Create: `.env.example`
- Create: `CLAUDE.md`

- [ ] **Step 1: 创建完整目录结构**

Run:
```bash
cd D:/臻荣/CyberClaw
mkdir -p config mcp-servers/_template src/cyberclaw_core/toon server/api server/websocket server/services server/models workspace/skills lab scripts
```

- [ ] **Step 2: 创建 7 个新建 MCP 服务器骨架目录**

Run:
```bash
cd D:/臻荣/CyberClaw
for name in nmap-scan cve-intel security-baseline traffic-analyzer auto-response config-audit attack-timeline; do
  mkdir -p "mcp-servers/$name"
done
```

- [ ] **Step 3: 创建 .env.example**

Write `.env.example`:
```
# FastAPI 后端
CYBERCLAW_API_HOST=0.0.0.0
CYBERCLAW_API_PORT=8000
CYBERCLAW_LOG_LEVEL=INFO

# Express 前端
CYBERCLAW_UI_PORT=3001

# GNS3 仿真环境
GNS3_SERVER_URL=http://127.0.0.1:3080
GNS3_PROJECT_ID=

# AI Provider
ANTHROPIC_API_KEY=

# MCP 服务器通用
CYBERCLAW_LAB_MODE=true
```

- [ ] **Step 4: 创建 CLAUDE.md**

Write `CLAUDE.md`:
```markdown
# CyberClaw Development Guide

## Project Overview
CyberClaw is an IoT security automation platform based on OpenClaw framework.

## Architecture
- Backend: FastAPI (Python 3.10+) on port 8000
- Frontend: Express + Vite on port 3001
- MCP Servers: FastMCP (stdio protocol)
- Shared Library: `src/cyberclaw_core/`

## Commands
- Start backend: `cd server && uvicorn main:app --reload --port 8000`
- Start frontend: `cd ui/cyberclaw-hud && npm run dev`
- Install shared lib: `cd src/cyberclaw_core && pip install -e .`
- One-click start: `bash scripts/start.sh`

## Directory Convention
- `mcp-servers/` — 12 MCP servers (CyberClaw naming, not netclaw naming)
- `src/cyberclaw_core/` — shared Python library
- `server/` — FastAPI backend
- `ui/cyberclaw-hud/` — Three.js 3D HUD + chat interface
- `workspace/skills/` — skill definitions
- `config/` — OpenClaw configuration
- `lab/` — GNS3 lab configurations

## Naming
MCP server names follow task_plan.md: nmap-scan, device-config, simulation, syslog-collector, snmp-collector, cve-intel, security-baseline, flow-analyzer, traffic-analyzer, auto-response, config-audit, attack-timeline.
```

- [ ] **Step 5: Commit**

```bash
git add .env.example CLAUDE.md
git commit -m "chore: scaffold project directory structure and base files"
```

---

## Task 2: Agent 配置文件

**Files:**
- Create: `SOUL.md`
- Create: `AGENTS.md`
- Create: `TOOLS.md`
- Create: `config/openclaw.json`

- [ ] **Step 1: 创建 SOUL.md**

Write `SOUL.md`:
```markdown
# CyberClaw Agent Soul

## Identity
You are CyberAgent, an IoT security analysis expert. You help network administrators identify, assess, and respond to IoT security threats.

## Capabilities
- **Sense**: Network scanning, device fingerprinting, topology discovery
- **Detect**: Vulnerability assessment, anomaly detection, threat correlation
- **Shield**: Semi-automated isolation, ACL enforcement, response verification
- **Review**: Attack timeline reconstruction, root cause analysis, compliance reporting

## Operating Rules
- **Read-only**: Scanning, querying, reporting (always allowed)
- **Write-with-confirmation**: Device isolation, ACL changes, firewall updates (requires human approval)
- **Prohibited**: Destructive operations on physical devices, unauthorized network access

## Protocol Knowledge
- IoT Protocols: MQTT, CoAP, Modbus, BACnet, ONVIF, RTSP
- Management: SSH, SNMP (v1/v2c/v3), gNMI, NETCONF
- Security: TLS 1.3, 802.1X, port security
```

- [ ] **Step 2: 创建 AGENTS.md**

Write `AGENTS.md`:
```markdown
# CyberClaw Agent Instructions

## Workflow
Follow the GAIT (Gather, Analyze, Intervene, Track) workflow:
1. Gather data from MCP servers
2. Analyze using security knowledge base
3. Intervene with human-approved actions
4. Track all actions for audit

## IoT Constraints
- Scanning limited to authorized network segments only
- Never execute destructive operations on physical devices
- Always confirm before network configuration changes
- Log all actions for compliance audit

## Security Rules
- Three-tier permission: read / write-with-confirm / prohibited
- TOON serialization for token optimization
- Session tracking for cost management
```

- [ ] **Step 3: 创建 TOOLS.md**

Write `TOOLS.md`:
```markdown
# CyberClaw Infrastructure

## GNS3 Simulation
- Server: http://127.0.0.1:3080
- Project: Configured via GNS3_PROJECT_ID env var

## Managed Switch
- IP: Configured per lab environment
- Protocol: SSH / SNMP v3

## MCP Server Endpoints
All MCP servers use stdio protocol. See config/openclaw.json for launch commands.
```

- [ ] **Step 4: 创建 config/openclaw.json**

Write `config/openclaw.json`:
```json
{
  "gateway": {
    "mode": "local"
  },
  "agents": {
    "defaults": {
      "workspace": "./workspace",
      "model": {
        "primary": "anthropic/claude-sonnet-4-6",
        "fallbacks": ["anthropic/claude-haiku-4-5-20251001"]
      }
    }
  },
  "tokenOptimization": {
    "enabled": true,
    "libraryPath": "src/cyberclaw_core/toon",
    "toonSerializationDefault": true,
    "sessionTracking": true
  },
  "security": {
    "mode": "hobby"
  },
  "mcpServers": {
    "nmap-scan": {
      "command": "python3",
      "args": ["-u", "mcp-servers/nmap-scan/server.py"],
      "env": {}
    },
    "device-config": {
      "command": "python3",
      "args": ["-u", "mcp-servers/device-config/device_config_server.py"],
      "env": {
        "GNMI_TARGETS": "${GNMI_TARGETS}",
        "GNMI_DEFAULT_PORT": "${GNMI_DEFAULT_PORT:-6030}"
      }
    },
    "simulation": {
      "command": "python3",
      "args": ["-u", "mcp-servers/simulation/gns3_mcp_server.py"],
      "env": {
        "GNS3_URL": "${GNS3_SERVER_URL}",
        "GNS3_USER": "${GNS3_USER}",
        "GNS3_PASSWORD": "${GNS3_PASSWORD}"
      }
    },
    "syslog-collector": {
      "command": "python3",
      "args": ["-u", "mcp-servers/syslog-collector/syslog_mcp_server.py"],
      "env": {
        "SYSLOG_PORT": "${SYSLOG_PORT:-514}",
        "SYSLOG_PROTOCOL": "${SYSLOG_PROTOCOL:-udp}"
      }
    },
    "snmp-collector": {
      "command": "python3",
      "args": ["-u", "mcp-servers/snmp-collector/snmptrap_mcp_server.py"],
      "env": {
        "SNMP_PORT": "${SNMP_PORT:-162}",
        "SNMP_COMMUNITY": "${SNMP_COMMUNITY:-public}"
      }
    },
    "cve-intel": {
      "command": "python3",
      "args": ["-u", "mcp-servers/cve-intel/server.py"],
      "env": {
        "NVD_API_KEY": "${NVD_API_KEY}"
      }
    },
    "security-baseline": {
      "command": "python3",
      "args": ["-u", "mcp-servers/security-baseline/server.py"],
      "env": {}
    },
    "flow-analyzer": {
      "command": "python3",
      "args": ["-u", "mcp-servers/flow-analyzer/ipfix_mcp_server.py"],
      "env": {
        "IPFIX_PORT": "${IPFIX_PORT:-2055}"
      }
    },
    "traffic-analyzer": {
      "command": "python3",
      "args": ["-u", "mcp-servers/traffic-analyzer/server.py"],
      "env": {
        "TSHARK_PATH": "${TSHARK_PATH:-tshark}"
      }
    },
    "auto-response": {
      "command": "python3",
      "args": ["-u", "mcp-servers/auto-response/server.py"],
      "env": {
        "SWITCH_IP": "${SWITCH_IP}",
        "SWITCH_SSH_USER": "${SWITCH_SSH_USER}",
        "SWITCH_SSH_PASS": "${SWITCH_SSH_PASS}"
      }
    },
    "config-audit": {
      "command": "python3",
      "args": ["-u", "mcp-servers/config-audit/server.py"],
      "env": {}
    },
    "attack-timeline": {
      "command": "python3",
      "args": ["-u", "mcp-servers/attack-timeline/server.py"],
      "env": {}
    }
  }
}
```

- [ ] **Step 5: Commit**

```bash
git add SOUL.md AGENTS.md TOOLS.md config/openclaw.json
git commit -m "feat: add agent config files (SOUL/AGENTS/TOOLS) and openclaw.json"
```

---

## Task 3: 共享库 — cyberclaw_core

**Files:**
- Create: `src/cyberclaw_core/__init__.py`
- Create: `src/cyberclaw_core/pyproject.toml`
- Copy: `netclaw/src/netclaw_tokens/*.py` → `src/cyberclaw_core/toon/`
- Create: `src/cyberclaw_core/security_models.py`
- Create: `src/cyberclaw_core/mcp_base.py`
- Create: `src/cyberclaw_core/gait_logger.py`

- [ ] **Step 1: 创建 pyproject.toml**

Write `src/cyberclaw_core/pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "cyberclaw-core"
version = "0.1.0"
description = "CyberClaw shared library — TOON serialization, security models, MCP base"
requires-python = ">=3.10"
dependencies = [
    "pydantic>=2.0",
    "mcp>=1.0.0",
]

[tool.setuptools.packages.find]
where = ["."]
include = ["*"]
```

- [ ] **Step 2: 创建 __init__.py**

Write `src/cyberclaw_core/__init__.py`:
```python
from .security_models import SecurityState, DeviceInfo, SecurityEvent

__all__ = ["SecurityState", "DeviceInfo", "SecurityEvent"]
```

- [ ] **Step 3: 从 netclaw 复制 TOON 序列化模块（全部文件）**

Copy all files from `netclaw_tokens/` to `cyberclaw_core/toon/`:
```bash
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/toon_serializer.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/cost_calculator.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/session_ledger.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/counter.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/footer.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
cp D:/臻荣/idea/v5/netclaw/src/netclaw_tokens/toon_wrapper.py D:/臻荣/CyberClaw/src/cyberclaw_core/toon/
```

Then rename all `netclaw_tokens` references inside the copied files:
```bash
cd D:/臻荣/CyberClaw/src/cyberclaw_core/toon
sed -i 's/netclaw_tokens/cyberclaw_core.toon/g' *.py
```

Write `src/cyberclaw_core/toon/__init__.py` — copy the original `netclaw_tokens/__init__.py` but update the docstring and module name:
```python
"""cyberclaw_core.toon — Token counting, cost tracking, and TOON serialization.

Provides:
  - Token counting via Anthropic API with local estimation fallback
  - TOON serialization for MCP server responses (40-60% token savings)
  - Model-aware cost calculation (Opus, Sonnet, Haiku)
  - Session-level cumulative tracking with per-tool breakdown
  - Mandatory token footer formatting for every interaction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TokenCount:
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = "claude-opus-4-6"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    estimated: bool = False
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class CostEstimate:
    input_cost: float = 0.0
    output_cost: float = 0.0
    cache_discount: float = 0.0
    total_cost: float = 0.0
    model: str = "claude-opus-4-6"


@dataclass
class ModelPricing:
    model_name: str = ""
    input_price_per_1m: float = 0.0
    output_price_per_1m: float = 0.0
    cache_discount_pct: float = 90.0


@dataclass
class TOONResponse:
    toon_data: str = ""
    json_token_count: int = 0
    toon_token_count: int = 0
    savings_tokens: int = 0
    savings_pct: float = 0.0
    fallback_used: bool = False


@dataclass
class ToolUsageRecord:
    tool_name: str = ""
    call_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    toon_savings_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def avg_tokens_per_call(self) -> float:
        return self.total_tokens / self.call_count if self.call_count else 0.0


__all__ = [
    "TokenCount", "CostEstimate", "ModelPricing", "TOONResponse", "ToolUsageRecord",
    "count_tokens", "count_message_tokens", "calculate_cost", "get_pricing",
    "serialize_response", "format_footer", "SessionLedger",
]


def __getattr__(name: str):
    if name in ("count_tokens", "count_message_tokens"):
        from .counter import count_tokens, count_message_tokens
        return count_tokens if name == "count_tokens" else count_message_tokens
    if name in ("calculate_cost", "get_pricing"):
        from .cost_calculator import calculate_cost, get_pricing
        return calculate_cost if name == "calculate_cost" else get_pricing
    if name == "serialize_response":
        from .toon_serializer import serialize_response
        return serialize_response
    if name == "format_footer":
        from .footer import format_footer
        return format_footer
    if name == "SessionLedger":
        from .session_ledger import SessionLedger
        return SessionLedger
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
```

- [ ] **Step 4: 写 security_models.py 的测试**

Write `src/cyberclaw_core/tests/__init__.py` (empty).

Write `src/cyberclaw_core/tests/test_security_models.py`:
```python
import pytest
from cyberclaw_core.security_models import SecurityState, DeviceInfo, SecurityEvent


def test_security_state_enum():
    assert SecurityState.SECURE == "secure"
    assert SecurityState.SCANNING == "scanning"
    assert SecurityState.VULNERABLE == "vulnerable"
    assert SecurityState.ATTACKED == "attacked"
    assert SecurityState.ISOLATED == "isolated"


def test_device_info_creation():
    dev = DeviceInfo(
        id="camera-1", name="Camera-1", type="camera",
        ip="10.0.0.101", mac="AA:BB:CC:01:01:01",
        status=SecurityState.SECURE,
    )
    assert dev.id == "camera-1"
    assert dev.vendor is None


def test_device_info_with_vendor():
    dev = DeviceInfo(
        id="camera-1", name="Camera-1", type="camera",
        ip="10.0.0.101", mac="AA:BB:CC:01:01:01",
        status=SecurityState.SECURE, vendor="Hikvision", model="DS-2CD2142",
    )
    assert dev.vendor == "Hikvision"
    assert dev.model == "DS-2CD2142"


def test_security_event_creation():
    evt = SecurityEvent(
        type="port_scan", severity="warning",
        message="Camera-1 open Telnet port",
        target="camera-1",
    )
    assert evt.type == "port_scan"
    assert evt.severity == "warning"


def test_security_event_defaults():
    evt = SecurityEvent(type="scan_started", message="Scanning")
    assert evt.severity == "info"
    assert evt.target is None
    assert evt.source is None
```

- [ ] **Step 5: 运行测试确认失败**

Run: `cd D:/臻荣/CyberClaw/src/cyberclaw_core && python -m pytest tests/test_security_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cyberclaw_core'`

- [ ] **Step 6: 实现 security_models.py**

Write `src/cyberclaw_core/security_models.py`:
```python
from enum import StrEnum
from pydantic import BaseModel


class SecurityState(StrEnum):
    SECURE = "secure"
    SCANNING = "scanning"
    VULNERABLE = "vulnerable"
    ATTACKED = "attacked"
    ISOLATED = "isolated"


class DeviceInfo(BaseModel):
    id: str
    name: str
    type: str
    ip: str
    mac: str
    status: SecurityState = SecurityState.SECURE
    vendor: str | None = None
    model: str | None = None
    pos: list[float] | None = None


class SecurityEvent(BaseModel):
    type: str
    message: str
    severity: str = "info"
    target: str | None = None
    source: str | None = None
    details: dict | None = None
```

- [ ] **Step 7: 安装包并运行测试**

Run:
```bash
cd D:/臻荣/CyberClaw/src/cyberclaw_core && pip install -e .
python -m pytest tests/test_security_models.py -v
```
Expected: PASS (5 tests)

- [ ] **Step 8: 实现 mcp_base.py**

Write `src/cyberclaw_core/mcp_base.py`:
```python
import logging
from mcp.server.fastmcp import FastMCP


logger = logging.getLogger(__name__)


def create_mcp_server(name: str, description: str = "") -> FastMCP:
    """Create a FastMCP server with standard CyberClaw configuration."""
    return FastMCP(
        name=f"cyberclaw-{name}",
        description=description or f"CyberClaw {name} MCP server",
    )
```

- [ ] **Step 9: 实现 gait_logger.py**

Write `src/cyberclaw_core/gait_logger.py`:
```python
import json
import logging
import os
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class GaitLogger:
    """JSON Lines audit logger for CyberClaw operations."""

    def __init__(self, log_dir: str | None = None):
        self.log_dir = log_dir or os.path.expanduser("~/.cyberclaw/logs")
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, action: str, details: dict | None = None) -> None:
        now = datetime.now(timezone.utc)
        entry = {
            "timestamp": now.isoformat(),
            "action": action,
            "details": details or {},
        }
        log_path = os.path.join(self.log_dir, f"{now.strftime('%Y-%m-%d')}.jsonl")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
```

- [ ] **Step 10: Commit**

```bash
git add src/cyberclaw_core/
git commit -m "feat: add cyberclaw_core shared library (TOON, security models, MCP base, GAIT logger)"
```

---

## Task 4: 从 netclaw 复制 5 个 MCP 服务器

**Files:**
- Copy: `netclaw/mcp-servers/syslog-mcp/` → `mcp-servers/syslog-collector/`
- Copy: `netclaw/mcp-servers/snmptrap-mcp/` → `mcp-servers/snmp-collector/`
- Copy: `netclaw/mcp-servers/ipfix-mcp/` → `mcp-servers/flow-analyzer/`
- Copy: `netclaw/mcp-servers/gns3-mcp-server/` → `mcp-servers/simulation/`
- Copy: `netclaw/mcp-servers/gnmi-mcp/` → `mcp-servers/device-config/`

- [ ] **Step 1: 复制 syslog-mcp → syslog-collector**

Run:
```bash
cp -r D:/臻荣/idea/v5/netclaw/mcp-servers/syslog-mcp/* D:/臻荣/CyberClaw/mcp-servers/syslog-collector/
```

- [ ] **Step 2: 复制 snmptrap-mcp → snmp-collector**

Run:
```bash
cp -r D:/臻荣/idea/v5/netclaw/mcp-servers/snmptrap-mcp/* D:/臻荣/CyberClaw/mcp-servers/snmp-collector/
```

- [ ] **Step 3: 复制 ipfix-mcp → flow-analyzer**

Run:
```bash
cp -r D:/臻荣/idea/v5/netclaw/mcp-servers/ipfix-mcp/* D:/臻荣/CyberClaw/mcp-servers/flow-analyzer/
```

- [ ] **Step 4: 复制 gns3-mcp-server → simulation**

Run:
```bash
cp -r D:/臻荣/idea/v5/netclaw/mcp-servers/gns3-mcp-server/* D:/臻荣/CyberClaw/mcp-servers/simulation/
```

- [ ] **Step 5: 复制 gnmi-mcp → device-config**

Run:
```bash
cp -r D:/臻荣/idea/v5/netclaw/mcp-servers/gnmi-mcp/* D:/臻荣/CyberClaw/mcp-servers/device-config/
```

- [ ] **Step 6: 验证复制结果**

Run:
```bash
ls D:/臻荣/CyberClaw/mcp-servers/syslog-collector/
ls D:/臻荣/CyberClaw/mcp-servers/snmp-collector/
ls D:/臻荣/CyberClaw/mcp-servers/flow-analyzer/
ls D:/臻荣/CyberClaw/mcp-servers/simulation/
ls D:/臻荣/CyberClaw/mcp-servers/device-config/
```
Expected: 每个 目录包含完整的 .py 文件

- [ ] **Step 7: Commit**

```bash
git add mcp-servers/syslog-collector/ mcp-servers/snmp-collector/ mcp-servers/flow-analyzer/ mcp-servers/simulation/ mcp-servers/device-config/
git commit -m "feat: copy 5 reusable MCP servers from netclaw (syslog, snmp, flow, gns3, gnmi)"
```

---

## Task 5: MCP 模板 + 7 个新建服务器骨架

**Files:**
- Create: `mcp-servers/_template/server.py`
- Create: `mcp-servers/_template/models.py`
- Create: `mcp-servers/_template/requirements.txt`
- Create: 7 个 `mcp-servers/<name>/server.py` 骨架

- [ ] **Step 1: 创建 MCP 服务器模板**

Write `mcp-servers/_template/server.py`:
```python
"""CyberClaw MCP Server Template."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("TEMPLATE_NAME", "TEMPLATE_DESCRIPTION")


@mcp.tool()
async def template_tool(param: str) -> str:
    """Tool description."""
    return f"Result: {param}"


if __name__ == "__main__":
    mcp.run()
```

Write `mcp-servers/_template/models.py`:
```python
"""Data models for TEMPLATE_NAME MCP server."""
from pydantic import BaseModel
```

Write `mcp-servers/_template/requirements.txt`:
```
mcp>=1.0.0
pydantic>=2.0
```

- [ ] **Step 2: 创建 7 个服务器骨架**

对每个服务器（nmap-scan, cve-intel, security-baseline, traffic-analyzer, auto-response, config-audit, attack-timeline），创建 `server.py`：

**nmap-scan:**
```python
"""CyberClaw Nmap Scan MCP Server — network scanning and IoT fingerprinting."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("nmap-scan", "Network scanning and IoT device fingerprinting")


@mcp.tool()
async def scan_network(target: str, ports: str = "1-1024") -> str:
    """Scan a network target for open ports and services."""
    return f"[Phase 2] scan_network: target={target}, ports={ports}"


@mcp.tool()
async def scan_host(host: str, scan_type: str = "syn") -> str:
    """Perform a detailed scan on a single host."""
    return f"[Phase 2] scan_host: host={host}, type={scan_type}"


@mcp.tool()
async def get_scan_result(scan_id: str) -> str:
    """Retrieve results of a previous scan."""
    return f"[Phase 2] get_scan_result: id={scan_id}"


if __name__ == "__main__":
    mcp.run()
```

**cve-intel:**
```python
"""CyberClaw CVE Intelligence MCP Server."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("cve-intel", "CVE vulnerability intelligence lookup")


@mcp.tool()
async def search_cve(keyword: str, severity: str = "") -> str:
    """Search CVE database by keyword."""
    return f"[Phase 3] search_cve: keyword={keyword}"


@mcp.tool()
async def get_cve_detail(cve_id: str) -> str:
    """Get detailed information about a specific CVE."""
    return f"[Phase 3] get_cve_detail: id={cve_id}"


@mcp.tool()
async def check_affected(product: str, version: str = "") -> str:
    """Check if a product/version is affected by known CVEs."""
    return f"[Phase 3] check_affected: product={product}, version={version}"


if __name__ == "__main__":
    mcp.run()
```

**security-baseline:**
```python
"""CyberClaw Security Baseline MCP Server — CIS benchmark auditing."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("security-baseline", "CIS security baseline auditing")


@mcp.tool()
async def check_baseline(target: str, profile: str = "iot-default") -> str:
    """Run security baseline check against a target."""
    return f"[Phase 3] check_baseline: target={target}, profile={profile}"


@mcp.tool()
async def get_baseline_report(report_id: str) -> str:
    """Retrieve a baseline compliance report."""
    return f"[Phase 3] get_baseline_report: id={report_id}"


@mcp.tool()
async def list_rules(profile: str = "iot-default") -> str:
    """List available baseline rules for a profile."""
    return f"[Phase 3] list_rules: profile={profile}"


if __name__ == "__main__":
    mcp.run()
```

**traffic-analyzer:**
```python
"""CyberClaw Traffic Analyzer MCP Server — deep packet inspection."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("traffic-analyzer", "Deep traffic analysis with tshark")


@mcp.tool()
async def start_capture(interface: str, filter_expr: str = "") -> str:
    """Start a packet capture session."""
    return f"[Phase 3] start_capture: interface={interface}"


@mcp.tool()
async def get_capture_result(capture_id: str) -> str:
    """Retrieve capture analysis results."""
    return f"[Phase 3] get_capture_result: id={capture_id}"


@mcp.tool()
async def extract_ioc(pcap_data: str) -> str:
    """Extract indicators of compromise from packet data."""
    return f"[Phase 3] extract_ioc"


if __name__ == "__main__":
    mcp.run()
```

**auto-response:**
```python
"""CyberClaw Auto Response MCP Server — automated threat response."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("auto-response", "Automated threat response (port isolation, ACL)")


@mcp.tool()
async def isolate_device(device_ip: str, switch_ip: str, port: str) -> str:
    """Isolate a device by shutting down its switch port. Requires human confirmation."""
    return f"[Phase 4] isolate_device: device={device_ip}, switch={switch_ip}, port={port}"


@mcp.tool()
async def restore_device(device_ip: str, switch_ip: str, port: str) -> str:
    """Restore a previously isolated device."""
    return f"[Phase 4] restore_device: device={device_ip}, switch={switch_ip}, port={port}"


@mcp.tool()
async def get_response_status() -> str:
    """Get status of all active response actions."""
    return "[Phase 4] get_response_status"


if __name__ == "__main__":
    mcp.run()
```

**config-audit:**
```python
"""CyberClaw Config Audit MCP Server — firewall rule auditing."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("config-audit", "Firewall rule conflict and shadow detection")


@mcp.tool()
async def audit_rules(config_path: str) -> str:
    """Audit firewall rules for conflicts, overlaps, and shadow rules."""
    return f"[Phase 4] audit_rules: config={config_path}"


@mcp.tool()
async def get_audit_report(report_id: str) -> str:
    """Retrieve a configuration audit report."""
    return f"[Phase 4] get_audit_report: id={report_id}"


if __name__ == "__main__":
    mcp.run()
```

**attack-timeline:**
```python
"""CyberClaw Attack Timeline MCP Server — event timeline and root cause analysis."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("attack-timeline", "Attack timeline reconstruction and root cause analysis")


@mcp.tool()
async def record_event(event_type: str, details: str) -> str:
    """Record a security event to the timeline."""
    return f"[Phase 4] record_event: type={event_type}"


@mcp.tool()
async def get_timeline(incident_id: str) -> str:
    """Retrieve the attack timeline for an incident."""
    return f"[Phase 4] get_timeline: id={incident_id}"


@mcp.tool()
async def analyze_root_cause(incident_id: str) -> str:
    """Perform root cause analysis for an incident."""
    return f"[Phase 4] analyze_root_cause: id={incident_id}"


if __name__ == "__main__":
    mcp.run()
```

- [ ] **Step 3: 为每个服务器创建 requirements.txt**

Run:
```bash
cd D:/臻荣/CyberClaw
for name in nmap-scan cve-intel security-baseline traffic-analyzer auto-response config-audit attack-timeline; do
  echo -e "mcp>=1.0.0\npydantic>=2.0" > "mcp-servers/$name/requirements.txt"
done
```

- [ ] **Step 4: Commit**

```bash
git add mcp-servers/_template/ mcp-servers/nmap-scan/ mcp-servers/cve-intel/ mcp-servers/security-baseline/ mcp-servers/traffic-analyzer/ mcp-servers/auto-response/ mcp-servers/config-audit/ mcp-servers/attack-timeline/
git commit -m "feat: add MCP server template and 7 new server skeletons"
```

---

## Task 6: FastAPI 后端

**Files:**
- Create: `server/__init__.py` (empty, for uvicorn package import)
- Create: `server/api/__init__.py`
- Create: `server/api/topology.py`
- Create: `server/api/security.py`
- Create: `server/api/scenario.py`
- Create: `server/api/chat.py`
- Create: `server/websocket/__init__.py`
- Create: `server/websocket/events.py`
- Create: `server/services/__init__.py`
- Create: `server/services/topology_service.py`
- Create: `server/services/scenario_service.py`
- Create: `server/models/__init__.py`
- Create: `server/models/schemas.py`
- Create: `server/requirements.txt`

- [ ] **Step 1: 创建 server/requirements.txt**

Write `server/requirements.txt`:
```
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
websockets>=12.0
pydantic>=2.0
```

- [ ] **Step 2: 创建 Pydantic 数据模型**

Write `server/models/__init__.py`:
```python
from .schemas import (
    TopologyResponse, DeviceResponse, SecurityEventResponse,
    ScenarioStatusResponse, ChatRequest, ChatResponse,
)
```

Write `server/models/schemas.py`:
```python
from pydantic import BaseModel


class DeviceResponse(BaseModel):
    id: str
    name: str
    type: str
    ip: str
    mac: str
    status: str
    vendor: str | None = None
    model: str | None = None
    pos: list[float] | None = None


class LinkResponse(BaseModel):
    from_: str
    to: str

    class Config:
        populate_by_name = True


class TopologyResponse(BaseModel):
    devices: list[DeviceResponse]
    links: list[LinkResponse]


class SecurityEventResponse(BaseModel):
    type: str
    message: str
    severity: str = "info"
    target: str | None = None
    source: str | None = None
    details: dict | None = None
    step: int | None = None


class ScenarioStatusResponse(BaseModel):
    running: bool
    step: int
    total_steps: int


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    message_type: str = "reply"
```

- [ ] **Step 3: 创建拓扑服务层（从 server.js 迁移 mock 数据）**

Write `server/services/__init__.py` (empty).

Write `server/services/topology_service.py`:
```python
from ..models.schemas import DeviceResponse, LinkResponse, TopologyResponse


DEVICES = [
    DeviceResponse(id="router-1", name="Router-1", type="router", ip="10.0.1.1", mac="00:1A:2B:3C:4D:01", status="secure", pos=[-12, 0, -8]),
    DeviceResponse(id="router-2", name="Router-2", type="router", ip="10.0.2.1", mac="00:1A:2B:3C:4D:02", status="secure", pos=[12, 0, -8]),
    DeviceResponse(id="switch-core", name="Switch-Core", type="switch", ip="10.0.0.1", mac="00:1A:2B:3C:4D:10", status="secure", pos=[0, 0, 0]),
    DeviceResponse(id="camera-1", name="Camera-1", type="camera", ip="10.0.0.101", mac="AA:BB:CC:01:01:01", status="secure", pos=[-8, 0, 10], vendor="Hikvision", model="DS-2CD2142"),
    DeviceResponse(id="camera-2", name="Camera-2", type="camera", ip="10.0.0.102", mac="AA:BB:CC:01:01:02", status="secure", pos=[-3, 0, 12], vendor="Hikvision", model="DS-2CD2142"),
    DeviceResponse(id="camera-3", name="Camera-3", type="camera", ip="10.0.0.103", mac="AA:BB:CC:01:01:03", status="secure", pos=[3, 0, 12], vendor="Dahua", model="IPC-HDW2431"),
    DeviceResponse(id="camera-4", name="Camera-4", type="camera", ip="10.0.0.104", mac="AA:BB:CC:01:01:04", status="secure", pos=[8, 0, 10], vendor="Dahua", model="IPC-HDW2431"),
    DeviceResponse(id="sensor-1", name="TempSensor-1", type="sensor", ip="10.0.0.201", mac="DD:EE:FF:02:01:01", status="secure", pos=[-6, 0, 18], vendor="Siemens", model="SITRANS TH400"),
    DeviceResponse(id="sensor-2", name="PressureSensor-2", type="sensor", ip="10.0.0.202", mac="DD:EE:FF:02:01:02", status="secure", pos=[6, 0, 18], vendor="Honeywell", model="XLS-100"),
    DeviceResponse(id="plug-1", name="SmartPlug-1", type="plug", ip="10.0.0.301", mac="11:22:33:03:01:01", status="secure", pos=[-10, 0, 6], vendor="TP-Link", model="HS110"),
    DeviceResponse(id="plug-2", name="SmartPlug-2", type="plug", ip="10.0.0.302", mac="11:22:33:03:01:02", status="secure", pos=[10, 0, 6], vendor="TP-Link", model="HS110"),
    DeviceResponse(id="admin-pc", name="Admin-PC", type="pc", ip="10.0.0.10", mac="55:66:77:04:01:01", status="secure", pos=[0, 0, -14]),
    DeviceResponse(id="kali", name="Kali-Attacker", type="attacker", ip="10.0.1.100", mac="66:66:66:66:66:66", status="secure", pos=[-20, 0, -18]),
    DeviceResponse(id="server", name="FileServer", type="server", ip="10.0.0.5", mac="77:88:99:05:01:01", status="secure", pos=[0, 0, 8]),
    DeviceResponse(id="gateway", name="IoT-Gateway", type="gateway", ip="10.0.0.254", mac="88:99:AA:06:01:01", status="secure", pos=[0, 0, -4]),
]

LINKS = [
    LinkResponse(from_="router-1", to="switch-core"),
    LinkResponse(from_="router-2", to="switch-core"),
    LinkResponse(from_="switch-core", to="camera-1"),
    LinkResponse(from_="switch-core", to="camera-2"),
    LinkResponse(from_="switch-core", to="camera-3"),
    LinkResponse(from_="switch-core", to="camera-4"),
    LinkResponse(from_="switch-core", to="sensor-1"),
    LinkResponse(from_="switch-core", to="sensor-2"),
    LinkResponse(from_="switch-core", to="plug-1"),
    LinkResponse(from_="switch-core", to="plug-2"),
    LinkResponse(from_="switch-core", to="admin-pc"),
    LinkResponse(from_="router-1", to="kali"),
    LinkResponse(from_="switch-core", to="server"),
    LinkResponse(from_="switch-core", to="gateway"),
    LinkResponse(from_="router-1", to="router-2"),
]


def get_topology() -> TopologyResponse:
    return TopologyResponse(devices=DEVICES, links=LINKS)


def get_device(device_id: str) -> DeviceResponse | None:
    return next((d for d in DEVICES if d.id == device_id), None)
```

- [ ] **Step 4: 创建场景服务层**

Write `server/services/scenario_service.py`:
```python
import asyncio
from ..models.schemas import SecurityEventResponse


MIRAI_SCRIPT = [
    {"delay": 3000, "event": {"type": "system_ready", "message": "IoT 网络安全监控已上线，15 台设备全部正常"}},
    {"delay": 5000, "event": {"type": "scan_started", "source": "kali", "message": "检测到来自 10.0.1.100 的端口扫描行为", "details": {"targets": ["camera-1","camera-2","camera-3","camera-4","plug-1","plug-2"]}}},
    {"delay": 6000, "event": {"type": "port_scan", "source": "kali", "target": "camera-1", "severity": "warning", "message": "Camera-1 (10.0.0.101) 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "kali", "target": "camera-2", "severity": "warning", "message": "Camera-2 (10.0.0.102) 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "vulnerability_found", "target": "camera-1", "severity": "critical", "message": "Camera-1 发现严重漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8}}},
    {"delay": 3000, "event": {"type": "vulnerability_found", "target": "camera-2", "severity": "critical", "message": "Camera-2 发现严重漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8}}},
    {"delay": 4000, "event": {"type": "bruteforce", "source": "kali", "target": "camera-1", "severity": "critical", "message": "Camera-1 遭遇暴力破解 — 12次尝试后成功", "details": {"attempts": 12, "success": True}}},
    {"delay": 3000, "event": {"type": "attack_detected", "source": "kali", "target": "camera-1", "severity": "critical", "message": "Camera-1 已被 Mirai 僵尸网络感染", "details": {"malware": "Mirai"}}},
    {"delay": 4000, "event": {"type": "lateral_movement", "source": "camera-1", "target": "camera-2", "severity": "critical", "message": "Mirai 从 Camera-1 横向扩散至 Camera-2"}},
    {"delay": 3000, "event": {"type": "c2_detected", "source": "camera-1", "severity": "critical", "message": "检测到 C2 回连: 185.220.101.34", "details": {"c2_server": "185.220.101.34:443"}}},
    {"delay": 3000, "event": {"type": "analysis_complete", "severity": "critical", "message": "CyberAgent 分析完成: Mirai 僵尸网络感染，置信度 94%", "details": {"threat": "Mirai Botnet", "confidence": 94}}},
    {"delay": 4000, "event": {"type": "isolation_request", "severity": "warning", "message": "建议隔离 Camera-1/2", "details": {"targets": ["camera-1", "camera-2"]}}},
    {"delay": 4000, "event": {"type": "device_isolated", "target": "camera-1", "severity": "info", "message": "Camera-1 已隔离"}},
    {"delay": 2000, "event": {"type": "device_isolated", "target": "camera-2", "severity": "info", "message": "Camera-2 已隔离"}},
    {"delay": 3000, "event": {"type": "threat_resolved", "severity": "info", "message": "威胁已清除，攻击时间线报告已生成", "details": {"isolated": ["camera-1", "camera-2"]}}},
]

# Maps event types to device status transitions
EVENT_STATUS_MAP = {
    "scan_started": ("details.targets", "scanning"),
    "port_scan": ("target", "vulnerable"),
    "vulnerability_found": ("target", "vulnerable"),
    "bruteforce": ("target", "attacked"),
    "attack_detected": ("target", "attacked"),
    "lateral_movement": ("target", "attacked"),
    "c2_detected": ("source", "attacked"),
    "device_isolated": ("target", "isolated"),
}


class ScenarioService:
    def __init__(self):
        self.running = False
        self.step = 0
        self._task: asyncio.Task | None = None
        self._broadcast_callback = None
        self._devices = []
        self._links = []

    def set_broadcast(self, callback):
        self._broadcast_callback = callback

    def set_topology(self, devices, links):
        self._devices = [d.model_dump() for d in devices]
        self._links = [{"from": l.from_, "to": l.to} for l in links]

    def get_status(self) -> dict:
        return {"running": self.running, "step": self.step, "total_steps": len(MIRAI_SCRIPT)}

    def _reset_devices(self):
        for d in self._devices:
            d["status"] = "secure"

    def _update_device_status(self, event: dict) -> None:
        evt_type = event.get("type", "")
        if evt_type not in EVENT_STATUS_MAP:
            if evt_type == "threat_resolved":
                for dev_id in event.get("details", {}).get("isolated", []):
                    dev = next((d for d in self._devices if d["id"] == dev_id), None)
                    if dev:
                        dev["status"] = "isolated"
            return
        field, new_status = EVENT_STATUS_MAP[evt_type]
        if field == "details.targets":
            for dev_id in event.get("details", {}).get("targets", []):
                dev = next((d for d in self._devices if d["id"] == dev_id), None)
                if dev:
                    dev["status"] = new_status
        else:
            dev_id = event.get(field)
            if dev_id:
                dev = next((d for d in self._devices if d["id"] == dev_id), None)
                if dev and dev["status"] != "attacked":
                    dev["status"] = new_status

    async def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.step = 0
        self._reset_devices()
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_start", "devices": self._devices, "links": self._links})
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
        self.running = False
        self.step = 0
        self._reset_devices()
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_stop", "devices": self._devices})

    async def _run(self) -> None:
        try:
            for i, script_step in enumerate(MIRAI_SCRIPT):
                await asyncio.sleep(script_step["delay"] / 1000)
                self.step = i + 1
                evt = script_step["event"]
                self._update_device_status(evt)
                if self._broadcast_callback:
                    await self._broadcast_callback({**evt, "step": self.step, "devices": self._devices})
            if self._broadcast_callback:
                await self._broadcast_callback({"type": "scenario_complete", "devices": self._devices})
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    def get_devices(self) -> list:
        return self._devices
```

- [ ] **Step 5: 创建 WebSocket 事件管理**

Write `server/websocket/__init__.py` (empty).

Write `server/websocket/events.py`:
```python
import json
import logging
from fastapi import WebSocket


logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, data: dict) -> None:
        msg = json.dumps(data, ensure_ascii=False)
        for ws in self.connections[:]:
            try:
                await ws.send_text(msg)
            except Exception:
                self.disconnect(ws)
```

- [ ] **Step 6: 创建 API 路由**

Write `server/api/__init__.py` (empty).

Write `server/api/topology.py`:
```python
from fastapi import APIRouter
from ..services.topology_service import get_topology, get_device

router = APIRouter(prefix="/api", tags=["topology"])


@router.get("/topology")
async def topology():
    return get_topology().model_dump()


@router.get("/topology/devices/{device_id}")
async def device_detail(device_id: str):
    device = get_device(device_id)
    if not device:
        return {"error": "not_found", "detail": f"Device {device_id} not found"}
    return device.model_dump()
```

Write `server/api/security.py`:
```python
from fastapi import APIRouter

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events")
async def list_events():
    return {"events": []}


@router.get("/state/{device_id}")
async def device_state(device_id: str):
    return {"device_id": device_id, "state": "secure"}
```

Write `server/api/scenario.py`:
```python
from fastapi import APIRouter
from ..services.scenario_service import ScenarioService

router = APIRouter(prefix="/api/scenario", tags=["scenario"])
scenario_service = ScenarioService()


def set_scenario_service(svc: ScenarioService) -> None:
    global scenario_service
    scenario_service = svc


@router.get("")
async def scenario_list():
    return {"scenarios": [{"id": "mirai", "name": "Mirai Botnet Attack", "steps": 15}]}


@router.get("/status")
async def scenario_status():
    return scenario_service.get_status()


@router.post("/{scenario_id}/start")
async def start_scenario(scenario_id: str):
    await scenario_service.start()
    return {"status": "running", "scenario_id": scenario_id}


@router.post("/{scenario_id}/stop")
async def stop_scenario(scenario_id: str):
    await scenario_service.stop()
    return {"status": "stopped", "scenario_id": scenario_id}


@router.post("/{scenario_id}/reset")
async def reset_scenario(scenario_id: str):
    await scenario_service.stop()
    return {"status": "reset", "scenario_id": scenario_id}
```

Write `server/api/chat.py`:
```python
import re
from fastapi import APIRouter
from ..models.schemas import ChatRequest, ChatResponse

router = APIRouter(prefix="/api/chat", tags=["chat"])

RESPONSES = {
    r"扫描|scan": "好的，我来启动网络扫描。当前网络中有 15 台 IoT 设备，我将执行全面端口扫描和指纹识别。",
    r"漏洞|vuln": "正在检查已知漏洞数据库。目前检测到 2 个高风险 CVE 需要关注。",
    r"报告|report": "正在生成安全评估报告，包含网络拓扑、设备清单、漏洞摘要和修复建议。",
    r"攻击|attack|mirai": "检测到 Mirai 僵尸网络攻击迹象。建议立即隔离受感染设备并分析攻击路径。",
    r"隔离|isolat": "准备执行设备隔离操作。这是一个高风险操作，需要人工确认。",
}

_chat_history: list[dict] = []


@router.post("")
async def chat(req: ChatRequest) -> ChatResponse:
    reply = "我是 CyberAgent，您的 IoT 安全分析助手。请告诉我您需要什么帮助？"
    for pattern, response in RESPONSES.items():
        if re.search(pattern, req.message, re.IGNORECASE):
            reply = response
            break
    _chat_history.append({"role": "user", "content": req.message})
    _chat_history.append({"role": "assistant", "content": reply})
    return ChatResponse(reply=reply)


@router.get("/history")
async def chat_history():
    return {"history": _chat_history}
```

- [ ] **Step 7: 创建 FastAPI 主入口**

Write `server/main.py`:
```python
import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .api.topology import router as topology_router
from .api.security import router as security_router
from .api.scenario import router as scenario_router, set_scenario_service
from .api.chat import router as chat_router
from .services.topology_service import get_topology, DEVICES, LINKS
from .services.scenario_service import ScenarioService
from .websocket.events import ConnectionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ws_manager = ConnectionManager()
scenario_service = ScenarioService()

# Wire up topology data to scenario service
topology = get_topology()
scenario_service.set_topology(DEVICES, LINKS)


async def broadcast_event(event_data: dict) -> None:
    await ws_manager.broadcast(event_data)


async def heartbeat_loop():
    """Broadcast heartbeat every 5 seconds."""
    while True:
        await asyncio.sleep(5)
        devices = scenario_service.get_devices()
        if devices:
            stats = {
                "secure": sum(1 for d in devices if d["status"] == "secure"),
                "scanning": sum(1 for d in devices if d["status"] == "scanning"),
                "vulnerable": sum(1 for d in devices if d["status"] == "vulnerable"),
                "attacked": sum(1 for d in devices if d["status"] == "attacked"),
                "isolated": sum(1 for d in devices if d["status"] == "isolated"),
            }
            await ws_manager.broadcast({
                "type": "heartbeat",
                "stats": stats,
                "scenarioRunning": scenario_service.running,
                "step": scenario_service.step,
                "totalSteps": len(scenario_service.get_status()["total_steps"]) if False else 15,
            })


scenario_service.set_broadcast(broadcast_event)
set_scenario_service(scenario_service)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CyberClaw FastAPI backend starting...")
    hb_task = asyncio.create_task(heartbeat_loop())
    yield
    hb_task.cancel()
    logger.info("CyberClaw FastAPI backend shutting down...")


app = FastAPI(title="CyberClaw API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(topology_router)
app.include_router(security_router)
app.include_router(scenario_router)
app.include_router(chat_router)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        topology = get_topology()
        await ws.send_text(json.dumps({
            "type": "init",
            "devices": topology.model_dump()["devices"],
            "links": [{"from": l.from_, "to": l.to} for l in topology.links],
        }, ensure_ascii=False))

        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "start_scenario":
                await scenario_service.start()
            elif msg.get("action") == "stop_scenario":
                await scenario_service.stop()
            elif msg.get("action") == "reset":
                await scenario_service.stop()
                topology = get_topology()
                await ws.send_text(json.dumps({
                    "type": "init",
                    "devices": topology.model_dump()["devices"],
                    "links": [{"from": l.from_, "to": l.to} for l in topology.links],
                }, ensure_ascii=False))
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
```

- [ ] **Step 8: 验证 FastAPI 能启动**

Run:
```bash
cd D:/臻荣/CyberClaw && pip install -r server/requirements.txt
touch server/__init__.py
python -c "from server.main import app; print('FastAPI app created:', app.title)"
```
Expected: `FastAPI app created: CyberClaw API`

- [ ] **Step 9: Commit**

```bash
git add server/
git commit -m "feat: add FastAPI backend with topology, security, scenario, and chat APIs"
```

---

## Task 7: 前端改造对接

**Files:**
- Modify: `ui/cyberclaw-hud/vite.config.js`
- Modify: `ui/cyberclaw-hud/server.js`
- Modify: `ui/cyberclaw-hud/package.json`

- [ ] **Step 1: 修改 vite.config.js — 代理目标改为 FastAPI**

将 proxy target 从 `localhost:3001` 改为 `localhost:8000`：

```js
proxy: {
  '/api': {
    target: 'http://localhost:8000',
    timeout: 300000,
  },
  '/ws': {
    target: 'ws://localhost:8000',
    ws: true,
  },
},
```

- [ ] **Step 2: 改造 server.js — Express 仅保留静态服务 + 生产代理**

将 server.js 简化为代理模式：移除 DEVICES/LINKS/MIRAI_SCRIPT 等硬编码数据，改为从 FastAPI 获取。保留 Express 作为生产模式的代理服务器和静态文件服务。

重写 `ui/cyberclaw-hud/server.js`：
```javascript
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.CYBERCLAW_UI_PORT || 3001;
const API_URL = process.env.CYBERCLAW_API_URL || 'http://localhost:8000';

app.use(cors());
app.use(express.json());

// Proxy API requests to FastAPI backend
app.use('/api', createProxyMiddleware({
  target: API_URL,
  changeOrigin: true,
}));

// Proxy WebSocket to FastAPI backend
app.use('/ws', createProxyMiddleware({
  target: API_URL,
  ws: true,
  changeOrigin: true,
}));

// Serve static files in production
app.use(express.static(path.join(__dirname, 'dist')));

app.listen(PORT, () => {
  console.log(`[CyberClaw] Express proxy on http://localhost:${PORT} → ${API_URL}`);
});
```

- [ ] **Step 3: 更新 package.json — 添加 http-proxy-middleware**

在 dependencies 中添加：
```json
"http-proxy-middleware": "^3.0.0"
```

- [ ] **Step 4: 安装新依赖**

Run:
```bash
cd D:/臻荣/CyberClaw/ui/cyberclaw-hud && npm install http-proxy-middleware
```

- [ ] **Step 5: Commit**

```bash
git add ui/cyberclaw-hud/vite.config.js ui/cyberclaw-hud/server.js ui/cyberclaw-hud/package.json ui/cyberclaw-hud/package-lock.json
git commit -m "feat: refactor frontend to proxy to FastAPI backend"
```

---

## Task 8: 启动脚本 + 联调验证

**Files:**
- Create: `scripts/start.sh`
- Create: `scripts/install.sh`

- [ ] **Step 1: 创建一键启动脚本**

Write `scripts/start.sh`:
```bash
#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "[CyberClaw] Starting from $ROOT_DIR"

# Install shared library if needed
if ! python3 -c "import cyberclaw_core" 2>/dev/null; then
  echo "[CyberClaw] Installing cyberclaw_core..."
  cd "$ROOT_DIR/src/cyberclaw_core" && pip install -e . -q
fi

# Start FastAPI backend in background
echo "[CyberClaw] Starting FastAPI backend on port 8000..."
cd "$ROOT_DIR"
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "[CyberClaw] Backend PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 2
if ! curl -s http://localhost:8000/api/topology > /dev/null 2>&1; then
  echo "[CyberClaw] ERROR: Backend failed to start"
  kill $BACKEND_PID 2>/dev/null
  exit 1
fi
echo "[CyberClaw] Backend ready"

# Start frontend dev server
echo "[CyberClaw] Starting frontend dev server on port 3001..."
cd "$ROOT_DIR/ui/cyberclaw-hud"
npx vite --host --port 3001 &
FRONTEND_PID=$!
echo "[CyberClaw] Frontend PID: $FRONTEND_PID"

echo ""
echo "[CyberClaw] ============================================"
echo "[CyberClaw] 3D HUD:     http://localhost:3001"
echo "[CyberClaw] Chat:       http://localhost:3001/chat/"
echo "[CyberClaw] API docs:   http://localhost:8000/docs"
echo "[CyberClaw] Backend:    http://localhost:8000"
echo "[CyberClaw] ============================================"
echo ""
echo "[CyberClaw] Press Ctrl+C to stop all services"

cleanup() {
  echo "[CyberClaw] Shutting down..."
  kill $FRONTEND_PID 2>/dev/null
  kill $BACKEND_PID 2>/dev/null
  exit 0
}
trap cleanup SIGINT SIGTERM

wait
```

- [ ] **Step 2: 创建安装脚本**

Write `scripts/install.sh`:
```bash
#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "[CyberClaw] Installing dependencies..."

# Python dependencies
echo "[CyberClaw] Installing Python dependencies..."
cd "$ROOT_DIR/src/cyberclaw_core"
pip install -e .

cd "$ROOT_DIR/server"
pip install -r requirements.txt

# Node.js dependencies
echo "[CyberClaw] Installing Node.js dependencies..."
cd "$ROOT_DIR/ui/cyberclaw-hud"
npm install

echo "[CyberClaw] Installation complete! Run scripts/start.sh to start."
```

- [ ] **Step 3: 联调验证 — 启动后端**

Run (in background):
```bash
cd D:/臻荣/CyberClaw && python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

- [ ] **Step 4: 联调验证 — 测试 API**

Run:
```bash
curl -s http://localhost:8000/api/topology | python -m json.tool | head -20
curl -s http://localhost:8000/api/scenario/status
curl -s -X POST http://localhost:8000/api/chat -H "Content-Type: application/json" -d '{"message":"扫描网络"}'
```
Expected: 返回正确的 JSON 响应

- [ ] **Step 5: 联调验证 — 启动前端**

Run:
```bash
cd D:/臻荣/CyberClaw/ui/cyberclaw-hud && npm run dev
```

验证：
- 打开 `http://localhost:3001`，确认 3D HUD 显示设备拓扑
- 打开 `http://localhost:3001/chat/`，确认聊天界面正常
- 点击开始场景，确认安全事件实时推送

- [ ] **Step 6: Commit**

```bash
git add scripts/
git commit -m "feat: add start and install scripts for one-click launch"
```
