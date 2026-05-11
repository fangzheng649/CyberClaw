# CyberClaw Phase 1: 项目骨架与代码框架设计

## 概述

CyberClaw 是基于 OpenClaw 框架的 IoT 安全自动化平台，核心实现"感知 → 检测 → 响应 → 复盘"全闭环安全能力。本文档定义 Phase 1 的代码框架搭建方案：从 netclaw 复用已有模块，构建精简的 IoT 安全项目骨架，并实现前后端联通。

**目标：** 2 天内完成可运行的项目框架，3D HUD 和聊天界面通过真实后端 API 获取数据。

## 决策记录

| 决策项 | 选择 | 理由 |
|-------|------|------|
| 搭建范围 | Phase 1 优先 | 渐进式开发，先搭骨架再填充 |
| 复用策略 | 复制 + 改造 | 简单直接，不引入包管理复杂度 |
| 前端策略 | 前后端联通 | Phase 1 就打通数据流 |
| 后端框架 | FastAPI + Express | FastAPI 做真实后端，Express 保留做代理和静态服务 |
| 目录结构 | 精简安全结构 | 只保留 IoT 安全相关模块 |
| 命名体系 | 遵循 task_plan.md | 统一为 CyberClaw 命名，避免与 netclaw 混淆 |

## 项目目录结构

```
CyberClaw/
├── config/
│   └── openclaw.json              # OpenClaw 主配置（精简版）
├── mcp-servers/
│   ├── _template/                 # MCP 服务器开发模板
│   │   ├── server.py
│   │   ├── models.py
│   │   ├── requirements.txt
│   │   └── README.md
│   ├── nmap-scan/                 # 网络扫描与 IoT 指纹识别
│   ├── device-config/             # 设备配置管理 (SSH/gNMI) ← 源: netclaw/gnmi-mcp
│   ├── simulation/                # GNS3 仿真环境管理 ← 源: netclaw/gns3-mcp-server
│   ├── syslog-collector/          # Syslog 日志采集 ← 源: netclaw/syslog-mcp
│   ├── snmp-collector/            # SNMP Trap 采集 ← 源: netclaw/snmptrap-mcp
│   ├── cve-intel/                 # CVE 漏洞情报查询
│   ├── security-baseline/         # CIS 安全基线审计
│   ├── flow-analyzer/             # NetFlow/IPFIX 流量分析 ← 源: netclaw/ipfix-mcp
│   ├── traffic-analyzer/          # 深度流量分析 (tshark)
│   ├── auto-response/             # 自动响应 (端口隔离/ACL)
│   ├── config-audit/              # 防火墙规则审计
│   └── attack-timeline/           # 攻击时间线与根因分析
├── src/
│   └── cyberclaw_core/            # 共享库
│       ├── __init__.py
│       ├── toon/                  # TOON 序列化（从 netclaw_tokens 精简）
│       │   ├── __init__.py
│       │   ├── toon_serializer.py
│       │   ├── cost_calculator.py
│       │   └── session_ledger.py
│       ├── security_models.py     # 安全状态、设备模型
│       ├── mcp_base.py            # MCP 服务器基类
│       └── gait_logger.py         # 审计日志
│       └── pyproject.toml         # 包安装配置
├── workspace/
│   └── skills/                    # Skills 编排定义
│       ├── network-discovery.md
│       ├── vulnerability-assessment.md
│       ├── incident-response.md
│       └── security-audit.md
├── server/                        # FastAPI 后端
│   ├── main.py                    # FastAPI 应用入口
│   ├── api/
│   │   ├── __init__.py
│   │   ├── topology.py            # 拓扑数据 API
│   │   ├── security.py            # 安全事件 API
│   │   ├── scenario.py            # 攻击场景 API
│   │   └── chat.py                # 聊天 API
│   ├── websocket/
│   │   ├── __init__.py
│   │   └── events.py              # WebSocket 事件推送
│   ├── services/
│   │   ├── __init__.py
│   │   ├── topology_service.py    # 拓扑数据管理
│   │   └── scenario_service.py    # 攻击场景管理
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py             # Pydantic 数据模型
│   └── requirements.txt
├── ui/
│   └── cyberclaw-hud/             # 现有前端（改造对接）
│       ├── server.js
│       ├── src/main.js
│       ├── chat/
│       ├── package.json
│       └── vite.config.js
├── lab/                           # GNS3 实验环境配置
├── scripts/
│   ├── install.sh                 # 安装脚本
│   ├── setup.sh                   # 配置向导
│   └── start.sh                   # 一键启动脚本
├── SOUL.md                        # Agent 身份定义
├── AGENTS.md                      # Agent 运行指令
├── TOOLS.md                       # 基础设施连接信息
├── .env.example                   # 环境变量模板
├── CLAUDE.md                      # Claude 开发指南
└── docs/
```

## 后端架构

### 双层服务器架构

Phase 1 有两种运行模式，代理策略不同：

**开发模式（Vite dev server 代理）：**
```
浏览器 → Vite dev server (localhost:3001)
              ├── 静态文件 → 本地文件系统
              ├── /api/* → 代理到 FastAPI (localhost:8000)
              └── /ws   → WebSocket 代理到 FastAPI (localhost:8000)
```

**生产模式（Express 代理）：**
```
浏览器 → Express (localhost:3001)
              ├── 静态文件 → dist/
              ├── /api/* → 代理到 FastAPI (localhost:8000)
              └── /ws   → WebSocket 代理到 FastAPI (localhost:8000)
```

启动流程：
1. 先启动 FastAPI：`cd server && uvicorn main:app --port 8000`
2. 再启动前端：`cd ui/cyberclaw-hud && npm run dev`（开发）或 `node server.js`（生产）
3. 或使用一键脚本：`scripts/start.sh`

### API 端点设计

**拓扑 API:**
- `GET /api/topology` — 获取 IoT 网络拓扑（设备列表 + 连接关系）
- `GET /api/topology/devices/{device_id}` — 获取单个设备详情

**安全事件 API:**
- `GET /api/security/events` — 获取安全事件列表（支持过滤）
- `POST /api/security/events` — 创建安全事件（内部触发）
- `GET /api/security/state/{device_id}` — 获取设备安全状态

**场景 API:**
- `GET /api/scenario` — 获取可用攻击场景列表
- `POST /api/scenario/{id}/start` — 启动场景
- `POST /api/scenario/{id}/stop` — 停止场景
- `POST /api/scenario/{id}/reset` — 重置场景

**聊天 API（对齐 2026-04-28-chat-interface-design.md）：**
- `POST /api/chat` — 发送聊天消息，返回 Mock AI 响应
- `GET /api/chat/history` — 获取聊天历史
- 聊天 WebSocket 消息类型（复用已有 chat interface 设计）：
  - `chat_message` — 用户发送消息
  - `chat_reply` — AI 直接回复
  - `chat_step` — 多步分析的步骤更新
  - `chat_confirmation` — 高风险操作确认请求

**安全事件 WebSocket:**
- `WS /ws` — 实时事件推送
- 标准事件类型（统一现有 server.js 和设计文档中的事件）：
  - `scene_init` — 场景初始化
  - `device_discovered` — 设备发现
  - `scan_started` — 扫描开始
  - `port_scan` — 端口扫描检测
  - `vulnerability_found` — 漏洞发现
  - `bruteforce` — 暴力破解检测
  - `attack_detected` — 攻击检测
  - `lateral_movement` — 横向移动检测
  - `c2_detected` — C2 通信检测
  - `malware_detected` — 恶意软件检测
  - `device_isolated` — 设备已隔离
  - `threat_resolved` — 威胁已解除
  - `analysis_complete` — 分析完成

### 数据策略

Phase 1 使用内存 mock 数据（从现有 server.js 迁移到 FastAPI services 层），API 接口按真实架构设计。后续 Phase 直接替换数据源为 MCP 服务器返回的真实数据，无需改接口。

### 错误处理策略

- HTTP 错误码遵循 RESTful 规范（400/404/422/500）
- 统一错误响应格式：`{"error": "type", "detail": "message"}`
- FastAPI 异常中间件捕获未处理异常
- `gait_logger.py` 记录所有操作审计日志（JSON Lines 格式，写入 `~/.cyberclaw/logs/`）

## MCP 服务器规划（共 12 个）

### 完整映射表

| # | CyberClaw 名称 | Phase | 源: netclaw 模块 | 复用度 | 改造内容 |
|---|---------------|-------|-----------------|--------|---------|
| 1 | nmap-scan | 2 | 无（全新） | - | 封装 python-nmap |
| 2 | device-config | 2 | gnmi-mcp | 高 | 保留 Get/Set/Subscribe，加 SSH/CLI，去掉厂商方言策略 |
| 3 | simulation | 2 | gns3-mcp-server | 高 | 不改，加 IoT 拓扑模板 |
| 4 | syslog-collector | 2 | syslog-mcp | 高 | 加 severity 过滤和安全事件分类 |
| 5 | snmp-collector | 2 | snmptrap-mcp | 高 | 加 IoT OID 映射和陷阱模板 |
| 6 | cve-intel | 3 | 无（全新） | - | NVD API + SQLite 缓存 |
| 7 | security-baseline | 3 | 无（全新） | - | CIS 九步审计 |
| 8 | flow-analyzer | 3 | ipfix-mcp | 高 | 加异常流量检测算法 |
| 9 | traffic-analyzer | 3 | 无（全新） | - | tshark 封装 + IoC 提取 |
| 10 | auto-response | 4 | 无（全新） | - | 端口隔离 + ACL + 验证 + 回滚 |
| 11 | config-audit | 4 | 无（全新） | - | 防火墙规则冲突/重叠/影子检测 |
| 12 | attack-timeline | 4 | 无（全新） | - | 事件记录 + 时间线 + 根因分析 |

### Phase 1 范围

Phase 1 不实现具体逻辑，只完成：
1. 创建 12 个 MCP 服务器的目录和骨架文件
2. 从 netclaw 复制 5 个可复用服务器的源码到对应目录
3. 创建 `_template/` 标准开发模板

### MCP 服务器模板

`mcp-servers/_template/` 提供标准开发模板，包含：
- FastMCP 服务器初始化
- Pydantic 数据模型
- 工具注册装饰器
- GAIT 审计日志集成
- 统一的错误处理

## 共享库设计

### src/cyberclaw_core/

**安装方式：** `pip install -e .`（开发模式），通过 `pyproject.toml` 管理。

**toon/ 子包（从 netclaw_tokens 精简）：**
- `toon_serializer.py` — TOON 序列化（节省 40-60% token）
- `cost_calculator.py` — API 成本计算（支持缓存折扣）
- `session_ledger.py` — 会话使用追踪

**顶层模块（新建）：**
- `security_models.py` — `SecurityState` 枚举（SECURE/SCANNING/VULNERABLE/ATTACKED/ISOLATED）、`DeviceInfo`、`SecurityEvent` Pydantic 模型
- `mcp_base.py` — FastMCP 服务器基类，封装通用初始化、审计、错误处理
- `gait_logger.py` — 操作审计日志（JSON Lines 格式）

## Agent 配置文件

### SOUL.md — Agent 身份定义
- 角色：IoT 安全分析专家
- 技能清单：引用安全闭环四阶段的 Skills
- 安全操作规则：三级权限（只读 / 写操作须确认 / 禁止）
- 协议知识库：IoT 协议识别特征和安全检查要点

### AGENTS.md — Agent 运行指令
- 继承 OpenClaw 标准 GAIT 工作流
- IoT 约束：扫描仅限授权网段、禁止对物理设备执行破坏性操作
- 安全规则执行方式

### TOOLS.md — 基础设施连接信息
- GNS3 服务器地址
- 可管理交换机 IP
- MCP 服务器配置模板

## 前端改造要点

### server.js 改造

现有 server.js 包含 mock 数据和 API 端点。改造为：
1. 拓扑数据 API → 调用 FastAPI `/api/topology`
2. 场景控制 API → 调用 FastAPI `/api/scenario/*`
3. 聊天 API → 调用 FastAPI `/api/chat`
4. WebSocket 事件 → FastAPI 推送，Express 转发给前端
5. 保留 Express 的静态文件服务和 CORS 配置

### vite.config.js 改造

开发模式下添加 FastAPI 代理（取代 server.js 的代理角色）：
```js
server: {
  proxy: {
    '/api': 'http://localhost:8000',
    '/ws': { target: 'ws://localhost:8000', ws: true }
  }
}
```

### 前端 WebSocket 连接改造

保持现有事件处理逻辑不变，连接地址通过代理指向 FastAPI。

## 环境变量模板 (.env.example)

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

## Phase 1 施工步骤

### Step 1: 项目骨架搭建
- 创建完整目录结构（mcp-servers/、src/cyberclaw_core/、workspace/skills/、server/、lab/、scripts/、config/）
- 创建 `.env.example`
- 创建 `CLAUDE.md`
- 创建顶层 `requirements.txt`

### Step 2: Agent 配置文件
- 创建 `SOUL.md` — IoT 安全分析专家身份
- 创建 `AGENTS.md` — IoT 安全运行指令
- 创建 `TOOLS.md` — 基础设施连接信息
- 配置 `config/openclaw.json` — 注册 12 个 CyberClaw MCP 服务器

### Step 3: 共享库
- 从 netclaw 复制 `src/netclaw_tokens/` → `src/cyberclaw_core/toon/`，精简掉 GAIT 导出
- 新建 `src/cyberclaw_core/security_models.py`、`mcp_base.py`、`gait_logger.py`
- 创建 `src/cyberclaw_core/pyproject.toml`

### Step 4: MCP 服务器模板 + 服务器骨架
- 创建 `_template/` 标准模板
- 从 netclaw 复制 5 个可复用服务器源码到对应 CyberClaw 目录
- 新建 7 个全新服务器骨架（只含 `server.py` 骨架、`models.py` 骨架、`requirements.txt`）

### Step 5: FastAPI 后端
- `server/main.py` — FastAPI 应用入口 + CORS + 异常中间件
- `server/api/` — 拓扑、安全事件、场景、聊天 API
- `server/websocket/` — WebSocket 事件推送
- `server/services/` — 数据服务层（从现有 server.js 迁移 mock 数据）
- `server/models/` — Pydantic 数据模型
- `server/requirements.txt`

### Step 6: 前端改造对接
- server.js 数据源改为调用 FastAPI API
- vite.config.js 添加开发代理配置
- WebSocket 连接对齐 FastAPI 端点
- 聊天 WebSocket 协议对齐 chat interface 设计文档

### Step 7: 联调验证 + 启动脚本
- 创建 `scripts/start.sh` 一键启动脚本（FastAPI + 前端）
- 启动验证 3D HUD 显示拓扑和安全事件
- 验证聊天界面交互
- 验证攻击场景启停

## 验收标准

1. `pip install -e .` + `npm install` + `scripts/start.sh` 能一键启动全部服务
2. FastAPI 后端提供完整的 REST API 和 WebSocket
3. 3D HUD 通过 FastAPI 获取拓扑数据，正确显示设备节点
4. 攻击场景能通过 API 启动/停止，安全事件实时推送到 HUD
5. 聊天界面能发送消息并收到 Mock AI 响应
6. Agent 能读取 SOUL.md/AGENTS.md/TOOLS.md 并初始化
7. 所有 12 个 MCP 服务器骨架就位，复用模块源码已复制
8. 共享库 `cyberclaw_core` 可被 MCP 服务器和后端 `import` 引用
9. openclaw.json 配置了所有 12 个 MCP 服务器入口
