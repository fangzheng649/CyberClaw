<div align="center">

# <img src="docs/cyberclaw-logo-transparent.svg" width="44" alt="CyberClaw"> CyberClaw

**IoT 全链路安全自动化平台**

**Sense → Detect → Shield → Review**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Three.js](https://img.shields.io/badge/Three.js-r170-black?logo=three.js&logoColor=white)](https://threejs.org/)
[![FastMCP](https://img.shields.io/badge/MCP-FastMCP-blueviolet)](https://github.com/jlowin/fastmcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[功能总览](#-功能总览) · [快速开始](#-快速开始) · [架构设计](#-架构设计) · [MCP 工具矩阵](#-mcp-工具矩阵) · [API 参考](#-api-参考) · [配置指南](#-配置指南)

</div>

---

CyberClaw 是一个面向物联网设备网络的**全链路安全自动化平台**。平台覆盖 **设备发现 → 漏洞检测 → 威胁响应 → 事后复盘** 四个安全阶段，内置 12 个 MCP (Model Context Protocol) 安全工具服务器，结合 Three.js 3D 实时态势可视化与 AI 智能分析，为 IoT 网络提供可观测、可响应、可复盘的一体化安全能力。

**核心特性：**

- **双模式运行** — 自动检测网络环境，智能切换演示模式（内置智能园区视频监控 Demo，19 台模拟设备）与实战模式
- **12 个 MCP 安全工具服务器** — 网络扫描、CVE 情报、基线审计、流量分析、自动隔离等能力模块化封装，总计 86 个工具
- **3D 实时态势感知** — Three.js + GSAP + WebGL 后处理管线，设备状态实时映射至 3D 空间，攻击光束与隔离护盾动画
- **AI 安全对话** — CyberAgent 智能助手（DeepSeek），自然语言驱动安全扫描、漏洞查询、设备隔离，支持定时任务
- **多协议数据采集** — Syslog / SNMP Trap / MQTT / IPFIX(NetFlow) / Suricata IDS 五路并行采集
- **自动化调度** — 内置安全任务调度器，支持定时扫描、CVE 检查、基线审计、流量分析、配置审计的周期性自动执行

---

## ◈ 功能总览

### 1. 设备发现与指纹识别

| 能力 | 技术实现 |
|------|----------|
| 多模式扫描 | nmap ping sweep + scapy ARP scan + 静态配置 fallback，自动选择可用方式 |
| 三层设备识别 | MAC OUI 厂商查询 → 主机名正则匹配 → 开放端口启发式判定，逐层细化 |
| 厂商覆盖 | 内置 18 家 IoT 厂商 MAC 前缀库（海康威视、大华、华为、H3C、TP-Link、西门子等） |
| 21 条启发式规则 | 基于 MAC 前缀 + 设备名模式 + IP 段的综合设备类型识别（`config/device_heuristics_rules.json`） |
| 自动周期扫描 | 可配置扫描间隔（默认 300s），自动发现新上线设备和离线告警 |

### 2. 多协议数据采集

| 协议 | 端口 | 能力 | 实现库 |
|------|------|------|--------|
| Syslog (RFC 3164/5424) | UDP 8514 | 实时日志接收、解析、存储与查询 | asyncio UDP server |
| SNMP | UDP 1162 | 设备信息查询 + Trap 实时接收 | pysnmp v7 |
| MQTT | TCP 1883 | Broker 连接、主题订阅、异常发布率检测 | paho-mqtt v2 |
| IPFIX / NetFlow | UDP 2055 | v5/v9/v10 流量记录解析与分析 | 自定义解析器 |
| Suricata IDS | — | eve.json 事件流实时监控，告警提取 | 文件监视 + JSON 解析 |

所有采集器均通过 **WebSocket 实时广播** 至前端，支持独立启停控制。

### 3. 安全检测能力

| 检测类型 | 详情 |
|----------|------|
| 端口扫描 | nmap connect/syn/udp/fin 四种模式，设备指纹服务识别 |
| CVE 漏洞查询 | 对接 NIST NVD API，内置 Hikvision、Dahua 等 7 条 IoT 专项 CVE 规则 |
| 安全基线审计 | 4 种审计 Profile：`iot-default` / `network-device` / `camera-specific` / `critical-infra` |
| 弱密码检测 | 自动检测 Telnet / SSH / HTTP 默认凭据，内置 IoT 常见弱密码字典 |
| 流量 IoC 提取 | 从网络流量中提取恶意 IP、C2 域名、可疑连接等威胁指标 |
| 配置合规审计 | SSH 获取设备配置，检测明文密码、Telnet 启用、HTTP 管理、默认 SNMP community、ACL 冲突与影子规则 |

### 4. 自动响应与设备隔离

| 隔离方式 | 适用场景 | 实现 |
|----------|----------|------|
| **iptables DROP** | Linux/WSL 环境（默认） | 直接在主机 iptables 添加 DROP 规则，无需额外硬件 |
| **SSH 交换机端口隔离** | 企业网络环境 | 通过 netmiko 连接华为 / Cisco / H3C 交换机，shutdown 对应端口 |
| **ACL IP 封堵** | IP 级别封锁 | 管理黑名单 ACL 规则，阻断指定 IP 的所有通信 |
| **记录降级** | 无可用隔离方式 | 记录操作日志，等待人工介入 |

三种权限级别：**read-only**（只读） / **write-with-confirmation**（写操作需确认） / **prohibited**（禁止执行）。

### 5. 攻击场景模拟与复盘

内置 Mirai 僵尸网络攻击演示场景，完整复现：

```
Phase 1 — 初始态势    19 台监控设备在线运行
Phase 2 — 侦察        攻击者扫描发现摄像头管理端口开放
Phase 3 — 漏洞发现    Hikvision CVE-2021-36260 / Dahua CVE-2021-33044
Phase 4 — 初始入侵    Telnet 暴力破解入侵入口摄像头
Phase 5 — 载荷植入    Mirai 恶意程序注入
Phase 6 — 横向扩散    同品牌漏洞利用 + 共享密码横向移动
Phase 7 — C2 通信     Tor 出口节点 + 组播 C2 信道
Phase 8 — CyberAgent  AI 自动分析，Mirai 感染置信度 96%
Phase 9 — 自动隔离    依次隔离 6 台受控设备
Phase 10 — 收尾       威胁清除报告生成
```

3D HUD 实时呈现攻击红色光束传播 → 蓝色护盾隔离的完整动画。

### 6. AI 安全助手 (CyberAgent)

基于 DeepSeek 大语言模型的 IoT 安全分析助手：

- **自然语言 → 工具调用**：用户提问自动匹配 MCP 工具意图，执行后返回分析结果
- **定时任务**：支持"5分钟后扫描网络"、"明天早上9点检查基线"等自然语言定时
- **隔离确认卡片**：要求隔离设备时生成可交互的确认卡片，防止误操作
- **多轮对话**：聊天历史持久化存储，支持多会话管理
- **Slash 命令**：`/scan`、`/cve`、`/baseline`、`/schedule` 等快捷操作

### 7. 通知与调度系统

**通知通道：**

| 通道 | 说明 |
|------|------|
| ntfy | 推送通知至移动端/桌面 |
| Webhook | 自定义 HTTP 回调 |
| WebSocket | 实时前端推送 |
| Chat 历史 | 定时任务结果自动写入对话 |

**告警路由规则：** 按严重程度（critical / high / warning / info）分级路由至不同通知通道。

**安全调度器：** 5 个预设安全任务自动周期执行：

| 任务 | 间隔 | 触发通知 |
|------|------|----------|
| 网络扫描 | 5 分钟 | 新设备 / 设备离线 |
| CVE 漏洞检查 | 1 小时 | 新漏洞发现 |
| 安全基线检查 | 30 分钟 | 合规评分下降 |
| 流量分析 | 10 分钟 | IoC 发现 |
| 配置审计 | 1 小时 | 配置异常 |

---

## ◈ 快速开始

### 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.10+ | 后端运行时 |
| Node.js | 18+ | 前端构建 |
| nmap（可选） | 最新 | 增强扫描能力 |
| Git | 最新 | 代码获取 |

### 方式一：一键启动（推荐）

**Windows 用户**直接双击 `start.bat`，脚本自动完成：

1. 环境检查（Python / Node.js）
2. 首次运行自动创建 `.env` 配置文件
3. 自动安装 Python / Node.js 依赖
4. 启动后端 (FastAPI :8000) + 前端 (Vite+Express :3000)
5. 健康检查通过后自动打开浏览器

```bat
:: 双击 start.bat 或命令行运行
start.bat
```

### 方式二：手动启动

```bash
# 1. 克隆仓库
git clone https://github.com/fangzheng649/CyberClaw.git
cd CyberClaw

# 2. 安装依赖
pip install -r server/requirements.txt
cd src/cyberclaw_core && pip install -e . && cd ../..
cd ui/cyberclaw-hud && npm install && cd ../..

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY

# 4. 启动后端（终端 1）
python -m uvicorn server.main:app --reload --port 8000

# 5. 启动前端（终端 2）
cd ui/cyberclaw-hud && npm run dev
```

### 访问地址

| 服务 | 地址 | 说明 |
|------|------|------|
| 3D 安全 HUD | http://localhost:3000 | Three.js 实时态势可视化 |
| AI 对话界面 | http://localhost:3000/chat/ | CyberAgent 安全助手 |
| API 文档 | http://localhost:8000/docs | Swagger UI 交互式 API 文档 |
| WebSocket | ws://localhost:8000/ws | 实时事件推送 |

### 安装 nmap（可选，推荐）

安装后设备发现和端口扫描能力大幅增强：

```bash
# Windows
winget install Insecure.Nmap --source winget

# Linux
sudo apt install nmap
```

---

## ◈ 架构设计

### 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                       CyberClaw HUD                          │
│              Three.js 3D 态势可视化 + AI 对话界面               │
│                   (Vite + Express :3000)                      │
└────────────────────────┬─────────────────────────────────────┘
                         │ WebSocket + REST API
┌────────────────────────▼─────────────────────────────────────┐
│                  FastAPI Backend (:8000)                      │
│                                                               │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐      │
│  │ Topology │ │ Discovery │ │ Scenario │ │   Chat    │      │
│  │   API    │ │    API    │ │   API    │ │    API    │      │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘      │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐      │
│  │  Tools   │ │Dashboard  │ │Workflow  │ │Scheduler  │      │
│  │   API    │ │   API     │ │   API    │ │   API     │      │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘      │
├──────────────────────────────────────────────────────────────┤
│                        服务层                                 │
│                                                               │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐ │
│  │  Discovery   │ │    SNMP      │ │    Isolation          │ │
│  │  (nmap/scapy)│ │  (pysnmp v7) │ │  (iptables/netmiko)  │ │
│  └──────────────┘ └──────────────┘ └───────────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐ │
│  │    MQTT      │ │   Suricata   │ │   Security Scheduler  │ │
│  │ (paho-mqtt)  │ │  IDS Monitor │ │   (croniter)          │ │
│  └──────────────┘ └──────────────┘ └───────────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐ │
│  │   Syslog     │ │    Mock      │ │   Notification        │ │
│  │  Collector   │ │   State Sim  │ │   Bridge              │ │
│  └──────────────┘ └──────────────┘ └───────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│                  12 MCP 安全工具服务器                         │
│                                                               │
│  ┌────────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐  │
│  │  nmap-scan │ │  cve-intel│ │   auto-   │ │  config-   │  │
│  │  (6 tools) │ │  (4 tools)│ │  response │ │  audit     │  │
│  │            │ │           │ │  (6 tools)│ │  (4 tools) │  │
│  └────────────┘ └───────────┘ └───────────┘ └────────────┘  │
│  ┌────────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐  │
│  │  syslog-   │ │   snmp-   │ │   flow-   │ │  security- │  │
│  │  collector │ │  collector│ │  analyzer │ │  baseline  │  │
│  │  (6 tools) │ │  (6 tools)│ │  (7 tools)│ │  (4 tools) │  │
│  └────────────┘ └───────────┘ └───────────┘ └────────────┘  │
│  ┌────────────┐ ┌───────────┐ ┌───────────┐                  │
│  │  traffic-  │ │  attack-  │ │  device-  │  ┌────────────┐  │
│  │  analyzer  │ │  timeline │ │  config   │  │ simulation │  │
│  │  (4 tools) │ │  (4 tools)│ │ (13 tools)│  │ (32 tools) │  │
│  └────────────┘ └───────────┘ └───────────┘  └────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                         数据层                                │
│          SQLite (设备/事件/拓扑持久化) + JSON 配置              │
└──────────────────────────────────────────────────────────────┘
```

### 数据流

```
┌──────────────┐     WebSocket      ┌──────────────┐
│   IoT 设备    │ ──────────────────→ │  3D HUD 前端  │
│  (真实/Mock)  │     状态/事件广播    │  实时态势渲染  │
└──────┬───────┘                    └──────────────┘
       │
       │ nmap / scapy / SNMP / MQTT / Syslog / NetFlow
       ▼
┌──────────────┐     工具调用        ┌──────────────┐
│  采集服务层   │ ──────────────────→ │  MCP 工具服务器│
│  Discovery   │     FastMCP/stdio   │  12 个 Server │
│  Collector   │ ←────────────────── │  86 个 Tool   │
└──────┬───────┘     结构化结果       └──────────────┘
       │
       │ 写入
       ▼
┌──────────────┐     REST API        ┌──────────────┐
│   SQLite DB  │ ←────────────────── │  AI Chat API │
│  设备/事件/   │     查询/更新        │  CyberAgent  │
│  拓扑持久化   │                    │  DeepSeek    │
└──────────────┘                    └──────────────┘
```

### 双模式自动切换

```
启动 → 读取 topology.json → 网络扫描
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              设备在线               未发现设备
              Real 实战模式         Mock 演示模式
              使用真实设备         19 台模拟视频监控设备
              实际扫描/采集         状态模拟器自动运行
```

### 安全状态 FSM

设备安全状态遵循 5 状态有限状态机：

```
  secure ──→ scanning ──→ vulnerable ──→ attacked ──→ isolated
    ↑                                                    │
    └──────────────── restore ───────────────────────────┘
```

| 状态 | 颜色 | 3D HUD 渲染 | 含义 |
|------|------|-------------|------|
| `secure` | 🟢 绿色 | 白色线框 + 微弱呼吸 | 设备安全 |
| `scanning` | 🔵 蓝色 | 蓝色脉冲 + 扫描环 | 正在被扫描探测 |
| `vulnerable` | 🟠 橙色 | 橙色警告 + 振荡 | 发现安全漏洞 |
| `attacked` | 🔴 红色 | 红色闪烁 + glitch 干扰 | 正在被攻击 |
| `isolated` | ⚪ 灰色 | 蓝色护盾 + 降透明度 | 已被网络隔离 |

状态定义：`src/cyberclaw_core/security_models.py` — `SecurityState(StrEnum)`

---

## ◈ MCP 工具矩阵

12 个 MCP 服务器通过 FastMCP 框架实现，使用 stdio 协议通信，由 `config/openclaw.json` 统一注册管理。

| 服务器 | 工具数 | 核心能力 |
|--------|--------|----------|
| **nmap-scan** | 6 | 网络扫描、主机发现、端口扫描、服务识别、IoT 设备指纹、OS 指纹 |
| **device-config** | 13 | gNMI/SSH 设备配置管理、接口状态、路由表、ARP 表、配置备份恢复 |
| **simulation** | 32 | GNS3 仿真全生命周期管理：项目/节点/链路/快照/包捕获 |
| **syslog-collector** | 6 | Syslog 消息接收、查询、过滤、统计、解析 |
| **snmp-collector** | 6 | SNMP Trap 接收、查询、设备信息采集、OID walk |
| **cve-intel** | 4 | CVE 漏洞查询（NIST NVD）、设备漏洞匹配、厂商漏洞统计 |
| **security-baseline** | 4 | CIS 安全基线审计、合规评分、多 Profile 支持、修复建议 |
| **flow-analyzer** | 7 | IPFIX/NetFlow v5/v9/v10 解析、流量统计、异常检测、Top-N 分析 |
| **traffic-analyzer** | 4 | 深度流量分析、IoC 提取、协议分布、异常连接检测 |
| **auto-response** | 6 | 自动响应：端口隔离、IP 封堵、ACL 管理、响应状态跟踪 |
| **config-audit** | 4 | 配置合规审计、ACL 冲突检测、影子规则发现、安全建议 |
| **attack-timeline** | 4 | 攻击事件时间线构建、根因分析、攻击链还原、报告生成 |

**总计：86 个安全工具**，覆盖从发现到响应的完整安全生命周期。

新增 MCP 服务器使用模板：

```python
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("my-server", "Description of the server")

@mcp.tool()
def my_tool(param: str) -> dict:
    """Tool description."""
    return {"result": "ok"}
```

---

## ◈ 前端界面

### 3D 安全 HUD（Three.js）

| 特性 | 实现 |
|------|------|
| 渲染引擎 | Three.js r170 + WebGLRenderer + 多通道后处理管线 |
| 动画系统 | GSAP 3.12（设备状态转换过渡、攻击光束、隔离护盾） |
| 实时通信 | WebSocket 持久连接，5s 心跳广播设备状态统计 |
| 设备渲染 | 类型化几何体（camera/switch/server/gateway/attacker/access），状态着色 |
| 攻击可视化 | 红色弧形光束 + 辉光粒子流，沿网络拓扑链路传播 |
| 隔离可视化 | 蓝色六角护盾 + 发光描边 + 透明度降低 |
| HUD 面板 | 告警时间线、设备详情、MCP 工具结果、安全指标卡片 |
| 品质控制 | 三档质量模式（High / Medium / Low）+ FPS 监控 |

### Dashboard

| 面板 | 内容 |
|------|------|
| 设备概览 | 类型分组的设备计数卡片（安全/扫描/漏洞/攻击/隔离） |
| 安全趋势 | ECharts 告警数量时间序列图 + 协议分布饼图 |
| 网络拓扑树 | Treeviz 交互式拓扑树，设备状态实时着色 |
| 告警列表 | 按严重程度分级的实时安全事件流 |
| 日志搜索 | Syslog / SNMP / MQTT / Suricata 统一查询 |

### AI 对话界面

| 功能 | 说明 |
|------|------|
| 多标签页 | 对话 / Dashboard / 设备 / 事件 / Automate 五个视图 |
| 多会话管理 | 左侧对话列表，支持新建/切换对话 |
| 快捷操作 | 一键扫描网络安全状态、分析漏洞、生成报告、攻击复盘 |
| 工具结果卡片 | MCP 工具执行结果可视化（端口列表、CVE 详情、合规评分条） |
| 隔离确认卡片 | 可交互的确认/取消按钮，防止误操作 |
| 采集器控制 | Syslog / SNMP / MQTT / Suricata 采集器独立启停 |
| 预设任务 | 安全扫描、CVE 检查、基线审计等一键执行 |
| 工作流管理 | 自定义自动化工作流的创建、编辑、启停 |

### 视觉风格

赛博朋克暗色主题 — void-black 底色 + bioluminescent accent 光效：

- 面板：`backdrop-filter: blur` 毛玻璃 + `::after` 内发光
- 卡片：顶部渐变装饰线 + hover 边框发光
- 按钮：active `scale(0.96)` 物理反馈 + glow shadow
- 进度条：`@keyframes shimmer` 流光动画
- 滚动条：4px 半透明 + hover 增强
- 字体：Share Tech Mono（数据） + JetBrains Mono（代码）

---

## ◈ API 参考

### 拓扑与设备

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/topology` | GET | 获取完整网络拓扑（设备 + 链路） |
| `/api/discovery/scan` | POST | 触发网络设备发现扫描 |
| `/api/discovery/status` | GET | 获取最近一次扫描结果 |
| `/api/discovery/register` | POST | 手动注册设备到拓扑 |

### 安全工具

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/tools/scan` | POST | 触发 nmap 端口扫描 |
| `/api/tools/cve-check` | POST | CVE 漏洞查询 |
| `/api/tools/baseline` | POST | CIS 安全基线审计 |
| `/api/tools/isolate` | POST | 隔离指定设备 |
| `/api/tools/restore` | POST | 恢复已隔离设备 |
| `/api/tools/snmp/start` | POST | 启动 SNMP Trap 接收器 |
| `/api/tools/snmp/query` | POST | SNMP 查询设备信息 |
| `/api/tools/mqtt/connect` | POST | 连接 MQTT Broker |
| `/api/tools/collector/start` | POST | 启动 Syslog 收集器 |

### AI 对话

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/chat` | POST | 发送消息，返回 AI 回复 + 工具执行结果 |
| `/api/chat/history` | GET | 获取完整聊天历史 |
| `/api/chat/history` | DELETE | 清空聊天历史 |
| `/api/chat/status` | GET | AI 服务状态、已加载 MCP 工具列表 |
| `/api/chat/call-tool` | POST | 直接调用指定 MCP 工具 |

### Dashboard

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/dashboard/mode` | GET | 获取系统运行模式（演示/实战） |
| `/api/dashboard/db/alerts` | GET | 分页安全告警列表 |
| `/api/dashboard/db/device-events` | GET | 设备关联事件查询 |
| `/api/dashboard/trend/alert-count` | GET | 告警数量趋势（24h） |
| `/api/dashboard/trend/protocol-dist` | GET | 协议分布统计 |
| `/api/dashboard/device-status-dist` | GET | 设备状态分布 |

### 场景模拟

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/scenario` | GET | 可用攻击场景列表 |
| `/api/scenario/{id}/start` | POST | 启动指定攻击场景 |
| `/api/scenario/{id}/stop` | POST | 停止运行中的场景 |

### 工作流与通知

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/workflows` | GET | 获取工作流列表 |
| `/api/workflows` | POST | 创建新工作流 |
| `/api/workflows/{id}/toggle` | POST | 启停工作流 |
| `/api/notifications` | GET | 获取通知历史 |
| `/api/notifications/channels` | GET | 获取通知通道配置 |
| `/api/scheduler/tasks` | GET | 获取调度任务列表 |
| `/api/scheduler/tasks/{id}/toggle` | POST | 启停调度任务 |

### WebSocket

```
ws://localhost:8000/ws
```

**消息类型：**

| type | 方向 | 说明 |
|------|------|------|
| `init` | Server → Client | 连接初始化，含设备列表 + 链路 + 模式 |
| `heartbeat` | Server → Client | 5s 周期心跳，含设备状态统计 |
| `device_update` | Server → Client | 设备状态变更 |
| `security_event` | Server → Client | 安全事件告警 |
| `scenario_step` | Server → Client | 攻击场景步骤推进 |
| `tool_result` | Server → Client | MCP 工具执行结果 |
| `start_scenario` | Client → Server | 启动攻击演示 |
| `stop_scenario` | Client → Server | 停止攻击演示 |
| `reset` | Client → Server | 重置所有设备状态 |

---

## ◈ 配置指南

### 环境变量（.env）

```bash
# ── 后端 ──────────────────────────────
CYBERCLAW_API_HOST=0.0.0.0       # 监听地址
CYBERCLAW_API_PORT=8000          # API 端口
CYBERCLAW_LOG_LEVEL=INFO         # 日志级别

# ── 前端 ──────────────────────────────
CYBERCLAW_UI_PORT=3000           # 前端端口

# ── AI 模型 ───────────────────────────
DEEPSEEK_API_KEY=                     # DeepSeek API Key（必填）
DEEPSEEK_MODEL=deepseek-chat          # 模型名称
DEEPSEEK_API_URL=https://api.deepseek.com/chat/completions

# ── 仿真环境 ──────────────────────────
GNS3_SERVER_URL=http://127.0.0.1:3080
GNS3_PROJECT_ID=

# ── 设备隔离 ──────────────────────────
ISOLATION_METHOD=iptables        # iptables / ssh_switch / record_only
SWITCH_TYPE=huawei               # huawei / cisco_ios / hp_comware
SWITCH_IP=10.0.0.1
SWITCH_SSH_USER=admin
SWITCH_SSH_PASS=

# ── 网络扫描 ──────────────────────────
SCAN_SUBNET=                     # 自动扫描子网（留空则从 topology.json 读取）
SCAN_INTERVAL=300                # 扫描间隔（秒）
```

### 设备拓扑（config/topology.json）

设备定义支持完整字段：

```json
{
  "id": "cam_entrance",
  "name": "IPC-Entrance-PTZ",
  "type": "camera",
  "ip": "192.168.10.101",
  "mac": "44:19:b6:3a:4c:21",
  "vendor": "Hikvision",
  "model": "DS-2DE4425IW",
  "pos": [16, 0, -9],
  "role": "target",
  "switch_port": "Gi1/0/1",
  "expected_ports": [80, 554, 8000],
  "protocols": ["http", "rtsp", "onvif"],
  "firmware_version": "V5.7.16"
}
```

**设备类型映射：** `camera` / `switch` / `server` / `gateway` / `attacker` / `access` / `pc` / `sensor` / `iot`

**网络层级：** 通过 `pos` 三维坐标控制设备在 3D HUD 中的空间位置，X 轴表示网络层次深度，Z 轴表示同层设备展开。

### 通知配置（config/notifications.json）

```json
{
  "channels": {
    "webhook": { "enabled": false },
    "ntfy": { "enabled": true, "server": "https://ntfy.sh", "topic": "cyberclaw-alerts" }
  },
  "rules": [
    { "severity": ["critical", "high"], "channels": ["ntfy"] },
    { "severity": ["warning"], "channels": ["ntfy"] }
  ]
}
```

### 调度任务（config/scheduler.json）

5 个预设安全任务，支持 `interval`（间隔执行）和 `cron`（cron 表达式）两种调度模式，每个任务可独立启停和配置通知触发条件。

---

## ◈ 项目结构

```
CyberClaw/
├── server/                          # FastAPI 后端
│   ├── main.py                      # 应用入口、生命周期、WebSocket 端点
│   ├── api/                         # REST API 路由
│   │   ├── topology.py              # 拓扑查询
│   │   ├── discovery.py             # 网络设备发现
│   │   ├── security.py              # 安全事件查询
│   │   ├── scenario.py              # 攻击场景模拟
│   │   ├── chat.py                  # AI 对话（DeepSeek + MCP 工具编排）
│   │   ├── tools.py                 # MCP 工具触发
│   │   ├── dashboard.py             # Dashboard 数据聚合
│   │   ├── workflow_router.py       # 自动化工作流
│   │   ├── notification_router.py   # 通知管理
│   │   └── scheduler_router.py      # 调度任务管理
│   ├── services/                    # 业务逻辑层
│   │   ├── topology_service.py      # 拓扑管理 + Mock 模式检测
│   │   ├── discovery_service.py     # 设备发现（nmap + scapy）
│   │   ├── scan_service.py          # 周期网络扫描调度
│   │   ├── snmp_service.py          # SNMP 查询与 Trap 接收
│   │   ├── mqtt_service.py          # MQTT Broker 监控
│   │   ├── suricata_service.py      # Suricata IDS 事件监控
│   │   ├── collector_service.py     # Syslog UDP 收集器
│   │   ├── isolation_service.py     # 设备隔离（iptables/SSH/ACL）
│   │   ├── mcp_tool_service.py      # MCP 工具意图匹配与执行
│   │   ├── scenario_service.py      # 攻击场景编排引擎
│   │   ├── mock_state_service.py    # Mock 设备状态模拟器
│   │   ├── security_scheduler.py    # 安全任务调度器
│   │   ├── notification_service.py  # 通知通道管理
│   │   ├── notification_bridge.py   # 通知桥接（DB + Webhook + ntfy）
│   │   ├── tool_broadcast_service.py# 工具执行结果 WebSocket 广播
│   │   └── nx_bridge.py             # 数据库持久化桥接
│   ├── models/                      # Pydantic v2 数据模型
│   │   └── schemas.py              # 请求/响应/事件模型定义
│   ├── db/                          # SQLite 数据层
│   └── websocket/                   # WebSocket 连接管理
│       └── events.py               # 广播管理器
│
├── mcp-servers/                     # 12 个 MCP 安全工具服务器
│   ├── _template/                   # 新建 MCP 服务器模板
│   ├── nmap-scan/server.py          # 网络扫描（6 工具）
│   ├── device-config/server.py      # 设备配置管理（13 工具）
│   ├── simulation/server.py         # GNS3 仿真（32 工具）
│   ├── syslog-collector/server.py   # Syslog 采集（6 工具）
│   ├── snmp-collector/server.py     # SNMP Trap 采集（6 工具）
│   ├── cve-intel/server.py          # CVE 漏洞情报（4 工具）
│   ├── security-baseline/server.py  # 安全基线审计（4 工具）
│   ├── flow-analyzer/server.py      # NetFlow/IPFIX 分析（7 工具）
│   ├── traffic-analyzer/server.py   # 深度流量分析（4 工具）
│   ├── auto-response/server.py      # 自动响应（6 工具）
│   ├── config-audit/server.py       # 配置审计（4 工具）
│   └── attack-timeline/server.py    # 攻击时间线（4 工具）
│
├── ui/cyberclaw-hud/                # 前端界面
│   ├── index.html                   # 3D HUD 主页面
│   ├── chat/index.html              # AI 对话界面
│   ├── src/
│   │   ├── main.js                  # Three.js 3D HUD 核心（1667 行）
│   │   ├── dashboard.js             # Dashboard 面板逻辑
│   │   ├── styles.css               # HUD 全局样式
│   │   └── dashboard.css            # Dashboard 面板样式
│   ├── chat/
│   │   ├── main.js                  # 对话界面逻辑（Slash 命令 + 工具可视化）
│   │   └── style.css                # 对话界面样式
│   ├── server.js                    # Express 代理服务器
│   ├── vite.config.js               # Vite 构建配置
│   └── package.json                 # 前端依赖
│
├── src/cyberclaw_core/              # 共享 Python 库
│   ├── mcp_base.py                  # MCP 服务器工厂函数
│   ├── security_models.py           # SecurityState 枚举 + 数据模型
│   ├── gait_logger.py               # 活动日志记录
│   ├── toon/                        # TOON 序列化优化
│   └── pyproject.toml               # 包配置
│
├── config/                          # 配置文件
│   ├── topology.json                # 真实设备拓扑定义
│   ├── mock_topology.json           # Demo 模拟拓扑（19 台设备）
│   ├── openclaw.json                # MCP 服务器注册表
│   ├── vendor_oui.json              # 18 家 IoT 厂商 MAC 前缀库
│   ├── device_heuristics_rules.json # 21 条设备识别启发式规则
│   ├── scheduler.json               # 调度任务定义
│   ├── notifications.json           # 通知通道与路由规则
│   ├── workflows.json               # 自动化工作流定义
│   └── ieee-oui.txt                 # IEEE OUI 完整数据库
│
├── data/                            # 运行时数据
│   └── chat_history.json            # AI 对话历史
│
├── simulation/                      # Docker IoT 仿真环境
│   ├── docker-compose.yml           # 10 个 IoT 容器编排
│   └── start_iot_lab.sh             # 仿真环境启动脚本
│
├── lab/                             # 实验参考
│   ├── event_generator.py           # 安全事件生成器
│   └── references/                  # 外部参考资料
│
├── start.bat                        # Windows 一键启动脚本
├── .env.example                     # 环境变量模板
└── server/requirements.txt          # Python 依赖清单
```

---

## ◈ 技术栈

| 层级 | 技术 | 版本 |
|------|------|------|
| **后端框架** | FastAPI + Uvicorn | 0.110+ |
| **数据模型** | Pydantic v2 | 2.0+ |
| **MCP 框架** | FastMCP (stdio) | 1.0+ |
| **数据库** | SQLite (内置) | — |
| **网络扫描** | python-nmap + scapy | 2.5+ |
| **SNMP** | pysnmp | 5.1+ |
| **MQTT** | paho-mqtt | 2.0+ |
| **设备隔离** | netmiko (SSH) + iptables | 4.2+ |
| **HTTP 客户端** | httpx (async) | 0.27+ |
| **定时调度** | croniter | 2.0+ |
| **AI 模型** | DeepSeek (deepseek-chat) | — |
| **前端框架** | Vite + Express | 5.4 / 4.18 |
| **3D 渲染** | Three.js | r170 |
| **动画引擎** | GSAP | 3.12 |
| **图表** | ECharts | 6.0 |
| **拓扑树** | Treeviz | — |
| **实时通信** | WebSocket (ws) | 8.16 |

---

## ◈ Docker 仿真环境

可使用 Docker Compose 模拟 IoT 设备网络进行离线测试：

```bash
cd simulation
docker-compose up -d
```

启动 10 个 IoT 容器：

| 容器 | 数量 | 模拟能力 |
|------|------|----------|
| 摄像头 | 4 | HTTP 管理页面 + RTSP 模拟 |
| 传感器 | 2 | MQTT 数据上报 |
| 智能插座 | 2 | HTTP API 控制 |
| 网关 | 1 | 协议转换 + 数据聚合 |
| MQTT Broker | 1 | Mosquitto 消息代理 |
| 扫描器 | 1 | 自动化安全测试 |

---

## ◈ 开发

### 新增 MCP 服务器

```bash
# 从模板创建
cp -r mcp-servers/_template mcp-servers/my-server

# 编辑 server.py，注册工具
# 在 config/openclaw.json 中添加服务器条目
```

### 前端开发

```bash
cd ui/cyberclaw-hud
npm run dev          # 开发模式（热更新）
npm run build        # 生产构建
npm run preview      # 预览构建产物
```

### 后端开发

```bash
# 启动开发服务器（热重载）
python -m uvicorn server.main:app --reload --port 8000

# 运行测试
pytest
```

---

## ◈ 许可证

[MIT License](LICENSE)

## ◈ 作者

[@fangzheng649](https://github.com/fangzheng649)
