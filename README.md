# CyberClaw — IoT 全链路安全自动化平台

> Sense → Detect → Shield → Review

CyberClaw 是一个面向 IoT 设备的网络安全自动化平台，覆盖 **设备发现 → 漏洞检测 → 威胁响应 → 事后复盘** 全流程。支持真实设备接入和 Docker 仿真环境，通过 12 个 MCP 安全工具服务器提供可扩展的安全能力。

## 架构概览

```
┌─────────────────────────────────────────────────────┐
│                    CyberClaw HUD                     │
│          Three.js 3D 态势可视化 + AI 对话界面           │
└──────────────────────┬──────────────────────────────┘
                       │ WebSocket + REST API
┌──────────────────────▼──────────────────────────────┐
│               FastAPI Backend (:8000)                │
│  Topology │ Discovery │ Scenario │ Chat │ Tools API  │
├──────────────────────────────────────────────────────┤
│                    服务层                              │
│  Discovery │ SNMP │ MQTT │ Isolation │ ConfigFetcher │
├──────────────────────────────────────────────────────┤
│               12 MCP 安全工具服务器                    │
│  nmap-scan │ cve-intel │ auto-response │ config-audit │
│  syslog-collector │ snmp-collector │ flow-analyzer    │
│  security-baseline │ traffic-analyzer │ attack-timeline│
│  device-config │ simulation                          │
└──────────────────────────────────────────────────────┘
```

## 核心功能

### 设备发现与识别

- **多方式扫描**：nmap ping sweep + scapy ARP scan + 静态配置 fallback
- **三层设备识别**：MAC OUI 厂商查询 → 主机名正则匹配 → 开放端口特征检测
- **厂商覆盖**：内置 18 家 IoT 厂商 MAC 前缀库（海康、大华、西门子、华为等）

### 多协议数据采集

| 协议 | 能力 | 端口 |
|------|------|------|
| Syslog | RFC 3164/5424 日志接收与解析 | UDP 8514 |
| SNMP | 设备信息查询 (pysnmp v7) + Trap 接收 | UDP 1162 |
| MQTT | Broker 连接、主题订阅、异常发布率检测 | TCP 1883 |
| IPFIX/NetFlow | v5/v9/v10 流量记录分析 | UDP 2055 |

### 安全检测

- **端口扫描**：nmap 多种扫描模式（connect/syn/udp/fin）
- **IoT 指纹识别**：MAC + 端口启发式设备类型判定
- **CVE 漏洞查询**：对接 NIST NVD API，内置 7 条 IoT 专项 CVE
- **安全基线审计**：4 种审计 profile（iot-default / network-device / camera-specific / critical-infra）
- **默认密码检测**：自动检测 Telnet/SSH/HTTP 默认凭据

### 自动响应

- **iptables 隔离**：Linux/WSL 环境 DROP 规则（默认方式，无需硬件）
- **SSH 交换机隔离**：通过 netmiko 管理华为/Cisco/H3C 交换机端口
- **ACL 封堵**：IP 黑名单管理
- **记录降级**：无可用隔离方式时记录操作日志

### 配置审计

- SSH 获取设备配置（`display current-configuration` / `show running-config`）
- 自动检测：明文密码、Telnet 启用、HTTP 管理、默认 SNMP community
- ACL 规则冲突检测与影子规则发现

### 攻击复盘

- 安全事件时间线自动构建
- 根因分析与攻击链还原
- 事后报告生成

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3.10+ / FastAPI / Pydantic 2 |
| MCP 服务器 | FastMCP / stdio 协议 |
| 前端 HUD | Three.js / WebGL / GSAP / Vite |
| AI 对话 | 智谱 GLM-4-flash |
| 仿真环境 | Docker / GNS3 REST API |
| 安全工具 | nmap / scapy / pysnmp / paho-mqtt / netmiko |

## 项目结构

```
CyberClaw/
├── server/                    # FastAPI 后端
│   ├── api/                   # REST + WebSocket 端点
│   │   ├── topology.py        # 拓扑查询
│   │   ├── discovery.py       # 网络设备发现
│   │   ├── security.py        # 安全事件查询
│   │   ├── scenario.py        # 攻击场景模拟
│   │   ├── chat.py            # AI 对话
│   │   └── tools.py           # MCP 工具触发
│   ├── services/              # 业务服务
│   │   ├── discovery_service.py   # 设备发现（nmap/scapy）
│   │   ├── snmp_service.py        # SNMP 查询与 Trap
│   │   ├── mqtt_service.py        # MQTT 监控
│   │   ├── isolation_service.py   # 设备隔离（iptables/SSH）
│   │   ├── config_fetcher.py      # 设备配置获取
│   │   ├── collector_service.py   # Syslog 收集
│   │   └── tool_broadcast_service.py  # MCP 工具调度
│   ├── models/                # Pydantic 数据模型
│   └── websocket/             # WebSocket 连接管理
├── mcp-servers/               # 12 个 MCP 安全工具服务器
│   ├── nmap-scan/             # 网络扫描与 IoT 指纹识别（6 个工具）
│   ├── device-config/         # gNMI 设备配置管理（13 个工具）
│   ├── simulation/            # GNS3 仿真管理（32 个工具）
│   ├── syslog-collector/      # Syslog 采集（6 个工具）
│   ├── snmp-collector/        # SNMP Trap 采集（6 个工具）
│   ├── cve-intel/             # CVE 漏洞情报（4 个工具）
│   ├── security-baseline/     # CIS 安全基线审计（4 个工具）
│   ├── flow-analyzer/         # NetFlow/IPFIX 分析（7 个工具）
│   ├── traffic-analyzer/      # 深度流量分析（4 个工具）
│   ├── auto-response/         # 自动响应（6 个工具）
│   ├── config-audit/          # 配置审计（4 个工具）
│   └── attack-timeline/       # 攻击时间线（4 个工具）
├── ui/cyberclaw-hud/          # 前端
│   ├── src/main.js            # 3D HUD（Three.js + 后处理管线）
│   ├── src/styles.css         # 赛博朋克风格 UI
│   ├── chat/                  # AI 对话界面
│   └── server.js              # Express 代理服务器
├── src/cyberclaw_core/        # 共享库
│   └── mcp_base.py            # MCP 服务器创建工具
├── config/
│   ├── topology.json          # 设备拓扑定义
│   └── vendor_oui.json        # IoT 厂商 MAC 前缀库
├── simulation/                # Docker IoT 实验环境
└── scripts/                   # 安装与启动脚本
```

## 快速开始

### 环境要求

- Python 3.10+
- Node.js 18+
- Windows 10/11 或 Linux

### 安装

```bash
# 1. 克隆仓库
git clone https://github.com/fangzheng649/CyberClaw.git
cd CyberClaw

# 2. 安装 Python 依赖
pip install -r server/requirements.txt
cd src/cyberclaw_core && pip install -e . && cd ../..

# 3. 安装前端依赖
cd ui/cyberclaw-hud && npm install && cd ../..

# 4. 配置环境变量
cp .env.example .env
# 编辑 .env 填入 GLM_API_KEY 等配置
```

### 启动

需要两个终端窗口：

```bash
# 终端 1：启动后端
python -m uvicorn server.main:app --reload --port 8000

# 终端 2：启动前端
cd ui/cyberclaw-hud && npm run dev
```

- **HUD 界面**：http://localhost:3001
- **API 文档**：http://localhost:8000/docs
- **WebSocket**：ws://localhost:8000/ws

### 可选：安装 nmap

安装 nmap 后设备发现和端口扫描能力大幅增强：

```bash
# Windows
winget install Insecure.Nmap --source winget

# Linux
sudo apt install nmap
```

## API 一览

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/topology` | GET | 获取网络拓扑 |
| `/api/discovery/scan` | POST | 触发网络设备发现 |
| `/api/discovery/status` | GET | 获取最近发现结果 |
| `/api/discovery/register` | POST | 手动注册设备 |
| `/api/tools/scan` | POST | 触发 nmap 扫描 |
| `/api/tools/cve-check` | POST | CVE 漏洞查询 |
| `/api/tools/baseline` | POST | 安全基线审计 |
| `/api/tools/isolate` | POST | 隔离设备 |
| `/api/tools/restore` | POST | 恢复设备 |
| `/api/tools/snmp/start` | POST | 启动 SNMP Trap 接收 |
| `/api/tools/snmp/query` | POST | SNMP 查询设备信息 |
| `/api/tools/mqtt/connect` | POST | 连接 MQTT Broker |
| `/api/tools/collector/start` | POST | 启动 Syslog 收集器 |
| `/api/chat` | POST | AI 安全对话 |
| `/api/scenario/{id}/start` | POST | 启动攻击场景模拟 |

## 设备拓扑配置

设备定义在 `config/topology.json`，支持以下字段：

```json
{
  "id": "camera_hk_1",
  "name": "Camera-HK-1",
  "type": "camera",
  "ip": "10.0.0.11",
  "mac": "AA:BB:CC:01:01:01",
  "vendor": "Hikvision",
  "model": "DS-2CD2142",
  "pos": [-8, 0, 10],
  "switch_port": "Gi0/1",
  "expected_ports": [23, 80, 554, 8000],
  "protocols": ["http", "rtsp", "onvif"]
}
```

## 隔离方式配置

通过 `.env` 环境变量控制：

```bash
# 隔离方式: iptables（默认）/ ssh_switch / record_only
ISOLATION_METHOD=iptables

# SSH 交换机配置（仅 ssh_switch 模式）
SWITCH_TYPE=huawei          # huawei / cisco_ios / hp_comware
SWITCH_IP=10.0.0.1
SWITCH_SSH_USER=admin
SWITCH_SSH_PASS=
```

## Docker 仿真环境

可使用 Docker 模拟 IoT 设备进行测试：

```bash
cd simulation
docker-compose up -d
```

会启动 10 个 IoT 容器：4 个摄像头、2 个传感器、2 个智能插座、1 个网关、1 个 MQTT Broker、1 个扫描器。

## 安全状态 FSM

设备安全状态遵循 5 状态有限状态机：

```
secure → scanning → vulnerable → attacked → isolated
   ↑                                              │
   └────────────── restore ───────────────────────┘
```

| 状态 | 颜色 | 含义 |
|------|------|------|
| secure | 绿色 | 设备安全 |
| scanning | 蓝色 | 正在被扫描 |
| vulnerable | 橙色 | 发现漏洞 |
| attacked | 红色 | 正在被攻击 |
| isolated | 灰色 | 已被隔离 |

## 致谢

- 基于 [OpenClaw](https://github.com/sunnyhuangcy/openclaw) 框架构建
- 设备识别参考 [NetAlertX](https://github.com/jcwilde/netalertx) 多层匹配模式
- 参考了 [UniversalScanner](https://github.com/jcwilde/UniversalScanner) 和 [lan-control](https://github.com/alexryaskin/lan-control) 的设计思路

## 许可证

MIT License

## 团队

- [@fangzheng649](https://github.com/fangzheng649)
