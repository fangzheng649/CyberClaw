# CyberClaw — IoT 全链路安全自动化平台：技术深度解析

> 日期：2025年5月
> 版本：v1.0

---

## 一、项目概述

### 1.1 CyberClaw 是什么？

CyberClaw 是一个面向 **物联网（IoT）设备** 的网络安全自动化平台。它的核心目标是解决一个现实问题：**大量 IoT 设备（摄像头、传感器、智能门锁、PLC 等）存在于网络中，但缺乏有效的安全监控和防护手段**。

CyberClaw 的设计理念可以用四个字概括：

```
感知(Sense) → 检测(Detect) → 防护(Shield) → 复盘(Review)
```

- **感知**：发现网络中有哪些设备，它们在用什么协议通信
- **检测**：找出设备的安全漏洞、配置缺陷、异常流量
- **防护**：当发现威胁时，自动隔离危险设备
- **复盘**：记录安全事件时间线，分析攻击根因

### 1.2 技术栈一览

| 层级 | 技术选型 | 说明 |
|------|---------|------|
| **后端框架** | Python 3.10+ / FastAPI | 高性能异步 Web 框架，自动生成 API 文档 |
| **MCP 服务器** | FastMCP / stdio 协议 | Model Context Protocol，AI Agent 工具调用标准 |
| **数据模型** | Pydantic v2 | 类型安全的数据验证和序列化 |
| **前端 3D 可视化** | Three.js / WebGL / GSAP | 浏览器端 3D 态势感知大屏 |
| **前端对话界面** | Vite + Express + AdminLTE | AI 安全助手对话 + 数据报表 |
| **AI 模型** | DeepSeek (deepseek-chat) | 大语言模型，用于安全分析对话 |
| **网络扫描** | nmap / scapy | 业界标准网络发现和端口扫描工具 |
| **协议采集** | pysnmp / paho-mqtt | SNMP 设备监控 + MQTT 消息监控 |
| **设备隔离** | iptables / netmiko | 防火墙规则 + SSH 交换机端口管理 |
| **仿真环境** | GNS3 REST API / Docker | 网络仿真和 IoT 设备容器模拟 |
| **数据库** | SQLite | 设备状态、安全事件持久化 |

---

## 二、系统架构深度解析

### 2.1 整体架构

```
┌──────────────────────────────────────────────────────────┐
│                    用户界面层                              │
│  ┌─────────────────────┐  ┌────────────────────────────┐ │
│  │   3D 态势感知 HUD    │  │    AI 安全助手 Chat        │ │
│  │   Three.js + WebGL  │  │    DeepSeek + MCP Tools    │ │
│  └─────────┬───────────┘  └────────────┬───────────────┘ │
│            │  WebSocket + REST API       │                 │
├────────────┼────────────────────────────┼─────────────────┤
│            ▼                            ▼                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              FastAPI 后端 (:8000)                     │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │  │
│  │  │Topology  │ │Discovery │ │Security  │ │ Chat   │ │  │
│  │  │API       │ │API       │ │API       │ │ API    │ │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │  │
│  │  │Tools API │ │Dashboard │ │Workflow  │ │Notif.  │ │  │
│  │  │          │ │API       │ │API       │ │ API    │ │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │  │
│  ├─────────────────────────────────────────────────────┤  │
│  │                   服务层                              │  │
│  │  Discovery │ SNMP │ MQTT │ Isolation │ ConfigFetcher│  │
│  │  ScanScheduler │ SuricataIDS │ Collector │ NXBridge │  │
│  ├─────────────────────────────────────────────────────┤  │
│  │              MCP 工具调度层                           │  │
│  │         mcp_tool_service (意图识别 → 工具调用)        │  │
│  ├─────────────────────────────────────────────────────┤  │
│  │           12 个 MCP 安全工具服务器                    │  │
│  │  ┌───────────────────────┐ ┌───────────────────────┐ │  │
│  │  │  感知层 (Sense)       │ │  检测层 (Detect)      │ │  │
│  │  │  nmap-scan            │ │  cve-intel            │ │  │
│  │  │  syslog-collector     │ │  security-baseline    │ │  │
│  │  │  snmp-collector       │ │  traffic-analyzer     │ │  │
│  │  │  flow-analyzer        │ │                       │ │  │
│  │  │  device-config        │ │                       │ │  │
│  │  │  simulation           │ │                       │ │  │
│  │  └───────────────────────┘ └───────────────────────┘ │  │
│  │  ┌───────────────────────┐ ┌───────────────────────┐ │  │
│  │  │  防护层 (Shield)      │ │  复盘层 (Review)      │ │  │
│  │  │  auto-response        │ │  attack-timeline      │ │  │
│  │  │  config-audit         │ │  simulation(快照回放) │ │  │
│  │  └───────────────────────┘ └───────────────────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
│                          │                                 │
│                   SQLite 数据库                            │
│              (设备状态 + 安全事件 + 时间线)                 │
└──────────────────────────────────────────────────────────┘
```

### 2.2 数据流：一次完整的安全事件处理

以"发现一台摄像头存在漏洞"为例，展示完整数据流：

```
1. 用户在 Chat 中输入："扫描网络中的设备"
       │
       ▼
2. mcp_tool_service 识别意图 → 调用 nmap-scan/network_scan
       │
       ▼
3. nmap-scan 执行扫描 → 发现 15 台设备，返回端口/厂商信息
       │
       ▼
4. tool_broadcast_service 自动链式调用 cve-intel/check_device_vulns
       │
       ▼
5. cve-intel 查询 NIST NVD → 发现 CVE-2021-36260（海康 RCE，CVSS 9.8）
       │
       ▼
6. WebSocket 广播安全事件到前端 → 3D HUD 设备变色（绿→橙）
       │
       ▼
7. 用户点击"隔离设备" → auto-response 执行 iptables DROP 规则
       │
       ▼
8. attack-timeline 记录完整事件链 → 生成事后报告
```

---

## 三、核心技术模块详解

### 3.1 MCP（Model Context Protocol）架构

#### 3.1.1 什么是 MCP？

**MCP（Model Context Protocol）** 是 Anthropic 公司提出的一种标准化协议，用于 AI 模型与外部工具之间的通信。你可以把它理解为 **AI 的"USB 接口"**——就像 USB 让任何设备都能连接电脑一样，MCP 让任何工具都能被 AI Agent 调用。

在 CyberClaw 中，MCP 的角色是：

```
用户提问 → AI 大模型(DeepSeek) → 理解意图 → 选择合适的 MCP 工具 → 执行 → 返回结果 → AI 分析结果
```

#### 3.1.2 CyberClaw 的 12 个 MCP 服务器

| 服务器 | 所属层级 | 工具数 | 协议 | 实现状态 |
|--------|---------|--------|------|---------|
| **nmap-scan** | 感知 | 6 | TCP 端口扫描 | 混合（真实 nmap + Mock 回退） |
| **syslog-collector** | 感知 | 6 | Syslog UDP/TCP | 真实（UDP 接收器） |
| **snmp-collector** | 感知 | 6 | SNMP Trap UDP | 真实（UDP 接收器） |
| **flow-analyzer** | 感知 | 7 | IPFIX/NetFlow UDP | 真实（UDP 接收器） |
| **device-config** | 感知 | 10 | gNMI/gRPC+TLS | 真实（需设备） |
| **simulation** | 感知 | 19 | GNS3 REST API | 真实（需 GNS3） |
| **cve-intel** | 检测 | 4 | NIST NVD HTTPS | 混合（真实 API + 7条 IoT CVE） |
| **security-baseline** | 检测 | 4 | TCP Socket 探测 | 真实（端口检查） |
| **traffic-analyzer** | 检测 | 4 | tshark/scapy 抓包 | 混合（tshark + 回退） |
| **auto-response** | 防护 | 6 | SSH/iptables | 真实（需交换机） |
| **config-audit** | 防护 | 4 | SSH/SNMP | 真实（需设备） |
| **attack-timeline** | 复盘 | 4 | SQLite 本地存储 | 真实 |

**总计：72 个 MCP 工具**

#### 3.1.3 MCP 工具如何被调用？

CyberClaw 采用 **意图匹配 + 动态加载** 的方式：

```python
# 用户输入 → 正则匹配意图 → 选择 MCP 工具 → 动态调用
# mcp_tool_service.py 核心逻辑

INTENTS = {
    r"扫描|scan|发现":    ("nmap-scan", "network_scan"),
    r"漏洞|cve|vuln":     ("cve-intel", "check_device_vulns"),
    r"基线|baseline|合规": ("security-baseline", "check_baseline"),
    r"隔离|isolate":      ("auto-response", "isolate_device"),
    r"流量|traffic|抓包":  ("traffic-analyzer", "start_capture"),
    r"审计|audit|配置":    ("config-audit", "audit_config"),
    r"时间线|timeline":    ("attack-timeline", "get_timeline"),
}
```

工具执行结果通过 **tool_broadcast_service** 自动广播到所有 WebSocket 连接的前端客户端，实现实时更新。

#### 3.1.4 共享基础设施模式

CyberClaw 的 MCP 服务器遵循三种共享设计模式：

**（1）MessageStore 模式**（用于 syslog、snmp、flow-analyzer）

```
UDP 接收 → 解析协议 → 去重（5秒窗口）→ 内存存储（24h 保留）→ 查询 API
```

**（2）RateLimiter 模式**（令牌桶限流）

```
令牌桶算法：容量=1000/秒，突发=5倍，防止数据洪泛
```

**（3）GAITLogger 模式**（审计日志）

```json
{"gait": true, "operation": "isolate_device", "target": "10.0.0.11", "status": "success"}
```

---

### 3.2 设备发现与识别

#### 3.2.1 三层发现机制

CyberClaw 采用 **三优先级回退策略** 发现网络设备：

```
第一层：nmap ping sweep（最准确，需安装 nmap）
   │ 失败/不可用
   ▼
第二层：scapy ARP 扫描（纯 Python，无需外部工具）
   │ 失败/不可用
   ▼
第三层：静态配置 fallback（读取 topology.json）
```

#### 3.2.2 三层设备识别

发现设备后，通过三层策略识别设备类型和厂商：

```
第一层：MAC OUI 厂商查询
  → 内置 18 家 IoT 厂商 MAC 前缀库
  → 海康(44:19:B6)、大华(3C:8C:40:...)、西门子(00:1C:25)、华为等

第二层：主机名正则匹配
  → "camera"/"cam" → 摄像头
  → "sensor"/"temp" → 传感器
  → "plc"/"s7" → PLC 控制器

第三层：开放端口特征检测
  → 554(RTSP) + 80(HTTP) → 摄像头
  → 102(S7comm) → 西门子 PLC
  → 1883(MQTT) → IoT 网关
  → 502(Modbus) → 工控设备
```

#### 3.2.3 IoT 指纹识别（nmap-scan 服务器）

```
MAC OUI 匹配 + 端口启发式 → 设备类型判定
├── 海康(Hikvision)：端口 80+554+8000 → camera
├── 大华(Dahua)：端口 80+554+37777 → camera
├── 西门子(Siemens)：端口 102 → plc
├── 西门子传感器：端口 443+4840 → sensor (OPC-UA)
├── TP-Link：端口 80+9999 → plug (智能插座)
├── 涂鸦(Tuya)：端口 80+6668 → lock (智能门锁)
└── 树莓派：端口 1883 → server (MQTT Broker)
```

#### 3.2.4 定期扫描调度

```python
# scan_service.py — 自动定期扫描
SCAN_SUBNET=192.168.1.0/24  # 环境变量配置
SCAN_INTERVAL=300            # 每 5 分钟扫描一次

# 启动后自动循环：
arp-scan → 失败 → nmap -sn → 解析结果 → 更新设备数据库
```

---

### 3.3 拓扑构建

#### 3.3.1 当前实现：预设拓扑

CyberClaw **当前采用静态预设拓扑**，定义在 `config/topology.json` 中：

```json
{
  "network": {"name": "Smart Building Lab", "subnet": "192.168.10.0/24"},
  "devices": [/* 15 台设备 */],
  "links": [/* 14 条连接 */]
}
```

预设拓扑包含 **15 台设备**，模拟一个智能建筑实验室场景：

| 设备类型 | 数量 | 示例 | 厂商 |
|---------|------|------|------|
| 核心交换机 | 1 | CoreSwitch-H3C | H3C |
| 防火墙 | 1 | USG-Firewall | 华为 |
| IoT 网关 | 1 | IoT-Gateway | 研华 |
| 摄像头 | 3 | Camera-Entrance/Lobby/ServerRoom | 海康/大华 |
| 传感器 | 2 | TempSensor/SmokeDetector | 西门子/霍尼韦尔 |
| 门禁 | 1 | AccessCtrl-Front | 海康 |
| 智能门锁 | 1 | SmartLock-B201 | 涂鸦 |
| PLC | 1 | PLC-Packaging | 西门子 |
| 智能插座 | 2 | SmartPlug-AC/Light | TP-Link |
| MQTT Broker | 1 | MQTT-Broker | 树莓派 |
| 管理主机 | 1 | CyberClaw-Console | 联想 |

#### 3.3.2 拓扑数据流

```
topology.json ──启动──→ FastAPI 内存加载
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
     3D HUD 渲染    API 查询     Scenario 驱动
     (Three.js)   (/api/topology) (攻击模拟)
           │             │             │
           └──── WebSocket 实时同步 ───┘
```

#### 3.3.3 动态拓扑发现能力（已有但未完全启用）

系统已内置 SNMP 拓扑发现能力：

```python
# snmp_service.py — discover_topology()
# 通过 SNMP ARP 表 + Bridge MIB 遍历自动发现拓扑关系
# GET /api/tools/snmp/discover-topology
{
    "switch_ip": "192.168.10.1",
    "community": "public",
    "version": "2c"
}
```

同时，nmap 扫描结果也会动态更新设备数据库：

```python
# tool_broadcast_service.py — _handle_network_scan()
# 扫描发现新设备后自动 upsert 到数据库
await bridge.upsert_device(device_id, {
    "devLastIP": ip,
    "devVendor": vendor,
    "devOpenPorts": ports,
    "devOsGuess": os_guess,
}, source="NMAP")
```

---

### 3.4 安全状态机（FSM）

#### 3.4.1 五状态模型

每台设备维护一个独立的安全状态，遵循以下状态机：

```
                    扫描发现
  ┌────────┐ ──────────────→ ┌──────────┐
  │ secure │                 │ scanning │
  │ (安全)  │                 │ (扫描中)  │
  └────────┘                 └──────────┘
       ↑                          │
       │                    发现漏洞 │
       │                          ▼
       │                    ┌───────────┐
       │                    │vulnerable │
       │ restore            │ (有漏洞)   │
       │ (恢复)              └───────────┘
       │                          │
       │                    检测攻击 │
       │                          ▼
       │                    ┌──────────┐
       └────────────────── │ attacked │
                            │ (被攻击)  │
                            └──────────┘
                                 │
                           执行隔离 │
                                 ▼
                            ┌──────────┐
                            │ isolated │
                            │ (已隔离)  │
                            └──────────┘
```

#### 3.4.2 状态映射与可视化

| 状态 | 颜色 | 含义 | 触发条件 |
|------|------|------|---------|
| `secure` | 绿色 `#00ff88` | 设备安全 | 初始状态 / restore 恢复 |
| `scanning` | 蓝色 `#00bbff` | 正在被扫描 | nmap 扫描启动 |
| `vulnerable` | 橙色 `#ffaa00` | 发现漏洞 | CVE 匹配 / 基线不合规 |
| `attacked` | 红色 `#ff2244` | 正在被攻击 | Suricata 告警 / 异常流量 |
| `isolated` | 灰色 `#5a6e88` | 已被隔离 | auto-response 执行隔离 |

前端 3D HUD 使用 **GSAP 动画引擎** 实现设备颜色的平滑过渡效果。

---

### 3.5 多协议数据采集

CyberClaw 支持四种网络协议的实时数据采集：

| 协议 | 端口 | 能力 | 实现 |
|------|------|------|------|
| **Syslog** | UDP 8514 | RFC 3164/5424 日志接收与解析 | 真实 UDP 接收器 |
| **SNMP** | UDP 1162 | v1/v2c/v3 Trap 接收 + 设备信息查询 | 真实 pysnmp v7 |
| **MQTT** | TCP 1883 | Broker 连接、主题订阅、异常发布率检测 | 真实 paho-mqtt |
| **IPFIX/NetFlow** | UDP 2055 | v5/v9/v10 流量记录分析 | 真实 UDP 解析器 |

所有采集器共享相同的设计模式：

```
                    ┌─── 去重窗口(5秒) ──┐
UDP 接收 → 协议解析 → 内存存储(24h) → 查询 API → WebSocket 广播
                    ├─── 令牌桶限流 ─────┤
                    └─── GAIT 审计日志 ──┘
```

---

### 3.6 AI 安全助手集成

#### 3.6.1 对话架构

```
用户提问
    │
    ▼
意图匹配 (mcp_tool_service.match_intent)
    │
    ├─→ 匹配成功 → 执行 MCP 工具 → 获取真实数据
    │                                    │
    └─→ 匹配失败 → 直接传递给 AI         │
                                         ▼
                              工具结果 + 上下文 → DeepSeek API
                                         │
                                         ▼
                                   AI 分析回复（含 Markdown）
```

#### 3.6.2 上下文构建

每次对话时，系统自动构建包含当前环境状态的 System Prompt：

```
当前环境：IoT 实验网络包含 15 台设备（camera×3、sensor×2、switch×1...）。
当前安全状态：secure×12、vulnerable×2、attacked×1。
最近 24 小时安全事件数：7。
```

#### 3.6.3 无 API Key 时的回退

当 DeepSeek API 不可用时，系统仍能工作——直接格式化工具结果为可读文本返回给用户，确保功能不中断。

---

### 3.7 前端 3D 态势感知

#### 3.7.1 技术实现

- **Three.js + WebGL**：浏览器端 3D 渲染，无需安装任何插件
- **后处理管线**：Bloom（辉光）+ Vignette（暗角）+ Glitch（故障效果）= 赛博朋克风格
- **GSAP 动画**：设备状态变化时的颜色平滑过渡
- **CSS2DRenderer**：在 3D 场景上叠加设备名称标签
- **OrbitControls**：鼠标拖拽旋转、缩放 3D 场景
- **Raycaster**：鼠标悬停/点击设备时的交互检测

#### 3.7.2 设备 3D 表示

不同类型设备使用不同几何体：

| 设备类型 | 3D 几何体 | 特征 |
|---------|----------|------|
| 交换机/防火墙 | 八面体(Octahedron) | 多面体代表核心设备 |
| 摄像头 | 球体(Sphere) | 代表监控视角 |
| 传感器 | 菱形(Dodecahedron) | 小型设备 |
| PLC | 立方体(Box) | 代表工控设备 |
| 网关 | 圆锥(Cone) | 代表连接枢纽 |

每个设备带有 **线框叠加** + **发光光晕** 效果，设备之间用半透明线条连接。

#### 3.7.3 实时交互效果

- **扫描波纹**：nmap 扫描时，设备发出蓝色扩散波
- **攻击光束**：检测到攻击时，红色光束连接攻击者和目标
- **防护盾牌**：设备被隔离时，灰色盾牌动画覆盖
- **设备详情面板**：点击设备展示端口、CVE、基线审计结果

---

### 3.8 场景模拟引擎

CyberClaw 内置了 Mirai 僵尸网攻击模拟场景：

```
Step 1: 扫描阶段 — nmap 扫描发现设备
Step 2: 漏洞利用 — 利用默认密码入侵摄像头
Step 3: 横向传播 — 通过 Telnet 感染其他设备
Step 4: C2 建立 — 建立 IRC 命令控制通道
Step 5: DDoS 攻击 — 被控设备发起拒绝服务攻击
```

每个步骤自动更新设备 FSM 状态，3D HUD 实时展示攻击过程。

---

## 四、优势分析

### 4.1 架构设计优势

| 优势 | 说明 |
|------|------|
| **全链路覆盖** | 从设备发现到事后复盘，覆盖完整安全生命周期，而非单一功能点 |
| **MCP 解耦架构** | 12 个 MCP 服务器完全独立，可单独开发、测试、部署，遵循"高内聚低耦合"原则 |
| **AI 原生设计** | 不是"安全工具 + AI 外壳"，而是从底层就以 MCP 工具调用的方式与 AI 模型集成 |
| **真实协议支持** | 4 种网络协议（Syslog/SNMP/MQTT/IPFIX）的真实接收器实现，不是简单的模拟 |
| **回退容错** | 每个模块都有回退机制：nmap→scapy→static，MCP→直接服务调用，DeepSeek→格式化回退 |

### 4.2 技术实现优势

| 优势 | 说明 |
|------|------|
| **三层设备识别** | MAC OUI → 主机名 → 端口特征，比单一识别方式更准确 |
| **多厂商覆盖** | 内置海康、大华、西门子、华为、霍尼韦尔、TP-Link 等 18 家 IoT 厂商指纹 |
| **4 种审计 Profile** | 针对 IoT、网络设备、摄像头、关键基础设施的不同安全基线 |
| **IoT 专项 CVE 库** | 内置 7 条高危 IoT CVE（CVSS 7.5-9.8），且支持在线查询 NIST NVD |
| **实时可视化** | Three.js 3D 态势大屏 + GSAP 状态动画 + WebSocket 实时推送 |
| **双模式运行** | Demo 模式（预设攻击脚本）和 Live 模式（实时安全事件驱动） |
| **多隔离方式** | iptables（软件防火墙）、SSH 交换机（硬件管理）、记录模式（无硬件时） |

### 4.3 工程质量优势

| 优势 | 说明 |
|------|------|
| **类型安全** | 全面使用 Pydantic v2 数据模型，API 请求/响应有完整的类型定义 |
| **自动 API 文档** | FastAPI 自动生成 Swagger 文档（/docs），方便测试和调试 |
| **共享基础设施** | MessageStore、RateLimiter、GAITLogger 三种模式在多个服务器间复用 |
| **动态工具加载** | MCP 工具服务动态加载服务器模块，无需硬编码依赖 |

---

## 五、劣势与不足分析

### 5.1 架构层面不足

| 不足 | 严重程度 | 说明 |
|------|---------|------|
| **拓扑静态预设** | 高 | 当前拓扑完全依赖 topology.json 手动定义，不具备自动拓扑发现和构建能力。虽然有 SNMP 拓扑发现接口，但未集成到主流程 |
| **MCP 未走 stdio 协议** | 中 | MCP 服务器定义了标准 stdio 传输协议，但实际调用是通过 Python 直接 import 模块，而非启动独立进程通过 stdio 通信。这失去了 MCP 的进程隔离优势 |
| **单机部署** | 中 | 所有服务运行在单台机器上，无分布式支持。SQLite 数据库不适合高并发场景 |
| **无认证/授权** | 中 | API 完全开放（CORS `allow_origins=["*"]`），无用户登录、Token、权限控制 |

### 5.2 功能层面不足

| 不足 | 严重程度 | 说明 |
|------|---------|------|
| **无真正设备接入** | 高 | 系统设计面向真实 IoT 设备，但当前演示完全基于预设数据。需要真实硬件才能展示完整能力 |
| **AI 依赖外部 API** | 中 | DeepSeek 通过云端 API 调用，离线环境无法使用。虽然有回退机制，但 AI 分析能力会降级 |
| **无持久化规则引擎** | 中 | 工作流定义在 JSON 文件中，无数据库持久化，不支持复杂条件判断和状态机 |
| **告警通知有限** | 低 | 支持 Webhook 和 ntfy 两种通知方式，缺少邮件、短信、钉钉/企微集成 |

### 5.3 工程层面不足

| 不足 | 严重程度 | 说明 |
|------|---------|------|
| **无单元测试** | 高 | 整个项目没有自动化测试套件，功能正确性依赖手动验证 |
| **Mock 数据分散** | 中 | Mock 数据分散在各个 MCP 服务器中，缺少统一的 Mock 管理和切换机制 |
| **日志不统一** | 低 | 使用 Python logging 但无结构化日志，不利于生产环境排查问题 |
| **配置硬编码** | 低 | 部分配置（如默认端口 8514、1162）硬编码在代码中而非统一配置 |

### 5.4 研究层面不足（对学术答辩/论文而言）

| 不足 | 说明 |
|------|------|
| **缺少对比实验** | 未与现有方案（如 SecurityOnion、Wazuh、OpenSCAP）进行性能或功能对比 |
| **缺少性能评估** | 无延迟、吞吐量、资源占用等量化指标 |
| **缺少威胁模型** | 未明确定义系统防御的威胁类型和攻击者模型 |
| **IoC 检测规则简单** | 流量分析中的 IoC 检测仅基于端口和简单模式匹配，缺少机器学习方法 |

---

## 六、总结

### 6.1 CyberClaw 的核心价值

CyberClaw 的核心创新在于 **将 AI Agent 与 IoT 安全工具链深度融合**：

1. **MCP 工具标准化**：72 个安全工具通过统一协议暴露给 AI，实现了"自然语言 → 安全操作"的自动化
2. **全链路自动化**：从发现到复盘的完整闭环，而非孤立的安全工具集合
3. **IoT 专项优化**：针对摄像头、PLC、传感器等 IoT 设备的指纹识别和漏洞检测

### 6.2 当前最大短板与改进路径

| 短板 | 改进路径 | 所需资源 |
|------|---------|---------|
| 无真实设备验证 | 接入 2-3 台真实 IoT 设备 | ¥1000-2500 硬件 |
| 拓扑静态预设 | 集成 SNMP 自动拓扑发现 | 可管理交换机 |
| 无量化评估 | 与 Wazuh/SecurityOnion 对比实验 | 时间 |
| MCP 未走 stdio | 改为独立进程 + stdio 通信 | 2-3 周开发 |
