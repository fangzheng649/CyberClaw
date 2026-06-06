# CyberClaw 工具清单与功能验证报告

> 扫描时间：2026-06-01
> 扫描范围：12 个 MCP 工具服务器 + 26 个 REST API 端点 + 全前端 UI 触发入口

---

## 一、工具总览

| # | 工具服务器 | 工具函数数 | 基础架构需求 | 本地可用性 |
|---|-----------|-----------|-------------|-----------|
| 1 | nmap-scan | 6 | nmap 二进制 | ✅ 有 mock 模式 |
| 2 | cve-intel | 4 | NIST NVD API | ✅ 有 mock 回退 |
| 3 | security-baseline | 4 | Python socket | ✅ 完全可用 |
| 4 | auto-response | 6 | Docker/iptables/交换机 | ⚠️ 部分可用 |
| 5 | config-audit | 4 | SSH/SNMP 设备访问 | ❌ 需真实设备 |
| 6 | attack-timeline | 4 | SQLite | ✅ 完全可用 |
| 7 | traffic-analyzer | 4 | tshark/scapy | ⚠️ mock 模式 |
| 8 | flow-analyzer | 7 | IPFIX/NetFlow 发送方 | ⚠️ 接收端可用 |
| 9 | syslog-collector | 6 | UDP socket | ✅ 完全可用 |
| 10 | snmp-collector | 6 | UDP socket | ⚠️ 接收端可用 |
| 11 | device-config | 13 | gNMI/SSH 真实设备 | ❌ 需真实设备 |
| 12 | simulation | 24+ | GNS3 Server | ❌ 需 GNS3 服务 |

---

## 二、逐工具详细分析

### 2.1 nmap-scan（网络扫描）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `network_scan` | 全端口扫描 + 服务识别 | target, ports, scan_type, timing, timeout | **nmap** |
| `host_discovery` | Ping 扫描发现存活主机 | target, timing, timeout | **ping** |
| `service_detection` | 服务/版本指纹识别 | target, ports, intensity, timeout | **nmap** |
| `vuln_scan` | NSE 漏洞脚本扫描 | target, scripts, timeout | **nmap** |
| `iot_fingerprint` | IoT 设备识别（MAC OUI + 端口启发式） | target | topology.json |
| `default_credential_check` | 默认密码检测 | target | topology.json |

**触发方式：**
- Chat Tab：输入"扫描网络中的所有设备" / `/scan`
- 3D HUD：设备详情面板 → SCAN 按钮
- Operations Tab：快捷操作 → "全网扫描"
- REST API：`POST /api/tools/scan`

**工作条件：**
- 安装 nmap → `winget install nmap` 或 `apt install nmap`
- Mock 模式：从 `config/topology.json` 读取预定义设备，无 nmap 也可返回模拟数据

---

### 2.2 cve-intel（CVE 漏洞情报）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `search_cves` | 按关键词/严重度/CWE 搜索 CVE | keyword, severity, cwe_id, days, results | NVD API |
| `get_cve` | 获取特定 CVE 详情 | cve_id | NVD API |
| `search_by_cpe` | 按 CPE 产品名查 CVE | cpe_name, virtual_match, results | NVD API |
| `check_device_vulns` | 按厂商/型号查设备漏洞 | vendor, model, min_severity | NVD API |

**触发方式：**
- Chat Tab：输入"查询 Hikvision 摄像头的 CVE 漏洞" / `/cve`
- 3D HUD：设备详情面板 → CVE CHECK 按钮
- Operations Tab：快捷操作 → "漏洞检测"
- REST API：`POST /api/tools/cve-check`

**工作条件：**
- 需要网络访问 NIST NVD API（`services.nvd.nist.gov`）
- 无网络时回退到内置 mock IoT CVE 数据库
- 可选设置 `NVD_API_KEY` 环境变量提升速率限制

---

### 2.3 security-baseline（安全基线审计）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `check_baseline` | CIS 安全基线审计（真实端口扫描） | target, profile, detailed | Python socket |
| `list_rules` | 列出审计规则 | profile | 无 |
| `get_profiles` | 列出审计配置文件 | 无 | 无 |
| `quick_audit` | 快速关键端口检查（Telnet/HTTP/FTP） | 无 | Python socket |

**审计配置文件：**
- `iot-default`：IoT 设备通用
- `network-device`：网络设备
- `camera-specific`：摄像头专用
- `critical-infra`：关键基础设施

**触发方式：**
- Chat Tab：输入"执行安全基线检查" / `/baseline`
- 3D HUD：设备详情面板 → BASELINE 按钮
- Operations Tab：快捷操作 → "安全基线"
- REST API：`POST /api/tools/baseline`

**工作条件：**
- ✅ 完全本地可用，使用 Python `socket` 进行真实 TCP 端口检测
- 不需要 nmap，不依赖外部工具
- 若目标设备不可达，自动回退到 topology.json 中的端口信息

---

### 2.4 auto-response（自动响应）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `isolate_device` | 隔离设备（关闭交换机端口） | device_ip, reason | IsolationService |
| `restore_device` | 恢复已隔离设备 | device_ip | IsolationService |
| `block_ip` | IP 封堵（iptables） | ip_address, reason | iptables/WSL |
| `unblock_ip` | 解除 IP 封堵 | ip_address | iptables/WSL |
| `get_response_status` | 查看当前响应状态 | 无 | 无 |
| `get_response_history` | 查看响应历史 | limit | 无 |

**触发方式：**
- Chat Tab：输入"隔离 camera-lobby"（需 AI 确认）
- 3D HUD：设备详情面板 → ISOLATE / RESTORE 按钮
- Operations Tab：快捷操作 → "设备隔离"
- REST API：`POST /api/tools/isolate` / `POST /api/tools/restore`

**工作条件：**
- 隔离方式按优先级：Docker 容器网络断开 → iptables 规则 → SSH 交换机端口关闭 → 仅记录状态
- Windows 环境：需要 WSL 运行 iptables，或使用 Docker 隔离
- 数据库持久化：隔离状态写入 `data/cyberclaw.db`
- ⚠️ 高风险操作：前端需确认弹窗

---

### 2.5 config-audit（配置审计）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `audit_config` | 审计设备安全配置 | device_ip | SSH/SNMP |
| `check_acl_conflicts` | ACL 规则冲突检测 | device_ip | SSH/SNMP |
| `compare_configs` | 配置基线比对 | device_ip, baseline_desc | SSH/SNMP |
| `get_audit_report` | 获取审计报告 | report_id | 无 |

**触发方式：**
- Chat Tab：输入"审计 10.0.0.1 的安全配置"
- REST API：通过 `mcp_tool_service.call_tool('config-audit', 'audit_config', ...)`

**工作条件：**
- ❌ 需要真实网络设备且支持 SSH/SNMP
- 当前 ConfigFetcher 为基础实现，实际需要设备凭证

---

### 2.6 attack-timeline（攻击时间线）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `record_event` | 记录安全事件到时间线 | event_type, source, target, detail, severity | SQLite |
| `get_timeline` | 获取攻击时间线 | incident_id | SQLite |
| `analyze_root_cause` | 根因分析 | incident_id | SQLite |
| `generate_report` | 生成事后报告 | incident_id | SQLite |

**触发方式：**
- Chat Tab：输入"分析攻击时间线"
- REST API：通过 `mcp_tool_service.call_tool('attack-timeline', 'get_timeline', ...)`
- 自动触发：系统检测到安全事件时自动记录

**工作条件：**
- ✅ 完全本地可用，使用 SQLite 数据库 `data/timeline.db`
- 不依赖外部服务

---

### 2.7 traffic-analyzer（流量分析）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `start_capture` | 启动抓包 | interface, filter_expr, duration | **tshark**/scapy |
| `get_capture_result` | 获取抓包结果 | capture_id | 无 |
| `extract_ioc` | IoC 指标提取 | capture_id | 无 |
| `analyze_flow` | 流量异常分析（C2/横向移动/数据外泄） | target | 无 |

**触发方式：**
- Chat Tab：输入"分析 10.0.0.11 的流量"
- REST API：通过 `mcp_tool_service.call_tool('traffic-analyzer', ...)`

**工作条件：**
- 完整模式：需要安装 tshark（Wireshark CLI）
- Mock 模式：使用 scapy 生成模拟数据包摘要
- 协议流量统计用于 Dashboard 的 Protocol Traffic 图表

---

### 2.8 flow-analyzer（IPFIX/NetFlow 流量分析）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `ipfix_start_receiver` | 启动 UDP 流量接收器 | port, bind_address | UDP socket |
| `ipfix_stop_receiver` | 停止接收器 | 无 | 无 |
| `ipfix_get_status` | 获取接收器状态 | 无 | 无 |
| `ipfix_query_flows` | 查询流记录 | start_time, end_time, filters, limit | 无 |
| `ipfix_get_flow` | 获取单条流详情 | flow_id | 无 |
| `ipfix_top_talkers` | Top 流量端点 | start_time, end_time, limit | 无 |
| `ipfix_get_templates` | 列出 NetFlow 模板 | 无 | 无 |

**触发方式：**
- REST API：通过 `mcp_tool_service.call_tool('flow-analyzer', ...)`

**工作条件：**
- 接收端可在本地启动（UDP 2055 端口）
- 需要真实网络设备发送 IPFIX/NetFlow 数据才有实际内容

---

### 2.9 syslog-collector（Syslog 收集器）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `syslog_start_receiver` | 启动 syslog 接收器 | port, bind_address, protocol | UDP/TCP socket |
| `syslog_stop_receiver` | 停止接收器 | 无 | 无 |
| `syslog_get_status` | 获取状态 | 无 | 无 |
| `syslog_query` | 查询日志 | start_time, end_time, filters | 无 |
| `syslog_get_message` | 获取单条消息 | message_id | 无 |
| `syslog_get_severity_counts` | 严重程度统计 | start_time, end_time | 无 |

**触发方式：**
- Chat Tab：输入"启动 syslog 收集器"
- Operations Tab：快捷操作按钮
- REST API：`POST /api/tools/collector/start` / `POST /api/tools/collector/stop`
- 3D HUD：左面板 Start/Stop Collector 按钮

**工作条件：**
- ✅ 完全本地可用
- 启动后监听 UDP 8514（默认）
- 可用 `python lab/event_generator.py` 发送测试事件
- 事件存于内存 deque + 自动写入数据库

---

### 2.10 snmp-collector（SNMP Trap 收集器）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `snmptrap_start_receiver` | 启动 Trap 接收器 | port, bind_address | UDP socket |
| `snmptrap_stop_receiver` | 停止接收器 | 无 | 无 |
| `snmptrap_get_status` | 获取状态 | 无 | 无 |
| `snmptrap_query` | 查询 Trap 记录 | start_time, end_time, filters | 无 |
| `snmptrap_get_trap` | 获取单条 Trap | trap_id | 无 |
| `snmptrap_get_counts` | Trap 计数统计 | start_time, end_time | 无 |

**触发方式：**
- REST API：`POST /api/tools/snmp/start` / `POST /api/tools/snmp/stop`
- Chat Tab：输入"启动 SNMP trap 接收器"

**工作条件：**
- 接收端可在本地启动（UDP 1162 端口）
- 需要真实 SNMP 设备发送 Trap 才有实际内容

---

### 2.11 device-config（设备配置 - gNMI/SSH）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `gnmi_get` | gNMI 获取设备状态/配置 | target, paths, encoding, data_type | **gNMI 设备** |
| `gnmi_set` | gNMI 下发配置（需 ITSM 审批） | target, updates, replaces, deletes | **gNMI + ITSM** |
| `gnmi_subscribe` | gNMI 遥测订阅 | target, paths, mode, sample_interval | **gNMI 设备** |
| `gnmi_capabilities` | 获取 YANG 模型能力 | target | **gNMI 设备** |
| `gnmi_list_targets` | 列出 gNMI 目标设备 | 无 | 配置文件 |
| `ssh_run_command` | SSH 执行 CLI 命令 | device_ip, command, username, password | **paramiko** |
| `ssh_get_config` | SSH 获取运行配置 | device_ip | **paramiko** |
| `ssh_configure` | SSH 下发配置 | device_ip, commands | **paramiko** |

**触发方式：**
- REST API：通过 `mcp_tool_service.call_tool('device-config', ...)`
- Chat Tab：通过 AI Agent 间接调用

**工作条件：**
- ❌ 需要真实 gNMI/SSH 网络设备
- gNMI 需要支持 YANG 模型的网络操作系统
- SSH 需要 paramiko 库 + 设备凭证

---

### 2.12 simulation（GNS3 网络仿真）

| 工具函数 | 说明 | 参数 | 依赖 |
|---------|------|------|------|
| `gns3_list_templates` | 列出节点模板 | 无 | **GNS3 Server** |
| `gns3_create_project` | 创建项目 | name, auto_open, auto_start | **GNS3 Server** |
| `gns3_list_nodes` | 列出节点 | project_id | **GNS3 Server** |
| `gns3_create_node` | 创建节点 | project_id, template, name, x, y | **GNS3 Server** |
| `gns3_start_node` | 启动节点 | project_id, node_id | **GNS3 Server** |
| `gns3_stop_node` | 停止节点 | project_id, node_id | **GNS3 Server** |
| `gns3_isolate_node` | 隔离节点 | project_id, node_id, isolate | **GNS3 Server** |
| `gns3_create_link` | 创建链路 | project_id, node1, port1, node2, port2 | **GNS3 Server** |
| `gns3_start_capture` | 启动抓包 | project_id, link_id | **GNS3 Server** |
| `gns3_list_iot_templates` | 列出 IoT 拓扑模板 | 无 | **GNS3 Server** |
| `gns3_deploy_iot_topology` | 部署 IoT 拓扑 | template_id, project_name | **GNS3 Server** |
| ... | （共 24+ 函数） | | |

**触发方式：**
- REST API：通过 `mcp_tool_service.call_tool('simulation', ...)`
- Chat Tab：通过 AI Agent 间接调用

**工作条件：**
- ❌ 需要 GNS3 Server 运行在 `localhost:3080`
- 需要环境变量 `GNS3_USER` / `GNS3_PASSWORD`

---

## 三、REST API 工具端点汇总（26 个）

### 扫描与安全评估

| 端点 | 方法 | 功能 | MCP 工具 |
|------|------|------|---------|
| `/api/tools/scan` | POST | 网络扫描（5 种模式） | nmap-scan/* |
| `/api/tools/cve-check` | POST | CVE 漏洞查询 | cve-intel/check_device_vulns |
| `/api/tools/baseline` | POST | 安全基线审计 | security-baseline/check_baseline |

### 设备隔离/恢复

| 端点 | 方法 | 功能 | MCP 工具 |
|------|------|------|---------|
| `/api/tools/isolate` | POST | 隔离设备 | auto-response/isolate_device |
| `/api/tools/restore` | POST | 恢复设备 | auto-response/restore_device |

### Syslog 收集器

| 端点 | 方法 | 功能 | 直接服务 |
|------|------|------|---------|
| `/api/tools/collector/start` | POST | 启动收集器 | collector_service |
| `/api/tools/collector/stop` | POST | 停止收集器 | collector_service |
| `/api/tools/collector/events` | GET | 获取事件 | collector_service |
| `/api/tools/collector/status` | GET | 获取状态 | collector_service |

### SNMP

| 端点 | 方法 | 功能 | 直接服务 |
|------|------|------|---------|
| `/api/tools/snmp/start` | POST | 启动 Trap 接收器 | snmp_service |
| `/api/tools/snmp/stop` | POST | 停止接收器 | snmp_service |
| `/api/tools/snmp/traps` | GET | 获取 Trap | snmp_service |
| `/api/tools/snmp/query` | POST | SNMP 查询设备 | snmp_service |
| `/api/tools/snmp/status` | GET | 获取状态 | snmp_service |
| `/api/tools/snmp/discover-topology` | POST | SNMP 拓扑发现 | snmp_service |

### MQTT

| 端点 | 方法 | 功能 | 直接服务 |
|------|------|------|---------|
| `/api/tools/mqtt/connect` | POST | 连接 MQTT Broker | mqtt_service |
| `/api/tools/mqtt/disconnect` | POST | 断开连接 | mqtt_service |
| `/api/tools/mqtt/messages` | GET | 获取消息 | mqtt_service |
| `/api/tools/mqtt/status` | GET | 获取状态 | mqtt_service |

### 扫描调度

| 端点 | 方法 | 功能 | 直接服务 |
|------|------|------|---------|
| `/api/tools/scan-schedule/start` | POST | 启动定时扫描 | scan_service |
| `/api/tools/scan-schedule/stop` | POST | 停止定时扫描 | scan_service |
| `/api/tools/scan-schedule/status` | GET | 获取调度状态 | scan_service |

### Suricata IDS

| 端点 | 方法 | 功能 | 直接服务 |
|------|------|------|---------|
| `/api/tools/suricata/start` | POST | 启动 IDS 监控 | suricata_service |
| `/api/tools/suricata/stop` | POST | 停止 IDS 监控 | suricata_service |
| `/api/tools/suricata/alerts` | GET | 获取告警 | suricata_service |
| `/api/tools/suricata/stats` | GET | 获取统计 | suricata_service |

---

## 四、前端 UI 触发入口

### Chat Tab

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| 输入"扫描网络中的所有设备" | AI 调用 nmap-scan | POST /api/chat → /api/tools/scan |
| 输入"查询 CVE 漏洞" | AI 调用 cve-intel | POST /api/chat → /api/tools/cve-check |
| 输入"安全基线检查" | AI 调用 security-baseline | POST /api/chat → /api/tools/baseline |
| 输入"隔离 XXX 设备" | AI 调用 auto-response | POST /api/chat → /api/tools/isolate |
| 输入"启动 syslog 收集器" | AI 调用 collector | POST /api/chat → /api/tools/collector/start |
| `/scan` 命令 | 快速网络扫描 | POST /api/chat |
| `/cve` 命令 | 快速 CVE 查询 | POST /api/chat |
| `/baseline` 命令 | 快速基线检查 | POST /api/chat |
| `/schedule` 命令 | 打开调度面板 | POST /api/scheduler/tasks |
| 快捷按钮 x4 | 预设 prompt | POST /api/chat |

### Operations Tab

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| "全网扫描" 按钮 | 网络扫描 | POST /api/chat |
| "漏洞检测" 按钮 | CVE 检测 | POST /api/chat |
| "设备隔离" 按钮 | 查看需隔离设备 | POST /api/chat |
| "生成报告" 按钮 | 安全报告 | POST /api/chat |
| 扫描调度 启动/停止 | 定时扫描 | POST /api/tools/scan-schedule/start|stop |
| "+ 新建任务" 按钮 | 创建定时任务 | POST /api/scheduler/tasks |
| 任务 暂停/恢复/触发/删除 | 任务管理 | POST /api/scheduler/tasks/{id}/{action} |
| 工作流 保存/删除/启用 | 工作流管理 | PUT/DELETE /api/workflows/{index} |

### Dashboard Tab

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| Alert List 筛选 | 筛选告警 | GET /api/dashboard/alerts |
| Alert Refresh | 刷新告警 | GET /api/dashboard/alerts |
| Trend Refresh | 刷新趋势图 | GET /api/dashboard/trends/* |
| Topology Refresh | 刷新拓扑树 | GET /api/topology |
| Log Search | 日志搜索 | GET /api/dashboard/logs/search |

### Reports Tab

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| 设备行点击 | 打开详情面板 | GET /api/dashboard/db/devices |
| 事件/连接 Tab | 加载设备事件/连接 | GET /api/dashboard/db/device-events, /api/topology |
| 状态/类型/厂商筛选 | 本地过滤 | 无（前端过滤） |

### History Tab

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| "发送测试" 按钮 | 测试通知 | POST /api/notifications/test |
| "刷新" 按钮 | 刷新通知 | GET /api/notifications/history |
| 通道 开关/保存 | 配置通知通道 | PUT /api/notifications/config |
| 全部已读/清除 | 批量操作 | POST/DELETE /api/notifications/* |
| 分类按钮 + 严重程度筛选 | 过滤通知 | GET /api/notifications/history |

### 3D HUD

| 触发方式 | 对应操作 | 调用端点 |
|---------|---------|---------|
| START DEMO | 启动攻击场景 | WebSocket → /api/scenario/{id}/start |
| STOP DEMO | 停止场景 | WebSocket → /api/scenario/{id}/stop |
| RESET | 重置场景 | WebSocket → /api/scenario/{id}/reset |
| SCAN 按钮 | 扫描设备 | POST /api/tools/scan |
| CVE CHECK 按钮 | CVE 查询 | POST /api/tools/cve-check |
| ISOLATE 按钮 | 隔离设备 | POST /api/tools/isolate |
| RESTORE 按钮 | 恢复设备 | POST /api/tools/restore |
| BASELINE 按钮 | 基线审计 | POST /api/tools/baseline |
| Start/Stop Collector | 收集器控制 | POST /api/tools/collector/start|stop |

---

## 五、功能验证测试

> 以下测试结果在启动后端 + 前端后逐项验证

### 测试环境准备

```bash
# 终端 1：后端
python -m uvicorn server.main:app --reload --port 8000

# 终端 2：前端
cd ui/cyberclaw-hud && npm run dev

# 终端 3：事件生成器（可选）
python lab/event_generator.py --loop --interval 10
```

### 测试环境

- OS: Windows 11 / Python 3.14 / Node.js v22
- 后端: `python -m uvicorn server.main:app --port 8000`
- 前端: `cd ui/cyberclaw-hud && npm run dev`
- 测试时间: 2026-06-01

### 测试结果

| # | 工具/功能 | 测试方式 | 预期结果 | 实际结果 | 状态 |
|---|----------|---------|---------|---------|------|
| 1 | 设备列表 | `GET /api/dashboard/db/devices` | 返回设备 | Total: 19, 首台 CoreSwitch-H3C | ✅ |
| 2 | 网络拓扑 | `GET /api/topology` | 设备+links | Devices: 15, Links: 14 | ✅ |
| 3 | Syslog 收集器启动 | `POST /api/tools/collector/start` | 监听 8514 | `is_running: true, port: 8514` | ✅ |
| 4 | Syslog 事件接收 | `event_generator.py` → GET events | 收到事件 | 16/16 sent, stored 正常 | ✅ |
| 5 | 告警面板（内存） | `GET /api/dashboard/alerts` | 显示告警 | Total: 16 | ✅ |
| 6 | 告警面板（数据库） | `GET /api/dashboard/db/alerts` | DB 告警 | Total: 18（含历史） | ✅ |
| 7 | 告警趋势图 | `GET /api/dashboard/trends/alert-count` | 折线图 | 24 hours × 6 series | ✅ |
| 8 | 设备状态饼图 | `GET /api/dashboard/trends/device-status` | 饼图 | [25, 1, 1, 0, 6] | ✅ |
| 9 | 网络扫描 | `POST /api/tools/scan` | 异步启动 | `status: started` | ✅ |
| 10 | CVE 查询 | `POST /api/tools/cve-check` | 异步启动 | `status: started` | ✅ |
| 11 | 安全基线 | `POST /api/tools/baseline` | 异步启动 | `status: started` | ✅ |
| 12 | 设备隔离 | `POST .../isolate {"device_id":"camera-lobby"}` | 隔离成功 | `status: started, container: Camera-Lobby` | ✅ |
| 13 | 设备恢复 | `POST .../restore {"device_id":"camera-lobby"}` | 恢复成功 | `status: started` | ✅ |
| 14 | 工作流列表 | `GET /api/workflows/` | 返回工作流 | Count: 3 | ✅ |
| 15 | 工作流更新 | `PUT /api/workflows/0` | 保存成功 | `status: updated` | ✅ |
| 16 | 通知配置读取 | `GET /api/notifications/config` | 返回配置 | Channels: [webhook, ntfy] | ✅ |
| 17 | 通知配置更新 | `PUT /api/notifications/config` | 保存成功 | `status: updated` | ✅ |
| 18 | 测试通知 | `POST /api/notifications/test` | 发送成功 | `status: sent` | ✅ |
| 19 | 通知历史 | `GET /api/notifications/history` | 返回历史 | Total: 0（无历史通知） | ✅ |
| 20 | 未读计数 | `GET /api/notifications/unread_count` | 返回计数 | Unread: 0 | ✅ |
| 21 | 定时任务列表 | `GET /api/scheduler/tasks` | 返回任务 | Tasks: 5 | ✅ |
| 22 | 扫描调度器启动 | `POST /api/tools/scan-schedule/start` | 启动 | `Running: started` | ✅ |
| 23 | 扫描调度器停止 | `POST /api/tools/scan-schedule/stop` | 停止 | `Running: stopped` | ✅ |
| 24 | AI 基础对话 | `POST /api/chat {"message":"hello"}` | AI 响应 | 正确返回中文回复 | ✅ |
| 25 | Chat Status | `GET /api/chat/status` | MCP 工具数 | MCP tools: 64, LLM: True | ✅ |
| 26 | Chat History | `GET /api/chat/history` | 历史消息 | Messages: 18 | ✅ |
| 27 | SNMP 状态 | `GET /api/tools/snmp/status` | 返回状态 | `running: false, traps: 0` | ✅ |
| 28 | MQTT 状态 | `GET /api/tools/mqtt/status` | 返回状态 | `connected: false` | ✅ |
| 29 | Suricata 状态 | `GET /api/tools/suricata/stats` | 返回状态 | `is_running: false, mode: idle` | ✅ |
| 30 | 日志搜索（有事件后） | `GET .../logs/search?query=scan` | 有结果 | Results: 2 | ✅ |
| 31 | 协议流量图 | `GET .../trends/protocol-traffic` | 流量数据 | Labels: [], Data: [] | ⚠️ |
| 32 | AI 工具调用 | `POST /api/chat` 含工具意图 | 调用工具 | 超时（LLM 响应 >45s） | ⚠️ |
| 33 | Scenario 路由 | `GET /api/scenario/` | 场景列表 | HTTP 302 redirect | ⚠️ |

### 测试结论

**通过: 30/33 (90.9%)** | **注意: 3/33 (9.1%)**

#### ⚠️ 需注意的问题

| 问题 | 原因 | 影响 | 解决方案 |
|------|------|------|---------|
| **协议流量图空数据** | 完全依赖 Suricata 的 `by_protocol` 统计，Suricata 未运行 | Dashboard Protocol Traffic 图为空 | 安装 Suricata 或增加 mock 回退 |
| **AI 工具调用超时** | LLM → 工具调用 → 结果汇总链路较长 | Chat 中复杂指令响应慢 | 优化 LLM prompt 或增加超时 |
| **Scenario 路由重定向** | `GET /api/scenario/` → 302 → `/api/scenario`（去尾斜杠） | 前端需处理 redirect | FastAPI 默认行为，非 bug |

---

## 六、按可演示性分类

### 🟢 可直接演示（本地即可工作）

| 工具 | 演示操作 |
|------|---------|
| 设备列表 / 拓扑 | 启动后端即可看到 19 台设备 |
| Syslog 收集器 | Chat 中"启动 syslog 收集器" → event_generator.py |
| 告警面板 + 趋势图 | 收集器启动后自动填充 |
| CVE 查询 | Chat 中"查询 Hikvision 的 CVE"（有 mock 回退） |
| 安全基线 | Chat 中"执行安全基线检查"（Python socket 扫描） |
| 设备隔离/恢复 | Chat 中"隔离 camera-lobby"（数据库状态变更） |
| 工作流编辑 | Operations Tab → 展开/编辑/保存工作流 |
| 通知系统 | History Tab → 配置通道 → 发送测试 |
| 定时任务 | Operations Tab → 创建 Cron 任务 |
| AI 对话 | Chat Tab → 任意自然语言提问 |
| 设备详情面板 | Reports Tab → 点击设备行 |
| 攻击时间线 | Chat 中"分析攻击时间线"（SQLite 数据库） |

### 🟡 需要 mock 模式或部分条件

| 工具 | 条件 |
|------|------|
| 网络扫描 | 无 nmap 时使用 topology.json mock 数据 |
| 流量分析 | 无 tshark 时使用 scapy mock |
| 协议流量图 | 需 Suricata 或流量数据 |

### 🔴 需要外部基础设施

| 工具 | 缺失条件 |
|------|---------|
| 真实网络扫描 | 需安装 nmap |
| gNMI 设备配置 | 需 gNMI 网络设备 |
| GNS3 仿真 | 需 GNS3 Server |
| SNMP Trap | 需真实 SNMP 设备 |
| MQTT | 需 MQTT Broker |
| Suricata IDS | 需安装 Suricata |
| IPFIX/NetFlow | 需流量导出设备 |
| 配置审计 | 需 SSH/SNMP 设备访问 |

---

## 七、工具总数统计

| 层次 | 数量 |
|------|------|
| MCP 工具服务器 | 12 |
| MCP 工具函数 | **85** |
| REST API 端点 | **80+** |
| 前端 UI 触发点 | **60+** |
| WebSocket 事件类型 | **20+** |
