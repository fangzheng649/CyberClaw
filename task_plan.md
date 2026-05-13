# CyberClaw 软件开发计划

## 目标
基于 OpenClaw 框架和 NetClaw 项目已有基础设施，构建面向 IoT 设备安全的智能自动化平台 CyberClaw，实现"感知→检测→响应→复盘"全闭环安全能力。

## 现有资产评估

| 组件 | NetClaw 现有 | CyberClaw 所需 | 复用度 |
|------|-------------|---------------|--------|
| gNMI MCP | 完整实现 (800行, TLS/YANG/订阅) | device-config 基础 | 高，需加 SSH/CLI |
| GNS3 MCP | 完整实现 (1400行, 含测试) | simulation 基础 | 高，需定制 IoT 拓扑模板 |
| Syslog MCP | 完整实现 (500行, TCP/UDP) | syslog-collector 基础 | 高，需加 severity 过滤和 WebSocket |
| SNMP Trap MCP | 完整实现 (400行) | snmp-collector 基础 | 高，需加 OID 映射和 WebSocket |
| IPFIX MCP | 完整实现 (500行) | flow-analyzer 基础 | 高，需加异常检测算法 |
| TOON 序列化 | 完整实现 (7模块) | 直接复用 | 100% |
| 3D HUD (Three.js) | 完整实现 (2900行 main.js + 59KB server.js) | 需大幅改造为安全 HUD | 中，框架和后处理管线可复用 |
| Skills 框架 | 159个 SKILL.md | 需全新编写 IoT 安全 Skills | 低，框架复用，内容全新 |
| OpenClaw 配置 | 完整 (openclaw.json 264行) | 需定制 MCP 服务器列表 | 中 |

**需全新开发的组件：**
- nmap-scan MCP（封装 python-nmap）
- cve-intel MCP（NVD API + SQLite 缓存）
- security-baseline MCP（CIS 九步审计）
- traffic-analyzer MCP（tshark 封装 + IoC 提取）
- auto-response MCP（端口隔离 + ACL + 验证 + 回滚）
- config-audit MCP（防火墙规则冲突/重叠/影子检测）
- attack-timeline MCP（事件记录 + 时间线 + 根因分析）
- 3D 安全 HUD 特效（攻击光束、防御盾牌、爆炸半径、安全着色 FSM）

---

## Phase 1: 项目骨架与 Agent 配置 [预计 2 天]

**状态：** `pending`

**目标：** 创建 CyberClaw 项目目录结构，定制 Agent 核心配置文件。

### 任务清单

- [ ] 1.1 创建 `cyberclaw/` 项目目录结构
  ```
  cyberclaw/
  ├── mcp-servers/          # 12 个 MCP 服务器
  │   ├── nmap-scan/
  │   ├── device-config/
  │   ├── simulation/
  │   ├── syslog-collector/
  │   ├── snmp-collector/
  │   ├── cve-intel/
  │   ├── security-baseline/
  │   ├── flow-analyzer/
  │   ├── traffic-analyzer/
  │   ├── auto-response/
  │   ├── config-audit/
  │   └── attack-timeline/
  ├── workspace/skills/     # IoT 安全 Skills
  ├── ui/cyberclaw-hud/     # 3D 安全 HUD
  ├── src/cyberclaw_core/   # 共享库 (TOON, 工具函数)
  ├── config/               # Agent 配置
  ├── lab/                  # GNS3 实验环境
  └── scripts/              # 安装/部署脚本
  ```

- [ ] 1.2 定制 `SOUL.md` — IoT 安全分析专家身份
  - 角色定义：IoT 安全分析专家
  - 技能清单：引用安全闭环四阶段的 Skills
  - 安全操作规则：三级权限（只读/写操作/禁止）
  - 协议知识库：IoT 协议识别特征和安全检查要点

- [ ] 1.3 定制 `AGENTS.md` — IoT 安全运行指令
  - 继承 OpenClaw 标准 GAIT 工作流
  - 新增 IoT 约束：扫描仅限授权网段、禁止对物理设备执行破坏性操作
  - 安全规则执行方式

- [ ] 1.4 定制 `TOOLS.md` — 本地基础设施连接信息
  - GNS3 服务器地址
  - 可管理交换机 IP
  - MCP 服务器配置模板

- [ ] 1.5 配置 `openclaw.json` — 注册 12 个 CyberClaw MCP 服务器
  - 每个服务器的启动命令、参数和环境变量

- [ ] 1.6 复用 TOON 序列化库
  - 从 NetClaw 复制 `src/netclaw_tokens/` → `src/cyberclaw_core/toon/`

### 验收标准
- CyberClaw 项目目录结构就位
- Agent 能读取 SOUL.md/AGENTS.md/TOOLS.md 并初始化
- openclaw.json 配置了所有 12 个 MCP 服务器入口

---

## Phase 2: 感知层 MCP 服务器 [预计 4 天]

**状态：** `pending`

**目标：** 实现感知层三个 MCP 服务器，完成设备发现、指纹识别、默认密码检测、设备配置管理和仿真环境管理。

### 任务清单

- [ ] 2.1 **nmap-scan MCP 服务器** (全新开发)
  - 封装 python-nmap + asyncio 异步执行
  - 6 个工具：network_scan, port_scan, service_detection, vuln_scan, iot_fingerprint, default_credential_check
  - iot_fingerprint: MAC OUI (0.20) + Banner (0.45) + 端口组合 (0.35) 加权融合
  - default_credential_check: 通用 50 组 + 厂商特定 70 组凭证
  - 全部输出 TOON 格式
  - 预估代码量：~600 行

- [ ] 2.2 **device-config MCP 服务器** (基于 gnmi-mcp 改造)
  - 复用 gNMI 连接层，新增 SSH/CLI 连接 (paramiko/asyncssh)
  - 4 个工具：get_config, get_interfaces, get_neighbors, set_config
  - Cisco IOS 命令模板 (show running-config, show ip interface brief, show cdp/lldp neighbors)
  - set_config 归入写操作权限，需审计日志
  - 拓扑自动构建：CDP/LLDP 邻居 + ARP 交叉验证
  - 预估代码量：改造 ~400 行

- [ ] 2.3 **simulation MCP 服务器** (基于 gns3-mcp-server 改造)
  - 复用 GNS3 REST API 封装，定制 IoT 攻防拓扑模板
  - 5 个工具：create_project, manage_node, get_nodes, capture_traffic, create_snapshot
  - 预设拓扑：2 路由器 + 1 核心交换机 + 10+ IoT 终端 + 1 Kali 攻击机
  - Kali 预置 4 类攻击脚本 (recon.sh, bruteforce.sh, mirai_infect.sh, c2_callback.sh)
  - 预估代码量：改造 ~300 行

### 验收标准
- nmap-scan 能扫描目标网段并返回设备列表、端口、服务、IoT 指纹
- device-config 能通过 SSH 连接交换机查询配置和邻居
- simulation 能创建 GNS3 项目并管理 IoT 拓扑节点
- 所有输出为 TOON 格式

---

## Phase 3: 检测层 MCP 服务器 [预计 5 天]

**状态：** `pending`

**目标：** 实现检测层六个 MCP 服务器，完成四路异构数据采集和关联分析能力。

### 任务清单

- [ ] 3.1 **syslog-collector MCP** (基于 syslog-mcp 改造)
  - 复用 UDP 514 监听和 RFC 5424 解析
  - 新增：severity 过滤 (默认 warning+)、WebSocket 实时推送
  - 3 个工具：get_alerts, subscribe, parse_raw
  - 预估代码量：改造 ~200 行

- [ ] 3.2 **snmp-collector MCP** (基于 snmptrap-mcp 改造)
  - 复用 UDP 162 监听和 SNMP v2c/v3 解析
  - 新增：OID 映射表 (linkDown/linkUp/ospfIfStateChange)、WebSocket 推送
  - 3 个工具：get_traps, subscribe, decode_trap
  - 预估代码量：改造 ~200 行

- [ ] 3.3 **cve-intel MCP** (全新开发)
  - 对接 NVD REST API v2.0
  - SQLite 本地缓存 (CPE 键, 24h 有效)
  - NVD 限流退避策略 (无 API Key: 5次/30s)
  - 4 个工具：search_cve, get_cve_details, cve_by_cpe, cve_by_device
  - CPE 2.3 自动构造算法
  - 预估代码量：~500 行

- [ ] 3.4 **security-baseline MCP** (全新开发)
  - CIS 九步安全基线审计
  - 跨 MCP 工具协调 (调用 nmap-scan 的 default_credential_check, device-config 的 get_config)
  - 4 个工具：cis_audit, check_open_ports, check_services, compliance_report
  - 批量审计 + 合规率统计
  - 预估代码量：~400 行

- [ ] 3.5 **flow-analyzer MCP** (基于 ipfix-mcp 改造)
  - 复用 NetFlow/IPFIX 采集解析
  - 新增：异常检测算法 (C2 回连、横向扫描、DDoS 参与)
  - 3 个工具：get_flows, top_talkers, detect_anomaly
  - 预估代码量：改造 ~300 行

- [ ] 3.6 **traffic-analyzer MCP** (全新开发)
  - 封装 tshark (Wireshark CLI)
  - BPF 过滤 + 时长控制
  - IoC 提取：恶意域名/DGA、恶意 IP、异常载荷
  - 3 个工具：capture_traffic, analyze_pcap, extract_ioc
  - 预估代码量：~400 行

### 验收标准
- syslog-collector 能接收并解析 Syslog 告警，按 severity 过滤
- snmp-collector 能接收 SNMP Trap 并映射为可读事件
- cve-intel 能查询 NVD 并返回 CVE 详情，缓存命中率 > 80%
- security-baseline 能对设备执行 CIS 九步审计
- flow-analyzer 能检测 C2 回连和横向扫描等异常
- traffic-analyzer 能提取 IoC 指标

---

## Phase 4: 响应层与复盘层 MCP 服务器 [预计 4 天]

**状态：** `pending`

**目标：** 实现响应层和复盘层三个 MCP 服务器，完成自动隔离、规则审计、攻击时间线和根因分析。

### 任务清单

- [ ] 4.1 **auto-response MCP** (全新开发)
  - 端口隔离：SSH→show mac address-table→定位端口→shutdown
  - ACL 封禁：创建命名扩展 ACL→deny ip host→应用到接口
  - 四步安全流程：get_baseline→deploy_acl+isolate_port→verify_isolation→rollback
  - 多厂商命令模板：Cisco IOS / Huawei VRP / Juniper JunOS
  - action_id (UUID) 贯穿操作生命周期
  - 5 个工具：get_baseline, isolate_port, deploy_acl, verify_isolation, rollback
  - 预估代码量：~600 行

- [ ] 4.2 **config-audit MCP** (全新开发)
  - 9 种厂商防火墙/ACL 语法解析器
  - 冲突规则、重叠规则、影子规则三种检测
  - 统一规则数据结构 (源/目的 IP, 端口, 协议, 动作)
  - 3 个工具：analyze_rules, check_conflicts, optimize_rules
  - 预估代码量：~500 行

- [ ] 4.3 **attack-timeline MCP** (全新开发)
  - 8 种标准化事件类型 (scan_started → verified)
  - 被动调用机制 (其他引擎触发 record_event)
  - Git 不可变审计链 (bare repo + pre-receive hook)
  - 根因分析四步算法 (入口识别→扩散路径→薄弱环节→改进建议)
  - 4 个工具：record_event, get_timeline, root_cause_analysis, generate_report
  - 预估代码量：~500 行

### 验收标准
- auto-response 能通过 SSH 关闭交换机端口并下发 ACL
- 四步流程 (基线→隔离→验证→回滚) 能正确执行
- config-audit 能检测 Cisco ACL 的冲突、重叠和影子规则
- attack-timeline 能记录事件并构建完整时间线
- 根因分析能从时间线数据中提取攻击入口和扩散路径

---

## Phase 5: 安全应用服务层 (四大引擎) [预计 3 天]

**状态：** `pending`

**目标：** 实现四个安全引擎，封装各阶段的业务逻辑，作为 Skills 和 MCP 工具之间的中间层。

### 任务清单

- [ ] 5.1 **CyberScan 感知引擎**
  - 协调 nmap-scan + device-config + simulation 三个 MCP
  - 全网扫描→服务识别→IoT 指纹→默认密码→拓扑构建→资产清单输出
  - 输出结构化设备资产清单 (TOON)

- [ ] 5.2 **CyberSense 检测引擎**
  - 协调 6 个检测类 MCP
  - 实现 anomaly-detect 六步调用链模板
  - 四路数据交叉关联 (日志 + CVE + 基线 + 流量)
  - 输出威胁判定 (攻击类型 + 置信度 + 影响范围 + 响应建议)

- [ ] 5.3 **CyberShield 响应引擎**
  - 协调 auto-response + config-audit 两个 MCP
  - 半自动响应：AI 生成建议→用户确认→自动执行
  - 响应策略表 (attack_type → 响应动作映射)
  - 审计日志贯穿

- [ ] 5.4 **CyberReview 复盘引擎**
  - 协调 attack-timeline MCP
  - 攻击时间线构建 + 根因分析
  - 三种报告生成 (incident/review/compliance)
  - 闭环反馈：改进建议写入 MemPalace

### 验收标准
- CyberScan 能端到端完成从扫描到资产清单输出的流程
- CyberSense 能接收告警触发多源关联分析并输出威胁判定
- CyberShield 能根据策略表生成处置建议并执行隔离
- CyberReview 能从事件链生成根因分析报告

---

## Phase 6: Skills 编排定义 [预计 2 天]

**状态：** `pending`

**目标：** 定义安全闭环各阶段的 SKILL.md 文件，声明式编排工具调用链。

### 任务清单

- [ ] 6.1 感知类 Skills
  - `network-discovery` — 全网设备发现
  - `iot-fingerprint` — IoT 设备指纹识别
  - `topology-build` — 网络拓扑构建
  - `default-password-check` — 默认密码检测

- [ ] 6.2 检测类 Skills
  - `vuln-assess` — 漏洞评估 (CVE 关联)
  - `baseline-check` — 安全基线检查
  - `anomaly-detect` — 异常检测 (多源关联分析)
  - `traffic-anomaly` — 流量异常分析

- [ ] 6.3 响应类 Skills
  - `device-isolate` — 设备端口隔离
  - `ip-block` — IP 地址封禁
  - `full-response` — 完整响应闭环

- [ ] 6.4 复盘类 Skills
  - `timeline-review` — 攻击时间线回顾
  - `root-cause` — 根因分析
  - `security-report` — 安全报告生成

- [ ] 6.5 全流程 Skills
  - `full-assess` — 感知+检测 完整安全评估
  - `full-response` — 检测→响应→复盘 完整闭环

### 验收标准
- 15+ 个 SKILL.md 文件就位
- 每个 Skill 包含完整的 YAML frontmatter 和 Markdown 工作流定义
- Agent 能通过 Skill 匹配正确调度 MCP 工具链

---

## Phase 7: 3D 安全 HUD [预计 6 天]

**状态：** `pending`

**目标：** 基于 NetClaw Three.js HUD 改造为安全可视化界面，实现五维安全态势编码和攻击特效。

### 任务清单

- [ ] 7.1 **后端 WebSocket 服务改造**
  - 复用 Express.js + ws 架构
  - 改造事件协议：7 种安全事件类型
  - 心跳保活 (5s interval, 携带安全统计)
  - 自动重连 (2.5s retry + 完整状态同步)
  - 预估改造量：~300 行

- [ ] 7.2 **3D 场景图重构**
  - 设备节点：路由器/交换机/摄像头/传感器/攻击机 (不同几何体)
  - 连接线：基于拓扑数据的 Three.js Line
  - 标签系统：CSS2DObject 设备信息标签
  - 层次化场景：环境层 + 设备层 + 特效层 + HUD 层

- [ ] 7.3 **安全着色 FSM**
  - 五状态有限状态机 (SECURE/VULNERABLE/ATTACKED/ISOLATED/SCANNING)
  - GSAP 颜色渐变 (0.8s, Power2.easeInOut)
  - CVSS→辉光强度线性映射
  - 脉冲频率、粒子密度参数化

- [ ] 7.4 **自定义 GLSL 着色器**
  - 全息节点着色器 (Fresnel + 扫描线)
  - 攻击光束着色器 (流动能量脉冲)
  - 防御盾牌着色器 (六边形网格 + 收缩动画)
  - 爆炸半径着色器 (同心冲击波)
  - 数据流管道着色器 (脉冲传输)

- [ ] 7.5 **后处理管线**
  - 复用 NetClaw 十层管线框架
  - 定制：GlitchPass 攻击时激活 (0.5s)
  - 三种画质模式：FOCUS/BALANCED/BROADCAST

- [ ] 7.6 **攻击链路可视化**
  - 对象池模式 (预分配 20 个光束)
  - 逐段生长动画 (蓝→橙→红→紫)
  - 终端卡片系统 (工具调用可视化)

- [ ] 7.7 **交互系统**
  - OrbitControls (旋转/缩放/平移)
  - Raycaster (节点点击 + 悬停)
  - 对话驱动交互 (自然语言→3D 视图控制)

- [ ] 7.8 **性能优化**
  - 几何体共享 + 材质缓存
  - InstancedMesh 粒子系统
  - 零分配动画循环
  - 目标：28 设备 + 40+ 连接线场景下 60 FPS

### 验收标准
- 3D HUD 能渲染 IoT 设备拓扑
- 安全状态变化实时反映到 3D 视图 (颜色、辉光、脉冲)
- 攻击光束和防御盾牌特效正常渲染
- WebSocket 事件推送延迟 < 500ms
- 28 设备场景下帧率 ≥ 60 FPS

---

## Phase 8: 集成测试与攻防演示环境 [预计 3 天]

**状态：** `pending`

**目标：** 搭建 GNS3 攻防环境，端到端验证安全闭环，准备演示场景。

### 任务清单

- [ ] 8.1 **GNS3 IoT 攻防环境搭建**
  - 预设拓扑：2 路由器 + 1 核心交换机 + 10+ IoT 终端 + Kali
  - Kali 预置攻击脚本 (recon/bruteforce/mirai_infect/c2_callback)
  - IoT 终端模拟 (默认密码、开放 Telnet)
  - 环境快照 (攻击前/攻击后)

- [ ] 8.2 **端到端闭环测试**
  - 测试场景：Mirai 僵尸网络感染
  - 感知→检测→响应→复盘 全流程验证
  - 各 MCP 工具调用链正常
  - 3D HUD 实时同步

- [ ] 8.3 **单元测试与集成测试**
  - 各 MCP 服务器单元测试 (pytest)
  - 引擎集成测试
  - WebSocket 通信测试
  - 异常处理和边界测试

- [ ] 8.4 **物理设备接入 (可选)**
  - 真实网络摄像头接入
  - 智能插座接入
  - 可管理交换机配置

### 验收标准
- GNS3 环境可一键部署
- Mirai 攻击场景端到端闭环演示成功
- 各组件单元测试通过
- 3D HUD 演示流畅

---

## 开发时间线总览

| Phase | 内容 | 预计天数 | 累计 |
|-------|------|---------|------|
| 1 | 项目骨架与 Agent 配置 | 2 天 | 2 天 |
| 2 | 感知层 MCP 服务器 | 4 天 | 6 天 |
| 3 | 检测层 MCP 服务器 | 5 天 | 11 天 |
| 4 | 响应层与复盘层 MCP 服务器 | 4 天 | 15 天 |
| 5 | 安全应用服务层 | 3 天 | 18 天 |
| 6 | Skills 编排定义 | 2 天 | 20 天 |
| 7 | 3D 安全 HUD | 6 天 | 26 天 |
| 8 | 集成测试与演示环境 | 3 天 | 29 天 |

**关键路径：** Phase 2→3→4 (MCP 服务器) 是核心开发瓶颈，应优先推进。
**并行机会：** Phase 6 (Skills) 可与 Phase 5 并行；Phase 7 (3D HUD) 可从 Phase 5 开始并行推进。

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| (暂无) | | |

---

## 决策记录

| 决策 | 理由 | 日期 |
|------|------|------|
| 基于 NetClaw 改造而非从零开发 | 已有 10 个 MCP 服务器、TOON 库、3D HUD 框架可复用 | 2026-04-27 |
| SSH/CLI 为主而非 gNMI | IoT 场景主流设备支持 SSH，gNMI 覆盖率有限 | 来自报告设计 |
| FastMCP + stdio 协议 | 与 OpenClaw 框架一致，无端口管理开销 | 来自报告设计 |
| 半自动响应模式 | IoT 设备误隔离后果严重，须人工确认写操作 | 来自报告设计 |
