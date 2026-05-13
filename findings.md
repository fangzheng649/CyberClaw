# CyberClaw 开发 — 研究发现与关键信息

## 1. NetClaw 代码库复用分析

### 可直接复用 (100%)
- **TOON 序列化库** (`src/netclaw_tokens/`): 7 个 Python 模块，toon_serializer.py 核心实现
- **OpenClaw 配置格式**: openclaw.json 的 MCP 服务器注册规范
- **Skills 框架**: SKILL.md 的 YAML frontmatter + Markdown 正文格式规范

### 高复用度改造 (70-90%)
- **syslog-mcp → syslog-collector**: 已有 UDP 514 监听 + RFC 5424 解析，需加 severity 过滤和 WebSocket
- **snmptrap-mcp → snmp-collector**: 已有 UDP 162 + SNMP v2c/v3 解析，需加 OID 映射表
- **ipfix-mcp → flow-analyzer**: 已有 NetFlow/IPFIX 采集解析，需加异常检测算法
- **gns3-mcp-server → simulation**: 已有 GNS3 REST API 封装和测试，需定制 IoT 拓扑模板
- **gnmi-mcp → device-config**: 已有 gNMI 客户端和 YANG 工具，需加 SSH/CLI 连接

### 中复用度改造 (30-50%)
- **3D HUD (ui/netclaw-visual/)**: main.js 2900 行、server.js 59KB
  - 可复用：Three.js 场景框架、后处理管线 (10层)、WebSocket 架构、Express API
  - 需重写：设备节点类型 (从网络设备→IoT设备)、安全着色 FSM、攻击特效着色器、事件协议

### 需全新开发
- **nmap-scan MCP**: python-nmap 封装 + IoT 指纹识别算法 + 默认密码检测
- **cve-intel MCP**: NVD API v2.0 对接 + SQLite 缓存 + CPE 构造
- **security-baseline MCP**: CIS 九步审计 + 跨 MCP 工具协调
- **traffic-analyzer MCP**: tshark 封装 + IoC 提取
- **auto-response MCP**: SSH→交换机命令 + 多厂商模板 + 四步安全流程
- **config-audit MCP**: 9 种厂商语法解析 + 冲突/重叠/影子检测
- **attack-timeline MCP**: 事件记录 + Git 审计链 + 根因分析

---

## 2. 技术栈确认

| 组件 | 技术选择 | 版本/备注 |
|------|---------|----------|
| Agent 运行时 | OpenClaw Framework | 已有 (NetClaw 项目) |
| LLM | Anthropic Claude | 通过 OpenClaw 接入 |
| MCP 框架 | FastMCP (Python 3.10+) | stdio 管道, JSON-RPC 2.0 |
| 扫描引擎 | nmap + python-nmap | asyncio 异步 |
| 设备连接 | paramiko / asyncssh (SSH/CLI) | 为主；gNMI 为辅 |
| CVE 数据库 | NVD REST API v2.0 | SQLite 本地缓存 |
| 流量采集 | NetFlow v5/v9, IPFIX, sFlow | 复用 ipfix-mcp |
| 协议分析 | tshark (Wireshark CLI) | BPF 过滤 |
| 暴力破解 | hydra | Kali 预置 |
| 3D 渲染 | Three.js 0.170.0 | WebGL + GSAP 3.12.5 |
| 后处理 | EffectComposer | Bloom/SMAA/Glitch/Film/Afterimage/RGBShift/Vignette |
| 实时通信 | WebSocket (ws 库) | Express.js 4.18.2 |
| 仿真环境 | GNS3 Server REST API | 端口 3080 |
| 审计存储 | Git bare repository | pre-receive hook 防篡改 |
| 缓存 | SQLite | CVE 结果缓存 |
| 测试 | pytest + unittest.mock | 参考 GNS3 MCP 测试 |

---

## 3. 关键设计约束

1. **MCP stdio 协议**: 不暴露网络端口，无端口管理，内核空间数据拷贝
2. **三级权限**: 只读 (自主) → 写操作 (须确认) → 破坏性 (禁止)
3. **TOON 序列化**: 所有 MCP 工具返回 TOON 格式，比 JSON 节省 40-60% token
4. **半自动响应**: AI 建议 → 人工确认 → 自动执行
5. **500ms 实时性**: 安全事件到 3D HUD 渲染端到端延迟 < 500ms
6. **60 FPS**: 28 设备 + 40+ 连接线场景下保持 60 FPS

---

## 4. IoT 指纹识别权重

| 维度 | 权重 | 依据 |
|------|------|------|
| Banner 解析 | 0.45 | 直接包含设备品牌标识 |
| 端口组合 | 0.35 | 模式区分能力强 |
| MAC OUI | 0.20 | 仅厂商层面推断 |

---

## 5. 安全状态 FSM

```
SECURE (绿) ──vuln_found──→ VULNERABLE (黄) ──attack_detected──→ ATTACKED (红)
                                                                    │
                                                        device_isolated
                                                                    ↓
                                                              ISOLATED (灰)

device_discovered → SECURE
* → SCANNING (蓝, 临时状态)
```

---

## 6. 攻击场景数据流 (Mirai 感染)

```
ReAct 轮次  |  Thought              |  Action                        |  Observation
1           | 了解告警详情           | syslog-collector/get_alerts     | 5min内12次登录失败
2           | 可能暴力破解,扫端口    | nmap-scan/port_scan             | Telnet(23)异常开放
3           | 查已知漏洞            | cve-intel/cve_by_device         | CVE CVSS 9.8 RCE
4           | 评估暴露面            | security-baseline/check_open_ports | 默认密码+Telnet+管理接口暴露
5           | 检查异常流量          | flow-analyzer/detect_anomaly    | 23/2323端口扫描150+IP
6           | 提取IoC确认          | traffic-analyzer/extract_ioc    | C2回连+恶意域名
7           | 证据充分,输出判定     | LLM综合分析                     | Mirai感染,置信度94%
```
