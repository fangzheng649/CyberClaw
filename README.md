# CyberClaw — 面向IoT安全的全链路智能闭环防护系统

> AI-Powered IoT Security Automation Platform

## 项目简介

CyberClaw 是一个基于 AI Agent 的 IoT 安全自动化平台，基于 [OpenClaw](https://github.com/sunnyhuangcy/openclaw) 框架构建，实现 **"感知 → 检测 → 响应 → 复盘"** 全闭环安全能力。

### 核心特性

- **CyberScan 感知引擎** — 网络扫描、IoT 设备指纹识别、默认密码检测、拓扑自动构建
- **CyberSense 检测引擎** — 多源异构数据关联分析（Syslog/SNMP/CVE/流量）、AI 驱动威胁判定
- **CyberShield 响应引擎** — 半自动端口隔离、ACL 封堵、多厂商交换机适配
- **CyberReview 复盘引擎** — 攻击时间线构建、根因分析、合规报告生成
- **3D 安全 HUD** — 基于 Three.js 的实时安全态势可视化

### 技术栈

| 层级 | 技术 |
|------|------|
| AI Agent | OpenClaw Framework + Claude |
| MCP 服务器 | Python 3.10+ / FastMCP / stdio |
| 3D 可视化 | Three.js / WebGL / GSAP / 自定义 GLSL 着色器 |
| 实时通信 | WebSocket (ws) / Express.js |
| 仿真环境 | GNS3 Server REST API |
| 安全工具 | nmap / hydra / tshark / NVD API |

## 项目结构

```
CyberClaw/
├── mcp-servers/          # 12 个 MCP 安全工具服务器
│   ├── nmap-scan/        # 网络扫描与 IoT 指纹识别
│   ├── device-config/    # 设备配置管理 (SSH/gNMI)
│   ├── simulation/       # GNS3 仿真环境管理
│   ├── syslog-collector/ # Syslog 日志采集
│   ├── snmp-collector/   # SNMP Trap 采集
│   ├── cve-intel/        # CVE 漏洞情报查询
│   ├── security-baseline/# CIS 安全基线审计
│   ├── flow-analyzer/    # NetFlow/IPFIX 流量分析
│   ├── traffic-analyzer/ # 深度流量分析 (tshark)
│   ├── auto-response/    # 自动响应 (端口隔离/ACL)
│   ├── config-audit/     # 防火墙规则审计
│   └── attack-timeline/  # 攻击时间线与根因分析
├── workspace/skills/     # 安全闭环 Skills 编排定义
├── ui/cyberclaw-hud/     # 3D 安全态势可视化
├── src/cyberclaw_core/   # 共享库 (TOON 序列化, 工具函数)
├── config/               # Agent 配置文件
├── lab/                  # GNS3 实验环境配置
└── scripts/              # 安装与部署脚本
```

## 快速开始

> 开发中，敬请期待。

## 基于

本项目基于 [NetClaw](https://github.com/sunnyhuangcy/openclaw) 项目的基础设施进行改造开发，复用其 MCP 服务器框架、TOON 序列化库、3D HUD 渲染引擎和 Skills 编排体系。

## 许可证

MIT License

## 团队

- [@fangzheng649](https://github.com/fangzheng649)

---

> 中国高校计算机大赛 - 网络技术挑战赛 参赛项目
