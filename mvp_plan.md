# CyberClaw MVP 计划 — 2 天冲刺

## 核心策略

**砍掉一切后端，全力聚焦 3D 安全 HUD 前端。** 用模拟数据代替真实 MCP 服务器，预编排 Mirai 攻击场景自动播放。

### 砍掉的 (MVP 不需要)
- ~~12 个 MCP 服务器~~ → 模拟数据生成器
- ~~OpenClaw Agent 框架~~ → 不需要
- ~~159 个 Skills~~ → 不需要
- ~~TOON 序列化~~ → JSON
- ~~真实 nmap/SSH/GNS3~~ → 全模拟
- ~~安全基线/CVE/流量分析~~ → 预设结果
- ~~config-audit/attack-timeline~~ → 简化版内嵌

### 保留并改造的 (MVP 核心)
- NetClaw 3D HUD 完整框架 (Three.js + GSAP + 后处理管线)
- WebSocket 实时推送架构
- 安全着色 FSM (SECURE/VULNERABLE/ATTACKED/ISOLATED)
- 攻击光束特效
- 设备拓扑可视化
- 安全指标面板

---

## 技术架构 (MVP)

```
┌─────────────────────────────────────────────────┐
│                CyberClaw 3D HUD                  │
│  (Three.js + GSAP + 10-layer Post-processing)   │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ IoT 拓扑  │  │ 安全着色  │  │ 攻击特效      │   │
│  │ 设备节点  │  │ FSM 状态机│  │ 光束/盾牌/爆炸 │   │
│  └──────────┘  └──────────┘  └──────────────┘   │
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │  Dashboard: 指标/时间线/告警/设备详情        │  │
│  └────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────┘
                     │ WebSocket
┌────────────────────┴────────────────────────────┐
│          Mock Data Server (server.js)             │
│                                                   │
│  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ IoT 拓扑数据  │  │ Mirai 攻击场景脚本        │  │
│  │ (15 设备)     │  │ (12 步自动播放)           │  │
│  └──────────────┘  └──────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

---

## Phase M1: 前端外壳 + 模拟后端 [Day 1, 0-12h]

**状态：** `pending`

### M1.1 复制 NetClaw HUD 基础框架
- 复制 `ui/netclaw-visual/` → `ui/cyberclaw-hud/`
- 安装依赖 (`npm install`)
- 验证能正常启动 (`npm run dev`)

### M1.2 品牌重塑 — NetClaw → CyberClaw
- `index.html`: 标题/品牌文字/样式 → CyberClaw
- `styles.css`: 主题色调整 (蓝→安全绿为基调)
- 加载动画: "NETCLAW" → "CYBERCLAW"
- Footer/侧栏文字更新

### M1.3 IoT 设备节点系统
**改造 `main.js` 中节点创建逻辑：**
- 删除 integrations 图谱逻辑
- 新增 IoT 设备类型定义 (6 种几何体):
  - `router`: 二十面体 (蓝灰色, 大)
  - `switch`: 八面体 (蓝灰色, 中)
  - `camera`: 球体 (绿色, 小)
  - `sensor`: 菱形 (绿色, 小)
  - `pc`: 立方体 (灰蓝色, 中)
  - `attacker`: 尖刺球 (红色, 中)
- 每设备携带安全状态属性 (SECURE/VULNERABLE/ATTACKED/ISOLATED)
- CSS2DObject 标签: 设备名 + IP + 状态指示灯

### M1.4 模拟 IoT 拓扑数据
**在 `server.js` 中硬编码拓扑:**
```
拓扑: 2 路由器 + 1 核心交换机 + 8 IoT 设备 + 1 管理PC + 1 Kali攻击机
  - Router-1 (10.0.1.1) ─── Switch-Core (10.0.0.1)
  - Router-2 (10.0.2.1) ─── Switch-Core
  - Switch-Core ─── Camera-1..4 (10.0.0.101-104)
  - Switch-Core ─── Sensor-1..2 (10.0.0.201-202)
  - Switch-Core ─── SmartPlug-1..2 (10.0.0.301-302)
  - Switch-Core ─── Admin-PC (10.0.0.10)
  - Router-1 ─── Kali (10.0.1.100) [攻击者]
```

### M1.5 安全着色 FSM 实现
- 五状态: SECURE(绿#00ff88) / SCANNING(蓝#00aaff) / VULNERABLE(黄#ffaa00) / ATTACKED(红#ff3344) / ISOLATED(灰#666688)
- GSAP 颜色渐变 (0.8s, Power2.easeInOut)
- 状态转换触发辉光强度变化
- 脉冲动画: ATTACKED 状态高频脉冲

### 验收标准
- [ ] `npm run dev` 启动，看到 CyberClaw 品牌
- [ ] 15 个 IoT 设备节点以 3D 拓扑呈现
- [ ] 设备有不同几何体和标签
- [ ] 安全着色 FSM 正常工作 (手动切换测试)

---

## Phase M2: 攻击特效 + 事件系统 [Day 1, 12-24h]

**状态：** `pending`

### M2.1 WebSocket 安全事件协议
定义 7 种事件类型:
```json
{
  "type": "device_discovered | vuln_found | attack_detected | port_scan | brute_force | malware_detected | device_isolated",
  "device": "Camera-1",
  "severity": "info | warning | critical",
  "details": { ... },
  "timestamp": "2026-04-27T10:00:00Z"
}
```

### M2.2 攻击光束特效
- 基于 Three.js Line2 / 自定义 BufferGeometry
- 流动粒子效果 (沿连接线方向移动的小光点)
- 颜色渐变: 蓝→橙→红→紫 (随攻击阶段变化)
- 对象池: 预分配 10 条光束，复用

### M2.3 防御盾牌特效
- 六边形网格球体 (custom shader)
- 从攻击目标位置展开 (0→1 scale, 1s)
- 半透明 + 边缘发光
- 颜色: 蓝色 (隔离中)

### M2.4 爆炸半径可视化
- 同心圆冲击波 (expanding ring geometry)
- 从受感染设备向外扩散
- 受影响设备高亮 (红橙色叠加)

### M2.5 后处理管线定制
- 复用 NetClaw 全部后处理层
- 定制 GlitchPass: 攻击检测时全局闪屏 (0.5s)
- Bloom 强度随威胁等级动态调整
- 三种画质模式保留

### 验收标准
- [ ] WebSocket 事件推送正常
- [ ] 攻击光束从一个设备流向另一设备
- [ ] 防御盾牌在目标设备展开
- [ ] 攻击时 GlitchPass 闪屏效果触发
- [ ] 后处理管线正常运行

---

## Phase M3: Dashboard 面板 + 告警系统 [Day 2, 0-12h]

**状态：** `pending`

### M3.1 顶部安全指标栏改造
替换 NetClaw 的 Integrations/Skills/Devices/Tools:
- **威胁等级**: 实时指标 (绿/黄/红/黑)
- **受感染设备**: X / 15
- **活跃告警**: 数量
- **已隔离设备**: 数量
- **扫描进度**: 百分比

### M3.2 左侧面板 — 告警时间线
替换 NetClaw 的 Filters/Settings:
- 实时告警流 (新告警从顶部滑入)
- 告警卡片: 时间 + 设备 + 类型 + 严重度颜色
- 点击告警 → 3D 视图聚焦到对应设备
- 告警过滤: All / Critical / Warning / Info

### M3.3 右侧面板 — 设备安全详情
替换 NetClaw 的 Selection/Detail:
- 设备名称、IP、类型、MAC
- 当前安全状态 (带状态转换图)
- 开放端口列表
- 已检测漏洞列表
- 最近事件时间线
- "隔离设备" 操作按钮 (模拟)

### M3.4 底部状态栏改造
- Agent 状态 (模拟: "CyberAgent 在线")
- 事件总数
- FPS 显示
- 攻击场景进度

### 验收标准
- [ ] 顶部指标随模拟事件实时更新
- [ ] 告警时间线正常滚动
- [ ] 点击告警能聚焦到 3D 设备
- [ ] 右侧面板显示完整设备安全信息

---

## Phase M4: Mirai 攻击演示场景 [Day 2, 12-24h]

**状态：** `pending`

### M4.1 Mirai 攻击剧本编排
12 步自动播放序列 (每步间隔 3-5 秒):

| 步骤 | 时间 | 事件 | 可视化 |
|------|------|------|--------|
| 1 | T+0s | 场景初始化, 15 设备全部 SECURE | 全绿色拓扑 |
| 2 | T+5s | Kali 开始端口扫描 | 蓝色扫描波从 Kali 扩散 |
| 3 | T+10s | 发现 Camera-1/2 开放 Telnet(23) | Camera-1/2 变为 VULNERABLE(黄) |
| 4 | T+15s | 暴力破解 Camera-1 密码 | 攻击光束 Kali→Camera-1, 红色闪烁 |
| 5 | T+20s | Camera-1 被攻陷 | Camera-1 变为 ATTACKED(红), 爆炸特效 |
| 6 | T+25s | Mirai 横向扩散到 Camera-2 | 攻击光束 Camera-1→Camera-2 |
| 7 | T+30s | Camera-2 被攻陷 | Camera-2 变为 ATTACKED |
| 8 | T+35s | 检测到 C2 回连异常 | 全局 Glitch 闪屏, 告警弹出 |
| 9 | T+40s | Agent 分析: Mirai 僵尸网络, 置信度 94% | 右侧面板显示分析结果 |
| 10 | T+45s | Agent 建议: 隔离 Camera-1/2 | 操作确认面板弹出 |
| 11 | T+50s | 确认隔离, 端口 shutdown | 防御盾牌展开, Camera-1/2 变为 ISOLATED(灰) |
| 12 | T+55s | 验证隔离成功, 威胁降级 | 指标变绿, 生成报告摘要 |

### M4.2 演示控制台
- "开始演示" 按钮
- 进度条 (12 步)
- "暂停/继续" 控制
- "重置" 按钮
- 手动触发单步事件 (可选)

### M4.3 最终打磨
- 加载动画优化 (安全主题)
- 响应式布局检查
- 截图/录屏友好 (Broadcast 模式)
- 整体色彩一致性

### 验收标准
- [ ] 点击"开始演示"后 Mirai 攻击场景自动播放
- [ ] 12 步事件依次触发, 3D 视图同步响应
- [ ] 告警面板实时滚动
- [ ] 演示结束后可重置重新播放
- [ ] 整体视觉效果专业流畅

---

## MVP 文件结构

```
cyberclaw/
├── ui/
│   └── cyberclaw-hud/          # 唯一开发的组件
│       ├── index.html           # 改造自 NetClaw
│       ├── package.json         # 改造自 NetClaw
│       ├── vite.config.js       # 直接复用
│       ├── server.js            # 改造: IoT 拓扑 + 模拟事件生成器
│       ├── src/
│       │   ├── main.js          # 大幅改造: IoT 设备节点 + 安全 FSM
│       │   └── styles.css       # 改造: CyberClaw 安全主题
│       └── public/
│           └── logos/
├── docs/
│   ├── mvp_plan.md              # 本文件
│   ├── findings.md              # 研究发现
│   └── progress.md              # 进度日志
└── README.md                    # 已推送到 GitHub
```

---

## 时间估算

| Phase | 内容 | 预计时间 | 累计 |
|-------|------|---------|------|
| M1 | 前端外壳 + 模拟后端 | 12h (Day 1 前半) | 12h |
| M2 | 攻击特效 + 事件系统 | 12h (Day 1 后半) | 24h |
| M3 | Dashboard 面板 | 12h (Day 2 前半) | 36h |
| M4 | Mirai 演示场景 | 12h (Day 2 后半) | 48h |

**关键路径:** M1→M2→M3→M4 是严格串行的。

---

## MVP vs 完整版对比

| 功能 | MVP | 完整版 |
|------|-----|--------|
| 3D 安全 HUD | ✅ | ✅ |
| 安全着色 FSM | ✅ 5 状态 | ✅ 5 状态 |
| 攻击光束特效 | ✅ 基础版 | ✅ 完整着色器 |
| 防御盾牌 | ✅ 基础版 | ✅ 六边形着色器 |
| Mirai 攻击演示 | ✅ 预编排 | ✅ 实时 ReAct |
| MCP 服务器 | ❌ Mock 数据 | ✅ 12 个 |
| OpenClaw Agent | ❌ | ✅ |
| Skills | ❌ | ✅ 15+ |
| GNS3 环境 | ❌ | ✅ |
| TOON 序列化 | ❌ | ✅ |
| 真实设备接入 | ❌ | ✅ |
| 后端完整闭环 | ❌ | ✅ |

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| (暂无) | | |
