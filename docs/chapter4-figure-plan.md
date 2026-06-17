# 第四章插图素材采集与批注方案

> 基于 31 张已视觉确认素材 + 正文 17 图位 + 代码/DB/配置交叉核对（含 critic 对抗验证）生成。
> **总原则：图与代码不一致时，以代码/图为准，正文需改。**

---

## 〇 前置：正文 ↔ 代码/数据 硬矛盾（critic 发现，截图/导出前必须先统一口径）

这些是「正文写了，但代码里不是这样」的硬伤，不先定口径，截图和导出的数据都会和正文打架。按优先级：

| # | 矛盾项 | 正文现写 | 代码/数据实际 | 建议决策 |
|---|---|---|---|---|
| 1 | **基线规则数** | 表4-5「53条规则」 | `security-baseline/server.py` 实际 **41条**（iot12+net15+cam10+cic4）；critical-infra profile 声明18实有4 | **改正文为41条**（不建议补14条SCADA规则，工作量大且无实测） |
| 2 | **攻击链步数** | 4.4「34步攻击脚本」+表4-4「34步事件」 | `scenario_service.py DEMO_SCRIPT` 实测 **28个delay事件/10阶段** | 改正文为「28步/10阶段」 |
| 3 | **表4-4 幽灵工具** | `flow-analyzer/detect_anomaly`、`auto-response/verify_isolation` | **这两个工具不存在**。flow-analyzer 实为 `ipfix_query_flows/ipfix_get_flow/...`；auto-response 实为 `isolate_device/restore_device/block_ip/get_response_status/...` | 表4-4 触发工具列改写为真实工具名 |
| 4 | **快捷按钮文案** | 4.3.2「扫描网络/检查漏洞/安全基线/帮助」 | `chat/main.js` quick-btn 实为「**扫描网络安全状态/分析安全漏洞/生成巡检报告/攻击复盘**」；「安全基线」「帮助」其实是 `/baseline`、`/help` **斜杠命令**，非快捷按钮 | 二选一统一（建议改正文对齐代码 UI，或改 UI 对齐正文） |
| 5 | **报告类型** | 4.3.5「事件报告/复盘报告/合规报告」 | `_infer_report_type` 实为「**复盘/巡检/合规**」，**「事件报告」不存在**（Mirai 报告走默认 report_type） | 改正文「事件报告」→「巡检报告」 |
| 6 | **ESP32 引脚** | 4.2.1「GPIO14」 | 固件 `#define DHT_PIN 4` → **GPIO4** | 改正文为 GPIO4（与代码一致），拍摄标注同步 |
| 7 | **MQTT topic** | 4.2.1「`cyberclaw/sensor/esp32-dht22`」 | 固件实为 **`cyberclaw/sensor/esp32-01/telemetry`** | 改正文 topic 名 |
| 8 | **AI 大模型** | 表4-1「DeepSeek API」 | `openclaw.json` 配 **`claude-sonnet-4-6`**（fallback haiku-4-5） | **核实实际部署用哪个**，全文统一（影响表4-1 + 所有 CyberAgent 截图可信度） |
| 9 | **性能数据** | 表4-5 全是「<30s/<50ms」占位符 + 声称「5次独立测量平均值」 | **全是估算上限，非实测，无原始数据** | 要么跑真实 benchmark（5次记录均值±标准差），要么删除「5次均值」声明 |
| 10 | **真实设备数据源** | （agent 称可从 DB 导出） | critic 警告：DB Devices 表当前 19 行可能**全是 mock**，真实设备在 `config/topology.json` | 导出 IP-MAC 表前**先核实 DB 是否有 config/mqtt 行**；稳妥起见从 topology.json 提取 |

> 这 10 条是整个第四章可信度的命门。建议在采集素材前先开一轮「正文断言 vs 代码事实」对账，定稿口径。

---

## 一、还需收集的素材

### A. Chat 界面指令截图（14 条 + 3 类界面）

> 指令原文已与 `INTENT_TOOL_MAP` / `match_intent` / `react_engine._REACT_BLOCKERS` / `SLASH_COMMANDS` / quick-btn `data-prompt` 逐一核对，**发出去就能截到对应卡片**。

| 优先级 | 指令原文（用户原话） | 预期 AI 输出 | 图位 | 状态 |
|---|---|---|---|---|
| **P0** | `扫描网络` | 2张步骤卡片(network_scan/iot_fingerprint) + 设备发现表(IP/端口/类型/厂商，端口着色) | **图4-7** | ❌缺 |
| **P0** | `分析当前有哪些安全漏洞` | cve-intel 卡片 + 漏洞清单表(CVE/CVSS/严重性) | 图4-7补充/快捷按钮印证 | ❌缺 |
| **P0** | `检查安全基线` | security-baseline 卡片(合规分+不合规项 Telnet/默认密码/SNMP) | **图4-12 右** | ❌缺 |
| **P0** | `隔离 192.168.1.11`（或`隔离 Camera-Entrance`） | 红框确认卡片(目标/原因/确认·取消按钮) | **图4-9 顶** | ❌缺 |
| **P0** | （点确认隔离后）执行进度消息 | iso-progress 逐条：连接交换机→下发端口关闭→验证隔离→完成 | **图4-9 中** | ❌缺（⚠️见伪方案预警） |
| **P0** | `生成Mirai攻击事件报告` | 5章 Markdown 报告(概述表+时间线+根因+处置+建议) | **图4-13** | ❌缺 |
| P0(已有) | `分析Camera-Entrance的安全状况` | 7张步骤卡片 + 底部结论 | **图4-8** | ✅有(chat七轮推理1/2) |
| **P1-strong** | `恢复设备` | auto-response/restore_device，解除隔离 | 图4-9 逆向(正文4.3.3点名) | ❌缺 |
| P1 | （界面）快捷按钮栏 welcome 屏 | 4个 quick-btn + placeholder | 4.3.2 印证 | ❌缺（⚠️受矛盾#4影响，先统一文案再截） |
| P1 | （界面）多会话管理 左侧栏 | conversation-list(标题/时间/active/删除) | 4.3.2 印证 | ❌缺 |
| P1 | `/help` | 斜杠菜单浮层 + 能力清单(5条命令) | 4.3.2「帮助」 | ❌缺 |
| ~~P2冻结~~ | ~~生成巡检报告 / 攻击复盘 / 定时任务~~ | — | — | P0未解前不做 |

**截图要点**：图4-8/4-13 用 Chrome **GoFullPage 整页长截图**；确认卡片要点「确认隔离」按钮；执行进度抓 ▸/✓ 混排帧或完成帧。

### B. 数据/表格型素材

| 优先级 | 素材 | 形式 | 来源 | 状态 |
|---|---|---|---|---|
| **P0** | **真实设备 IP-MAC-型号-角色映射表**（你点名） | 表 | `config/topology.json`（⚠️DB可能mock，见矛盾#10） | 待核实来源 |
| P0 | 24台设备完整清单(5物理+18仿真IoT+1攻击源) | 表 | topology.json + mock_topology.json | 可导出 |
| P0 | CVE 漏洞清单(含CVSS/CWE) | 表 | `cve-intel/server.py _MOCK_CVES`(7条) + scenario 剧本引用 | 可导出 |
| P0 | 安全基线 41 条规则清单 | 表 | `security-baseline/server.py RULES` | 可导出（注意矛盾#1） |
| P0 | 攻击链 28 步/10阶段时间线 | 表 | `scenario_service.py DEMO_SCRIPT` 或 DB security_events | 可导出（注意矛盾#2） |
| P0 | MQTT topic + payload JSON schema | 图/代码 | firmware main.cpp + mqtt_service.py | 可导出（注意矛盾#7） |
| P0 | 协议端口清单(风险着色依据) | 表 | security-baseline `_PORT_RULE_MAP` + topology expected_ports | 可导出 |
| **P0** | **性能测试原始数据(5次实测)** | 表 | **需跑 benchmark**（扫描/CVE/推理/帧率/隔离） | ❌缺（矛盾#9） |
| P0 | 12 MCP 服务器注册表 | 表 | `config/openclaw.json` + 各 server.py @mcp.tool 统计 | 可导出 |
| P1 | 隔离执行审计记录(action_id) | 表 | DB security_events(fsm_state=isolated) | 可导出 |
| P1 | 安全事件来源分布(支撑图4-11) | 表 | DB security_events GROUP BY source_type/fsm_state/severity | 可导出 |
| P2 | 18条链路清单 / ntfy三通道配置 / Dashboard数据样本 | 表 | mock_topology.json / notifications.json / DB | 可导出 |

**agent 已挖出的真实设备数据（待核实来源）**：
```
交换机   TP-LINK TL-SG2210LPF    192.168.1.1   60:A3:E3:61:81:0F  infrastructure
摄像头   海康 DS-2CD1023G2-L     192.168.1.11  8C:22:D2:41:0B:CA  target (Camera-Entrance)
摄像头   海康 DS-2CD1023G2-L     192.168.1.12  8C:22:D2:41:09:08  target (Camera-Lobby)
NVR      海康 DS-7108N-F1/8P     192.168.1.60  04:EE:CD:03:2C:46  infrastructure
传感器   ESP32-S3+DHT22          10.168.9.229  E8:3D:C1:F3:B4:58  target (WiFi网段)
```
> ⚠️ ESP32 在独立 WiFi 子网(10.168.9.x)，与 192.168.1.0/24 物理网段不同，broker 在笔记本 10.168.9.244，正文需如实说明。

### C. 实物/环境照 shot list

| 优先级 | 拍什么 | 图位 | 要点 |
|---|---|---|---|
| **P0** | 实验台正式全景（黑底干净版） | 图4-2a | 黑布/深灰卡纸铺底、双灯45°、正俯拍+30°斜拍、网线理顺、>3000px（现「真实设备图.png」可用但缺干净底版） |
| **P0** | 交换机正面特写（露Port1/2/3） | 图4-2b | 竖起/45°拍端口面，Port1/2插摄像头、Port3插NVR，Link灯常亮，贴标签或后期引线 |
| **P0** | ESP32+DHT22 杜邦线引脚特写 | 图4-2d | 微距拍排针丝印 **3V3/GPIO4/GND**（注意矛盾#6），三色线区分，DHT22 的+/OUT 丝印入镜 |
| **P0** | 设备铭牌型号特写×3 | 图4-2子图/佐证表4-2 | 交换机 TL-SG2210LPF、摄像头 DS-2CD1023G2-L×2、NVR DS-7108N-F1/8P，SN打码 |
| P1 | ESP32 USB→电脑实物链路 | 图4-3右上旁证 | 两端入镜，可与串口日志合成 |
| P1 | PoE 供电（推荐Web页） | 图4-2b右半 | 登录 192.168.1.1 截 PoE 供电页(Port1/2功率) |
| P1 | 网络物理拓扑示意 | 图4-2e(新增) | PPT画：交换机为中心，标IP/MAC/端口/协议 |
| P2 | 温湿度实测环境 / Web端口状态 / 现场署名防质疑照 | 附录/佐证 | 署名纸条「CyberClaw 安全验证 2026-06」入镜防网图质疑 |

### D. critic 补的关键缺口（五维方案漏掉的）

| 优先级 | 缺口 | 支撑 |
|---|---|---|
| **P0** | **隔离效果验证终端截图**（nmap/arping 验证端口无响应） | 表4-4「响应/设备隔离效果验证」行，当前只有HUD前后对比，无终端实证 |
| **P0** | **端到端18秒=4+13+1 拆分证据**（带时间戳的日志/chat） | 表4-5 性能断言，当前无任何佐证 |
| **P0** | **5次测量原始数据**（均值±标准差） | 4.5节「5次独立测量平均值」学术规范 |
| P0 | **表4-1 硬件环境行**（CPU/RAM/GPU/主机型号） | 章节标题「软硬件环境」却只有软件栈 |
| P1 | 默认密码 50+组凭证字典来源证据 | 表4-5「default_credential_check 50+组」可验证性 |
| P1 | 图4-5 详情面板「合规评分/事件时间线」两维度可见性 + 合规分(72 vs 62)核实 | 图4-5 正文6维度 |

### E. 伪方案预警（截图前必须先核实前端有无渲染逻辑）

| 图位 | 子图 | 风险 | 核实点 |
|---|---|---|---|
| 图4-3 | 右下「ESP32详情面板」 | 可能是伪方案 | 核实 `main.js` 是否有 sensor 节点 MQTT payload 详情面板渲染；无则开发或删该子图 |
| 图4-9 | 中部「执行进度」 | 可能只有1条 | 核实 `main.js` 的 `iso-progress/stages` 数组是否真渲染多条（可能只有一条 `Isolating...`） |

---

## 二、批注 + 合并方案

### A. 工具选型（统一）

- **PIL 脚本（主力B）**：单图统一红框+序号+打码+图注，批量遍历 `raw/` → `final/`。项目已装 Pillow 12.0.0。
- **PPT（主力A）**：7张合成图 + 黄箭头 + 引线，一个 `chapter4_figs.pptx` 每图一 slide，样式用「设为默认形状」锁死。
- **Snipaste（辅助）**：截图时临时框选/取色。
- **不用**：OpenCV（未装）/ matplotlib（非批注用）/ Excalidraw（手绘风不符）/ Photoshop（过重）。

### B. 全章统一色值/字体表（锁死，不得漂移）

| 元素 | 色值/字体 |
|---|---|
| 红框（关键圈注） | `#D9342B` 实线，单图3px / 合成图4px |
| 黄箭头（模块关联） | `#FFC107`，末端实心三角 |
| 黄底高亮（强调值） | `#FFF59D` 黑字 |
| 橙底高亮（警告值） | `#FB8C00` 白字 |
| 打码块 | `#5A5A5A` 实心（**不用马赛克颗粒**） |
| 分割线（合成图） | `#C8C8C8` 1.5px |
| 序号圆 | 白底 `#FFFFFF` + 红字 `#D9342B`，单图直径40px / 合成56px |
| 引线 | `#000000` 2px + 黄箭头 |
| 外描边 | `#BDBDBD` 1px |
| 图注字 | `#1A1A1A`，微软雅黑 Regular 10.5pt 居中 |
| 中文字体 | 微软雅黑 `msyh.ttc`（图注10.5pt / 序号Bold12pt / 子图标签9pt） |
| 等宽字体 | Consolas（终端高亮/打码白字 12pt） |
| 图注格式 | 「图4-x 标题(子图说明)」，居中，距图底8px |

> ⚠️ workflow 两个 agent 给了 `#E53935` 和 `#D9342B` 两个红，本方案**统一用 `#D9342B`**（朱红，区别于设备 attacked 状态红 `#F44336`）。

### C. 每类图批注规范

| 图类 | 红框 | 序号 | 高亮 | 特殊 |
|---|---|---|---|---|
| 终端日志(4-1左/4-3右上) | 圈关键行(12 MCP/MQTT connected) | 行首①②③ | 关键值黄底 | 截图前确认 Consolas/Cascadia Mono |
| 3D HUD(4-4/4-5/4-6/4-14) | 4px圈节点/面板 | 白底红框圆(背景有色) | CVE/CVSS 黄底 | 图旁加状态色图例(绿/蓝/橙/红/灰) |
| Chat(4-7/4-8/4-9/4-13) | 圈输入框/卡片/结论 | 卡片左侧①~⑦ | 结论橙底白字(置信度96%) | 长图GoFullPage |
| 实物照(4-2) | 4px圈铭牌/网口/杜邦线 | 白底红框圆 | — | 引线标 Port/VCC·GPIO4·GND/PoE |
| 合成图(4-1/3/6/9/12/14) | 2px圈关键 | 子图(a)(b)(c)+主序①②③ | — | 16px白边分隔，整体1px灰描边 |

### D. 打码规范

| 信息 | 处理 | 样式 |
|---|---|---|
| 内网IP(192.168.x/10.x) | **保留不打码**（实验网段，增真实感） | — |
| 公网IP(如185.220.101.34) | 打码后3位 | `185.220.xxx.xxx` 灰块 |
| 账号/密码(admin/12345、WiFi密码) | 整段打码 | `●●●●●` 灰块 |
| Token/API Key | 整段打码 | `sk-●●●●●(API KEY)` 保留前缀 |
| 手机号/WiFi SSID(含个人信息) | 打码 | 灰块 |
| 姓名/个人路径(C:\Users\xxx) | 打码 | 灰块 |
| MAC地址 | 前三字节(OUI)保留，后三打码 | `8C:22:D2:XX:XX:XX` |
| 序列号 | 整段打码 | 灰块 |

> 统一用**灰色实心块 `#5A5A5A`**（不用马赛克颗粒——缩印时糊成瑕疵）；块上叠白色等宽字标注类型（如`(API KEY)`），让评审明白码的是什么。

### E. 6 个合成图排版（ASCII + 像素）

通用：单栏1650px / 双栏1888px @300dpi，Pad12，Gutter16，纯白底。

**图4-1 启动** — 左右1:1，1888×637
```
+--------------------+--------------------+
| (a) [后端日志]      | (b) [3D HUD 全绿]   |
| [红框:12 MCP/tools] |                    |
+--------------------+--------------------+
  (a) 后端启动日志      (b) 3D安全HUD初始加载
            图4-1 系统启动运行效果
```

**图4-3 发现+传感器通道** — 左6右4，1888×753（⚠️右下缺素材）
```
+----------------------+----------------------+
| (a)                  | (b) [ESP32日志]       |
| [5物理设备HUD]       | [红框:MQTT connected] |
| [红框:节点群]        +----------------------+
|                      | (c) [ESP32详情面板]⚠️缺|
+----------------------+----------------------+
  (a)物理设备HUD  (b)ESP32日志  (c)详情面板
```

**图4-6 五状态横拼** — 5等分，1888×317（每张下加状态色条）
```
+-------+-------+-------+-------+-------+
|①绿    |②蓝波纹|③橙振荡|④红光束|⑤灰盾  |
+=======+=======+=======+=======+=======+
|■secure|■scan  |■vuln  |■attack|■isolat|
+-------+-------+-------+-------+-------+
```
> 候选帧：①1.png ②6.png ③15.png ④18.png ⑤29.png（⚠️节点状态色在3D节点上，边框是灰，必须靠色条区分）

**图4-9 隔离三段纵叠** — 3:2:5，1888×1166（⚠️上中段缺素材）
```
+----------------------------------------+
| ① [红框确认卡片: 设备/IP/Mirai 96%] ⚠️缺|
|   [红框:确认隔离按钮]                   |
+----------------------------------------+
| ② [Chat执行进度: 封禁→验证通过] ⚠️缺    |
+----------------------------------------+
| ③ (左)attacked红 | → | (右)isolated灰盾 |
+----------------------------------------+
```

**图4-12 设备列表+基线** — 左右1:1，1888×637（⚠️右缺素材）
```
+--------------------+--------------------+
| (a) 设备清单表格    | (b) [合规62分红条]⚠️缺|
| [红框:attacked+Telnet]| [Critical]Telnet   |
|                    | [Critical]默认密码   |
+--------------------+--------------------+
```

**图4-14 六宫格** — 2×3，1888×890（每格下加阶段色条）
```
+----------+----------+----------+
|①初始全绿 |②7台蓝scan|③入口红attack|
+----------+----------+----------+
|④6台红扩散|⑤6台灰isol|⑥清除完成   |
+----------+----------+----------+
```
> 候选帧：①1.png ②6.png ③18.png ④22.png ⑤29.png ⑥32.png

### F. PIL 批注脚本骨架（`scripts/annotate_chapter4.py`）

```python
from PIL import Image, ImageDraw, ImageFont

RED=(217,52,43)      # #D9342B
YEL=(255,193,7)      # #FFC107
YELBG=(255,245,157)
ORN=(251,140,0)
GRAY=(90,90,90)      # 打码
CAP=(26,26,26)

f_yh   = ImageFont.truetype('C:/Windows/Fonts/msyh.ttc', 21)    # 微软雅黑 10.5pt
f_yh_b = ImageFont.truetype('C:/Windows/Fonts/msyhbd.ttc', 24)  # Bold 序号
f_mono = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 24)

def annotate(img_path, boxes, out_path, caption):
    """boxes: [(x1,y1,x2,y2,num), ...] 红框+序号"""
    im = Image.open(img_path).convert('RGB')
    d = ImageDraw.Draw(im, 'RGBA')
    for (x1,y1,x2,y2,num) in boxes:
        d.rectangle([x1,y1,x2,y2], outline=RED, width=3)
        d.ellipse([x1-20,y1-20,x1+20,y1+20], fill='white', outline=RED, width=3)
        d.text((x1-12,y1-16), num, font=f_yh_b, fill=RED)
    w = d.textlength(caption, font=f_yh)
    d.text(((im.width-w)/2, im.height+8), caption, font=f_yh, fill=CAP)
    im.save(out_path)

def redact(im, box, label=None):
    """统一打码：灰色实心块 + 可选白色类型标签"""
    d = ImageDraw.Draw(im)
    x1,y1,x2,y2 = box
    d.rectangle([x1-2,y1-2,x2+2,y2+2], fill=GRAY)
    if label:
        d.text((x1+4,y1+2), label, font=f_mono, fill='white')
```

合成图脚本骨架：`scripts/figure_compose/compose_fig4-X.py`（每图一份），共用 `_common.py`（make_canvas/paste_fit/draw_divider/draw_badge/draw_redbox/draw_caption）。色条配色：`SECURE=#3FA34D, SCANNING=#2D7DD2, VULN=#F39237, ATTACKED=#D9342B, ISOLATED=#9AA0A6`。

---

## 采集执行优先级（建议顺序）

1. **先定口径**：解决前置矛盾 #1~#10（尤其 #1/#2/#3/#4/#5/#8，影响表格与截图文案）
2. **核实伪方案**：图4-3右下、图4-9中部前端渲染（决定是否要开发）
3. **截 P0 chat 指令**：扫描网络/隔离/生成报告/检查基线（5条，开发已就绪发指令即出）
4. **导出数据表**：IP-MAC映射/设备清单/CVE/基线/攻击链（从代码+config）
5. **重拍实物 P0**：全景黑底版/交换机正面/ESP32引脚/铭牌
6. **跑性能 benchmark**：表4-5 五次实测（或删「5次均值」声明）
7. **批注+合成**：PIL 批量批注 → PPT 合成 7 张 → 导出 300dpi PNG
