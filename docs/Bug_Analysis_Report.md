# CyberClaw 全项目诊断报告

> 生成日期：2026-06-03  
> 覆盖范围：后端 17 个 API 端点、17 个服务文件、12 个 MCP 服务器、8 个前端文件、6 项集成检查

---

## 一、已修复的关键 Bug

### Bug #1：调度任务 trigger/delete 操作静默失败

**文件**：`ui/cyberclaw-hud/chat/main.js` → `handleTaskAction()`（line 934）

**问题描述**：  
`handleTaskAction` 函数对所有操作（pause/resume/trigger/delete）统一使用 URL 模式 `/api/scheduler/tasks/${taskId}/${action}` + `POST` 方法。但后端 `scheduler_router.py` 的路由定义不同：

| 前端构造的 URL | 后端实际路由 | 问题 |
|---|---|---|
| `POST /api/scheduler/tasks/{id}/pause` | `POST /api/scheduler/tasks/{id}/pause` | ✅ 匹配 |
| `POST /api/scheduler/tasks/{id}/resume` | `POST /api/scheduler/tasks/{id}/resume` | ✅ 匹配 |
| `POST /api/scheduler/tasks/{id}/trigger` | `POST /api/scheduler/trigger/{id}` | ❌ 路径结构不同 |
| `POST /api/scheduler/tasks/{id}/delete` | `DELETE /api/scheduler/tasks/{id}` | ❌ 方法和路径都不同 |

**系统影响**：  
- trigger 请求发送到 `/api/scheduler/tasks/{id}/trigger`，后端返回 `404 Not Found`
- delete 请求发送到 `/api/scheduler/tasks/{id}/delete`，后端返回 `404 Not Found`
- 但前端 `handleTaskAction` 在 `action === 'delete'` 时跳过了错误检查（`if (!resp.ok && action !== 'delete')`），导致 delete 操作连错误提示都没有

**前端体现**：  
- 用户点击任务卡片的"立即触发"按钮 → 无反应，不执行也不报错
- 用户点击"删除"按钮 → 任务列表不刷新，任务仍然存在
- 操作历史中可能偶尔出现错误记录，但大部分时候静默失败

**修复方案**：  
按后端路由分别构建 URL 和 HTTP method：
```javascript
if (action === 'trigger') {
  url = `/api/scheduler/trigger/${taskId}`;
  method = 'POST';
} else if (action === 'delete') {
  url = `/api/scheduler/tasks/${taskId}`;
  method = 'DELETE';
} else {
  url = `/api/scheduler/tasks/${taskId}/${action}`;
  method = 'POST';
}
```

---

### Bug #2：Font Awesome 图标 `fa-radar` 不存在

**文件**：`ui/cyberclaw-hud/chat/main.js`（line 514）

**问题描述**：  
`/scan` 斜杠命令使用了 `<i class="fa-solid fa-radar"></i>`，但 Font Awesome 6.5.x Free 版本中不存在 `fa-radar` 图标。

**系统影响**：  
Font Awesome 无法识别该图标类名，渲染为空白元素，不显示任何图标。

**前端体现**：  
- 用户在 Chat 输入框输入 `/` 弹出命令菜单
- `/scan` 命令旁边显示空白区域，没有图标
- 与其他命令的图标（`fa-tower-broadcast`、`fa-shield-halved` 等）形成视觉不一致

**修复方案**：  
替换为 `fa-satellite-dish`，属于同语义图标且在 Font Awesome Free 中可用。

---

### Bug #3：`scheduler_router.py` 的 `update_config` 调用不存在的方法

**文件**：`server/api/scheduler_router.py`（line 148-151）

**问题描述**：  
```python
@router.put("/config")
async def update_config(body: dict):
    scheduler = get_security_scheduler()
    scheduler.update_config(body)  # ← AttributeError!
```
`SecurityScheduler` 类只有 `_load_config()` 和 `_save_config()` 私有方法，没有 `update_config()` 公开方法。

**系统影响**：  
- 任何对 `PUT /api/scheduler/config` 的请求都会触发 `AttributeError`
- FastAPI 返回 `500 Internal Server Error` 并附带完整 traceback
- 调度器的全局配置（如 `enabled` 开关）无法通过 API 修改

**前端体现**：  
- 前端目前没有直接调用此端点，但如果有设置面板尝试切换调度器启用/禁用，会看到 500 错误

**修复方案**：  
直接操作 `_config` dict 并调用 `_save_config()`：
```python
for k, v in body.items():
    if v is not None:
        scheduler._config[k] = v
scheduler._save_config()
```

---

### Bug #4：通知 API 裸 `dict` 参数导致 422 Unprocessable Entity

**文件**：`server/api/notification_router.py`（line 74, 83）

**问题描述**：  
```python
@router.post("/mark-all-read")
async def mark_all_read(body: dict = None):  # ← FastAPI 无法解析

@router.delete("/history")
async def clear_notifications(body: dict = None):  # ← 同样问题
```
FastAPI 要求 POST/DELETE 请求的 JSON body 必须通过 `Body()` 注解或 Pydantic 模型声明。裸 `dict` 参数在没有请求体时会触发 `422 ValidationError`。

**系统影响**：  
- 前端调用 `POST /api/notifications/mark-all-read`（不发送 body）→ 422
- 前端调用 `DELETE /api/notifications/history`（不发送 body）→ 422
- 通知的"全部已读"和"清空"功能完全无法使用

**前端体现**：  
- 用户点击"全部已读"按钮 → 通知状态不变，未读标记不清除
- 用户点击"清空通知"按钮 → 通知列表不清空
- 浏览器开发者工具 Network 面板可见 422 响应
- 同文件中的 `update_notification_config`（line 23）和 `test_notification`（line 32）也存在同样问题

**修复方案**：  
使用 `Request` 对象手动解析可选的 JSON body：
```python
async def mark_all_read(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
```

---

### Bug #5：演示结束后设备状态永远停留在 `isolated`

**文件**：`server/services/scenario_service.py` → `_reset_devices()` + `_run()`

**问题描述**：  
Mirai 演示的 25 步脚本执行完毕后：
1. `_update_device_status()` 将受感染设备标记为 `isolated`
2. 场景运行时通过 `nx_bridge.update_device_status()` 将状态写入数据库
3. 演示结束后 `_reset_devices()` 只重置了内存中的设备列表
4. 数据库中的 `devStatus` 字段仍为 `isolated`/`attacked`/`vulnerable`
5. 前端刷新页面时从数据库读取拓扑，继承旧状态

**系统影响**：  
- 演示结束后，Camera-Entrance/Lobby/ServerRoom 和 SmartPlug-AC 在数据库中永远标记为 `isolated`
- 下次打开前端，即使没有运行任何场景，设备也显示为隔离/受攻击状态
- 手动停止场景同样不清理数据库

**前端体现**：  
- 3D HUD：设备节点永远显示为红色（attacked）或灰色（isolated）
- Chat 界面"设备清单"：设备状态列显示 "isolated" 而非 "secure"
- Dashboard：安全评分因设备状态异常而偏低
- 唯一恢复方式：手动清空数据库或重启整个服务

**修复方案**：  
1. `_reset_devices()` 改为 `async`，新增 `reset_db=True` 参数，同时更新数据库
2. `start()`、`stop()`、`_run()` 完成时均调用 `_reset_devices(reset_db=True)`
3. 演示完成后增加 3 秒延迟 + `scenario_reset` 广播事件

---

### Bug #6：3D HUD 攻击光束渲染失败

**文件**：`ui/cyberclaw-hud/src/main.js`（line 964）

**问题描述**：  
```javascript
fireAttackBeam(msg.source || 'kali', msg.target, 0xffaa00);
```
当 WebSocket 收到 `lateral_movement` 事件时，`msg.source` 为设备 ID（如 `camera-entrance`），如果 source 为空则回退到 `'kali'`。但当前拓扑中没有 ID 为 `kali` 的设备（旧拓扑的攻击机），`fireAttackBeam` 在 `state.devices` 中找不到匹配设备，攻击光束不会渲染。

**系统影响**：  
- 部分攻击事件的视觉反馈缺失
- 不影响功能逻辑（设备状态仍正确更新），仅影响 3D 可视化

**前端体现**：  
- 当 `source` 字段为空时（理论上不应该，但防御性编码需要考虑），攻击光束不显示
- 日志中无错误（静默跳过）

**修复方案**：  
将回退 ID 改为拓扑中存在的 `firewall`（防火墙设备，语义上也合理表示外部攻击来源）。

---

### Bug #7：Chat 界面快捷操作图标与风格不符

**文件**：`ui/cyberclaw-hud/chat/index.html`（line 86-97）

**问题描述**：  
四个快捷操作按钮使用了 emoji 图标（📡🔍🛡️📊），但整个界面其他位置已统一使用 Font Awesome 图标。

**前端体现**：  
- emoji 图标在不同操作系统上渲染效果不同（Windows 彩色 vs macOS 风格化）
- 与旁边"调度任务"的 Font Awesome 图标形成明显风格断裂
- 在深色背景下，彩色 emoji 尤其突兀

**修复方案**：  
全部替换为 Font Awesome 图标：
- 📡 → `fa-tower-broadcast`
- 🔍 → `fa-bug`
- 🛡️ → `fa-shield-halved`
- 📊 → `fa-chart-line`

---

## 二、已修复的非 Bug 问题

### Alert Timeline 白色滚动条

**文件**：`ui/cyberclaw-hud/src/styles.css` → `.alert-list`

**问题**：`.alert-list` 设置了 `overflow-y: auto` 但没有覆盖浏览器默认的滚动条样式，Windows 11 上显示为白色粗滚动条。

**前端体现**：3D HUD 右侧 Alert Timeline 区域出现与深色主题完全不协调的白色滚动条。

**修复**：添加 `scrollbar-width: thin` + `scrollbar-color` + `::-webkit-scrollbar` 规则。

---

### Dashboard 告警列表滚动条

**文件**：`ui/cyberclaw-hud/src/dashboard.css` → `.da-list`

**问题**：缺少 `scrollbar-track` 和 `scrollbar-width`，部分浏览器仍显示白色轨道。

**修复**：补充 `scrollbar-track: transparent` + `scrollbar-width: thin`。

---

### Syslog Collector 设备匹配

**文件**：`ui/cyberclaw-hud/src/main.js`（line 1103）

**问题**：  
```javascript
const hostDev = state.devices.find(d => d.ip === evt.hostname);
```
3D HUD 中设备数据结构为 `{ id, payload: { ip, name, ... }, status }`，没有顶层 `ip` 属性，导致 `d.ip` 始终为 `undefined`。

**系统影响**：  
收到高危 syslog 事件时，应该将对应设备标记为 `attacked` 状态，但因为匹配失败，设备状态不变。

**前端体现**：  
- Syslog Collector 收到来自 192.168.10.11 的 critical 事件
- Alert Timeline 正常显示告警卡片
- 但设备节点不会变红（状态不变）
- 数据库也不更新（因为前端没触发 `updateDeviceStatus`）

**修复**：`d.ip || d.payload?.ip`。

---

## 三、未修复的后端问题

### 3.1 数据库连接泄漏

**文件**：
- `server/services/notification_bridge.py` — `_persist_notification`、`_mark_processed`、`get_notifications`、`get_unread_count`、`mark_read`、`mark_all_read`、`clear_notifications`
- `server/services/security_scheduler.py` — `_record_run`、`get_history`
- `server/services/process_scan.py` — `_enrich_device`

**问题**：DB 连接在 `conn = get_temp_db_connection()` 之后、`conn.close()` 之前如果抛出异常，连接不会被关闭。

**系统影响**：  
SQLite 使用文件锁，泄漏的连接会占用文件句柄。在长时间运行后，可能导致：
- `OperationalError: database is locked` — 新操作无法获取锁
- 文件描述符耗尽
- 内存缓慢增长

**前端体现**：  
- 间歇性地，通知历史页面加载缓慢或返回空结果
- 调度任务执行后历史记录不更新
- 严重时，所有涉及数据库的 API 返回 500 错误

---

### 3.2 `process_scan.py` 下线检测为死代码

**文件**：`server/services/process_scan.py` → `_sync_update_presence`

**问题**：  
1. 第一步将 CurrentScan 中所有设备设为 `devPresentLastScan=1`
2. 第二步查询 `devPresentLastScan=1 AND NOT IN CurrentScan` 来检测下线设备
3. 由于第一步已经将所有 CurrentScan 设备设为 1，第二步的 `NOT IN CurrentScan` 条件与 `devPresentLastScan=1` 互斥
4. 同理，重连检测也因同样的原因为死代码

**系统影响**：  
- 设备从在线变为离线时不会触发通知
- 设备从离线恢复时不会触发通知
- "down_devices" 通知通道永远为空

**前端体现**：  
- 历史标签中"离线"分类永远没有通知
- Dashboard 不显示设备下线事件
- 安全评分不受设备离线影响

---

### 3.3 `scenario_service.py` Live 模式重放旧事件

**文件**：`server/services/scenario_service.py` → `_run_live`

**问题**：  
`_last_seen_event_id` 初始化为 0。如果数据库中已有历史安全事件，`get_security_events(limit=50)` 会返回这些旧事件，由于 ID 都大于 0，它们会被当作"新事件"全部重放。

**系统影响**：  
- 切换到 Live 模式时，前端突然涌入大量旧事件
- 设备状态被旧事件覆盖（例如已被隔离的设备因旧的"secure"事件恢复正常）

**前端体现**：  
- Alert Timeline 突然出现大量历史告警
- 设备节点颜色快速闪烁变化

---

### 3.4 `dashboard.py` 告警总数不准确

**文件**：`server/api/dashboard.py`（line 39）

**问题**：  
`count_security_events()` 返回过去 24 小时的事件总数，忽略了前端传入的 `severity`/`source_type` 过滤条件。分页查询 `get_security_events()` 应用了过滤，但 `total` 字段始终是未过滤的总数。

**系统影响**：  
分页逻辑基于错误的 total 计算，可能导致：
- 显示"共 200 条"但实际只筛选出 10 条 critical 事件
- 分页按钮显示错误（total=200 但只有 1 页数据）

**前端体现**：  
- Dashboard 告警列表上方的总数不随筛选条件变化
- 切换严重度过滤后，总数不变

---

### 3.5 相对路径问题

**文件**：
- `server/api/chat.py` — `Path('data/chat_history.json')`
- `server/api/notification_router.py` — `Path('config/notifications.json')`
- `server/services/nx_bridge.py` — `'config/workflows.json'`

**问题**：使用相对路径，依赖进程工作目录为项目根目录。如果从其他目录启动 uvicorn，路径将解析错误。

**系统影响**：  
- 从非项目根目录启动时，聊天历史无法保存/加载
- 通知配置找不到
- 工作流事件处理失败

**前端体现**：  
- 聊天记录在重启后丢失
- 通知配置重置为默认值

---

## 四、未修复的前端问题

### 4.1 Scan Scheduler HTML 元素缺失（功能完全失效）

**文件**：`ui/cyberclaw-hud/chat/main.js`（line 1355-1407）+ `chat/index.html`

**问题**：  
`main.js` 中 `initScanScheduler()` 查找 `#btn-scan-start`、`#btn-scan-stop`、`#scan-subnet`、`#scan-interval` 等 DOM 元素，但 `index.html` 中从未添加这些元素。

**系统影响**：  
- `initScanScheduler()` 在 line 1357 处 `if (!btnStart || !btnStop) return` 直接退出
- `renderScanStatus()` 在 line 1386 处 `if (!dotEl) return` 直接退出
- 整个 Scan Scheduler 功能为死代码，完全不可用

**前端体现**：  
- Operations 标签中没有扫描调度 UI
- 快捷操作中的"全网扫描"按钮通过 Chat API 工作（绕过了 Scan Scheduler）
- `GET /api/tools/scan-schedule/status` 仍然可用但无人调用

---

### 4.2 CSS 变量 `--text-dim` 未定义

**文件**：`ui/cyberclaw-hud/chat/style.css`（line 1799, 1899）

**问题**：  
这两行引用了 `var(--text-dim)` 但 `:root` 块中没有定义此变量。

**前端体现**：  
- 调度任务面板中部分文字颜色回退为浏览器默认（通常为黑色）
- 在深色背景下，这些文字可能几乎不可见

---

### 4.3 缺失 CSS 类

**文件**：`ui/cyberclaw-hud/chat/style.css`

| 缺失的 CSS 类 | 引用位置 | 影响 |
|---|---|---|
| `.mcp-tools-count` | main.js line 1316 | MCP 服务器工具计数无样式 |
| `.td-name` | main.js line 1694, 2592 | 设备表格名称列无特殊样式 |
| `.report-item` | main.js line 1461 | 报告列表项无样式 |
| `.report-list-container` | index.html line 97 | 报告列表容器无样式 |

**前端体现**：这些元素虽然可见但缺少预期的间距、字体大小和颜色，与周围元素风格不一致。

---

### 4.4 WebSocket 重连无退避策略

**文件**：`ui/cyberclaw-hud/src/main.js`（line 880-881）

**问题**：  
```javascript
ws.onclose = () => setTimeout(connectWS, 2500);
```
无论服务器是否可恢复，都固定每 2.5 秒重连，没有指数退避或最大重试次数。

**前端体现**：  
- 后端关闭时，浏览器控制台每 2.5 秒输出连接错误日志
- 长时间离线后重新启动后端，WebSocket 能恢复但已经浪费了大量重连尝试
- 在移动设备上可能导致电池消耗

---

### 4.5 XSS 风险（innerHTML 注入未转义数据）

**文件**：`ui/cyberclaw-hud/src/main.js`（line 674-678, 797, 804-810）

**问题**：  
多个 `innerHTML` 赋值直接注入服务器返回的数据（设备名称、告警消息、IP 地址等），未经 HTML 转义。

**系统影响**：  
如果恶意设备发送包含 `<script>` 标签的 syslog 消息，理论上可在前端执行任意 JavaScript。由于 CyberClaw 是本地部署的安全工具，实际风险较低，但作为安全产品应当注意。

**前端体现**：  
仅在攻击者能控制 syslog 消息内容时触发，正常使用不会出现。

---

## 五、MCP 服务器问题

### 5.1 config-audit 导入不存在的模块

**文件**：`mcp-servers/config-audit/server.py`（line 31）

**问题**：  
```python
from server.services.config_fetcher import fetch_config
```
`server/services/config_fetcher.py` 文件不存在。导入被 try/except 捕获，工具函数进入 fallback 路径返回 `status=unavailable`。

**系统影响**：  
- `config-audit` MCP 服务器的所有审计工具永远返回"不可用"
- 无法对设备配置进行安全审计
- 不影响其他功能，因为 MCP 工具调用有错误处理

---

### 5.2 device-config 引用旧项目名

**文件**：`mcp-servers/device-config/gnmi_mcp_server.py`

**问题**：  
- 模块文档字符串中包含 "NetClaw"（违反 CLAUDE.md 命名规则）
- 导入 `netclaw_tokens.toon_serializer`（不存在于当前项目，但被 try/except 静默跳过）

**系统影响**：  
不影响功能，但违反项目命名规范，可能造成维护混淆。

---

### 5.3 多个 MCP 服务器文件名不符合规范

CLAUDE.md 要求 `mcp-servers/{name}/server.py`，但以下服务器使用不同文件名：

| 目录 | 实际文件名 | 说明 |
|---|---|---|
| `device-config/` | `gnmi_mcp_server.py` | 继承自 gnmi-mcp |
| `simulation/` | `gns3_mcp_server.py` | 继承自 gns3-mcp-server（CLAUDE.md 已标注例外） |
| `syslog-collector/` | `syslog_mcp_server.py` | 继承自 syslog-mcp |
| `snmp-collector/` | `snmptrap_mcp_server.py` | 继承自 snmptrap-mcp |
| `flow-analyzer/` | `ipfix_mcp_server.py` | 继承自 ipfix-mcp |

**系统影响**：`config/openclaw.json` 中需要配置非标准文件名，新开发者可能找不到入口文件。

---

## 六、诊断方法与覆盖范围

本次诊断使用多阶段并行验证，共 60 个分析 Agent：

| 阶段 | 内容 | 数量 | 方法 |
|---|---|---|---|
| Backend APIs | 17 个 REST 端点 | 17 | curl 实际请求 + 响应校验 |
| Backend Services | 17 个 Python 文件 | 17 | py_compile 语法检查 + 代码审查 |
| MCP Servers | 12 个服务器 | 12 | 语法检查 + 工具注册验证 + 规范审查 |
| Frontend | 8 个 JS/CSS/HTML 文件 | 8 | 交叉引用分析 + DOM ID 匹配 + API URL 校验 |
| Integration | 6 项跨模块检查 | 6 | WebSocket 事件匹配 + 设备 ID 一致性 + API 路由匹配 |

**总计**：60 个 Agent、719 次工具调用、~180 万 token 分析。
