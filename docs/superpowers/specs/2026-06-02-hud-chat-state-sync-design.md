# HUD / Chat 状态同步设计

## 日期
2026-06-02

## 问题
HUD (`/`) 和 Chat (`/chat/`) 是两个独立的 HTML 页面。当前 HUD → Chat 使用 `<a href>` 跳转，导致 HUD 页面被销毁，所有内存状态丢失（告警、扫描数据、对话历史等）。

## 方案
**保持双页架构 + localStorage 持久化 + BroadcastChannel 实时通知**

- 两个页面各自独立，通过各自 URL 直接访问
- 关键状态变更时写入 localStorage
- BroadcastChannel / storage 事件实时通知另一页面
- 页面加载时从 localStorage 恢复历史状态

## 需要保留的状态

| 状态 | 来源 | localStorage Key |
|------|------|------------------|
| Chat 对话历史 | chat/main.js `state.messages` | `cc_chat_messages` |
| HUD 告警时间线 | src/main.js `state.alerts` | `cc_hud_alerts` |
| HUD per-device 事件 | src/main.js `state.deviceEvents` | `cc_hud_device_events` |
| HUD 扫描数据 | src/main.js `state.deviceScanData` | `cc_hud_scan_data` |
| HUD 基线数据 | src/main.js `state.baselineData` | `cc_hud_baseline_data` |
| HUD 基线汇总 | src/main.js `state.baselineOverall` | `cc_hud_baseline_overall` |
| HUD 设备状态 | src/main.js `state.devices[].status` | `cc_hud_device_statuses` |

## 改动清单

### 1. 新建 `ui/cyberclaw-hud/shared/state-sync.js`
共享同步模块，导出 `saveState(key, data)`、`loadState(key, default)`、`onStateChange(callback)`。

### 2. 改造导航：`index.html` + `src/main.js`
- `<a href="/chat/">` → `<button id="nav-chat">`
- `setupInteraction()` 中绑定 `window.open('/chat/', 'cyberclaw-chat')`

### 3. Chat 侧：`chat/main.js`
- `addMessage()` 追加 `saveState(STORAGE_KEYS.chatMessages, state.messages)`
- `DOMContentLoaded` 追加从 localStorage 恢复对话历史
- 消息上限 100 条，超出截断

### 4. HUD 侧：`src/main.js`
- `addAlert()` 追加 `saveState()` 告警和设备事件
- `handleWSMessage()` 中 scan_result / cve_result / baseline_result 追加 `saveState()`
- `updateDeviceStatus()` 追加 `saveState()` 设备状态映射
- `boot()` 中 `connectWS()` 前从 localStorage 恢复历史数据

### 5. Vite 配置
- 无需修改。`shared/state-sync.js` 可被两个页面通过相对路径 `import`。

## 不改动的部分
- 两个页面的 HTML 结构不变
- 现有函数签名、参数、返回值不变
- CSS 不变
- 后端不变
- WebSocket 连接逻辑不变（仅追加持久化）

## 数据量预估
总计 ~100KB，localStorage 5MB 限制内。消息上限 100 条，告警上限 50 条。

## 验证步骤
1. 打开 HUD，执行扫描，产生告警和扫描数据
2. 通过按钮打开 Chat，发送几条消息
3. 刷新 Chat 页面 → 对话历史恢复
4. 刷新 HUD 页面 → 告警时间线和扫描数据恢复
5. 两个页面同时打开，HUD 侧产生新告警 → Chat 侧收到 toast 通知
