// ═══════════════════════════════════════════════════════════════════
// CyberClaw CyberAgent Chat — Mock AI Interaction
// ═══════════════════════════════════════════════════════════════════

import { initDashboard, onDashboardMessage } from '../src/dashboard.js';
import { saveState, loadState, onStateChange, KEYS } from '../shared/state-sync.js';

// ── Session Storage Keys ──────────────────────────────────────────
const SESSIONS_KEY = 'cc_chat_sessions';
const CURRENT_SESSION_KEY = 'cc_current_session';

// ── MCP & Skills Data ─────────────────────────────────────────────
// MCP_SERVERS will be populated from the backend via /api/chat/status.
// The hardcoded list below is kept as a fallback in case the fetch fails.
const MCP_SERVERS_FALLBACK = [
  { name: 'nmap-scan', status: 'online' },
  { name: 'device-config', status: 'online' },
  { name: 'simulation', status: 'online' },
  { name: 'syslog-collector', status: 'online' },
  { name: 'snmp-collector', status: 'online' },
  { name: 'cve-intel', status: 'online' },
  { name: 'security-baseline', status: 'online' },
  { name: 'flow-analyzer', status: 'online' },
  { name: 'traffic-analyzer', status: 'busy' },
  { name: 'auto-response', status: 'online' },
  { name: 'config-audit', status: 'online' },
  { name: 'attack-timeline', status: 'online' },
];

let MCP_SERVERS = [...MCP_SERVERS_FALLBACK];

const SKILLS = [
  { name: 'network-discovery', type: 'perception' },
  { name: 'iot-fingerprint', type: 'perception' },
  { name: 'topology-build', type: 'perception' },
  { name: 'default-password-check', type: 'perception' },
  { name: 'vuln-assess', type: 'detection' },
  { name: 'baseline-check', type: 'detection' },
  { name: 'anomaly-detect', type: 'detection' },
  { name: 'traffic-anomaly', type: 'detection' },
  { name: 'device-isolate', type: 'response' },
  { name: 'ip-block', type: 'response' },
  { name: 'full-response', type: 'response' },
  { name: 'timeline-review', type: 'review' },
  { name: 'root-cause', type: 'review' },
  { name: 'security-report', type: 'review' },
  { name: 'full-assess', type: 'perception' },
];

// ── API Connection ─────────────────────────────────────────────────
const API_BASE = '/api/chat';

// ── State ─────────────────────────────────────────────────────────
const state = {
  currentTab: 'chat',
  messages: [],
  sessions: [],
  currentSessionId: null,
  opHistory: [],
  sessions: [],
  isProcessing: false,
  workflows: [],
  devices: [],
  devicePage: 0,
  devicePageSize: 15,
  deviceSortKey: 'devLastIP',
  deviceSortDir: 'asc',
  deviceSearch: '',
  deviceStatusFilter: '',
  events: [],
  eventsSevFilter: '',
  eventsSourceFilter: '',
  eventsSearch: '',
  eventsTimeRange: '',
  eventsSortKey: 'timestamp',
  eventsSortDir: 'desc',
  eventsPage: 0,
  eventsPageSize: 30,
  _expandedEvt: null,
  selectedDeviceIndex: -1,
  devicePanelTab: 'overview',
  filteredDevices: [],
  deviceTypeFilter: '',
  deviceVendorFilter: '',
  _expandedWf: -1,
  mockMode: false,
};

// ── DOM ───────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Init ──────────────────────────────────────────────────────────
async function loadMcpStatus() {
  try {
    const resp = await fetch('/api/chat/status');
    if (resp.ok) {
      const data = await resp.json();
      // data.mcp_tools is [{server: "...", tool: "..."}]
      // Convert to MCP_SERVERS format
      const tools = data.mcp_tools || [];
      if (tools.length > 0) {
        const serverNames = [...new Set(tools.map(t => t.server))];
        MCP_SERVERS = serverNames.map(s => ({
          name: s,
          status: data.llm_connected ? 'online' : 'busy',
          tools: tools.filter(t => t.server === s).map(t => t.tool),
        }));
      }
      // Store mock mode state
      if (data.mock_mode !== undefined) {
        state.mockMode = data.mock_mode;
      }
      // Re-render MCP panel
      if (typeof populateMcpList === 'function') populateMcpList();
    }
  } catch (e) {
    console.warn('MCP status fetch failed, using fallback data:', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initInput();
  initAutomate();
  initHudLink();
  initDashboard();
  initDevices();
  loadMcpStatus();
  initEvents();

  // ── Load sessions & render conversation list ────────────────────
  loadSessions();
  renderConversationList();
  renderCurrentSession();
  initSidebarEvents();
});

// ── Session (Multi-Conversation) Management ────────────────────────

function generateSessionId() {
  return 'sess-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
}

function getCurrentSession() {
  return state.sessions.find(s => s.id === state.currentSessionId) || null;
}

function loadSessions() {
  let sessions = loadState(SESSIONS_KEY, []);

  // Migration: convert old flat chatMessages into a session
  if (sessions.length === 0) {
    const oldMessages = loadState(KEYS.chatMessages, []);
    if (oldMessages.length > 0) {
      const session = {
        id: generateSessionId(),
        title: '历史对话',
        created: new Date().toISOString(),
        messages: oldMessages,
      };
      const firstUserMsg = oldMessages.find(m => m.role === 'user');
      if (firstUserMsg) {
        session.title = firstUserMsg.content.substring(0, 24);
        if (firstUserMsg.content.length > 24) session.title += '...';
      }
      sessions.push(session);
    }
  }

  state.sessions = sessions;

  // Restore current session pointer
  const savedId = loadState(CURRENT_SESSION_KEY, null);
  if (savedId && sessions.find(s => s.id === savedId)) {
    state.currentSessionId = savedId;
  } else if (sessions.length > 0) {
    state.currentSessionId = sessions[0].id;
  }

  // Point state.messages to current session
  const session = getCurrentSession();
  state.messages = session ? session.messages : [];
}

function saveSessions() {
  saveState(SESSIONS_KEY, state.sessions);
}

function saveCurrentSessionId() {
  saveState(CURRENT_SESSION_KEY, state.currentSessionId);
}

function createNewSession() {
  const session = {
    id: generateSessionId(),
    title: '新对话',
    created: new Date().toISOString(),
    messages: [],
  };
  state.sessions.unshift(session);
  state.currentSessionId = session.id;
  state.messages = session.messages;
  saveSessions();
  saveCurrentSessionId();
  renderConversationList();
  renderCurrentSession();
  return session;
}

function switchSession(id) {
  if (id === state.currentSessionId) return;
  if (state.isProcessing) return; // don't switch mid-response
  state.currentSessionId = id;
  const session = getCurrentSession();
  state.messages = session ? session.messages : [];
  saveCurrentSessionId();
  renderConversationList();
  renderCurrentSession();
}

function deleteSession(id) {
  if (state.isProcessing) return;
  state.sessions = state.sessions.filter(s => s.id !== id);

  if (state.currentSessionId === id) {
    if (state.sessions.length > 0) {
      state.currentSessionId = state.sessions[0].id;
      const session = getCurrentSession();
      state.messages = session ? session.messages : [];
    } else {
      createNewSession();
      return;
    }
  }
  saveSessions();
  saveCurrentSessionId();
  renderConversationList();
  renderCurrentSession();
}

function autoTitleSession(session) {
  if (!session || session.title !== '新对话') return;
  const firstUserMsg = session.messages.find(m => m.role === 'user');
  if (firstUserMsg) {
    session.title = firstUserMsg.content.substring(0, 24);
    if (firstUserMsg.content.length > 24) session.title += '...';
    saveSessions();
    renderConversationList();
  }
}

function formatSessionTime(isoStr) {
  try {
    const date = new Date(isoStr);
    const now = new Date();
    const diff = now - date;
    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return Math.floor(diff / 60000) + ' 分钟前';
    if (diff < 86400000) return Math.floor(diff / 3600000) + ' 小时前';
    if (diff < 172800000) return '昨天';
    return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
  } catch {
    return '';
  }
}

// ── Conversation List Rendering ────────────────────────────────────

function renderConversationList() {
  const list = $('#conversation-list');
  if (!list) return;

  if (state.sessions.length === 0) {
    list.innerHTML = '<div class="empty-state" style="padding:20px 10px;font-size:11px;">暂无对话</div>';
    return;
  }

  list.innerHTML = state.sessions.map(s => {
    const active = s.id === state.currentSessionId;
    const time = formatSessionTime(s.created);
    const msgCount = s.messages.filter(m => m.role === 'user').length;
    return `
      <div class="conversation-item ${active ? 'active' : ''}" data-session-id="${s.id}">
        <div class="conv-icon"><i class="fa-regular fa-comment"></i></div>
        <div class="conv-info">
          <div class="conv-title">${escapeHtml(s.title)}</div>
          <div class="conv-meta">${time} · ${msgCount} 条对话</div>
        </div>
        <button class="conv-delete" data-delete-session="${s.id}" title="删除此对话">
          <i class="fa-solid fa-trash"></i>
        </button>
      </div>
    `;
  }).join('');

  // Bind click events
  list.querySelectorAll('.conversation-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('.conv-delete')) return;
      switchSession(item.dataset.sessionId);
    });
  });

  list.querySelectorAll('.conv-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteSession(btn.dataset.deleteSession);
    });
  });
}

// ── Current Session Rendering ──────────────────────────────────────

function renderCurrentSession() {
  const container = $('#chat-messages');
  if (!container) return;

  const session = getCurrentSession();

  if (!session || session.messages.length === 0) {
    container.innerHTML = `
      <div class="chat-welcome">
        <div class="welcome-icon">⬡</div>
        <h2>CyberAgent 就绪</h2>
        <p>IoT 安全智能助手已上线。你可以用自然语言提问或下达安全指令。</p>
        <div class="quick-actions">
          <button class="quick-btn" data-prompt="帮我检查网络中所有 IoT 设备的安全状态">扫描网络安全状态</button>
          <button class="quick-btn" data-prompt="分析当前有哪些安全漏洞">分析安全漏洞</button>
          <button class="quick-btn" data-prompt="生成今天的安全巡检报告">生成巡检报告</button>
          <button class="quick-btn" data-prompt="回放最近的攻击过程">攻击复盘</button>
        </div>
      </div>
    `;
    // Re-bind quick action buttons
    container.querySelectorAll('.quick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const prompt = btn.dataset.prompt;
        if (prompt) {
          $('#chat-input').value = prompt;
          sendMessage();
        }
      });
    });
    return;
  }

  const renderMd = (typeof marked !== 'undefined' && marked.parse) ? marked.parse : (s) => s.replace(/\n/g, '<br>');

  container.innerHTML = '';
  session.messages.forEach(m => {
    const div = document.createElement('div');
    if (m.role === 'user') {
      div.className = 'msg msg-user';
      div.innerHTML = `<div class="msg-bubble">${escapeHtml(m.content)}</div>`;
    } else if (m.role === 'ai') {
      div.className = 'msg msg-ai';
      div.innerHTML = `<div class="msg-bubble">
        <div class="msg-sender"><span class="dot"></span>CyberAgent</div>
        <div class="msg-text">${renderMd(m.content)}</div>
      </div>`;
    }
    container.appendChild(div);
  });

  container.scrollTop = container.scrollHeight;

  // Re-bind confirm buttons
  container.querySelectorAll('.confirm-btn').forEach(btn => {
    btn.addEventListener('click', () => handleConfirm(btn.dataset.action, btn));
  });
}

// ── Sidebar Event Bindings ─────────────────────────────────────────

function initSidebarEvents() {
  const newChatBtn = $('#btn-new-chat');
  if (newChatBtn) {
    newChatBtn.addEventListener('click', () => createNewSession());
  }
}

// ── Timer result polling ───────────────────────────────────────────
let _lastHistoryLen = 0;
let _historyInitialized = false;
function startHistoryPoll() {
  // Initial baseline load — don't show old timer results on page load
  fetch(`${API_BASE}/history?limit=100`).then(r => r.json()).then(data => {
    const history = data.history || [];
    _lastHistoryLen = history.length;
    _historyInitialized = true;
  }).catch(() => { _historyInitialized = true; });

  setInterval(async () => {
    if (!_historyInitialized) return;
    try {
      const resp = await fetch(`${API_BASE}/history?limit=100`);
      if (!resp.ok) return;
      const data = await resp.json();
      const history = data.history || [];
      if (history.length <= _lastHistoryLen) return;
      const newMsgs = history.slice(_lastHistoryLen);
      _lastHistoryLen = history.length;
      for (const msg of newMsgs) {
        if (msg.role === 'assistant' && msg.content.startsWith('⏰')) {
          const container = $('#chat-messages');
          // Avoid duplicates — check if this exact content is already shown
          const existing = container.querySelectorAll('.msg-text');
          let isDup = false;
          existing.forEach(el => { if (el.textContent.includes(msg.content.substring(0, 50))) isDup = true; });
          if (isDup) continue;

          const div = document.createElement('div');
          div.className = 'msg msg-ai msg-timer-result';
          const renderMd = (typeof marked !== 'undefined' && marked.parse) ? marked.parse : (s) => s.replace(/\n/g, '<br>');
          div.innerHTML = `<div class="msg-bubble">
            <div class="msg-sender"><span class="dot"></span><i class="fa-solid fa-clock"></i> 定时任务</div>
            <div class="msg-text">${renderMd(msg.content)}</div>
          </div>`;
          container.appendChild(div);
          container.scrollTop = container.scrollHeight;
        }
      }
    } catch (e) { /* silent */ }
  }, 5000);

  // WebSocket for real-time notification toasts
  startNotifWebSocket();
}

function startNotifWebSocket() {
  const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${location.host}/ws`;
  let ws;
  let reconnectDelay = 1000;

  function connect() {
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => { reconnectDelay = 1000; };
      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data.type === 'notification') {
            showNotifToast(data);
          }
          // Route scenario & collector events to Dashboard for real-time refresh
          onDashboardMessage(data);
        } catch {}
      };
      ws.onclose = () => {
        setTimeout(connect, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 30000);
      };
      ws.onerror = () => { ws.close(); };
    } catch {}
  }
  connect();
}

function showNotifToast(data) {
  // Same visual style as HUD's showNotificationToast
  const container = document.getElementById('notification-toast-container') || (() => {
    const c = document.createElement('div');
    c.id = 'notification-toast-container';
    c.style.cssText = 'position:fixed;top:20px;right:20px;z-index:10000;display:flex;flex-direction:column;gap:8px;max-width:400px;';
    document.body.appendChild(c);
    return c;
  })();

  const colors = { critical: '#ff4444', warning: '#ff9800', info: '#2196f3' };
  const bg = colors[data.severity] || colors.info;
  const title = data.title || '';
  const message = (data.message || '').substring(0, 200);

  const toast = document.createElement('div');
  toast.style.cssText = `background:${bg}22;border:1px solid ${bg};border-radius:8px;padding:12px 16px;color:#fff;font-size:13px;animation:toastIn 0.3s ease;backdrop-filter:blur(8px);`;

  // Add "查看详情" button when notification carries rich data
  const detailBtn = data.has_detail
    ? `<button class="notif-toast-detail-btn" data-guid="${escapeHtml(data.guid || '')}">查看详情</button>`
    : '';
  toast.innerHTML = `<div style="font-weight:600;margin-bottom:4px;">${escapeHtml(title)}</div><div style="opacity:0.85;line-height:1.4;">${escapeHtml(message)}</div>${detailBtn}`;

  container.appendChild(toast);

  // Bind detail button click
  const btn = toast.querySelector('.notif-toast-detail-btn');
  if (btn) {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      showNotifDetailByGuid(data.guid);
    });
  }

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.5s';
    setTimeout(() => toast.remove(), 500);
  }, 5000);
}

// ── Tabs ──────────────────────────────────────────────────────────
function initTabs() {
  $$('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      switchTab(tab.dataset.tab);
    });
  });
}

function switchTab(name) {
  state.currentTab = name;
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.tab-content').forEach(tc => tc.classList.toggle('active', tc.id === `tab-${name}`));
  if (name === 'dashboard') {
    window.dispatchEvent(new Event('resize'));
    window.dispatchEvent(new Event('dashboard-visible'));
  }
  if (name === 'devices') {
    fetchDevices();
  }
  if (name === 'events') {
    fetchSecurityEvents();
  }
  if (name === 'automate') {
    fetchNotificationConfig();
    fetchNotificationHistory();
    fetchWorkflowEvents();
  }
}

// ── Input ─────────────────────────────────────────────────────────
const SLASH_COMMANDS = [
  { cmd: '/schedule', desc: '设置定时任务', icon: '<i class="fa-solid fa-clock"></i>' },
  { cmd: '/scan', desc: '扫描网络设备', icon: '<i class="fa-solid fa-satellite-dish"></i>' },
  { cmd: '/cve', desc: '查询CVE漏洞', icon: '<i class="fa-solid fa-shield-halved"></i>' },
  { cmd: '/baseline', desc: '安全基线检查', icon: '<i class="fa-solid fa-list-check"></i>' },
  { cmd: '/help', desc: '查看可用命令', icon: '❓' },
];

function initInput() {
  const input = $('#chat-input');
  const btn = $('#btn-send');

  btn.addEventListener('click', () => sendMessage());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (_slashMenuVisible) { closeSlashMenu(); return; }
      sendMessage();
    }
    if (e.key === 'Escape') closeSlashMenu();
  });

  // Slash command detection
  input.addEventListener('input', () => {
    const val = input.value;
    if (val.startsWith('/') && !val.includes(' ')) {
      showSlashMenu(val);
    } else {
      closeSlashMenu();
    }
  });

  // Quick action buttons on welcome screen
  $$('.quick-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.dataset.prompt;
      if (prompt) {
        input.value = prompt;
        sendMessage();
      }
    });
  });
}

let _slashMenuVisible = false;
function showSlashMenu(filter) {
  closeSlashMenu();
  const input = $('#chat-input');
  const wrapper = input.closest('.chat-input-wrap') || input.parentElement;

  const menu = document.createElement('div');
  menu.id = 'slash-menu';
  menu.className = 'slash-menu';

  const filtered = SLASH_COMMANDS.filter(c => c.cmd.startsWith(filter));
  if (filtered.length === 0) { closeSlashMenu(); return; }

  filtered.forEach(cmd => {
    const item = document.createElement('div');
    item.className = 'slash-menu-item';
    item.innerHTML = `<span class="slash-icon">${cmd.icon}</span><span class="slash-cmd">${cmd.cmd}</span><span class="slash-desc">${cmd.desc}</span>`;
    item.addEventListener('click', () => {
      closeSlashMenu();
      handleSlashCommand(cmd.cmd);
    });
    menu.appendChild(item);
  });

  wrapper.style.position = 'relative';
  wrapper.appendChild(menu);
  _slashMenuVisible = true;
}

function closeSlashMenu() {
  const existing = $('#slash-menu');
  if (existing) existing.remove();
  _slashMenuVisible = false;
}

function handleSlashCommand(cmd) {
  const input = $('#chat-input');
  input.value = '';

  if (cmd === '/schedule') {
    switchTab('automate');
    showTaskModal();
  } else if (cmd === '/scan') {
    input.value = '扫描网络中的所有设备';
    sendMessage();
  } else if (cmd === '/cve') {
    input.value = '查询 Hikvision 设备的 CVE 漏洞';
    sendMessage();
  } else if (cmd === '/baseline') {
    input.value = '检查安全基线';
    sendMessage();
  } else if (cmd === '/help') {
    addMessage('user', '/help');
    const helpText = SLASH_COMMANDS.map(c => `${c.icon} **${c.cmd}** — ${c.desc}`).join('\n');
    const aiDiv = createAIMessage();
    aiDiv.querySelector('.msg-sender').innerHTML = '<span class="dot"></span>CyberAgent';
    const renderMd = (typeof marked !== 'undefined' && marked.parse) ? marked.parse : (s) => s.replace(/\n/g, '<br>');
    aiDiv.querySelector('.msg-text').innerHTML = renderMd(helpText);
    aiDiv.querySelector('.msg-text').style.display = 'block';
  }
}

function showTaskModal() {
  const overlay = $('#task-modal-overlay');
  const modal = $('#task-modal');
  if (!overlay || !modal) return;

  // Build tool options from MCP_SERVERS
  const toolOptions = MCP_SERVERS.map(s => {
    const tools = s.tools || [];
    if (tools.length === 0) return '';
    return tools.map(t => `<option value="${s.name}|${t}">${s.name} / ${t}</option>`).join('');
  }).join('');

  const cronPresets = [
    { label: '每5分钟', expr: '*/5 * * * *' },
    { label: '每30分钟', expr: '*/30 * * * *' },
    { label: '每小时', expr: '0 * * * *' },
    { label: '每天9:00', expr: '0 9 * * *' },
    { label: '工作日9:00', expr: '0 9 * * 1-5' },
    { label: '每天凌晨2:00', expr: '0 2 * * *' },
  ];

  modal.innerHTML = `
    <div class="schedule-panel">
      <div class="schedule-header">
        <span class="schedule-title"><i class="fa-solid fa-clock"></i> 创建定时任务</span>
        <button class="schedule-close" id="task-modal-close">✕</button>
      </div>
      <div class="schedule-mode-tabs">
        <button class="schedule-mode-tab active" data-mode="delay">延迟</button>
        <button class="schedule-mode-tab" data-mode="once">定时</button>
        <button class="schedule-mode-tab" data-mode="cron">循环</button>
      </div>
      <div class="schedule-body">
        <div class="schedule-input-group">
          <label>任务内容</label>
          <input type="text" class="schedule-prompt-input" id="sch-prompt"
                 placeholder="输入自定义指令，如：扫描网络中的所有设备" />
        </div>
        <div class="schedule-input-group">
          <label>关联工具（可选）</label>
          <select class="schedule-select" id="sch-tool">
            <option value="">自由指令（无工具）</option>
            ${toolOptions}
          </select>
        </div>

        <!-- Delay mode -->
        <div class="schedule-mode-content" id="sch-mode-delay">
          <label class="schedule-label">延迟执行</label>
          <div class="schedule-times">
            <button class="schedule-time-btn active" data-seconds="180">3 分钟</button>
            <button class="schedule-time-btn" data-seconds="300">5 分钟</button>
            <button class="schedule-time-btn" data-seconds="600">10 分钟</button>
            <button class="schedule-time-btn" data-seconds="1800">30 分钟</button>
            <button class="schedule-time-btn" data-seconds="3600">1 小时</button>
          </div>
          <div class="schedule-custom">
            <span style="color:var(--muted);font-size:12px;">自定义:</span>
            <input type="number" class="ops-input" id="sch-custom-min" placeholder="分钟" min="1" max="1440" style="width:80px;padding:4px 8px;font-size:13px;" />
          </div>
        </div>

        <!-- Once mode -->
        <div class="schedule-mode-content" id="sch-mode-once" style="display:none">
          <label class="schedule-label">指定执行时间</label>
          <div style="display:flex;gap:8px;margin-top:4px;">
            <input type="date" class="ops-input" id="sch-date" style="flex:1;padding:6px 10px;font-size:12px;" />
            <input type="time" class="ops-input" id="sch-time" style="flex:1;padding:6px 10px;font-size:12px;" />
          </div>
          <div style="margin-top:6px;font-size:11px;color:var(--muted);">也可直接输入自然语言，如：明天早上9点扫描网络</div>
        </div>

        <!-- Cron mode -->
        <div class="schedule-mode-content" id="sch-mode-cron" style="display:none">
          <label class="schedule-label">Cron 表达式</label>
          <div style="display:flex;gap:6px;margin-top:4px;">
            <input type="text" class="schedule-prompt-input" id="sch-cron" placeholder="*/5 * * * *" value="*/5 * * * *" style="flex:1;font-size:13px;font-family:var(--mono);" />
            <span class="sch-cron-validity" id="sch-cron-icon" style="line-height:34px;"></span>
          </div>
          <div class="schedule-cron-presets">
            ${cronPresets.map(p => `<button class="schedule-cron-preset" data-expr="${p.expr}">${p.label}</button>`).join('')}
          </div>
          <div class="schedule-cron-preview" id="sch-cron-preview"></div>
        </div>
      </div>
      <div class="schedule-footer">
        <button class="schedule-cancel-btn" id="task-modal-cancel">取消</button>
        <button class="schedule-confirm-btn" id="schedule-confirm">✓ 确认创建</button>
      </div>
    </div>
  `;

  overlay.style.display = 'flex';

  // Close handlers
  const closeModal = () => { overlay.style.display = 'none'; };
  modal.querySelector('#task-modal-close')?.addEventListener('click', closeModal);
  modal.querySelector('#task-modal-cancel')?.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

  // ── Mode switching ──
  let currentMode = 'delay';
  modal.querySelectorAll('.schedule-mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      modal.querySelectorAll('.schedule-mode-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentMode = tab.dataset.mode;
      modal.querySelectorAll('.schedule-mode-content').forEach(c => c.style.display = 'none');
      const modeEl = modal.querySelector(`#sch-mode-${currentMode}`);
      if (modeEl) modeEl.style.display = '';
      if (currentMode === 'cron') validateCronPreview();
    });
  });

  // ── Delay mode: preset selection ──
  modal.querySelectorAll('.schedule-time-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      modal.querySelectorAll('.schedule-time-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const ci = modal.querySelector('#sch-custom-min');
      if (ci) ci.value = '';
    });
  });

  // ── Cron mode: preset + live validation ──
  modal.querySelectorAll('.schedule-cron-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      modal.querySelector('#sch-cron').value = btn.dataset.expr;
      validateCronPreview();
    });
  });

  let _cronTimer = null;
  modal.querySelector('#sch-cron')?.addEventListener('input', () => {
    clearTimeout(_cronTimer);
    _cronTimer = setTimeout(validateCronPreview, 300);
  });

  async function validateCronPreview() {
    const expr = modal.querySelector('#sch-cron')?.value?.trim();
    const icon = modal.querySelector('#sch-cron-icon');
    const preview = modal.querySelector('#sch-cron-preview');
    if (!expr || !preview) return;
    try {
      const resp = await fetch('/api/scheduler/validate-cron', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cron_expr: expr }),
      });
      const data = await resp.json();
      if (data.valid) {
        if (icon) icon.innerHTML = '<i class="fa fa-check" style="color:var(--accent)"></i>';
        preview.innerHTML = data.next_runs.map(r =>
          `<div class="preview-run">→ ${formatTs(r)}</div>`
        ).join('');
      } else {
        if (icon) icon.innerHTML = '<i class="fa fa-xmark" style="color:var(--danger)"></i>';
        preview.innerHTML = `<span style="color:var(--danger)">${escapeHtml(data.error)}</span>`;
      }
    } catch {
      if (icon) icon.innerHTML = '';
      preview.innerHTML = '';
    }
  }

  // ── Confirm ──
  modal.querySelector('#schedule-confirm').addEventListener('click', async () => {
    const prompt = modal.querySelector('#sch-prompt')?.value?.trim();
    const toolVal = modal.querySelector('#sch-tool')?.value || '';

    if (currentMode === 'delay') {
      const timeBtn = modal.querySelector('.schedule-time-btn.active');
      const customMin = modal.querySelector('#sch-custom-min')?.value;
      let seconds = timeBtn ? parseInt(timeBtn.dataset.seconds) : 0;
      if (customMin && parseInt(customMin) > 0) seconds = parseInt(customMin) * 60;
      if (!seconds) seconds = 180;

      const taskPrompt = prompt || (toolVal ? `使用 ${toolVal.replace('|', '/')} 执行任务` : '执行安全扫描');
      const taskName = `延迟: ${taskPrompt.slice(0, 30)}`;
      await _createSchedulerTask({ name: taskName, prompt: taskPrompt, schedule_mode: 'interval', interval_seconds: seconds, ...(toolVal ? _parseToolVal(toolVal) : {}) });
      closeModal();

    } else if (currentMode === 'once') {
      const dateVal = modal.querySelector('#sch-date')?.value;
      const timeVal = modal.querySelector('#sch-time')?.value;
      if (!dateVal || !timeVal) return;
      const runAt = new Date(`${dateVal}T${timeVal}:00`).toISOString();
      const taskName = prompt || (toolVal ? `定时: ${toolVal.split('|')[1]}` : '自定义定时任务');
      await _createSchedulerTask({ name: taskName, prompt: prompt || undefined, schedule_mode: 'once', run_at: runAt, ...(toolVal ? _parseToolVal(toolVal) : {}) });
      closeModal();

    } else if (currentMode === 'cron') {
      const cronExpr = modal.querySelector('#sch-cron')?.value?.trim();
      if (!cronExpr) return;
      const taskName = prompt || (toolVal ? `循环: ${toolVal.split('|')[1]}` : '自定义循环任务');
      await _createSchedulerTask({ name: taskName, prompt: prompt || undefined, schedule_mode: 'cron', cron_expr: cronExpr, ...(toolVal ? _parseToolVal(toolVal) : {}) });
      closeModal();
    }
  });

  // Init cron preview
  validateCronPreview();
}

function _parseToolVal(val) {
  const [server, tool] = val.split('|');
  return { tool_server: server, tool_name: tool, tool_args: {} };
}

async function _createSchedulerTask(cfg) {
  try {
    const resp = await fetch('/api/scheduler/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    const data = await resp.json();
    if (data.error) {
      addOpHistory('error', '创建任务失败', data.error);
    } else {
      addOpHistory('success', `任务已创建: ${cfg.name}`, `模式: ${cfg.schedule_mode}`);
      fetchActiveTasks();
    }
  } catch (e) {
    addOpHistory('error', '创建任务失败', e.message);
  }
}

// ── Active Tasks (Operations tab) ──────────────────────────────────

const PRESET_TASKS = [
  { id: 'network_scan', name: '网络扫描', icon: 'fa-solid fa-satellite-dish',
    color: '#00bbff', desc: '定期扫描子网发现新设备与离线设备', defaultInterval: 300 },
  { id: 'cve_check', name: 'CVE 漏洞检查', icon: 'fa-solid fa-shield-halved',
    color: '#ff2244', desc: '检查已知 CVE 漏洞，关注高危设备', defaultInterval: 3600 },
  { id: 'baseline_check', name: '安全基线检查', icon: 'fa-solid fa-list-check',
    color: '#00ff88', desc: '审计设备安全配置与合规基线', defaultInterval: 1800 },
  { id: 'traffic_analysis', name: '流量分析', icon: 'fa-solid fa-chart-line',
    color: '#ffaa00', desc: '分析网络流量，提取 IoC 与异常指标', defaultInterval: 600 },
  { id: 'config_audit', name: '配置审计', icon: 'fa-solid fa-gear',
    color: '#f97316', desc: '审计设备配置变更与安全隐患', defaultInterval: 3600 },
];

let _taskCountdownInterval = null;

async function handlePresetToggle(presetId, enabled) {
  try {
    const resp = await fetch(`/api/scheduler/tasks/${presetId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, paused: !enabled }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    fetchActiveTasks();
  } catch (e) {
    // silent — task completion/failure will be notified via WebSocket
  }
}

async function handlePresetIntervalEdit(presetId, seconds) {
  if (seconds < 60) return;
  try {
    const resp = await fetch(`/api/scheduler/tasks/${presetId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interval_seconds: seconds }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    fetchActiveTasks();
  } catch (e) {
    // silent — task completion/failure will be notified via WebSocket
  }
}

async function fetchActiveTasks() {
  try {
    const resp = await fetch('/api/scheduler/tasks');
    if (!resp.ok) return;
    const data = await resp.json();
    renderPresetTasks(data.tasks || []);
    renderCustomTasks(data.tasks || []);
  } catch {
    const presetWrap = $('#preset-tasks-grid');
    if (presetWrap) presetWrap.innerHTML = '<div class="empty-state">加载失败</div>';
  }
}

function renderPresetTasks(allTasks) {
  const grid = $('#preset-tasks-grid');
  if (!grid) return;

  const presetMap = {};
  allTasks.filter(t => t.type === 'preset').forEach(t => { presetMap[t.id] = t; });

  grid.innerHTML = PRESET_TASKS.map(def => {
    const t = presetMap[def.id];
    const running = t && t.status === 'running';
    const enabled = t ? t.enabled : false;
    const statusCls = !enabled ? 'disabled' : running ? 'running' : 'paused';
    const intervalSec = t ? (t.interval_seconds || def.defaultInterval) : def.defaultInterval;
    const intervalMin = Math.round(intervalSec / 60);
    const countdown = (t && t.next_run_in > 0 && running) ? `<span class="preset-countdown" data-seconds="${t.next_run_in}">下次: ${formatCountdown(t.next_run_in)}</span>` : '';
    const runCount = t ? (t.run_count || 0) : 0;
    const lastRun = t && t.last_run ? formatTs(t.last_run, false) : '';

    return `<div class="preset-task-card ${statusCls}" data-preset-id="${def.id}">
      <div class="preset-left">
        <span class="preset-icon" style="color:${def.color}"><i class="${def.icon}"></i></span>
        <label class="wf-toggle">
          <input type="checkbox" ${enabled ? 'checked' : ''} data-preset-toggle="${def.id}" />
          <span class="wf-toggle-slider"></span>
        </label>
      </div>
      <div class="preset-body">
        <div class="preset-name">${def.name}</div>
        <div class="preset-desc">${def.desc}</div>
        <div class="preset-meta">
          <span class="preset-interval">每 ${intervalMin < 1 ? intervalSec + ' 秒' : intervalMin + ' 分钟'}</span>
          ${countdown}
          ${runCount ? `<span>运行: ${runCount} 次</span>` : ''}
          ${lastRun ? `<span>上次: ${lastRun}</span>` : ''}
        </div>
        <div class="preset-interval-edit" id="preset-edit-${def.id}" style="display:none">
          <input type="number" value="${intervalSec}" min="60" />
          <span style="color:var(--muted);font-size:9px;">秒</span>
          <button class="preset-edit-btn" data-preset-save="${def.id}">保存</button>
          <button class="preset-edit-btn cancel" data-preset-cancel="${def.id}">取消</button>
        </div>
        <div class="preset-actions">
          <button class="task-action-btn" data-action="trigger" data-id="${def.id}">立即触发</button>
          <button class="task-action-btn" data-preset-edit="${def.id}">编辑间隔</button>
        </div>
      </div>
    </div>`;
  }).join('');

  // Bind toggle switches
  grid.querySelectorAll('[data-preset-toggle]').forEach(cb => {
    cb.addEventListener('change', () => {
      handlePresetToggle(cb.dataset.presetToggle, cb.checked);
    });
  });

  // Bind edit interval buttons
  grid.querySelectorAll('[data-preset-edit]').forEach(btn => {
    btn.addEventListener('click', () => {
      const editRow = $(`#preset-edit-${btn.dataset.presetEdit}`);
      if (editRow) editRow.style.display = editRow.style.display === 'none' ? 'flex' : 'none';
    });
  });

  // Bind save/cancel in inline editor
  grid.querySelectorAll('[data-preset-save]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.presetSave;
      const editRow = $(`#preset-edit-${id}`);
      const input = editRow?.querySelector('input');
      if (input) handlePresetIntervalEdit(id, parseInt(input.value) || 300);
    });
  });
  grid.querySelectorAll('[data-preset-cancel]').forEach(btn => {
    btn.addEventListener('click', () => {
      const editRow = $(`#preset-edit-${btn.dataset.presetCancel}`);
      if (editRow) editRow.style.display = 'none';
    });
  });

  // Bind trigger buttons
  grid.querySelectorAll('[data-action="trigger"]').forEach(btn => {
    btn.addEventListener('click', () => handleTaskAction(btn.dataset.id, 'trigger'));
  });

  // Start countdown timer
  if (_taskCountdownInterval) clearInterval(_taskCountdownInterval);
  _taskCountdownInterval = setInterval(() => {
    grid.querySelectorAll('.preset-countdown').forEach(el => {
      let sec = parseInt(el.dataset.seconds) - 1;
      if (sec < 0) sec = 0;
      el.dataset.seconds = sec;
      el.textContent = `下次: ${formatCountdown(sec)}`;
    });
  }, 1000);
}

function renderCustomTasks(allTasks) {
  const wrap = $('#custom-tasks-list');
  if (!wrap) return;

  const custom = allTasks.filter(t => t.type !== 'preset');
  if (!custom.length) {
    wrap.innerHTML = '<div class="empty-state">暂无自定义任务</div>';
    return;
  }

  wrap.innerHTML = custom.map(t => {
    const statusCls = t.status || 'stopped';
    const statusLabel = { running: '运行中', paused: '已暂停', stopped: '已停止' }[statusCls] || statusCls;
    const scheduleStr = t.schedule_mode === 'cron' ? (t.cron_expr || '') :
                        t.schedule_mode === 'once' ? formatTs(t.run_at).slice(0, 16) :
                        `每 ${Math.round((t.interval_seconds || 0) / 60)} 分钟`;
    return `
      <div class="active-task-card" data-id="${t.id}">
        <div class="active-task-header">
          <span class="active-task-name"><i class="fa-solid fa-clock"></i> ${escapeHtml(t.name || t.id)}</span>
          <span class="active-task-status ${statusCls}">${statusLabel}</span>
        </div>
        <div class="active-task-meta">
          <span>${escapeHtml(scheduleStr)}</span>
          ${t.next_run_in > 0 && t.status === 'running' ? `<span class="active-task-countdown" data-seconds="${t.next_run_in}">下次: ${formatCountdown(t.next_run_in)}</span>` : ''}
          ${t.last_run ? `<span>上次: ${formatTs(t.last_run, false)}</span>` : ''}
          <span>运行: ${t.run_count || 0} 次</span>
        </div>
        <div class="active-task-actions">
          ${t.status === 'running' ? `<button class="task-action-btn" data-action="pause">暂停</button>` : ''}
          ${t.status === 'paused' ? `<button class="task-action-btn" data-action="resume">恢复</button>` : ''}
          <button class="task-action-btn" data-action="trigger">立即触发</button>
          <button class="task-action-btn danger" data-action="delete">删除</button>
        </div>
      </div>
    `;
  }).join('');

  wrap.querySelectorAll('.task-action-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const card = btn.closest('.active-task-card');
      const taskId = card?.dataset.id;
      const action = btn.dataset.action;
      if (taskId && action) handleTaskAction(taskId, action);
    });
  });
}

function formatCountdown(seconds) {
  if (seconds <= 0) return '即将执行';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}时${m}分${s}秒`;
  if (m > 0) return `${m}分${s}秒`;
  return `${s}秒`;
}

async function handleTaskAction(taskId, action) {
  // Show loading state on trigger button
  const triggerBtn = document.querySelector(`[data-action="trigger"][data-id="${taskId}"]`);
  const origText = triggerBtn?.textContent;
  if (triggerBtn && action === 'trigger') {
    triggerBtn.disabled = true;
    triggerBtn.textContent = '执行中...';
  }
  try {
    let url, method;
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
    const resp = await fetch(url, { method });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    // For trigger: show immediate notification from API response
    if (action === 'trigger') {
      try {
        const data = await resp.json();
        const preset = PRESET_TASKS.find(p => p.id === taskId);
        const name = preset ? preset.name : taskId;
        const issues = data.issues || 0;
        const hasError = data.result && data.result.error;
        let title, message, severity;
        if (hasError) {
          title = `任务失败: ${name}`;
          message = `执行出错: ${data.result.error.substring(0, 100)}`;
          severity = 'warning';
        } else if (issues > 0) {
          title = `安全检查: ${name}`;
          message = `${name} 发现 ${issues} 个问题`;
          severity = issues >= 5 ? 'critical' : 'warning';
        } else {
          title = `任务完成: ${name}`;
          message = `${name} 执行成功，未发现问题`;
          severity = 'info';
        }
        showNotifToast({
          title, message, severity, section: 'scheduled_checks',
          has_detail: !hasError && !!data.result,
          guid: data.notif_guid || '',
          task_type: data.check || taskId,
        });
      } catch {}
      // Show "已完成" briefly before refresh
      if (triggerBtn) {
        triggerBtn.textContent = '已完成 ✓';
        triggerBtn.style.color = '#00ff88';
        await new Promise(r => setTimeout(r, 1500));
      }
    }
    fetchActiveTasks();
  } catch (e) {
    console.error('[handleTaskAction]', action, taskId, e);
  } finally {
    if (triggerBtn) {
      triggerBtn.disabled = false;
      triggerBtn.textContent = origText || '立即触发';
      triggerBtn.style.color = '';
    }
  }
}

function sendMessage() {
  const input = $('#chat-input');
  const text = input.value.trim();
  if (!text || state.isProcessing) return;

  input.value = '';

  if (state.currentTab !== 'chat') switchTab('chat');

  // Ensure we have an active session
  if (!getCurrentSession()) createNewSession();

  const welcome = $('.chat-welcome');
  if (welcome) welcome.remove();

  addMessage('user', text);

  // Save to session & auto-title
  const session = getCurrentSession();
  if (session) {
    session.messages.push({ role: 'user', content: text, time: new Date().toISOString() });
    autoTitleSession(session);
    saveSessions();
  }

  processAIResponse(text);
}

// ── Message Rendering ─────────────────────────────────────────────
function addMessage(role, content) {
  const container = $('#chat-messages');
  const div = document.createElement('div');
  div.className = `msg msg-${role}`;

  if (role === 'user') {
    div.innerHTML = `<div class="msg-bubble">${escapeHtml(content)}</div>`;
  }

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;

  return div;
}

function createAIMessage() {
  const container = $('#chat-messages');
  const div = document.createElement('div');
  div.className = 'msg msg-ai';
  div.innerHTML = `
    <div class="msg-bubble">
      <div class="msg-sender"><span class="dot analyzing"></span>CyberAgent 分析中</div>
      <div class="analysis-steps"></div>
      <div class="msg-text" style="display:none;"></div>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

// ── AI Response Processing ────────────────────────────────────────
async function processAIResponse(text) {
  state.isProcessing = true;
  $('#btn-send').disabled = true;

  const msgEl = createAIMessage();
  const stepsContainer = msgEl.querySelector('.analysis-steps');
  const textContainer = msgEl.querySelector('.msg-text');

  try {
    // Build conversation history from current session
    const session = getCurrentSession();
    const history = (session ? session.messages : state.messages)
      .filter(m => m.role === 'user' || m.role === 'ai')
      .slice(0, -1) // exclude current user message just added
      .slice(-20)
      .map(m => ({
        role: m.role === 'ai' ? 'assistant' : m.role,
        content: m.content,
      }));

    const resp = await fetch(API_BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, history }),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Animate analysis steps
    if (data.steps && data.steps.length > 0) {
      const esc = s => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      for (const step of data.steps) {
        const stepEl = document.createElement('div');
        const isVerdict = step.round === 7 && step.status && step.status !== 'skip';
        const isSkip = step.status === 'skip';
        const isReact = step.thought != null && !isVerdict;

        if (isVerdict) {
          const icon = { critical: '🎯', high: '⚠️', medium: '🔔', low: '✅' }[step.status] || '✅';
          stepEl.className = `step step-verdict verdict-${step.status}`;
          stepEl.innerHTML =
            `<div class="step-verdict-head"><span class="step-verdict-icon">${icon}</span>第 ${step.round} 轮 · 综合判定</div>` +
            `<div class="step-verdict-body">${esc(step.summary)}</div>`;
        } else if (isSkip) {
          stepEl.className = 'step step-skip';
          stepEl.innerHTML = `<span class="step-summary">⚡ ${esc(step.summary)}</span>`;
        } else if (isReact) {
          stepEl.className = 'step step-react';
          stepEl.innerHTML =
            `<div class="step-react-head">` +
              `<span class="step-icon running">⟳</span>` +
              `<span class="step-round">第 ${step.round} 轮</span>` +
              `<span class="step-tool">${esc(step.tool)}</span>` +
            `</div>` +
            `<div class="step-thought">💭 ${esc(step.thought)}</div>` +
            `<span class="step-summary">▸ ${esc(step.summary)}</span>`;
        } else {
          stepEl.className = 'step';
          stepEl.innerHTML =
            `<span class="step-icon running">⟳</span>` +
            `<span class="step-tool">${esc(step.tool)}</span>` +
            `<span class="step-summary">${esc(step.summary)}</span>`;
        }
        stepsContainer.appendChild(stepEl);
        stepsContainer.scrollTop = stepsContainer.scrollHeight;
        await delay(isReact ? 1000 : 800 + Math.random() * 600);
        const icon = stepEl.querySelector('.step-icon');
        if (icon) { icon.className = 'step-icon done'; icon.textContent = '✓'; }
      }

      const expandEl = document.createElement('div');
      expandEl.className = 'expand-link';
      expandEl.textContent = '▲ 收起详情';
      expandEl.addEventListener('click', () => {
        const collapsed = expandEl.textContent.includes('收起');
        expandEl.textContent = collapsed ? '▼ 展开详情' : '▲ 收起详情';
        const steps = stepsContainer.querySelectorAll('.step');
        steps.forEach(s => s.style.display = collapsed ? 'none' : '');
      });
      stepsContainer.appendChild(expandEl);
    }

    // Render structured tool result cards
    if (data.tool_results && data.tool_results.length > 0) {
      const resultsWrap = document.createElement('div');
      resultsWrap.className = 'tool-results-wrap';
      for (const tr of data.tool_results) {
        const card = renderToolResultCard(tr);
        if (card) resultsWrap.appendChild(card);
      }
      if (resultsWrap.children.length > 0) {
        msgEl.querySelector('.msg-bubble').insertBefore(resultsWrap, textContainer);
      }
    }

    // Mark sender as done
    msgEl.querySelector('.msg-sender').innerHTML = '<span class="dot"></span>CyberAgent';

    // Show reply (with markdown rendering)
    const renderMd = (typeof marked !== 'undefined' && marked.parse) ? marked.parse : (s) => s.replace(/\n/g, '<br>');
    textContainer.innerHTML = renderMd(data.reply);
    textContainer.style.display = 'block';

    // Attach confirm button handlers if present in HTML
    const confirmBtns = textContainer.querySelectorAll('.confirm-btn');
    if (confirmBtns.length > 0) {
      // Extract device info from AI response and set as pending state for handleConfirm
      const ipMatch = data.reply ? data.reply.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/) : null;
      if (ipMatch) {
        window._pendingIsolateIp = ipMatch[1];
        // Also try to find a device_id if the reply contains one
        const idMatch = data.reply.match(/device[_-]?id[=:]\s*["']?([a-zA-Z0-9_-]+)/i);
        window._pendingIsolateId = idMatch ? idMatch[1] : '';
      }
      confirmBtns.forEach(btn => {
        btn.addEventListener('click', () => handleConfirm(btn.dataset.action, btn));
      });
    }

    // Track AI response in session (reuse `session` from history build above)
    if (session) {
      session.messages.push({ role: 'ai', content: data.reply, time: new Date().toISOString() });
      saveSessions();
    }

    addOpHistory('scan', '分析请求执行完成', text);

  } catch (error) {
    msgEl.querySelector('.msg-sender').innerHTML = '<span class="dot" style="background:#ff4466"></span>错误';
    textContainer.innerHTML = `请求失败: ${escapeHtml(error.message)}`;
    textContainer.style.display = 'block';
  } finally {
    state.isProcessing = false;
    $('#btn-send').disabled = false;
    const container = $('#chat-messages');
    container.scrollTop = container.scrollHeight;
  }
}

async function handleConfirm(action, btn) {
  // Find the specific confirm-card this button belongs to
  const confirmCard = btn.closest('.confirm-card');
  if (!confirmCard) return;

  // Only disable buttons within THIS card, not all cards in the message
  const actions = confirmCard.querySelectorAll('.confirm-btn');
  actions.forEach(b => b.disabled = true);

  if (action === 'confirm') {
    // Extract device IP from this specific card's content
    let deviceIp = '';
    const ipMatch = confirmCard.textContent.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipMatch) deviceIp = ipMatch[1];

    let deviceId = '';

    // Fallback: try to extract an IP from surrounding message text
    if (!deviceIp) {
      const msgEl = btn.closest('.msg');
      const msgText = msgEl ? msgEl.querySelector('.msg-text') : null;
      if (msgText) {
        const ipMatch2 = msgText.textContent.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch2) deviceIp = ipMatch2[1];
      }
    }

    if (!deviceIp) {
      if (confirmCard) {
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#ff4466">Error</div>
          <div class="confirm-details">
            <div>Cannot determine device IP. Isolation aborted.</div>
          </div>`;
        _syncConfirmCardToMessages(confirmCard);
      }
      return;
    }

    confirmCard.innerHTML = `
      <div class="confirm-title" style="color:#00bbff">正在隔离 ${escapeHtml(deviceIp)}</div>
      <div class="confirm-details iso-progress"><div class="iso-step iso-active">▸ 正在执行网络封禁...</div></div>`;

    // Staged progress messages shown while isolation executes
    const stages = [
      '正在连接接入交换机...',
      '正在下发端口关闭指令...',
      '正在验证隔离效果 (ping/端口探测)...',
    ];
    let stageIdx = 0;
    const stageTimer = setInterval(() => {
      const progressEl = confirmCard.querySelector('.iso-progress');
      if (!progressEl) return;
      const prev = progressEl.querySelector('.iso-active');
      if (prev) { prev.classList.remove('iso-active'); prev.classList.add('iso-done'); prev.textContent = prev.textContent.replace('▸', '✓'); }
      if (stageIdx < stages.length) {
        const step = document.createElement('div');
        step.className = 'iso-step iso-active';
        step.textContent = '▸ ' + stages[stageIdx];
        progressEl.appendChild(step);
        stageIdx++;
      }
    }, 850);

    try {
      const resp = await fetch('/api/tools/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId, device_ip: deviceIp }),
      });
      const data = await resp.json();
      clearInterval(stageTimer);

      if (data.task_id || data.status === 'started') {
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#00ff88">✓ 隔离完成</div>
          <div class="confirm-details">
            <div>设备 <strong>${escapeHtml(deviceIp)}</strong> 网络封禁规则已生效</div>
            <div class="iso-verify">✓ 隔离验证通过：ping 不可达，端口无响应</div>
            <div style="margin-top:4px;color:rgba(255,255,255,0.5);font-size:10px;">Task ID: ${escapeHtml(data.task_id || 'N/A')}</div>
          </div>`;
        addOpHistory('success', '设备隔离完成', `${deviceIp} — task ${data.task_id || 'N/A'}`);

        // Notify HUD via BroadcastChannel for immediate cross-page update
        _broadcastIsolation(deviceIp, deviceId);

      } else {
        clearInterval(stageTimer);
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#ffaa00">隔离响应</div>
          <div class="confirm-details"><div><code>${escapeHtml(JSON.stringify(data))}</code></div></div>`;
        addOpHistory('warning', 'Isolation response received', JSON.stringify(data));
      }
    } catch (e) {
      clearInterval(stageTimer);
      confirmCard.innerHTML = `
        <div class="confirm-title" style="color:#ff4466">隔离失败</div>
        <div class="confirm-details"><div>${escapeHtml(e.message)}</div></div>`;
      addOpHistory('error', 'Isolation failed', e.message);
    }

    // Sync updated confirm-card HTML back to state.messages so it persists
    _syncConfirmCardToMessages(confirmCard);

    // Clean up pending state
    delete window._pendingIsolateIp;
    delete window._pendingIsolateId;
  } else if (action === 'cancel') {
    if (confirmCard) {
      confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--muted)">Operation cancelled</div>`;
      _syncConfirmCardToMessages(confirmCard);
    }
    delete window._pendingIsolateIp;
    delete window._pendingIsolateId;
  } else {
    if (confirmCard) {
      confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--info)">Please enter a modified plan below</div>`;
      _syncConfirmCardToMessages(confirmCard);
    }
  }
}

/**
 * After confirm-card DOM is updated, replace the confirm-card portion
 * in the corresponding AI message in state.messages with the new HTML,
 * then persist to localStorage. This prevents buttons from re-appearing
 * after page refresh / state restoration.
 */
function _syncConfirmCardToMessages(confirmCard) {
  const msgEl = confirmCard.closest('.msg');
  if (!msgEl) return;

  // Find all AI messages and match by DOM element
  const allAiMsgs = document.querySelectorAll('.msg-ai');
  let msgIndex = -1;
  allAiMsgs.forEach((el, i) => {
    if (el === msgEl) msgIndex = i;
  });
  if (msgIndex < 0) return;

  // Map to state.messages — AI messages are at specific indices
  const aiMessages = state.messages.filter(m => m.role === 'ai');
  if (msgIndex >= aiMessages.length) return;

  const aiMsg = aiMessages[msgIndex];
  const oldCardPattern = /<div class="confirm-card">[\s\S]*?<\/div>\s*<\/div>\s*<\/div>/;
  const newCardHtml = confirmCard.outerHTML;

  if (oldCardPattern.test(aiMsg.content)) {
    aiMsg.content = aiMsg.content.replace(oldCardPattern, newCardHtml);
    saveSessions();
  } else {
    // Fallback: just save the whole updated textContent
    const textContainer = msgEl.querySelector('.msg-text');
    if (textContainer) {
      aiMsg.content = textContainer.innerHTML;
      saveSessions();
    }
  }
}

/**
 * Broadcast isolation event to HUD via BroadcastChannel,
 * providing a reliable cross-page notification path that
 * does not depend on backend WebSocket timing.
 */
function _broadcastIsolation(deviceIp, deviceId) {
  try {
    const bc = new BroadcastChannel('cyberclaw-sync');
    bc.postMessage({
      key: 'cc_isolation_event',
      deviceIp,
      deviceId,
      timestamp: Date.now(),
    });
    bc.close();
  } catch {}
}

// ── Operations Tab (now Automate) ────────────────────────────────

// ── Collector Management ────────────────────────────────────────
const COLLECTORS = [
  { id: 'syslog', name: 'Syslog', icon: 'fa-solid fa-scroll', color: '#00bbff',
    startApi: '/api/tools/collector/start', stopApi: '/api/tools/collector/stop', statusApi: '/api/tools/collector/status',
    startBody: { port: 8514 }, statusField: 'is_running', countField: 'stored_events', label: 'UDP 8514' },
  { id: 'snmp', name: 'SNMP Trap', icon: 'fa-solid fa-network-wired', color: '#00ff88',
    startApi: '/api/tools/snmp/start', stopApi: '/api/tools/snmp/stop', statusApi: '/api/tools/snmp/status',
    startBody: { port: 1162 }, statusField: 'trap_receiver_running', countField: 'traps_stored', label: 'UDP 1162' },
  { id: 'mqtt', name: 'MQTT', icon: 'fa-solid fa-tower-broadcast', color: '#eab308',
    startApi: '/api/tools/mqtt/connect', stopApi: '/api/tools/mqtt/disconnect', statusApi: '/api/tools/mqtt/status',
    statusField: 'connected', countField: 'messages_stored', label: 'Broker',
    startBody: { broker: '127.0.0.1', port: 1883, topics: ['cyberclaw/sensor/#'] },
    needsConfig: true },
  { id: 'suricata', name: 'Suricata IDS', icon: 'fa-solid fa-shield-halved', color: '#f97316',
    startApi: '/api/tools/suricata/start', stopApi: '/api/tools/suricata/stop', statusApi: '/api/tools/suricata/stats',
    statusField: 'is_running', countField: 'total_alerts', label: 'IDS Engine' },
];

async function fetchCollectors() {
  const grid = $('#collectors-grid');
  if (!grid) return;

  const statuses = await Promise.all(COLLECTORS.map(async (c) => {
    try {
      const r = await fetch(c.statusApi);
      return r.ok ? await r.json() : {};
    } catch { return {}; }
  }));

  grid.innerHTML = COLLECTORS.map((c, i) => {
    const s = statuses[i] || {};
    const running = !!s[c.statusField];
    const count = s[c.countField] ?? 0;
    const statusText = running ? '运行中' : '已停止';
    const statusCls = running ? 'running' : 'stopped';

    return `<div class="collector-card ${statusCls}" data-collector="${c.id}">
      <div class="cl-header">
        <span class="cl-icon" style="color:${c.color}"><i class="${c.icon}"></i></span>
        <span class="cl-name">${c.name}</span>
        <span class="cl-status-dot ${statusCls}"></span>
        <span class="cl-status-text ${statusCls}">${statusText}</span>
      </div>
      <div class="cl-info">
        <span class="cl-label">${c.label}</span>
        <span class="cl-count">${count} 条</span>
      </div>
      ${c.needsConfig ? `<div class="cl-config" id="cl-cfg-${c.id}" style="display:none">
        <input type="text" class="ops-input cl-cfg-field" id="cl-mqtt-broker" placeholder="Broker 地址 (如 127.0.0.1)" value="127.0.0.1" />
        <input type="number" class="ops-input cl-cfg-field" id="cl-mqtt-port" placeholder="端口" value="1883" style="width:60px" />
        <input type="text" class="ops-input cl-cfg-field" id="cl-mqtt-topics" placeholder="Topics (逗号分隔)" value="cyberclaw/sensor/#" />
      </div>` : ''}
      <div class="cl-actions">
        ${c.needsConfig ? `<button class="ops-action-btn start cl-toggle" data-collector="${c.id}" data-action="config" ${running ? 'style="display:none"' : ''}>配置并启动</button>` : ''}
        <button class="ops-action-btn start cl-toggle" data-collector="${c.id}" data-action="start" ${running ? 'style="display:none"' : ''}>启动</button>
        <button class="ops-action-btn stop cl-toggle" data-collector="${c.id}" data-action="stop" ${!running ? 'style="display:none"' : ''}>停止</button>
      </div>
    </div>`;
  }).join('');

  // Bind toggle buttons
  grid.querySelectorAll('.cl-toggle').forEach(btn => {
    btn.addEventListener('click', () => toggleCollector(btn.dataset.collector, btn.dataset.action));
  });
}

async function toggleCollector(collectorId, action) {
  const c = COLLECTORS.find(x => x.id === collectorId);
  if (!c) return;
  const grid = $('#collectors-grid');
  const card = grid?.querySelector(`[data-collector="${collectorId}"]`);
  if (!card) return;

  // Show loading state
  const btns = card.querySelectorAll('.cl-toggle');
  btns.forEach(b => b.disabled = true);

  try {
    let body;
    if (action === 'config') {
      // MQTT config + start
      const broker = $('#cl-mqtt-broker')?.value?.trim();
      const port = parseInt($('#cl-mqtt-port')?.value) || 1883;
      const topicsStr = $('#cl-mqtt-topics')?.value?.trim();
      const topics = topicsStr ? topicsStr.split(',').map(t => t.trim()).filter(Boolean) : ['#'];
      if (!broker) { alert('请输入 Broker 地址'); btns.forEach(b => b.disabled = false); return; }
      body = { broker, port, topics };
    } else if (action === 'start') {
      body = c.startBody;
    }

    const url = action === 'stop' ? c.stopApi : c.startApi;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || err.error || `HTTP ${resp.status}`);
    }
  } catch (e) {
    alert(`${c.name} 操作失败: ${e.message}`);
  }

  // Refresh all collector statuses
  await fetchCollectors();
}

function initAutomate() {
  fetchCollectors();
  initWorkflows();
  fetchActiveTasks();
  // Refresh active tasks every 30s
  setInterval(fetchActiveTasks, 30000);
  // Bind add-task button → open modal in-place
  const addBtn = $('#btn-add-task');
  if (addBtn) addBtn.addEventListener('click', () => showTaskModal());
  // Init notification section
  fetchNotificationConfig();
  fetchNotificationHistory();
  fetchWorkflowEvents();
  // Start notification polling
  startHistoryPoll();

  const testBtn = $('#btn-notif-test');
  if (testBtn) testBtn.addEventListener('click', sendTestNotification);

  const filters = document.querySelectorAll('.notif-filter-btn');
  filters.forEach(btn => {
    btn.addEventListener('click', () => {
      filters.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _currentNotifSection = btn.dataset.section;
      fetchNotificationHistory(_currentNotifSection || undefined);
    });
  });

  const refreshBtn = document.getElementById('btn-notif-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', () => fetchNotificationHistory(_currentNotifSection || undefined));

  const sevFilter = document.getElementById('notif-sev-filter');
  if (sevFilter) sevFilter.addEventListener('change', (e) => {
    _notifSeverityFilter = e.target.value;
    fetchNotificationHistory(_currentNotifSection || undefined);
  });
}

function addOpHistory(type, title, desc) {
  // Kept as a utility for internal tracking, no longer renders to UI
  state.opHistory.push({ type, title, desc, time: new Date() });
}

// ── Reports ───────────────────────────────────────────────────────

// ── Scan Scheduler ────────────────────────────────────────────────
// ── Workflows ─────────────────────────────────────────────────────
async function initWorkflows() {
  await fetchWorkflows();
}

async function fetchWorkflows() {
  try {
    const resp = await fetch('/api/workflows/');
    if (!resp.ok) return;
    const data = await resp.json();
    state.workflows = data.workflows || data || [];
    renderWorkflows();
  } catch {
    const list = $('#wf-list');
    if (list) list.innerHTML = '<div class="empty-state">无法加载工作流</div>';
  }
}

async function toggleWorkflow(index, enabled) {
  try {
    const resp = await fetch(`/api/workflows/${index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    state.workflows[index].enabled = enabled;
    addOpHistory('info', `工作流 ${enabled ? '启用' : '禁用'}`, state.workflows[index].name || '');
  } catch (e) {
    addOpHistory('error', '工作流操作失败', e.message);
    renderWorkflows();
  }
}
// ── HUD Link ──────────────────────────────────────────────────────
function initHudLink() {
  $('#btn-open-hud').addEventListener('click', () => {
    const hudUrl = window.location.origin + '/';
    window.open(hudUrl, 'cyberclaw-hud');
  });
}

// ── Utils ─────────────────────────────────────────────────────────
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Convert UTC ISO timestamp to local display string.
 *  "2026-06-04T06:54:13" → "2026-06-04 14:54:13" (in UTC+8)
 *  Returns "--" for empty/invalid input. */
function formatTs(ts, withDate = true) {
  if (!ts) return '--';
  try {
    const d = new Date(ts.includes('Z') || ts.includes('+') ? ts : ts + 'Z');
    if (isNaN(d.getTime())) return ts.replace('T', ' ').slice(0, 19);
    const pad = n => String(n).padStart(2, '0');
    if (withDate) return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch { return ts.replace('T', ' ').slice(0, 19); }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Devices Tab ───────────────────────────────────────────────────
function initDevices() {
  renderDevicesControls();
  fetchDevices();
}

function renderDevicesControls() {
  const wrap = $('#dev-controls');
  if (!wrap) return;
  wrap.innerHTML = `
    <input type="text" class="ops-input rp-search" id="dev-device-search" placeholder="搜索设备名称/IP/MAC..." value="${escapeHtml(state.deviceSearch)}" />
    <select class="ops-input rp-select" id="dev-device-status">
      <option value="">全部状态</option>
      <option value="secure">Secure</option>
      <option value="scanning">Scanning</option>
      <option value="vulnerable">Vulnerable</option>
      <option value="attacked">Attacked</option>
      <option value="isolated">Isolated</option>
    </select>
    <select class="ops-input rp-select" id="dev-device-type">
      <option value="">全部类型</option>
      ${[...new Set(state.devices.map(d => d.devType).filter(Boolean))].sort().map(t =>
        `<option value="${t}" ${state.deviceTypeFilter === t ? 'selected' : ''}>${t}</option>`
      ).join('')}
    </select>
    <select class="ops-input rp-select" id="dev-device-vendor">
      <option value="">全部厂商</option>
      ${[...new Set(state.devices.map(d => d.devVendor).filter(Boolean))].sort().map(v =>
        `<option value="${v}" ${state.deviceVendorFilter === v ? 'selected' : ''}>${v}</option>`
      ).join('')}
    </select>
  `;
  const searchInput = $('#dev-device-search');
  const statusSelect = $('#dev-device-status');
  const typeSelect = $('#dev-device-type');
  const vendorSelect = $('#dev-device-vendor');
  if (searchInput) searchInput.addEventListener('input', debounce((e) => {
    state.deviceSearch = e.target.value;
    state.devicePage = 0;
    renderDeviceTable();
  }, 250));
  if (statusSelect) {
    statusSelect.value = state.deviceStatusFilter;
    statusSelect.addEventListener('change', (e) => {
      state.deviceStatusFilter = e.target.value;
      state.devicePage = 0;
      renderDeviceTable();
    });
  }
  if (typeSelect) typeSelect.addEventListener('change', (e) => {
    state.deviceTypeFilter = e.target.value;
    state.devicePage = 0;
    renderDeviceTable();
  });
  if (vendorSelect) vendorSelect.addEventListener('change', (e) => {
    state.deviceVendorFilter = e.target.value;
    state.devicePage = 0;
    renderDeviceTable();
  });
}

// ── Events Tab ────────────────────────────────────────────────────
function initEvents() {
  renderEventsControls();
  fetchSecurityEvents();
}

const EVT_SOURCE_ICONS = {
  syslog: '<i class="fa-solid fa-scroll" title="Syslog"></i>',
  snmp: '<i class="fa-solid fa-network-wired" title="SNMP"></i>',
  mqtt: '<i class="fa-solid fa-tower-broadcast" title="MQTT"></i>',
  suricata: '<i class="fa-solid fa-shield-halved" title="Suricata IDS"></i>',
  scenario: '<i class="fa-solid fa-flask" title="Scenario"></i>',
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const _SEV_MAP = { emergency:'critical', alert:'critical', error:'high', warning:'medium', notice:'low', debug:'info' };
function normSev(s) { return _SEV_MAP[s] || (SEV_ORDER[s] !== undefined ? s : 'info'); }

function renderEventsControls() {
  const wrap = $('#evt-controls');
  if (!wrap) return;
  wrap.innerHTML = `
    <input type="text" class="ops-input evt-search" id="evt-search" placeholder="搜索事件 / IP / 设备..." value="${escapeHtml(state.eventsSearch)}" />
    <select class="ops-input rp-select" id="evt-source">
      <option value="">全部来源</option>
      <option value="syslog">Syslog</option>
      <option value="snmp">SNMP</option>
      <option value="mqtt">MQTT</option>
      <option value="suricata">Suricata</option>
      <option value="scenario">Scenario</option>
    </select>
    <select class="ops-input rp-select" id="evt-sev">
      <option value="">全部严重程度</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
    <select class="ops-input rp-select" id="evt-time">
      <option value="">全部时间</option>
      <option value="1h">近 1 小时</option>
      <option value="6h">近 6 小时</option>
      <option value="24h">近 24 小时</option>
      <option value="7d">近 7 天</option>
    </select>
    <select class="ops-input rp-select" id="evt-sort">
      <option value="timestamp-desc">时间 ↓</option>
      <option value="timestamp-asc">时间 ↑</option>
      <option value="severity-asc">严重性 ↓</option>
      <option value="severity-desc">严重性 ↑</option>
      <option value="source-asc">来源 ↑</option>
    </select>
    <button class="dp-btn" id="evt-refresh" title="刷新"><i class="fa-solid fa-rotate"></i></button>
    <button class="dp-btn dp-btn-danger" id="evt-clear" title="清除所有事件"><i class="fa-solid fa-trash-can"></i></button>
  `;
  const sevEl = $('#evt-sev');
  const srcEl = $('#evt-source');
  const timeEl = $('#evt-time');
  const sortEl = $('#evt-sort');
  const searchEl = $('#evt-search');
  if (sevEl) { sevEl.value = state.eventsSevFilter; sevEl.onchange = e => { state.eventsSevFilter = e.target.value; state.eventsPage = 0; renderSecurityEvents(); }; }
  if (srcEl) { srcEl.value = state.eventsSourceFilter; srcEl.onchange = e => { state.eventsSourceFilter = e.target.value; state.eventsPage = 0; fetchSecurityEvents(); }; }
  if (timeEl) { timeEl.value = state.eventsTimeRange; timeEl.onchange = e => { state.eventsTimeRange = e.target.value; state.eventsPage = 0; renderSecurityEvents(); }; }
  if (sortEl) {
    sortEl.value = `${state.eventsSortKey}-${state.eventsSortDir}`;
    sortEl.onchange = e => {
      const [k, d] = e.target.value.split('-');
      state.eventsSortKey = k;
      state.eventsSortDir = d;
      state.eventsPage = 0;
      renderSecurityEvents();
    };
  }
  if (searchEl) {
    let _searchTimer;
    searchEl.oninput = e => {
      clearTimeout(_searchTimer);
      _searchTimer = setTimeout(() => { state.eventsSearch = e.target.value; state.eventsPage = 0; renderSecurityEvents(); }, 250);
    };
    searchEl.onkeydown = e => { if (e.key === 'Enter') { clearTimeout(_searchTimer); state.eventsSearch = e.target.value; state.eventsPage = 0; renderSecurityEvents(); } };
  }
  $('#evt-refresh')?.addEventListener('click', () => fetchSecurityEvents());
  $('#evt-clear')?.addEventListener('click', () => {
    if (!state.events.length) return;
    if (!confirm(`确认清除全部 ${state.events.length} 条安全事件？此操作不可撤销。`)) return;
    fetch('/api/dashboard/alerts/clear', { method: 'DELETE' })
      .then(r => r.json())
      .then(() => { state.events = []; state.eventsPage = 0; renderSecurityEvents(); })
      .catch(e => alert('清除失败: ' + e.message));
  });
}

async function fetchDevices() {
  try {
    const resp = await fetch('/api/dashboard/db/devices');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    state.devices = data.devices || [];
    renderDevicesControls();
    renderDeviceTable();
  } catch (e) {
    const body = $('#dev-body');
    if (body) body.innerHTML = `<div class="empty-state">加载设备失败: ${escapeHtml(e.message)}</div>`;
  }
}

let renderDeviceTable = function() {
  const body = $('#rp-body');
  if (!body) return;

  let devs = [...state.devices];

  // Filter by status
  if (state.deviceStatusFilter) {
    devs = devs.filter(d => (d.devStatus || d.devForceStatus || 'secure') === state.deviceStatusFilter);
  }

  // Filter by type
  if (state.deviceTypeFilter) {
    devs = devs.filter(d => d.devType === state.deviceTypeFilter);
  }

  // Filter by vendor
  if (state.deviceVendorFilter) {
    devs = devs.filter(d => d.devVendor === state.deviceVendorFilter);
  }

  // Filter by search
  if (state.deviceSearch) {
    const q = state.deviceSearch.toLowerCase();
    devs = devs.filter(d =>
      (d.devMAC || '').toLowerCase().includes(q) ||
      (d.devName || '').toLowerCase().includes(q) ||
      (d.devLastIP || '').toLowerCase().includes(q) ||
      (d.devVendor || '').toLowerCase().includes(q) ||
      (d.devType || '').toLowerCase().includes(q)
    );
  }

  // Sort
  const key = state.deviceSortKey;
  const dir = state.deviceSortDir === 'asc' ? 1 : -1;
  devs.sort((a, b) => {
    const va = (a[key] || '').toString().toLowerCase();
    const vb = (b[key] || '').toString().toLowerCase();
    return va < vb ? -dir : va > vb ? dir : 0;
  });

  // Paginate
  const total = devs.length;
  const pages = Math.max(1, Math.ceil(total / state.devicePageSize));
  state.devicePage = Math.min(state.devicePage, pages - 1);
  const start = state.devicePage * state.devicePageSize;
  const page = devs.slice(start, start + state.devicePageSize);

  const sortIcon = (k) => state.deviceSortKey === k
    ? (state.deviceSortDir === 'asc' ? ' ▲' : ' ▼')
    : '';

  body.innerHTML = `
    <div class="device-stat-cards">
      <div class="stat-card"><div class="stat-num">${state.devices.length}</div><div class="stat-label">总设备</div></div>
      <div class="stat-card stat-online"><div class="stat-num">${state.devices.filter(d => (d.devStatus || 'secure') !== 'isolated').length}</div><div class="stat-label">在线</div></div>
      <div class="stat-card stat-cam"><div class="stat-num">${state.devices.filter(d => d.devType === 'camera').length}</div><div class="stat-label">摄像头</div></div>
      <div class="stat-card stat-sensor"><div class="stat-num">${state.devices.filter(d => d.devType === 'sensor' || d.devType === 'plc').length}</div><div class="stat-label">工控</div></div>
      <div class="stat-card stat-infra"><div class="stat-num">${state.devices.filter(d => ['switch','gateway','firewall'].includes(d.devType)).length}</div><div class="stat-label">基础设施</div></div>
    </div>
    <div class="rp-device-table-wrap">
      <table class="device-table">
        <thead>
          <tr>
            <th class="sortable" data-sort="devName">名称${sortIcon('devName')}</th>
            <th>状态</th>
            <th class="sortable" data-sort="devType">类型${sortIcon('devType')}</th>
            <th class="sortable" data-sort="devLastIP">IP${sortIcon('devLastIP')}</th>
            <th>MAC</th>
            <th class="sortable" data-sort="devVendor">厂商${sortIcon('devVendor')}</th>
            <th>型号</th>
            <th>开放端口</th>
            <th>协议</th>
            <th>交换机端口</th>
            <th>固件</th>
          </tr>
        </thead>
        <tbody>
          ${page.map(d => {
            const status = d.devStatus || d.devForceStatus || 'secure';
            const ports = (() => { try { return JSON.parse(d.devOpenPorts || '[]'); } catch { return []; } })();
            const protos = (() => { try { return JSON.parse(d.devProtocols || '[]'); } catch { return []; } })();
            const portsHtml = ports.slice(0, 5).map(p => '<span class="port-badge">' + p + '</span>').join('') || '-';
            const protosHtml = protos.slice(0, 4).map(p => '<span class="proto-badge">' + p + '</span>').join('') || '-';
            return `<tr>
              <td class="td-name">${escapeHtml(d.devName || '-')}</td>
              <td><span class="status-badge ${status}">${status}</span></td>
              <td>${escapeHtml(d.devType || '-')}</td>
              <td class="td-mono">${escapeHtml(d.devLastIP || '-')}</td>
              <td class="td-mono td-mac">${escapeHtml(d.devMAC || '-')}</td>
              <td>${escapeHtml(d.devVendor || '-')}</td>
              <td class="td-model">${escapeHtml(d.devModel || '-')}</td>
              <td class="td-ports">${portsHtml}</td>
              <td class="td-protos">${protosHtml}</td>
              <td class="td-mono">${escapeHtml(d.devSwitchPort || '-')}</td>
              <td class="td-fw">${escapeHtml(d.devFirmwareVersion || '-')}</td>
            </tr>`;
          }).join('')}
          ${page.length === 0 ? '<tr><td colspan="11" class="td-empty">无匹配设备</td></tr>' : ''}
        </tbody>
      </table>
    </div>
    ${renderPagination(total, state.devicePage, state.devicePageSize, 'device')}
  `;

  // Bind sort headers
  body.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (state.deviceSortKey === k) {
        state.deviceSortDir = state.deviceSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        state.deviceSortKey = k;
        state.deviceSortDir = 'asc';
      }
      renderDeviceTable();
    });
  });

  bindPagination(body, 'device', (p) => { state.devicePage = p; renderDeviceTable(); });
}

async function fetchSecurityEvents() {
  try {
    // Fetch all events (no severity filter at API level — we normalize client-side)
    const params = new URLSearchParams({ limit: '500' });
    if (state.eventsSourceFilter) params.set('source_type', state.eventsSourceFilter);
    const resp = await fetch(`/api/dashboard/alerts?${params}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    state.events = data.alerts || [];
    renderSecurityEvents();
  } catch (e) {
    const body = $('#evt-body');
    if (body) body.innerHTML = `<div class="empty-state">加载事件失败: ${escapeHtml(e.message)}</div>`;
  }
}

function _filterEvents() {
  let evts = [...state.events];

  // Client-side severity filter (normalized)
  if (state.eventsSevFilter) {
    evts = evts.filter(e => normSev(e.severity || 'info') === state.eventsSevFilter);
  }

  // Client-side time range filter
  if (state.eventsTimeRange) {
    const now = Date.now();
    const rangeMs = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000 };
    const cutoff = now - (rangeMs[state.eventsTimeRange] || 0);
    evts = evts.filter(e => {
      try { return new Date(e.timestamp).getTime() >= cutoff; } catch { return true; }
    });
  }

  // Client-side keyword search
  if (state.eventsSearch) {
    const q = state.eventsSearch.toLowerCase();
    evts = evts.filter(e =>
      (e.message || '').toLowerCase().includes(q) ||
      (e.source || '').toLowerCase().includes(q) ||
      (e.target || '').toLowerCase().includes(q) ||
      (e.source_type || '').toLowerCase().includes(q) ||
      (e.category || '').toLowerCase().includes(q)
    );
  }

  // Sort
  const key = state.eventsSortKey;
  const dir = state.eventsSortDir === 'asc' ? 1 : -1;
  evts.sort((a, b) => {
    if (key === 'severity') {
      const sa = SEV_ORDER[normSev(a.severity)] ?? 9;
      const sb = SEV_ORDER[normSev(b.severity)] ?? 9;
      return (sa - sb) * dir;
    }
    if (key === 'source') {
      return ((a.source || '').toLowerCase() < (b.source || '').toLowerCase() ? -1 : 1) * dir;
    }
    // timestamp
    const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
    const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
    return (ta - tb) * dir;
  });

  return evts;
}

function renderSecurityEvents() {
  const body = $('#evt-body');
  if (!body) return;

  // ── Severity stat cards ────────────────────────────────────────
  const allSevs = ['critical', 'high', 'medium', 'low', 'info'];
  const sevCounts = {};
  allSevs.forEach(s => sevCounts[s] = 0);
  state.events.forEach(e => { const s = normSev(e.severity || 'info'); sevCounts[s]++; });

  const statsHtml = `<div class="evt-stats-row">
    ${allSevs.map(s => {
      const active = state.eventsSevFilter === s;
      return `<div class="evt-stat-card sev-${s} ${active ? 'active' : ''}" data-evt-sev-filter="${s}">
        <div class="evt-stat-num">${sevCounts[s]}</div>
        <div class="evt-stat-label">${s.toUpperCase()}</div>
      </div>`;
    }).join('')}
    <div class="evt-stat-card ${!state.eventsSevFilter ? 'active' : ''}" data-evt-sev-filter="">
      <div class="evt-stat-num">${state.events.length}</div>
      <div class="evt-stat-label">ALL</div>
    </div>
  </div>`;

  // ── Filter + sort (client-side) ────────────────────────────────
  const filtered = _filterEvents();

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / state.eventsPageSize));
  state.eventsPage = Math.min(state.eventsPage, pages - 1);
  const start = state.eventsPage * state.eventsPageSize;
  const page = filtered.slice(start, start + state.eventsPageSize);

  // ── Event list ─────────────────────────────────────────────────
  const listHtml = `<div class="events-list">
    ${page.map((evt, idx) => {
      const sev = normSev(evt.severity || 'info');
      const ts = evt.timestamp ? formatTs(evt.timestamp) : '--';
      const srcIcon = EVT_SOURCE_ICONS[evt.source_type] || '<i class="fa-solid fa-circle-question"></i>';
      const srcType = evt.source_type || '';
      const src = evt.source || '';
      const tgt = evt.target || '';
      const proto = evt.protocol || evt.details?.protocol || '';
      const fsm = evt.fsm_state || evt.details?.fsm_state || '';
      const cat = evt.category || evt.details?.category || '';
      const expanded = state._expandedEvt === (evt.id || idx);

      // source → target line
      let flowParts = [];
      if (src) flowParts.push(escapeHtml(src));
      if (src && tgt) flowParts.push('<span class="evt-arrow">→</span>');
      if (tgt) flowParts.push(escapeHtml(tgt));
      const flowHtml = flowParts.length ? flowParts.join(' ') : '';

      // Tags
      const tagParts = [];
      if (proto) tagParts.push(`<span class="evt-tag">${escapeHtml(proto)}</span>`);
      if (fsm) tagParts.push(`<span class="evt-tag evt-tag-fsm">${fsm}</span>`);
      if (cat) tagParts.push(`<span class="evt-tag">${escapeHtml(cat)}</span>`);

      // Detail section (collapsed by default)
      const detailObj = evt.details || {};
      const detailKeys = Object.keys(detailObj);
      const detailHtml = (detailKeys.length > 0)
        ? `<div class="evt-detail-json"><pre>${escapeHtml(JSON.stringify(detailObj, null, 2))}</pre></div>` : '';
      const extraFields = [];
      if (evt.type) extraFields.push(`<span class="evt-detail-field"><b>type</b> ${escapeHtml(evt.type)}</span>`);
      if (evt.target_mac) extraFields.push(`<span class="evt-detail-field"><b>mac</b> ${escapeHtml(evt.target_mac)}</span>`);

      return `<div class="evt-item sev-${sev} ${expanded ? 'expanded' : ''}" data-evt-id="${evt.id || idx}">
        <div class="evt-left">
          <span class="evt-sev-badge sev-${sev}">${sev.toUpperCase()}</span>
        </div>
        <div class="evt-body">
          <div class="evt-msg">${escapeHtml(evt.message || '')}</div>
          <div class="evt-flow">
            ${flowHtml}
            ${tagParts.length ? '<span class="evt-tags">' + tagParts.join('') + '</span>' : ''}
          </div>
          <div class="evt-meta">
            <span class="evt-src-icon">${srcIcon}</span>
            <span class="evt-src-type">${escapeHtml(srcType)}</span>
            <span class="evt-time">${ts}</span>
            <span class="evt-actions">
              <button class="evt-action-btn" data-evt-action="analyze" data-evt-idx="${start + idx}" title="在对话中分析"><i class="fa-solid fa-comment-dots"></i> 分析</button>
              ${tgt ? `<button class="evt-action-btn" data-evt-action="device" data-evt-target="${escapeHtml(tgt)}" title="查看设备"><i class="fa-solid fa-desktop"></i> 设备</button>` : ''}
            </span>
          </div>
          ${expanded ? `<div class="evt-detail">
            ${extraFields.length ? '<div class="evt-detail-fields">' + extraFields.join('') + '</div>' : ''}
            ${detailHtml}
          </div>` : ''}
        </div>
        <button class="evt-expand-btn" data-evt-toggle="${evt.id || idx}" title="展开详情">
          <i class="fa-solid fa-chevron-${expanded ? 'up' : 'down'}"></i>
        </button>
      </div>`;
    }).join('')}
    ${page.length === 0 ? '<div class="empty-state">无匹配事件</div>' : ''}
  </div>`;

  body.innerHTML = `
    ${statsHtml}
    ${listHtml}
    ${renderPagination(total, state.eventsPage, state.eventsPageSize, 'event')}
  `;

  // ── Bind interactions ──────────────────────────────────────────
  // Stat card click → severity filter
  body.querySelectorAll('.evt-stat-card[data-evt-sev-filter]').forEach(card => {
    card.addEventListener('click', () => {
      const val = card.dataset.evtSevFilter;
      state.eventsSevFilter = (state.eventsSevFilter === val) ? '' : val;
      const sevEl = $('#evt-sev');
      if (sevEl) sevEl.value = state.eventsSevFilter;
      state.eventsPage = 0;
      renderSecurityEvents();
    });
  });

  // Expand/collapse
  body.querySelectorAll('.evt-expand-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.evtToggle;
      state._expandedEvt = (state._expandedEvt === id) ? null : id;
      renderSecurityEvents();
    });
  });

  // Action: analyze in chat
  body.querySelectorAll('[data-evt-action="analyze"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.evtIdx, 10);
      const evt = filtered[idx];
      if (!evt) return;
      const summary = `[安全事件] ${evt.severity?.toUpperCase()} — ${evt.message || ''}${evt.source ? ' (来源: ' + evt.source + ')' : ''}${evt.target ? ' (目标: ' + evt.target + ')' : ''}`;
      switchTab('chat');
      const input = $('#chat-input');
      if (input) { input.value = '分析这个安全事件: ' + summary; input.focus(); }
    });
  });

  // Action: view device — switch to devices tab and let user locate it
  body.querySelectorAll('[data-evt-action="device"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const target = btn.dataset.evtTarget;
      if (!target) return;
      switchTab('devices');
      // Pre-fill search to locate the device
      const devSearch = $('#dev-device-search');
      if (devSearch) {
        devSearch.value = target;
        state.deviceSearch = target;
        state.devicePage = 0;
        renderDeviceTable();
      }
    });
  });

  bindPagination(body, 'event', (p) => { state.eventsPage = p; renderSecurityEvents(); });
}

function renderPagination(total, current, pageSize, prefix) {
  if (total <= pageSize) return '';
  const totalPages = Math.ceil(total / pageSize);
  const pages = [];
  const start = Math.max(0, current - 2);
  const end = Math.min(totalPages - 1, current + 2);
  for (let i = start; i <= end; i++) pages.push(i);

  return `<div class="rp-pagination">
    <span class="pg-info">${total} 条 · 第 ${current + 1}/${totalPages} 页</span>
    <button class="pg-btn" data-${prefix}-page="0" ${current === 0 ? 'disabled' : ''}>«</button>
    ${pages.map(p => `<button class="pg-btn ${p === current ? 'active' : ''}" data-${prefix}-page="${p}">${p + 1}</button>`).join('')}
    <button class="pg-btn" data-${prefix}-page="${totalPages - 1}" ${current === totalPages - 1 ? 'disabled' : ''}>»</button>
  </div>`;
}

function bindPagination(container, prefix, handler) {
  container.querySelectorAll(`[data-${prefix}-page]`).forEach(btn => {
    btn.addEventListener('click', () => {
      handler(parseInt(btn.dataset[`${prefix}Page`], 10));
    });
  });
}

// ── History/Notification helpers (used by Automate tab) ───────────
let _currentNotifSection = '';
let _notifSearch = '';
let _notifSeverityFilter = '';

async function fetchNotificationConfig() {
  try {
    const resp = await fetch('/api/notifications/config');
    if (!resp.ok) return;
    const data = await resp.json();
    renderNotificationConfig(data);
  } catch {
    const wrap = $('#notif-channels');
    if (wrap) wrap.innerHTML = '<div class="empty-state">加载失败</div>';
  }
}

function renderNotificationConfig(config) {
  const wrap = $('#notif-channels');
  if (!wrap) return;

  const channels = config.channels || {};
  const channelDefs = [
    { key: 'webhook', label: 'Webhook', fields: [
      { name: 'url', label: 'URL', type: 'text' },
      { name: 'secret', label: 'Secret', type: 'password' },
    ]},
    { key: 'ntfy', label: 'ntfy', fields: [
      { name: 'server', label: 'Server', type: 'text' },
      { name: 'topic', label: 'Topic', type: 'text' },
    ]},
  ];

  wrap.innerHTML = channelDefs.map(ch => {
    const chData = channels[ch.key] || {};
    const enabled = chData.enabled === true || chData.enabled === 'Yes' || chData.enabled === 'yes';
    return `
      <div class="notif-channel" data-channel="${ch.key}">
        <div class="notif-channel-header">
          <span class="notif-channel-label">${ch.label}</span>
          <label class="wf-toggle">
            <input type="checkbox" ${enabled ? 'checked' : ''} data-ch-key="${ch.key}" class="ch-enabled-toggle" />
            <span class="wf-toggle-slider"></span>
          </label>
        </div>
        <div class="notif-channel-fields ${enabled ? 'open' : ''}">
          ${ch.fields.map(f => `
            <div class="ch-field">
              <label>${f.label}</label>
              <input type="${f.type}" class="ops-input ch-input" data-ch-key="${ch.key}" data-field="${f.name}" value="${escapeHtml(chData[f.name] || '')}" />
            </div>
          `).join('')}
          <button class="ops-action-btn start ch-save-btn" data-ch-key="${ch.key}">SAVE</button>
        </div>
      </div>
    `;
  }).join('');

  // Toggle expand/collapse
  wrap.querySelectorAll('.ch-enabled-toggle').forEach(input => {
    input.addEventListener('change', (e) => {
      const card = e.target.closest('.notif-channel');
      const fields = card.querySelector('.notif-channel-fields');
      fields.classList.toggle('open', e.target.checked);
    });
  });

  // Save buttons
  wrap.querySelectorAll('.ch-save-btn').forEach(btn => {
    btn.addEventListener('click', () => saveNotificationChannelConfig(btn.dataset.chKey));
  });
}

async function saveNotificationChannelConfig(chKey) {
  const card = document.querySelector(`.notif-channel[data-channel="${chKey}"]`);
  if (!card) return;

  const enabled = card.querySelector('.ch-enabled-toggle')?.checked || false;
  const fields = {};
  card.querySelectorAll('.ch-input').forEach(input => {
    fields[input.dataset.field] = input.value;
  });

  try {
    // Fetch current config first
    const resp = await fetch('/api/notifications/config');
    const config = resp.ok ? await resp.json() : { channels: {}, rules: [] };
    if (!config.channels) config.channels = {};

    config.channels[chKey] = { ...config.channels[chKey], ...fields, enabled };
    const putResp = await fetch('/api/notifications/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!putResp.ok) throw new Error(`HTTP ${putResp.status}`);
    addOpHistory('success', `通知通道 ${chKey} 已保存`, enabled ? '已启用' : '已禁用');
  } catch (e) {
    addOpHistory('error', '保存通知配置失败', e.message);
  }
}

async function sendTestNotification() {
  try {
    const resp = await fetch('/api/notifications/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'CyberClaw Test', message: '测试通知 — 请忽略', severity: 'info' }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    addOpHistory('success', '测试通知已发送', '');
    await fetchNotificationHistory();
  } catch (e) {
    addOpHistory('error', '发送测试通知失败', e.message);
  }
}

async function fetchNotificationHistory(section) {
  try {
    const params = new URLSearchParams({ limit: '50' });
    if (section) params.set('section', section);
    if (_notifSeverityFilter) params.set('severity', _notifSeverityFilter);
    if (_notifSearch) params.set('search', _notifSearch);
    const resp = await fetch(`/api/notifications/history?${params}`);
    if (!resp.ok) return;
    const data = await resp.json();
    renderNotificationHistory(data.notifications || []);
    // Update unread count
    const countResp = await fetch('/api/notifications/unread_count');
    if (countResp.ok) {
      const countData = await countResp.json();
      const badge = document.getElementById('notif-unread-badge');
      if (badge) {
        if (countData.count > 0) {
          badge.style.display = 'inline';
          badge.textContent = countData.count;
        } else {
          badge.style.display = 'none';
        }
      }
    }
  } catch {
    const wrap = $('#notif-history');
    if (wrap) wrap.innerHTML = '<div class="empty-state">加载失败</div>';
  }
}

// NetAlertX-style section icons
const SECTION_ICONS = {
  new_devices: '<i class="fa-solid fa-circle-plus"></i>',
  down_devices: '<i class="fa-solid fa-circle-xmark"></i>',
  security_events: '<i class="fa-solid fa-bolt"></i>',
  scheduled_checks: '<i class="fa-solid fa-clock"></i>',
  system: '<i class="fa-solid fa-circle-info"></i>',
};

const SEVERITY_COLORS = {
  critical: '#ff2222',
  warning: '#ffaa00',
  high: '#ff6600',
  info: '#00cc88',
};

function renderNotificationHistory(notifs) {
  const wrap = $('#notif-history');
  if (!wrap) return;

  // Toolbar with batch operations + search
  const toolbar = `
    <div class="notif-batch-toolbar">
      <button class="notif-batch-btn" id="btn-mark-all-read">全部已读</button>
      <button class="notif-batch-btn danger" id="btn-clear-all">清空</button>
      <input type="text" class="notif-search-input" id="notif-search"
             placeholder="搜索通知..." value="${escapeHtml(_notifSearch)}" />
    </div>
  `;

  if (!notifs.length) {
    wrap.innerHTML = toolbar + '<div class="empty-state">暂无通知记录</div>';
    bindNotifToolbarEvents();
    return;
  }

  wrap.innerHTML = toolbar + notifs.map(n => {
    const ts = formatTs(n.created_at || n.pushed_at);
    const section = n.section || 'system';
    const icon = SECTION_ICONS[section] || 'ℹ️';
    const severity = n.severity || 'info';
    const color = SEVERITY_COLORS[severity] || '#888';
    const channels = (n.channels || '').split(',').filter(c => c).join(', ');
    const isNew = n.status === 'new';
    const hasDetail = n.extra_json && n.extra_json.length > 2;
    const detailBtnHtml = hasDetail
      ? `<button class="notif-detail-btn" onclick="event.stopPropagation(); showNotifDetailModal(${n.id})">查看详情</button>`
      : '';
    return `
      <div class="notif-item ${isNew ? 'unread' : ''} severity-${severity}" data-id="${n.id}" onclick="markNotifRead(${n.id})">
        <div class="notif-dot" style="background:${color}"></div>
        <div class="notif-body">
          <div class="notif-title">${icon} ${escapeHtml(n.title || '')}</div>
          <div class="notif-msg">${escapeHtml((n.message || '').substring(0, 200))}</div>
          <div class="notif-meta">${channels ? escapeHtml(channels) + ' · ' : ''}${ts}${detailBtnHtml}</div>
        </div>
      </div>
    `;
  }).join('');

  bindNotifToolbarEvents();
}

function bindNotifToolbarEvents() {
  // Mark all read
  const markAllBtn = document.getElementById('btn-mark-all-read');
  if (markAllBtn) markAllBtn.addEventListener('click', async () => {
    try {
      await fetch('/api/notifications/mark-all-read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ section: _currentNotifSection || undefined }),
      });
      fetchNotificationHistory(_currentNotifSection || undefined);
    } catch {}
  });

  // Clear all
  const clearBtn = document.getElementById('btn-clear-all');
  if (clearBtn) clearBtn.addEventListener('click', async () => {
    if (!confirm('确定要清空所有通知吗？此操作不可撤销。')) return;
    try {
      await fetch('/api/notifications/history', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ section: _currentNotifSection || undefined }),
      });
      fetchNotificationHistory(_currentNotifSection || undefined);
    } catch {}
  });

  // Search (debounced)
  const searchInput = document.getElementById('notif-search');
  if (searchInput) {
    let _searchTimer = null;
    searchInput.addEventListener('input', (e) => {
      clearTimeout(_searchTimer);
      _searchTimer = setTimeout(() => {
        _notifSearch = e.target.value.trim();
        fetchNotificationHistory(_currentNotifSection || undefined);
      }, 300);
    });
  }
}

// Mark notification as read on click
window.markNotifRead = async function(id) {
  try {
    await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
    const el = document.querySelector(`.notif-item[data-id="${id}"]`);
    if (el) el.classList.remove('unread');
  } catch {}
};

// ── Notification Detail Modal ────────────────────────────────────────

async function showNotifDetailByGuid(guid) {
  if (!guid) return;
  try {
    const resp = await fetch(`/api/notifications/by-guid/${encodeURIComponent(guid)}`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data && data.id) showNotifDetailModal(data.id);
  } catch {}
}

async function showNotifDetailModal(notificationId) {
  // Create modal overlay
  const overlay = document.createElement('div');
  overlay.className = 'notif-detail-overlay';
  overlay.innerHTML = `
    <div class="notif-detail-modal">
      <div class="notif-detail-header">
        <span class="notif-detail-title">加载中...</span>
        <button class="notif-detail-close">&times;</button>
      </div>
      <div class="notif-detail-body">
        <div class="empty-state">加载详情...</div>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  overlay.querySelector('.notif-detail-close').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  // ESC to close
  const escHandler = (e) => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escHandler); } };
  document.addEventListener('keydown', escHandler);

  try {
    const resp = await fetch(`/api/notifications/${notificationId}`);
    if (!resp.ok) throw new Error('加载失败');
    const data = await resp.json();

    overlay.querySelector('.notif-detail-title').textContent = data.title || '通知详情';
    const body = overlay.querySelector('.notif-detail-body');
    const extra = data.extra;

    if (!extra || !extra.result) {
      // No rich data — show basic info
      body.innerHTML = `
        <div class="notif-detail-summary">
          <div class="notif-detail-meta">
            <div class="notif-detail-row"><span class="label">严重性</span><span class="sev-badge sev-${data.severity === 'critical' ? 'critical' : data.severity === 'warning' ? 'high' : 'info'}">${escapeHtml(data.severity || 'info')}</span></div>
            <div class="notif-detail-row"><span class="label">时间</span><span>${formatTs(data.created_at)}</span></div>
          </div>
        </div>
        <div style="font-size:12px;color:var(--text);line-height:1.6;">${escapeHtml(data.message || '')}</div>`;
      return;
    }

    const taskType = extra.task_type || '';
    const result = extra.result;

    // Summary header
    let html = renderNotifDetailSummary(data, taskType);

    // Dispatch to task-specific renderer
    switch (taskType) {
      case 'network_scan':      html += renderNetworkScanDetail(result); break;
      case 'cve_check':         html += renderCveCheckDetail(result); break;
      case 'baseline_check':    html += renderBaselineCheckDetail(result); break;
      case 'traffic_analysis':  html += renderTrafficAnalysisDetail(result); break;
      case 'config_audit':      html += renderConfigAuditDetail(result); break;
      default:                  html += `<div class="notif-detail-raw"><pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre></div>`;
    }

    body.innerHTML = html;
  } catch (e) {
    overlay.querySelector('.notif-detail-body').innerHTML = `<div class="empty-state">加载失败: ${escapeHtml(e.message)}</div>`;
  }
}
window.showNotifDetailModal = showNotifDetailModal;

// ── Task-specific detail renderers ──────────────────────────────────

const TASK_TYPE_LABELS = {
  network_scan: '网络扫描', cve_check: 'CVE 漏洞检查',
  baseline_check: '安全基线检查', traffic_analysis: '流量分析', config_audit: '配置审计',
};

function renderNotifDetailSummary(data, taskType) {
  const label = TASK_TYPE_LABELS[taskType] || taskType;
  const sevCls = data.severity === 'critical' ? 'critical' : data.severity === 'warning' ? 'high' : data.severity === 'info' ? 'info' : 'medium';
  return `
    <div class="notif-detail-summary">
      <div class="notif-detail-meta">
        <div class="notif-detail-row"><span class="label">类型</span><span>${escapeHtml(label)}</span></div>
        <div class="notif-detail-row"><span class="label">严重性</span><span class="sev-badge sev-${sevCls}">${escapeHtml(data.severity || 'info')}</span></div>
        <div class="notif-detail-row"><span class="label">时间</span><span>${formatTs(data.created_at)}</span></div>
      </div>
      <div style="font-size:11px;color:var(--text);margin-top:8px;line-height:1.5;">${escapeHtml(data.message || '')}</div>
    </div>`;
}

function renderNetworkScanDetail(result) {
  const hosts = result.hosts || [];
  const hostsUp = result.hosts_up || hosts.length;
  if (!hosts.length) return `<div class="detail-section"><div class="detail-section-title">扫描结果</div><div class="empty-state">发现 ${hostsUp} 台设备在线（无详细列表）</div></div>`;

  return `
    <div class="detail-section">
      <div class="detail-section-title">发现设备 (${hosts.length})</div>
      <table class="tool-table">
        <thead><tr><th>IP 地址</th><th>MAC 地址</th><th>主机名</th><th>厂商</th></tr></thead>
        <tbody>${hosts.map(h => `<tr>
          <td class="td-mono">${escapeHtml(h.ip || '')}</td>
          <td class="td-mono">${escapeHtml(h.mac || '-')}</td>
          <td>${escapeHtml(h.hostname || '-')}</td>
          <td>${escapeHtml(h.vendor || '-')}</td>
        </tr>`).join('')}</tbody>
      </table>
    </div>`;
}

function renderCveCheckDetail(result) {
  const cves = result.cves || [];
  const total = result.total_cves || cves.length;
  if (!cves.length) return `<div class="detail-section"><div class="detail-section-title">CVE 列表</div><div class="empty-state">发现 ${total} 个 CVE（无详细列表）</div></div>`;

  return `
    <div class="detail-section">
      <div class="detail-section-title">CVE 列表 (${total} 个，${result.critical || 0} 严重，${result.high || 0} 高危)</div>
      ${cves.map(c => {
        const cvss = c.cvss_v3 || c.cvss || 0;
        const sev = (c.severity || '').toLowerCase();
        const cls = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
        const cweStr = Array.isArray(c.cwe) ? c.cwe.join(', ') : (c.cwe || '');
        return `<div class="cve-card" style="border-left-color:${cls === 'critical' ? '#ff4444' : cls === 'high' ? '#ff6600' : '#ffaa00'}">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <span class="cve-id">${escapeHtml(c.cve_id || '')}</span>
            <span class="sev-badge sev-${cls}">${sev.toUpperCase()}</span>
            <span style="color:var(--muted);font-size:10px;">CVSS ${cvss}</span>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-top:4px;line-height:1.4;">${escapeHtml((c.description || '').substring(0, 300))}</div>
          ${cweStr ? `<div style="font-size:9px;color:rgba(255,255,255,0.3);margin-top:2px;">CWE: ${escapeHtml(cweStr)}</div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
}

function renderBaselineCheckDetail(result) {
  const score = result.overall_score || 0;
  const devices = result.devices || [];
  const summary = result.summary || {};
  const color = score >= 80 ? '#4caf50' : score >= 50 ? '#ff9800' : '#f44336';
  const totalFail = summary.total_fail || 0;
  const critFail = summary.critical_failures || 0;

  let html = `
    <div class="detail-section">
      <div class="detail-section-title">安全基线评分</div>
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:8px;">
        <span style="font-size:28px;font-weight:700;color:${color};font-family:var(--mono);">${score}<span style="font-size:14px;color:var(--muted);">/100</span></span>
        <div style="flex:1;height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;">
          <div style="width:${score}%;height:100%;background:${color};border-radius:3px;transition:width 0.5s;"></div>
        </div>
        <span style="font-size:10px;color:var(--muted);">${totalFail} 项不合规 · ${critFail} 项严重</span>
      </div>
    </div>`;

  devices.forEach(d => {
    const failedRules = d.failed_rules || [];
    if (!failedRules.length) return;
    html += `
      <div class="detail-section">
        <div class="detail-section-title">${escapeHtml(d.ip || d.device || '设备')} — ${d.score || 0} 分，${d.fail || 0} 项失败</div>
        ${d.open_ports && d.open_ports.length ? `<div style="font-size:9px;color:var(--muted);margin-bottom:6px;">开放端口: ${d.open_ports.join(', ')}</div>` : ''}
        <table class="tool-table">
          <thead><tr><th>严重性</th><th>规则</th><th>描述</th><th>修复建议</th></tr></thead>
          <tbody>${failedRules.map(r => {
            const sev = (r.severity || '').toLowerCase();
            const cls = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
            return `<tr>
              <td><span class="sev-badge sev-${cls}">${sev.toUpperCase()}</span></td>
              <td>${escapeHtml(r.title || r.id || '')}</td>
              <td style="max-width:200px;">${escapeHtml((r.description || '').substring(0, 100))}</td>
              <td style="color:var(--accent, #00ff88);max-width:180px;">${escapeHtml((r.remediation || '').substring(0, 80))}</td>
            </tr>`;
          }).join('')}</tbody>
        </table>
      </div>`;
  });

  return html;
}

function renderTrafficAnalysisDetail(result) {
  const indicators = result.indicators || [];
  if (!indicators.length) return `<div class="detail-section"><div class="detail-section-title">IoC 指标</div><div class="empty-state">未发现 IoC 指标</div></div>`;

  const pktInfo = result.packets_analyzed ? `<span style="color:var(--muted);font-size:10px;">分析 ${result.packets_analyzed} 个数据包</span>` : '';

  return `
    <div class="detail-section">
      <div class="detail-section-title">IoC 威胁指标 (${indicators.length})</div>
      ${pktInfo}
      ${indicators.map(ioc => {
        const sev = (ioc.severity || '').toLowerCase();
        const cls = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
        const borderColor = cls === 'critical' ? '#ff4444' : cls === 'high' ? '#ff6600' : '#ffaa00';
        return `<div class="ioc-card" style="border-left-color:${borderColor}">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <span class="sev-badge sev-${cls}">${escapeHtml((ioc.type || 'unknown').toUpperCase())}</span>
            <span style="color:var(--text);font-weight:600;font-size:11px;">${escapeHtml(ioc.detail || '')}</span>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-top:4px;">
            ${ioc.source ? `来源: <span class="td-mono">${escapeHtml(ioc.source)}</span>` : ''}${ioc.target ? ` → 目标: <span class="td-mono">${escapeHtml(ioc.target)}</span>` : ''}
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

function renderConfigAuditDetail(result) {
  const findings = result.findings || [];
  if (!findings.length) return `<div class="detail-section"><div class="detail-section-title">配置审计</div><div class="empty-state">未发现问题</div></div>`;

  return `
    <div class="detail-section">
      <div class="detail-section-title">审计发现 (${result.total_findings || findings.length} 项 — ${(result.critical || 0)} 严重，${(result.high || 0)} 高危)</div>
      ${result.device ? `<div style="font-size:10px;color:var(--muted);margin-bottom:6px;">设备: <span class="td-mono">${escapeHtml(result.device)}</span></div>` : ''}
      <table class="tool-table">
        <thead><tr><th>严重性</th><th>规则</th><th>配置</th><th>问题</th><th>修复建议</th></tr></thead>
        <tbody>${findings.map(f => {
          const sev = (f.severity || '').toLowerCase();
          const cls = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
          return `<tr>
            <td><span class="sev-badge sev-${cls}">${sev.toUpperCase()}</span></td>
            <td>${escapeHtml(f.rule || '')}</td>
            <td class="td-mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml((f.config || '').substring(0, 50))}</td>
            <td style="max-width:140px;">${escapeHtml((f.issue || '').substring(0, 80))}</td>
            <td style="color:var(--accent, #00ff88);max-width:160px;">${escapeHtml((f.fix || '').substring(0, 80))}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>`;
}

async function fetchWorkflowEvents() {
  try {
    const resp = await fetch('/api/workflows/events?limit=30');
    if (!resp.ok) return;
    const data = await resp.json();
    renderWorkflowEvents(data.events || []);
  } catch {
    const wrap = $('#wf-evt-list');
    if (wrap) wrap.innerHTML = '<div class="empty-state">加载失败</div>';
  }
}

function renderWorkflowEvents(events) {
  const wrap = $('#wf-evt-list');
  if (!wrap) return;

  if (!events.length) {
    wrap.innerHTML = '<div class="empty-state">暂无工作流事件</div>';
    return;
  }

  wrap.innerHTML = events.map(evt => {
    const ts = evt.timestamp ? formatTs(evt.timestamp, false) : '';
    return `
      <div class="wf-evt-item">
        <div class="wf-evt-dot"></div>
        <div class="wf-evt-body">
          <div class="wf-evt-type">${escapeHtml(evt.object_type || evt.event_type || 'event')}</div>
          <div class="wf-evt-time">${ts}</div>
        </div>
      </div>
    `;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// Toast + Modal System
// ═══════════════════════════════════════════════════════════════════

function showToast({ type = 'info', message = '', duration = 3000 } = {}) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const icons = { info: 'ℹ', success: '✓', warning: '⚠', danger: '✕' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon ${type}">${icons[type] || 'ℹ'}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(el);
  setTimeout(() => {
    el.classList.add('removing');
    setTimeout(() => el.remove(), 300);
  }, duration);
}

function showModal({ type = 'info', title = '', body = '', actions = [{ label: 'OK', cls: 'btn-primary', value: 'ok' }], onAction } = {}) {
  const overlay = document.createElement('div');
  overlay.className = 'modal fade';
  overlay.style.cssText = 'display:block;opacity:1;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';
  const dangerCls = type === 'danger' ? 'border:1px solid rgba(255,34,68,0.3);' : '';
  const actionBtns = actions.map(a =>
    `<button type="button" class="btn ${a.cls || 'btn-default'}" data-action="${a.value}" style="min-width:80px;font-family:var(--mono);font-size:11px;">${a.label}</button>`
  ).join('');

  overlay.innerHTML = `
    <div class="modal-dialog" style="margin-top:15vh;">
      <div class="modal-content" style="${dangerCls}">
        <div class="modal-header">
          <h5 class="modal-title" style="font-size:13px;">${title}</h5>
          <button type="button" class="close" data-action="close">&times;</button>
        </div>
        <div class="modal-body" style="font-size:12px;line-height:1.6;">${body}</div>
        <div class="modal-footer">${actionBtns}</div>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => { overlay.style.opacity = '0'; setTimeout(() => overlay.remove(), 200); };
  overlay.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      const val = btn.dataset.action;
      if (val !== 'close' && onAction) onAction(val);
      close();
    });
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
  });
}

// ═══════════════════════════════════════════════════════════════════
// Device Detail Slide Panel
// ═══════════════════════════════════════════════════════════════════

function openDevicePanel(deviceIndex) {
  const dev = state.filteredDevices[deviceIndex];
  if (!dev) return;
  state.selectedDeviceIndex = deviceIndex;
  state.devicePanelTab = 'overview';

  const panel = document.getElementById('device-panel');
  const nameEl = document.getElementById('dpn-name');
  const badgeEl = document.getElementById('dpn-status-badge');
  const posEl = document.getElementById('dpn-position');

  nameEl.textContent = dev.devName || dev.devMAC || 'Unknown';
  const status = dev.devStatus || dev.devForceStatus || 'secure';
  badgeEl.className = `status-badge ${status}`;
  badgeEl.textContent = status;
  posEl.textContent = `${deviceIndex + 1} / ${state.filteredDevices.length}`;

  document.querySelectorAll('.dpn-tab').forEach(t => t.classList.toggle('active', t.dataset.dpn === 'overview'));
  renderDevicePanelContent(dev, 'overview');
  panel.classList.add('open');
}

function closeDevicePanel() {
  document.getElementById('device-panel')?.classList.remove('open');
  state.selectedDeviceIndex = -1;
}

function renderDevicePanelContent(dev, tab) {
  const body = document.getElementById('dpn-body');
  if (!body) return;
  if (tab === 'overview') renderDPOverview(body, dev);
  else if (tab === 'events') renderDPEvents(body, dev);
  else if (tab === 'connections') renderDPConnections(body, dev);
}

function renderDPOverview(body, dev) {
  const status = dev.devStatus || dev.devForceStatus || 'secure';
  const FSM_C = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
  const fields = [
    ['MAC', dev.devMAC], ['IP', dev.devLastIP || dev.devPrimaryIPv4],
    ['Vendor', dev.devVendor], ['Model', dev.devModel],
    ['Type', dev.devType], ['Status', status],
    ['Parent MAC', dev.devParentMAC], ['Parent Port', dev.devParentPort],
    ['Site', dev.devSite], ['Location', dev.devLocation],
    ['Notes', dev.devNotes],
  ];
  body.innerHTML = `
    <div class="dpn-metric-row">
      <div class="dpn-metric" style="--tile-color:${FSM_C[status]}">
        <div class="dpn-metric-val" style="color:${FSM_C[status]};text-shadow:0 0 8px ${FSM_C[status]}">${status.toUpperCase()}</div>
        <div class="dpn-metric-label">Current Status</div>
      </div>
    </div>
    <div class="dpn-field-grid">
      ${fields.map(([k, v]) => v ? `<span class="dpn-field-label">${k}</span><span class="dpn-field-value">${escapeHtml(v)}</span>` : '').join('')}
    </div>`;
}

async function renderDPEvents(body, dev) {
  body.innerHTML = '<div class="empty-state">Loading events...</div>';
  try {
    const resp = await fetch(`/api/dashboard/db/alerts?limit=30`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const alerts = (data.alerts || []).filter(a => {
      const target = a.target || a.source_type || '';
      return target.includes(dev.devMAC) || target.includes(dev.devLastIP) || target.includes(dev.devName);
    });
    if (!alerts.length) { body.innerHTML = '<div class="empty-state">无关联事件</div>'; return; }
    const SEV_C = { critical: '#ff2244', high: '#f97316', medium: '#eab308', low: '#00bbff', info: '#64748b' };
    body.innerHTML = alerts.map(a => {
      const sev = a.severity || 'info';
      const ts = a.timestamp ? formatTs(a.timestamp) : '';
      return `<div class="dpn-timeline-item">
        <div class="dpn-timeline-dot" style="background:${SEV_C[sev]};box-shadow:0 0 4px ${SEV_C[sev]}"></div>
        <div class="dpn-timeline-body">
          <div class="dpn-timeline-msg">${escapeHtml(a.message || '')}</div>
          <div class="dpn-timeline-meta">${sev.toUpperCase()} · ${ts}</div>
        </div>
      </div>`;
    }).join('');
  } catch (e) { body.innerHTML = `<div class="empty-state">加载失败: ${escapeHtml(e.message)}</div>`; }
}

async function renderDPConnections(body, dev) {
  body.innerHTML = '<div class="empty-state">Loading topology...</div>';
  try {
    const resp = await fetch('/api/topology');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const allDevs = data.devices || [];

    // Match dashboard device to topology device by IP or MAC
    const devIP = dev.devLastIP || dev.devPrimaryIPv4 || '';
    const devMAC = (dev.devMAC || '').toLowerCase();
    const topoDev = allDevs.find(d =>
      (d.ip && d.ip === devIP) ||
      (d.mac && d.mac.toLowerCase() === devMAC) ||
      (d.name && d.name === dev.devName)
    );
    const deviceId = topoDev ? topoDev.id : (dev.devMAC || dev.devName);
    const links = (data.links || []).filter(l => l.from === deviceId || l.to === deviceId);

    if (!links.length) { body.innerHTML = '<div class="empty-state">无连接信息</div>'; return; }
    const FSM_C = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
    body.innerHTML = links.map(l => {
      const peerId = l.from === deviceId ? l.to : l.from;
      const peer = allDevs.find(d => d.id === peerId) || {};
      const st = peer.status || 'secure';
      return `<div class="dpn-conn-card">
        <div class="dpn-conn-dot" style="background:${FSM_C[st]};box-shadow:0 0 4px ${FSM_C[st]}"></div>
        <div class="dpn-conn-name">${escapeHtml(peer.name || peerId)}</div>
        <div class="dpn-conn-ip">${escapeHtml(peer.ip || '')}</div>
        <span class="status-badge ${st}" style="font-size:8px">${st}</span>
      </div>`;
    }).join('');
  } catch (e) { body.innerHTML = `<div class="empty-state">加载失败: ${escapeHtml(e.message)}</div>`; }
}

function navigateDevice(dir) {
  const idx = state.selectedDeviceIndex + dir;
  if (idx < 0 || idx >= state.filteredDevices.length) return;
  openDevicePanel(idx);
}

// Bind device panel events (once)
function initDevicePanel() {
  const closeBtn = document.getElementById('dpn-close');
  const prevBtn = document.getElementById('dpn-prev');
  const nextBtn = document.getElementById('dpn-next');
  if (closeBtn) closeBtn.addEventListener('click', closeDevicePanel);
  if (prevBtn) prevBtn.addEventListener('click', () => navigateDevice(-1));
  if (nextBtn) nextBtn.addEventListener('click', () => navigateDevice(1));

  document.querySelectorAll('.dpn-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.dpn-tab').forEach(t => t.classList.toggle('active', t === tab));
      state.devicePanelTab = tab.dataset.dpn;
      const dev = state.filteredDevices[state.selectedDeviceIndex];
      if (dev) renderDevicePanelContent(dev, state.devicePanelTab);
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// Workflow Editor (Expandable Cards)
// ═══════════════════════════════════════════════════════════════════

const WF_OBJ_TYPES = ['device', 'alert', 'traffic', 'syslog', 'snmp', 'mqtt', 'suricata'];
const WF_EVT_TYPES = ['created', 'updated', 'deleted', 'threshold_exceeded', 'status_change'];
const WF_FIELDS = ['devStatus', 'devType', 'devVendor', 'severity', 'source_type', 'message'];
const WF_OPS = ['equals', 'not_equals', 'contains', 'greater_than', 'less_than'];
const WF_ACT_TYPES = ['notify', 'isolate', 'block', 'log', 'webhook'];

function renderWorkflows() {
  const list = document.getElementById('wf-list');
  if (!list) return;
  const wfs = state.workflows;
  if (!wfs.length) { list.innerHTML = '<div class="empty-state">暂无工作流</div>'; return; }

  list.innerHTML = wfs.map((wf, i) => renderWorkflowCard(wf, i)).join('');
  bindWorkflowEvents(list);
}

function renderWorkflowCard(wf, i) {
  const enabled = wf.enabled === true || wf.enabled === 'Yes' || wf.enabled === 'yes';
  const trigger = wf.trigger || {};
  const conditions = wf.conditions || [];
  const actions = wf.actions || [];
  const expanded = state._expandedWf === i;

  return `<div class="wf-card ${enabled ? 'enabled' : 'disabled'} ${expanded ? 'expanded' : ''}" data-wf="${i}">
    <div class="wf-card-header" data-wf-toggle="${i}">
      <span class="wf-card-expand">▶</span>
      <span class="wf-card-title">${escapeHtml(wf.name || `Workflow ${i + 1}`)}</span>
      <label class="wf-toggle" onclick="event.stopPropagation()">
        <input type="checkbox" ${enabled ? 'checked' : ''} data-wf-enable="${i}" />
        <span class="wf-toggle-slider"></span>
      </label>
    </div>
    <div class="wf-card-body">
      <div class="wf-card-inner">
        <div class="wf-section">
          <div class="wf-section-title">Trigger</div>
          <div class="wf-fields">
            <select class="ops-input" data-wf-field="${i}.trigger.object_type">
              <option value="">Object Type</option>
              ${WF_OBJ_TYPES.map(t => `<option value="${t}" ${trigger.object_type === t ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
            <select class="ops-input" data-wf-field="${i}.trigger.event_type">
              <option value="">Event Type</option>
              ${WF_EVT_TYPES.map(t => `<option value="${t}" ${trigger.event_type === t ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="wf-section">
          <div class="wf-section-title">Conditions</div>
          ${conditions.map((c, ci) => `<div class="wf-condition-row">
            <select class="ops-input" data-wf-field="${i}.conditions.${ci}.field">
              <option value="">field</option>
              ${WF_FIELDS.map(f => `<option value="${f}" ${c.field === f ? 'selected' : ''}>${f}</option>`).join('')}
            </select>
            <select class="ops-input" data-wf-field="${i}.conditions.${ci}.operator">
              <option value="">op</option>
              ${WF_OPS.map(o => `<option value="${o}" ${c.operator === o ? 'selected' : ''}>${o}</option>`).join('')}
            </select>
            <input class="ops-input" style="flex:1" value="${escapeHtml(c.value || '')}" data-wf-field="${i}.conditions.${ci}.value" />
            <button class="wf-remove-btn" data-wf-rm-cond="${i}.${ci}">×</button>
          </div>`).join('')}
          <button class="wf-add-btn" data-wf-add-cond="${i}">+ Condition</button>
        </div>
        <div class="wf-section">
          <div class="wf-section-title">Actions</div>
          ${actions.map((a, ai) => `<div class="wf-action-row">
            <select class="ops-input" data-wf-field="${i}.actions.${ai}.type">
              <option value="">type</option>
              ${WF_ACT_TYPES.map(t => `<option value="${t}" ${a.type === t ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
            <input class="ops-input" style="flex:1" value="${escapeHtml(a.target || a.url || '')}" data-wf-field="${i}.actions.${ai}.target" />
            <button class="wf-remove-btn" data-wf-rm-act="${i}.${ai}">×</button>
          </div>`).join('')}
          <button class="wf-add-btn" data-wf-add-act="${i}">+ Action</button>
        </div>
        <div class="wf-card-actions">
          <button class="ops-action-btn start" data-wf-save="${i}">SAVE</button>
          <button class="ops-action-btn stop" data-wf-delete="${i}">DELETE</button>
        </div>
      </div>
    </div>
  </div>`;
}

function bindWorkflowEvents(list) {
  // Toggle expand
  list.querySelectorAll('[data-wf-toggle]').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.wfToggle, 10);
      state._expandedWf = state._expandedWf === idx ? -1 : idx;
      renderWorkflows();
    });
  });
  // Enable toggle
  list.querySelectorAll('[data-wf-enable]').forEach(el => {
    el.addEventListener('change', () => {
      const idx = parseInt(el.dataset.wfEnable, 10);
      toggleWorkflow(idx, el.checked);
    });
  });
  // Field changes → update state
  list.querySelectorAll('[data-wf-field]').forEach(el => {
    el.addEventListener('change', () => updateWfField(el.dataset.wfField, el.value));
    if (el.tagName === 'INPUT') el.addEventListener('blur', () => updateWfField(el.dataset.wfField, el.value));
  });
  // Save
  list.querySelectorAll('[data-wf-save]').forEach(el => {
    el.addEventListener('click', () => saveWorkflow(parseInt(el.dataset.wfSave, 10)));
  });
  // Delete
  list.querySelectorAll('[data-wf-delete]').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.wfDelete, 10);
      showModal({
        type: 'danger', title: 'Delete Workflow',
        body: `确定要删除 <strong>${escapeHtml(state.workflows[idx]?.name || `Workflow ${idx + 1}`)}</strong> 吗？`,
        actions: [{ label: 'Cancel', cls: 'btn-default', value: 'cancel' }, { label: 'Delete', cls: 'btn-danger', value: 'delete' }],
        onAction: (v) => { if (v === 'delete') deleteWorkflow(idx); }
      });
    });
  });
  // Add condition
  list.querySelectorAll('[data-wf-add-cond]').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.wfAddCond, 10);
      if (!state.workflows[idx].conditions) state.workflows[idx].conditions = [];
      state.workflows[idx].conditions.push({ field: '', operator: '', value: '' });
      renderWorkflows();
    });
  });
  // Remove condition
  list.querySelectorAll('[data-wf-rm-cond]').forEach(el => {
    el.addEventListener('click', () => {
      const [wi, ci] = el.dataset.wfRmCond.split('.').map(Number);
      state.workflows[wi].conditions?.splice(ci, 1);
      renderWorkflows();
    });
  });
  // Add action
  list.querySelectorAll('[data-wf-add-act]').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.wfAddAct, 10);
      if (!state.workflows[idx].actions) state.workflows[idx].actions = [];
      state.workflows[idx].actions.push({ type: '', target: '' });
      renderWorkflows();
    });
  });
  // Remove action
  list.querySelectorAll('[data-wf-rm-act]').forEach(el => {
    el.addEventListener('click', () => {
      const [wi, ai] = el.dataset.wfRmAct.split('.').map(Number);
      state.workflows[wi].actions?.splice(ai, 1);
      renderWorkflows();
    });
  });
}

function updateWfField(path, value) {
  const parts = path.split('.');
  const wi = parseInt(parts[0], 10);
  let obj = state.workflows[wi];
  for (let i = 1; i < parts.length - 1; i++) {
    if (parts[i] === 'trigger') { if (!obj.trigger) obj.trigger = {}; obj = obj.trigger; }
    else if (parts[i] === 'conditions') { const ci = parseInt(parts[++i], 10); if (!obj.conditions) obj.conditions = []; if (!obj.conditions[ci]) obj.conditions[ci] = {}; obj = obj.conditions[ci]; }
    else if (parts[i] === 'actions') { const ai = parseInt(parts[++i], 10); if (!obj.actions) obj.actions = []; if (!obj.actions[ai]) obj.actions[ai] = {}; obj = obj.actions[ai]; }
  }
  obj[parts[parts.length - 1]] = value;
}

async function saveWorkflow(index) {
  try {
    const resp = await fetch(`/api/workflows/${index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.workflows[index]),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast({ type: 'success', message: `Workflow "${state.workflows[index]?.name || index}" saved` });
    addOpHistory('success', '工作流已保存', state.workflows[index]?.name || '');
  } catch (e) {
    showToast({ type: 'danger', message: `Save failed: ${e.message}` });
  }
}

async function deleteWorkflow(index) {
  try {
    const resp = await fetch(`/api/workflows/${index}`, { method: 'DELETE' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    state.workflows.splice(index, 1);
    state._expandedWf = -1;
    renderWorkflows();
    showToast({ type: 'success', message: 'Workflow deleted' });
  } catch (e) {
    showToast({ type: 'danger', message: `Delete failed: ${e.message}` });
  }
}

// ═══════════════════════════════════════════════════════════════════
// Override renderDeviceTable with enhanced columns + stat cards + row clicks
// ═══════════════════════════════════════════════════════════════════

renderDeviceTable = function() {
  const body = document.getElementById('dev-body');
  if (!body) return;
  let devs = [...state.devices];
  if (state.deviceStatusFilter) devs = devs.filter(d => (d.devStatus || d.devForceStatus || 'secure') === state.deviceStatusFilter);
  if (state.deviceTypeFilter) devs = devs.filter(d => (d.devType || '') === state.deviceTypeFilter);
  if (state.deviceVendorFilter) devs = devs.filter(d => (d.devVendor || '') === state.deviceVendorFilter);
  if (state.deviceSearch) {
    const q = state.deviceSearch.toLowerCase();
    devs = devs.filter(d => ['devMAC','devName','devLastIP','devVendor','devType','devModel'].some(k => (d[k]||'').toLowerCase().includes(q)));
  }
  const key = state.deviceSortKey;
  const dir = state.deviceSortDir === 'asc' ? 1 : -1;
  devs.sort((a, b) => { const va = (a[key]||'').toString().toLowerCase(); const vb = (b[key]||'').toString().toLowerCase(); return va < vb ? -dir : va > vb ? dir : 0; });

  state.filteredDevices = devs;
  const total = devs.length;
  const pages = Math.max(1, Math.ceil(total / state.devicePageSize));
  state.devicePage = Math.min(state.devicePage, pages - 1);
  const start = state.devicePage * state.devicePageSize;
  const page = devs.slice(start, start + state.devicePageSize);
  const sortIcon = (k) => state.deviceSortKey === k ? (state.deviceSortDir === 'asc' ? ' ▲' : ' ▼') : '';

  const parseJSON = (s) => { try { return JSON.parse(s || '[]'); } catch { return []; } };

  body.innerHTML = `
    <div class="device-stat-cards">
      <div class="stat-card"><div class="stat-num">${state.devices.length}</div><div class="stat-label">总设备</div></div>
      <div class="stat-card stat-online"><div class="stat-num">${state.devices.filter(d => (d.devStatus || 'secure') !== 'isolated').length}</div><div class="stat-label">在线</div></div>
      <div class="stat-card stat-cam"><div class="stat-num">${state.devices.filter(d => d.devType === 'camera').length}</div><div class="stat-label">摄像头</div></div>
      <div class="stat-card stat-sensor"><div class="stat-num">${state.devices.filter(d => ['sensor','plc'].includes(d.devType)).length}</div><div class="stat-label">工控</div></div>
      <div class="stat-card stat-infra"><div class="stat-num">${state.devices.filter(d => ['switch','gateway','firewall'].includes(d.devType)).length}</div><div class="stat-label">基础设施</div></div>
    </div>
    <div class="rp-device-table-wrap">
      <table class="device-table">
        <thead><tr>
          <th class="sortable" data-sort="devName">名称${sortIcon('devName')}</th>
          <th>状态</th>
          <th class="sortable" data-sort="devType">类型${sortIcon('devType')}</th>
          <th class="sortable" data-sort="devLastIP">IP${sortIcon('devLastIP')}</th>
          <th>MAC</th>
          <th class="sortable" data-sort="devVendor">厂商${sortIcon('devVendor')}</th>
          <th>型号</th>
          <th>开放端口</th>
          <th>协议</th>
          <th>交换机端口</th>
          <th>固件</th>
        </tr></thead>
        <tbody>
          ${page.map((d, pi) => {
            const status = d.devStatus || d.devForceStatus || 'secure';
            const ports = parseJSON(d.devOpenPorts);
            const protos = parseJSON(d.devProtocols);
            const portsHtml = ports.slice(0, 5).map(p => '<span class="port-badge">' + p + '</span>').join('') || '-';
            const protosHtml = protos.slice(0, 4).map(p => '<span class="proto-badge">' + p + '</span>').join('') || '-';
            return `<tr data-dev-index="${start + pi}">
              <td class="td-name">${escapeHtml(d.devName || '-')}</td>
              <td><span class="status-badge ${status}">${status}</span></td>
              <td>${escapeHtml(d.devType || '-')}</td>
              <td class="td-mono">${escapeHtml(d.devLastIP || '-')}</td>
              <td class="td-mono td-mac">${escapeHtml(d.devMAC || '-')}</td>
              <td>${escapeHtml(d.devVendor || '-')}</td>
              <td class="td-model">${escapeHtml(d.devModel || '-')}</td>
              <td class="td-ports">${portsHtml}</td>
              <td class="td-protos">${protosHtml}</td>
              <td class="td-mono">${escapeHtml(d.devSwitchPort || '-')}</td>
              <td class="td-fw">${escapeHtml(d.devFirmwareVersion || '-')}</td>
            </tr>`;
          }).join('')}
          ${page.length === 0 ? '<tr><td colspan="11" class="td-empty">无匹配设备</td></tr>' : ''}
        </tbody>
      </table>
    </div>
    ${renderPagination(total, state.devicePage, state.devicePageSize, 'device')}`;

  body.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (state.deviceSortKey === k) state.deviceSortDir = state.deviceSortDir === 'asc' ? 'desc' : 'asc';
      else { state.deviceSortKey = k; state.deviceSortDir = 'asc'; }
      renderDeviceTable();
    });
  });
  bindPagination(body, 'device', (p) => { state.devicePage = p; renderDeviceTable(); });
  body.querySelectorAll('.device-table tbody tr[data-dev-index]').forEach(tr => {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', () => {
      const idx = parseInt(tr.dataset.devIndex, 10);
      if (!isNaN(idx)) openDevicePanel(idx);
    });
  });
};

// Type + Vendor filters already included in renderReportsControls above

// ═══════════════════════════════════════════════════════════════════
// Add Workflow Button
// ═══════════════════════════════════════════════════════════════════

function initAddWorkflowBtn() {
  const btn = document.getElementById('btn-add-wf');
  if (!btn) return;
  btn.addEventListener('click', () => {
    state.workflows.push({ name: 'New Workflow', enabled: true, trigger: { object_type: '', event_type: '' }, conditions: [], actions: [] });
    state._expandedWf = state.workflows.length - 1;
    renderWorkflows();
  });
}

// ═══════════════════════════════════════════════════════════════════
// Dashboard Topology Tree
// ═══════════════════════════════════════════════════════════════════

// Patch dashboard init to add topology tree
const _origInitDash = initDashboard;
// We'll add topology via a custom event instead to avoid circular imports

// ═══════════════════════════════════════════════════════════════════
// Init all new features
// ═══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  initDevicePanel();
  initAddWorkflowBtn();
});

// ═══════════════════════════════════════════════════════════════════
// Tool Result Card Rendering
// ═══════════════════════════════════════════════════════════════════

function renderToolResultCard(tr) {
  const r = tr.result || {};
  if (r.error || !r || Object.keys(r).length === 0) return null;

  const tool = tr.tool || '';
  const server = tr.server || '';

  // Scan results — host table
  if (r.hosts && Array.isArray(r.hosts) && r.hosts.length > 0) {
    const rows = r.hosts.slice(0, 12).map(h => {
      const ports = (h.ports || []).slice(0, 6).map(p =>
        `<span class="port-badge">${typeof p === 'object' ? p.port || p.num : p}</span>`
      ).join(' ');
      return `<tr>
        <td>${escapeHtml(h.ip || '')}</td>
        <td>${escapeHtml(h.mac || '')}</td>
        <td>${escapeHtml(h.vendor || '')}</td>
        <td>${ports || '-'}</td>
        <td>${escapeHtml(h.os || '')}</td>
      </tr>`;
    }).join('');
    return el('div', 'tool-card tool-card-scan', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-tower-broadcast"></i></span>
        <span class="tool-card-title">网络扫描结果</span>
        <span class="tool-card-badge">${r.hosts_found || r.hosts.length} 台设备</span>
      </div>
      <div class="tool-card-body"><table class="tool-table">
        <tr><th>IP</th><th>MAC</th><th>厂商</th><th>开放端口</th><th>系统</th></tr>
        ${rows}
      </table></div>
    `);
  }

  // IoT fingerprint
  if (r.devices && Array.isArray(r.devices) && r.iot_devices_found !== undefined) {
    const typeCounts = {};
    r.devices.forEach(d => { const t = d.type || 'unknown'; typeCounts[t] = (typeCounts[t] || 0) + 1; });
    const chips = Object.entries(typeCounts).map(([t, c]) =>
      `<span class="iot-chip iot-chip-${t}">${t} ×${c}</span>`
    ).join('');
    return el('div', 'tool-card tool-card-iot', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-magnifying-glass"></i></span>
        <span class="tool-card-title">IoT 设备指纹</span>
        <span class="tool-card-badge">${r.iot_devices_found} 台</span>
      </div>
      <div class="tool-card-body">${chips}</div>
    `);
  }

  // Baseline audit
  if (r.devices_audited !== undefined) {
    const score = r.overall_score || 0;
    const color = score >= 80 ? '#4caf50' : score >= 50 ? '#ff9800' : '#f44336';
    // Collect failed rules across all audited devices (deduped by title)
    const seenRules = new Set();
    const failedRules = [];
    (r.devices || []).forEach(d => {
      (d.failed_rules || []).forEach(fr => {
        const title = fr.title || fr.id || '';
        if (title && !seenRules.has(title)) {
          seenRules.add(title);
          failedRules.push(fr);
        }
      });
    });
    const failList = failedRules.slice(0, 6).map(fr => {
      const sev = (fr.severity || '').toLowerCase();
      const sevLabel = sev === 'critical' ? 'Critical' : sev === 'high' ? 'High' : sev === 'medium' ? 'Medium' : 'Low';
      return `<div class="baseline-check check-fail">
        <span class="bl-sev bl-sev-${sev || 'low'}">${sevLabel}</span>
        <span class="bl-title">${escapeHtml(fr.title || fr.id || '')}</span>
      </div>`;
    }).join('');
    const summary = r.summary || {};
    return el('div', 'tool-card tool-card-baseline', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-shield-halved"></i></span>
        <span class="tool-card-title">安全基线审计</span>
        <span class="tool-card-badge">${r.devices_audited} 台设备</span>
      </div>
      <div class="tool-card-body">
        <div class="baseline-score">
          <svg viewBox="0 0 36 36" class="score-ring"><path class="score-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="score-fill" stroke="${color}" stroke-dasharray="${score}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/></svg>
          <span class="score-num" style="color:${color}">${score}%</span>
        </div>
        ${summary.critical_failures ? `<div class="baseline-summary">严重违规 ${summary.critical_failures} 项 / 共 ${summary.total_fail || failedRules.length} 项不合规</div>` : ''}
        ${failList || '<div class="baseline-check check-pass"><span>✓</span> 未发现不合规项</div>'}
      </div>
    `);
  }

  // CVE results
  if (r.cves && Array.isArray(r.cves)) {
    const rows = r.cves.slice(0, 6).map(c => {
      const cvss = c.cvss_v3 || c.cvss || c.score || 0;
      const rawSev = (c.severity || '').toUpperCase();
      const sev = rawSev === 'CRITICAL' ? 'critical' : rawSev === 'HIGH' ? 'high' : rawSev === 'MEDIUM' ? 'medium' : rawSev === 'LOW' ? 'low'
        : (cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low');
      return `<tr>
        <td><span class="cve-id">${escapeHtml(c.id || c.cve_id || '')}</span></td>
        <td><span class="sev-badge sev-${sev}">${sev}</span></td>
        <td>${cvss}</td>
        <td>${escapeHtml((c.description || '').substring(0, 60))}</td>
      </tr>`;
    }).join('');
    return el('div', 'tool-card tool-card-cve', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-triangle-exclamation"></i></span>
        <span class="tool-card-title">CVE 漏洞查询</span>
        <span class="tool-card-badge">${r.total_cves || r.cves.length} 条</span>
      </div>
      <div class="tool-card-body"><table class="tool-table">
        <tr><th>CVE ID</th><th>严重程度</th><th>CVSS</th><th>描述</th></tr>
        ${rows}
      </table></div>
    `);
  }

  // Vuln scan
  if (r.vulnerabilities && Array.isArray(r.vulnerabilities) && r.vulnerabilities_found !== undefined) {
    const rows = r.vulnerabilities.slice(0, 6).map(v =>
      `<tr><td>${escapeHtml(v.target || v.host || '')}</td><td>${escapeHtml(v.port || '')}</td><td>${escapeHtml(v.name || v.vuln || '')}</td></tr>`
    ).join('');
    return el('div', 'tool-card tool-card-vuln', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-lock-open"></i></span>
        <span class="tool-card-title">漏洞扫描</span>
        <span class="tool-card-badge">${r.vulnerabilities_found} 个</span>
      </div>
      <div class="tool-card-body"><table class="tool-table">
        <tr><th>目标</th><th>端口</th><th>漏洞</th></tr>${rows}
      </table></div>
    `);
  }

  // Default creds
  if (r.default_creds_found !== undefined || r.weak_credential_count !== undefined) {
    const n = r.default_creds_found || r.weak_credential_count || 0;
    const devices = (r.devices || []).slice(0, 6).map(d =>
      `<div class="cred-item">${escapeHtml(d.ip || d.name || '')} — ${escapeHtml(d.username || 'admin')}/${escapeHtml(d.password || '')}</div>`
    ).join('');
    return el('div', 'tool-card tool-card-creds', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-key"></i></span>
        <span class="tool-card-title">弱密码检测</span>
        <span class="tool-card-badge">${n} 台弱密码</span>
      </div>
      <div class="tool-card-body">${devices || '所有设备密码安全'}</div>
    `);
  }

  // Timeline events
  if (r.events !== undefined && Array.isArray(r.timeline)) {
    const items = r.timeline.slice(0, 6).map(e =>
      `<div class="timeline-item"><span class="timeline-time">${escapeHtml(e.time || e.timestamp || '')}</span> ${escapeHtml(e.type || '')}: ${escapeHtml(e.detail || e.message || '')}</div>`
    ).join('');
    return el('div', 'tool-card tool-card-timeline', `
      <div class="tool-card-header">
        <span class="tool-card-icon"><i class="fa-solid fa-list-check"></i></span>
        <span class="tool-card-title">攻击时间线</span>
        <span class="tool-card-badge">${r.events} 个事件</span>
      </div>
      <div class="tool-card-body">${items || '无事件'}</div>
    `);
  }

  return null;
}

function el(tag, cls, html) {
  const e = document.createElement(tag);
  e.className = cls;
  e.innerHTML = html;
  return e;
}
