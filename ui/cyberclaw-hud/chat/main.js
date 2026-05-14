// ═══════════════════════════════════════════════════════════════════
// CyberClaw CyberAgent Chat — Mock AI Interaction
// ═══════════════════════════════════════════════════════════════════

import { initDashboard } from '../src/dashboard.js';

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
  reports: [],
  opHistory: [],
  sessions: [],
  isProcessing: false,
  scanRunning: false,
  scanStatus: null,
  workflows: [],
  _scanTimer: null,
  devices: [],
  devicePage: 0,
  devicePageSize: 15,
  deviceSortKey: 'devLastIP',
  deviceSortDir: 'asc',
  deviceSearch: '',
  deviceStatusFilter: '',
  rpTab: 'devices',
  events: [],
  eventsSevFilter: '',
  eventsPage: 0,
  eventsPageSize: 30,
  selectedDeviceIndex: -1,
  devicePanelTab: 'overview',
  filteredDevices: [],
  deviceTypeFilter: '',
  deviceVendorFilter: '',
  _expandedWf: -1,
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
  initOps();
  initHudLink();
  populateMcpList();
  populateSkillsList();
  loadMcpStatus();
  initDashboard();
  initReports();
  initHistory();
});

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
  }
  if (name === 'history') {
    fetchNotificationConfig();
    fetchNotificationHistory();
    fetchWorkflowEvents();
  }
}

// ── Input ─────────────────────────────────────────────────────────
function initInput() {
  const input = $('#chat-input');
  const btn = $('#btn-send');

  btn.addEventListener('click', () => sendMessage());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
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

// Separate init for ops buttons (they trigger after DOM is ready)
function initOpsButtons() {
  $$('.ops-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.dataset.prompt;
      if (prompt) {
        $('#chat-input').value = prompt;
        sendMessage();
      }
    });
  });
}

function sendMessage() {
  const input = $('#chat-input');
  const text = input.value.trim();
  if (!text || state.isProcessing) return;

  input.value = '';

  if (state.currentTab !== 'chat') switchTab('chat');

  const welcome = $('.chat-welcome');
  if (welcome) welcome.remove();

  addMessage('user', text);
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
  state.messages.push({ role, content, time: new Date() });
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
    // Build conversation history (exclude current user message, already in state.messages)
    const history = state.messages.slice(0, -1).slice(-20).map(m => ({
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
      for (const step of data.steps) {
        const stepEl = document.createElement('div');
        stepEl.className = 'step';
        stepEl.innerHTML = `
          <span class="step-icon running">⟳</span>
          <span class="step-tool">${step.tool}</span>
          <span class="step-summary">${step.summary}</span>
        `;
        stepsContainer.appendChild(stepEl);
        await delay(800 + Math.random() * 600);
        stepEl.querySelector('.step-icon').className = 'step-icon done';
        stepEl.querySelector('.step-icon').textContent = '✓';
      }

      const expandEl = document.createElement('div');
      expandEl.className = 'expand-link';
      expandEl.textContent = '▼ 展开详情';
      expandEl.addEventListener('click', () => {
        expandEl.textContent = expandEl.textContent.includes('展开') ? '▲ 收起详情' : '▼ 展开详情';
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
        btn.addEventListener('click', () => handleConfirm(btn.dataset.action, msgEl));
      });
    }

    // Add report if security-report step was used
    if (data.steps && data.steps.some(s => s.tool === 'security-report')) {
      state.reports.push({
        id: Date.now(),
        title: '安全巡检报告 ' + new Date().toLocaleDateString('zh-CN'),
        time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
        type: 'scan',
      });
      renderReportList();
    }

    // Track AI response in history
    state.messages.push({ role: 'ai', content: data.reply, time: new Date() });

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

async function handleConfirm(action, msgEl) {
  const actions = msgEl.querySelectorAll('.confirm-btn');
  actions.forEach(b => b.disabled = true);

  const confirmCard = msgEl.querySelector('.confirm-card');

  if (action === 'confirm') {
    // Extract device info from window._pending state or from the AI message context
    let deviceIp = window._pendingIsolateIp || '';
    let deviceId = window._pendingIsolateId || '';

    // Fallback: try to extract an IP from the message text near the confirm card
    if (!deviceIp) {
      const msgText = msgEl.querySelector('.msg-text');
      if (msgText) {
        const ipMatch = msgText.textContent.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch) deviceIp = ipMatch[1];
      }
    }

    if (!deviceIp) {
      if (confirmCard) {
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#ff4466">Error</div>
          <div class="confirm-details">
            <div>Cannot determine device IP. Isolation aborted.</div>
          </div>`;
      }
      return;
    }

    confirmCard.innerHTML = `
      <div class="confirm-title" style="color:#00bbff">Isolating ${escapeHtml(deviceIp)}...</div>
      <div class="confirm-details"><div>Contacting auto-response service...</div></div>`;

    try {
      const resp = await fetch('/api/tools/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId, device_ip: deviceIp }),
      });
      const data = await resp.json();

      if (data.task_id || data.status === 'started') {
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#00ff88">Isolation Submitted</div>
          <div class="confirm-details">
            <div>Device <strong>${escapeHtml(deviceIp)}</strong> is being isolated.</div>
            <div style="margin-top:4px;color:rgba(255,255,255,0.5);">Task ID: ${escapeHtml(data.task_id || 'N/A')}</div>
          </div>`;
        addOpHistory('success', 'Port isolation submitted', `${deviceIp} — task ${data.task_id || 'N/A'}`);
      } else {
        confirmCard.innerHTML = `
          <div class="confirm-title" style="color:#ffaa00">Isolation Response</div>
          <div class="confirm-details"><div><code>${escapeHtml(JSON.stringify(data))}</code></div></div>`;
        addOpHistory('warning', 'Isolation response received', JSON.stringify(data));
      }
    } catch (e) {
      confirmCard.innerHTML = `
        <div class="confirm-title" style="color:#ff4466">Isolation Failed</div>
        <div class="confirm-details"><div>${escapeHtml(e.message)}</div></div>`;
      addOpHistory('error', 'Isolation failed', e.message);
    }

    // Clean up pending state
    delete window._pendingIsolateIp;
    delete window._pendingIsolateId;
  } else if (action === 'cancel') {
    if (confirmCard) {
      confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--muted)">Operation cancelled</div>`;
    }
    delete window._pendingIsolateIp;
    delete window._pendingIsolateId;
  } else {
    if (confirmCard) {
      confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--info)">Please enter a modified plan below</div>`;
    }
  }
}

// ── Operations Tab ────────────────────────────────────────────────
function initOps() {
  initOpsButtons();
  initScanScheduler();
  initWorkflows();
}

function populateMcpList() {
  const list = $('#mcp-list');
  list.innerHTML = MCP_SERVERS.map(s => {
    const toolsHtml = (s.tools && s.tools.length)
      ? `<span class="mcp-tools-count" title="${s.tools.join(', ')}">${s.tools.length} tools</span>`
      : '';
    return `
    <div class="mcp-row">
      <span class="mcp-name">${s.name}</span>
      ${toolsHtml}
      <span class="mcp-status ${s.status}">● ${s.status === 'online' ? '在线' : s.status === 'busy' ? '忙碌' : '离线'}</span>
    </div>`;
  }).join('');
}

function populateSkillsList() {
  const list = $('#skills-list');
  list.innerHTML = SKILLS.map(s => `
    <span class="skill-tag ${s.type}">${s.name}</span>
  `).join('');
}

function addOpHistory(type, title, desc) {
  const history = $('#op-history');
  const emptyState = history.querySelector('.empty-state');
  if (emptyState) emptyState.remove();

  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  const el = document.createElement('div');
  el.className = `op-item ${type}`;
  el.innerHTML = `
    <div class="op-title"><span>${title}</span><span class="op-time">${time}</span></div>
    <div class="op-desc">${desc}</div>
  `;
  history.insertBefore(el, history.firstChild);

  state.opHistory.push({ type, title, desc, time: new Date() });
}

// ── Reports ───────────────────────────────────────────────────────

// ── Scan Scheduler ────────────────────────────────────────────────
function initScanScheduler() {
  const btnStart = $('#btn-scan-start');
  const btnStop = $('#btn-scan-stop');
  if (!btnStart || !btnStop) return;

  btnStart.addEventListener('click', () => toggleScanScheduler('start'));
  btnStop.addEventListener('click', () => toggleScanScheduler('stop'));

  fetchScanStatus();
  state._scanTimer = setInterval(fetchScanStatus, 10000);
}

async function fetchScanStatus() {
  try {
    const resp = await fetch('/api/tools/scan-schedule/status');
    if (!resp.ok) return;
    const data = await resp.json();
    state.scanRunning = data.running;
    state.scanStatus = data;
    renderScanStatus(data);
  } catch {
    // silently ignore
  }
}

function renderScanStatus(data) {
  const dot = $('#scan-dot');
  const text = $('#scan-status-text');
  const btnStart = $('#btn-scan-start');
  const btnStop = $('#btn-scan-stop');
  const stats = $('#scan-stats');

  if (!dot) return;

  if (data.running) {
    dot.className = 'scan-status-dot running';
    text.textContent = '运行中';
    btnStart.disabled = true;
    btnStop.disabled = false;
  } else {
    dot.className = 'scan-status-dot';
    text.textContent = '已停止';
    btnStart.disabled = false;
    btnStop.disabled = true;
  }

  if (stats && data.cycles !== undefined) {
    stats.innerHTML = `cycles: <strong>${data.cycles}</strong> · devices: <strong>${data.devices_found ?? 0}</strong> · last: ${data.last_scan ?? '-'}`;
  }
}

async function toggleScanScheduler(action) {
  const subnet = $('#scan-subnet')?.value || '192.168.1.0/24';
  const interval = parseInt($('#scan-interval')?.value || '300', 10);

  try {
    const resp = await fetch(`/api/tools/scan-schedule/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet, interval }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    await fetchScanStatus();
    addOpHistory(action === 'start' ? 'info' : 'success',
      `扫描调度${action === 'start' ? '已启动' : '已停止'}`,
      `子网: ${subnet}, 间隔: ${interval}s`);
  } catch (e) {
    addOpHistory('error', '扫描调度操作失败', e.message);
  }
}

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
function renderReportList() {
  const list = $('#report-list');
  list.innerHTML = state.reports.map(r => `
    <div class="report-item ${r.type}" data-id="${r.id}">
      <div class="title">${r.title}</div>
      <div class="meta">${r.time} · AI 生成</div>
    </div>
  `).join('') || '<div class="empty-state">暂无报告</div>';
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

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Reports Tab ───────────────────────────────────────────────────
function initReports() {
  $$('.rp-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.rp-tab').forEach(b => b.classList.toggle('active', b === btn));
      state.rpTab = btn.dataset.rp;
      state.devicePage = 0;
      state.eventsPage = 0;
      renderReportsControls();
      loadReportsData();
    });
  });
  renderReportsControls();
  loadReportsData();
}

let renderReportsControls = function() {
  const wrap = $('#rp-controls');
  if (!wrap) return;

  if (state.rpTab === 'devices') {
    wrap.innerHTML = `
      <input type="text" class="ops-input rp-search" id="rp-device-search" placeholder="搜索设备名称/IP/MAC..." value="${escapeHtml(state.deviceSearch)}" />
      <select class="ops-input rp-select" id="rp-device-status">
        <option value="">全部状态</option>
        <option value="secure">Secure</option>
        <option value="scanning">Scanning</option>
        <option value="vulnerable">Vulnerable</option>
        <option value="attacked">Attacked</option>
        <option value="isolated">Isolated</option>
      </select>
      <select class="ops-input rp-select" id="rp-device-type">
        <option value="">全部类型</option>
        ${[...new Set(state.devices.map(d => d.devType).filter(Boolean))].sort().map(t =>
          `<option value="${t}" ${state.deviceTypeFilter === t ? 'selected' : ''}>${t}</option>`
        ).join('')}
      </select>
      <select class="ops-input rp-select" id="rp-device-vendor">
        <option value="">全部厂商</option>
        ${[...new Set(state.devices.map(d => d.devVendor).filter(Boolean))].sort().map(v =>
          `<option value="${v}" ${state.deviceVendorFilter === v ? 'selected' : ''}>${v}</option>`
        ).join('')}
      </select>
    `;
    const searchInput = $('#rp-device-search');
    const statusSelect = $('#rp-device-status');
    const typeSelect = $('#rp-device-type');
    const vendorSelect = $('#rp-device-vendor');
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
  } else {
    wrap.innerHTML = `
      <select class="ops-input rp-select" id="rp-events-sev">
        <option value="">全部严重程度</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
    `;
    const sevSelect = $('#rp-events-sev');
    if (sevSelect) {
      sevSelect.value = state.eventsSevFilter;
      sevSelect.addEventListener('change', (e) => {
        state.eventsSevFilter = e.target.value;
        state.eventsPage = 0;
        renderSecurityEvents();
      });
    }
  }
}

async function loadReportsData() {
  if (state.rpTab === 'devices') {
    await fetchDevices();
  } else {
    await fetchSecurityEvents();
  }
}

async function fetchDevices() {
  try {
    const resp = await fetch('/api/dashboard/db/devices');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    state.devices = data.devices || [];
    renderReportsControls();
    renderDeviceTable();
  } catch (e) {
    const body = $('#rp-body');
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
    const params = new URLSearchParams({ limit: '500' });
    if (state.eventsSevFilter) params.set('severity', state.eventsSevFilter);
    const resp = await fetch(`/api/dashboard/db/alerts?${params}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    state.events = data.alerts || [];
    renderSecurityEvents();
  } catch (e) {
    const body = $('#rp-body');
    if (body) body.innerHTML = `<div class="empty-state">加载事件失败: ${escapeHtml(e.message)}</div>`;
  }
}

function renderSecurityEvents() {
  const body = $('#rp-body');
  if (!body) return;

  const total = state.events.length;
  const pages = Math.max(1, Math.ceil(total / state.eventsPageSize));
  state.eventsPage = Math.min(state.eventsPage, pages - 1);
  const start = state.eventsPage * state.eventsPageSize;
  const page = state.events.slice(start, start + state.eventsPageSize);

  body.innerHTML = `
    <div class="events-list">
      ${page.map(evt => {
        const sev = evt.severity || 'info';
        const ts = evt.timestamp ? evt.timestamp.slice(11, 19) : '--:--:--';
        return `<div class="evt-item sev-${sev}">
          <div class="evt-left">
            <span class="evt-sev-badge sev-${sev}">${sev.toUpperCase()}</span>
          </div>
          <div class="evt-body">
            <div class="evt-msg">${escapeHtml(evt.message || '')}</div>
            <div class="evt-meta">
              <span class="evt-source">${escapeHtml(evt.source_type || evt.source || '')}</span>
              <span class="evt-time">${ts}</span>
            </div>
          </div>
        </div>`;
      }).join('')}
      ${page.length === 0 ? '<div class="empty-state">无安全事件</div>' : ''}
    </div>
    ${renderPagination(total, state.eventsPage, state.eventsPageSize, 'event')}
  `;

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

// ── History Tab (Notifications + Workflow Audit) ──────────────────
function initHistory() {
  fetchNotificationConfig();
  fetchNotificationHistory();
  fetchWorkflowEvents();

  const testBtn = $('#btn-notif-test');
  if (testBtn) testBtn.addEventListener('click', sendTestNotification);
}

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

async function fetchNotificationHistory() {
  try {
    const resp = await fetch('/api/notifications/history?limit=50');
    if (!resp.ok) return;
    const data = await resp.json();
    renderNotificationHistory(data.notifications || []);
  } catch {
    const wrap = $('#notif-history');
    if (wrap) wrap.innerHTML = '<div class="empty-state">加载失败</div>';
  }
}

function renderNotificationHistory(notifs) {
  const wrap = $('#notif-history');
  if (!wrap) return;

  if (!notifs.length) {
    wrap.innerHTML = '<div class="empty-state">暂无通知记录</div>';
    return;
  }

  wrap.innerHTML = notifs.map(n => {
    const ok = n.status === 'sent' || n.status === 'delivered' || n.status === 'success';
    const ts = n.timestamp ? n.timestamp.replace('T', ' ').slice(0, 19) : '';
    return `
      <div class="notif-item ${ok ? 'ok' : 'fail'}">
        <div class="notif-dot"></div>
        <div class="notif-body">
          <div class="notif-title">${escapeHtml(n.title || n.channel || 'Notification')}</div>
          <div class="notif-msg">${escapeHtml(n.message || '')}</div>
          <div class="notif-meta">${escapeHtml(n.channel || '')} · ${ts}</div>
        </div>
      </div>
    `;
  }).join('');
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
    const ts = evt.timestamp ? evt.timestamp.replace('T', ' ').slice(11, 19) : '';
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
      const ts = a.timestamp ? a.timestamp.replace('T', ' ').slice(0, 19) : '';
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
  const body = document.getElementById('rp-body');
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
        <span class="tool-card-icon">📡</span>
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
        <span class="tool-card-icon">🔍</span>
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
    const checks = (r.checks || r.results || []).slice(0, 6).map(c => {
      const passed = c.status === 'pass' || c.passed;
      return `<div class="baseline-check ${passed ? 'check-pass' : 'check-fail'}">
        <span>${passed ? '✓' : '✗'}</span> ${escapeHtml(c.rule || c.name || c.id || '')}
      </div>`;
    }).join('');
    return el('div', 'tool-card tool-card-baseline', `
      <div class="tool-card-header">
        <span class="tool-card-icon">🛡️</span>
        <span class="tool-card-title">安全基线审计</span>
        <span class="tool-card-badge">${r.devices_audited} 台设备</span>
      </div>
      <div class="tool-card-body">
        <div class="baseline-score">
          <svg viewBox="0 0 36 36" class="score-ring"><path class="score-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="score-fill" stroke="${color}" stroke-dasharray="${score}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/></svg>
          <span class="score-num" style="color:${color}">${score}%</span>
        </div>
        ${checks || '<div class="baseline-check">无详细检查结果</div>'}
      </div>
    `);
  }

  // CVE results
  if (r.cves && Array.isArray(r.cves)) {
    const rows = r.cves.slice(0, 6).map(c => {
      const cvss = c.cvss || c.score || 0;
      const sev = cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
      return `<tr>
        <td><span class="cve-id">${escapeHtml(c.id || c.cve_id || '')}</span></td>
        <td><span class="sev-badge sev-${sev}">${sev}</span></td>
        <td>${cvss}</td>
        <td>${escapeHtml((c.description || '').substring(0, 60))}</td>
      </tr>`;
    }).join('');
    return el('div', 'tool-card tool-card-cve', `
      <div class="tool-card-header">
        <span class="tool-card-icon">⚠️</span>
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
        <span class="tool-card-icon">🔓</span>
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
        <span class="tool-card-icon">🔑</span>
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
        <span class="tool-card-icon">📋</span>
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
