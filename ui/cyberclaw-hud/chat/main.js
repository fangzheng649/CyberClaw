// ═══════════════════════════════════════════════════════════════════
// CyberClaw CyberAgent Chat — Mock AI Interaction
// ═══════════════════════════════════════════════════════════════════

// ── MCP & Skills Data ─────────────────────────────────────────────
const MCP_SERVERS = [
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
};

// ── DOM ───────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Init ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initInput();
  initOps();
  initHudLink();
  populateMcpList();
  populateSkillsList();
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

    // Mark sender as done
    msgEl.querySelector('.msg-sender').innerHTML = '<span class="dot"></span>CyberAgent';

    // Show reply
    textContainer.innerHTML = data.reply.replace(/\n/g, '<br>');
    textContainer.style.display = 'block';

    // Attach confirm button handlers if present in HTML
    const confirmBtns = textContainer.querySelectorAll('.confirm-btn');
    if (confirmBtns.length > 0) {
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
    confirmCard.innerHTML = `
      <div class="confirm-title" style="color:#00ff88">✓ 隔离操作已执行</div>
      <div class="confirm-details">
        <div>• Switch-Core Gi0/1 → shutdown ✓</div>
        <div>• Switch-Core Gi0/2 → shutdown ✓</div>
        <div style="margin-top:4px;color:rgba(255,255,255,0.4);">Camera-1 和 Camera-2 已成功隔离</div>
      </div>
    `;
    addOpHistory('success', '端口隔离执行成功', 'Camera-1, Camera-2 已断网');
  } else if (action === 'cancel') {
    confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--muted)">操作已取消</div>`;
  } else {
    confirmCard.innerHTML = `<div class="confirm-title" style="color:var(--info)">请在下方输入修改方案</div>`;
  }
}

// ── Operations Tab ────────────────────────────────────────────────
function initOps() {
  initOpsButtons();
}

function populateMcpList() {
  const list = $('#mcp-list');
  list.innerHTML = MCP_SERVERS.map(s => `
    <div class="mcp-row">
      <span class="mcp-name">${s.name}</span>
      <span class="mcp-status ${s.status}">● ${s.status === 'online' ? '在线' : s.status === 'busy' ? '忙碌' : '离线'}</span>
    </div>
  `).join('');
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
