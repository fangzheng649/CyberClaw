import * as echarts from 'echarts';

const DS = {
  alerts: [],
  charts: {},
  refreshMs: 30000,
  autoRefresh: true,
  _timer: null,
};

const $ = s => document.querySelector(s);

const SEV_COLORS = { critical: '#ff2244', high: '#f97316', medium: '#eab308', low: '#00bbff', info: '#64748b' };
const FSM_COLORS = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
const SRC_ICONS = { syslog: 'SYS', snmp: 'SNP', mqtt: 'MQT', suricata: 'IDS' };

export function initDashboard() {
  const wrap = $('#dashboard-content');
  if (!wrap) return;
  renderAlertPanel(wrap);
  renderDeviceOverview(wrap);
  renderTrendPanel(wrap);
  renderTopologyTree(wrap);
  renderLogPanel(wrap);
  fetchData();
  fetchDeviceOverview();
  fetchTopologyTree();
  DS._timer = setInterval(() => { if (DS.autoRefresh) { fetchData(); fetchDeviceOverview(); } }, DS.refreshMs);
}

function renderAlertPanel(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>Alert List</h3>
      <div class="dp-filters">
        <select id="da-sev"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        <select id="da-src"><option value="">All</option><option value="syslog">Syslog</option><option value="snmp">SNMP</option><option value="mqtt">MQTT</option><option value="suricata">Suricata</option></select>
        <button class="dp-btn" id="da-refresh">Refresh</button>
      </div>
    </div>
    <div class="dp-stats"><span class="dp-badge critical">Crit <b id="ds-crit">0</b></span><span class="dp-badge high">High <b id="ds-high">0</b></span><span class="dp-badge medium">Med <b id="ds-med">0</b></span><span class="dp-badge low">Low <b id="ds-low">0</b></span></div>
    <div id="da-list" class="da-list"></div>`;
  wrap.appendChild(sec);
  $('#da-refresh')?.addEventListener('click', fetchAlerts);
  $('#da-sev')?.addEventListener('change', fetchAlerts);
  $('#da-src')?.addEventListener('change', fetchAlerts);
}

function renderTrendPanel(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>Security Trends</h3><button class="dp-btn" id="dt-refresh">Refresh</button></div>
    <div class="dp-charts-grid">
      <div id="dt-alert-count" class="dp-chart"></div>
      <div id="dt-device-status" class="dp-chart"></div>
      <div id="dt-protocol" class="dp-chart"></div>
    </div>`;
  wrap.appendChild(sec);
  $('#dt-refresh')?.addEventListener('click', fetchTrends);
}

function renderLogPanel(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>Log Search</h3></div>
    <div class="dp-search-bar">
      <input type="text" id="dl-query" placeholder="Search logs..."/>
      <select id="dl-sev"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select>
      <select id="dl-src"><option value="">All</option><option value="syslog">Syslog</option><option value="snmp">SNMP</option><option value="mqtt">MQTT</option><option value="suricata">Suricata</option></select>
      <button class="dp-btn" id="dl-search">Search</button>
    </div>
    <div id="dl-results" class="dl-results"></div>`;
  wrap.appendChild(sec);
  $('#dl-search')?.addEventListener('click', searchLogs);
  $('#dl-query')?.addEventListener('keydown', e => { if (e.key === 'Enter') searchLogs(); });
}

async function fetchData() { await Promise.all([fetchAlerts(), fetchTrends()]); }

// ── Device Overview Tiles ──────────────────────────────────────────
function renderDeviceOverview(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>Device Overview</h3><button class="dp-btn" id="do-refresh">Refresh</button></div>
    <div class="do-tiles" id="do-tiles"></div>
    <div class="dp-header" style="margin-top:12px;border-top:1px solid rgba(0,187,255,.15);padding-top:10px"><h3>Workflow Events</h3></div>
    <div class="do-wf-list" id="do-wf-list"><div class="dp-empty">Loading...</div></div>`;
  wrap.appendChild(sec);
  $('#do-refresh')?.addEventListener('click', fetchDeviceOverview);
}

async function fetchDeviceOverview() {
  try {
    const [devResp, wfResp] = await Promise.all([
      fetch('/api/dashboard/db/devices'),
      fetch('/api/workflows/events?limit=5'),
    ]);
    const devData = devResp.ok ? await devResp.json() : { devices: [] };
    const wfData = wfResp.ok ? await wfResp.json() : { events: [] };
    renderDeviceTiles(devData.devices || []);
    renderWfMiniEvents(wfData.events || []);
  } catch (e) { console.error('fetchDeviceOverview', e); }
}

function renderDeviceTiles(devices) {
  const wrap = $('#do-tiles');
  if (!wrap) return;

  const states = ['secure', 'scanning', 'vulnerable', 'attacked', 'isolated'];
  const icons = { secure: '✓', scanning: '⟳', vulnerable: '!', attacked: '✕', isolated: '⊘' };
  const counts = {};
  states.forEach(s => counts[s] = 0);
  devices.forEach(d => {
    const s = d.devStatus || d.devForceStatus || 'secure';
    counts[s] = (counts[s] || 0) + 1;
  });

  wrap.innerHTML = states.map(s => `
    <div class="do-tile" style="--tile-color: ${FSM_COLORS[s]}">
      <div class="do-tile-icon">${icons[s]}</div>
      <div class="do-tile-count">${counts[s]}</div>
      <div class="do-tile-label">${s}</div>
    </div>
  `).join('');
}

function renderWfMiniEvents(events) {
  const wrap = $('#do-wf-list');
  if (!wrap) return;
  if (!events.length) {
    wrap.innerHTML = '<div class="dp-empty">No workflow events</div>';
    return;
  }
  wrap.innerHTML = events.map(evt => {
    const ts = evt.timestamp ? evt.timestamp.replace('T', ' ').slice(11, 19) : '';
    return `<div class="do-wf-item">
      <span class="do-wf-dot"></span>
      <span class="do-wf-type">${esc(evt.object_type || evt.event_type || 'event')}</span>
      <span class="do-wf-time">${ts}</span>
    </div>`;
  }).join('');
}

async function fetchAlerts() {
  try {
    const sev = $('#da-sev')?.value || '';
    const src = $('#da-src')?.value || '';
    let url = `/api/dashboard/alerts?limit=200`;
    if (sev) url += `&severity=${sev}`;
    const r = await fetch(url);
    const d = await r.json();
    DS.alerts = d.alerts || [];
    if (src) DS.alerts = DS.alerts.filter(a => a.source_type === src);
    renderAlerts();
  } catch (e) { console.error('fetchAlerts', e); }
}

function renderAlerts() {
  const box = $('#da-list');
  if (!box) return;
  if (!DS.alerts.length) { box.innerHTML = '<div class="dp-empty">No alerts</div>'; updateStats(); return; }
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  box.innerHTML = DS.alerts.slice(0, 100).map(a => {
    counts[a.severity] = (counts[a.severity] || 0) + 1;
    const icon = SRC_ICONS[a.source_type] || '???';
    const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '';
    return `<div class="da-item ${a.severity}">
      <div class="da-row"><span class="da-sev ${a.severity}">${a.severity.toUpperCase()}</span><span class="da-src">${icon} ${a.source_type}</span><span class="da-time">${ts}</span></div>
      <div class="da-msg">${esc(a.message)}</div>
      ${a.target ? `<div class="da-meta">Target: ${esc(a.target)}</div>` : ''}
    </div>`;
  }).join('');
  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  set('#ds-crit', counts.critical); set('#ds-high', counts.high); set('#ds-med', counts.medium); set('#ds-low', counts.low);
}

function updateStats() { ['crit','high','med','low'].forEach(k => { const e = $(`#ds-${k}`); if (e) e.textContent = '0'; }); }

async function fetchTrends() {
  try {
    const [ac, ds, pt] = await Promise.all([
      fetch('/api/dashboard/trends/alert-count?hours=24').then(r => r.json()),
      fetch('/api/dashboard/trends/device-status').then(r => r.json()),
      fetch('/api/dashboard/trends/protocol-traffic').then(r => r.json()),
    ]);
    renderAlertCountChart(ac);
    renderDeviceStatusChart(ds);
    renderProtocolChart(pt);
  } catch (e) { console.error('fetchTrends', e); }
}

function getChart(id) {
  if (!DS.charts[id]) {
    const dom = $(id);
    if (!dom) return null;
    DS.charts[id] = echarts.init(dom);
    window.addEventListener('resize', () => DS.charts[id]?.resize());
  }
  return DS.charts[id];
}

function renderAlertCountChart(d) {
  const c = getChart('#dt-alert-count');
  if (!c) return;
  c.setOption({
    title: { text: 'Alerts / Hour', left: 'center', textStyle: { color: '#94a3b8', fontSize: 12 } },
    tooltip: { trigger: 'axis' },
    grid: { left: 36, right: 12, top: 32, bottom: 24 },
    xAxis: { type: 'category', data: (d.labels || []).map(l => l.slice(-5)), axisLabel: { color: '#64748b', fontSize: 9 } },
    yAxis: { type: 'value', axisLabel: { color: '#64748b' }, splitLine: { lineStyle: { color: '#1e293b' } } },
    series: ['critical','high','medium','low'].map(k => ({
      name: k, type: 'line', stack: 'total', areaStyle: { opacity: .25 },
      data: d.series?.[k] || [], itemStyle: { color: SEV_COLORS[k] },
    })),
  });
}

function renderDeviceStatusChart(d) {
  const c = getChart('#dt-device-status');
  if (!c) return;
  const labels = d.labels || ['secure','scanning','vulnerable','attacked','isolated'];
  c.setOption({
    title: { text: 'Device Status', left: 'center', textStyle: { color: '#94a3b8', fontSize: 12 } },
    tooltip: { trigger: 'item' },
    series: [{ type: 'pie', radius: ['35%','65%'], center: ['50%','55%'],
      data: labels.map((l, i) => ({ value: d.data?.[i] || 0, name: l, itemStyle: { color: FSM_COLORS[l] || '#64748b' } })),
      label: { color: '#94a3b8', fontSize: 10 },
    }],
  });
}

function renderProtocolChart(d) {
  const c = getChart('#dt-protocol');
  if (!c) return;
  const colors = ['#00e5ff','#7c3aed','#f97316','#22c55e','#ef4444','#eab308'];
  c.setOption({
    title: { text: 'Protocol Traffic', left: 'center', textStyle: { color: '#94a3b8', fontSize: 12 } },
    tooltip: { trigger: 'item' },
    series: [{ type: 'pie', radius: '55%', center: ['50%','55%'],
      data: (d.labels || []).map((l, i) => ({ value: d.data?.[i] || 0, name: l.toUpperCase(), itemStyle: { color: colors[i % colors.length] } })),
      label: { color: '#94a3b8', fontSize: 10 },
    }],
  });
}

async function searchLogs() {
  const q = $('#dl-query')?.value || '';
  const sev = $('#dl-sev')?.value || '';
  const src = $('#dl-src')?.value || '';
  const box = $('#dl-results');
  if (!box) return;
  try {
    const url = `/api/dashboard/logs/search?query=${encodeURIComponent(q)}&severity=${sev}&source=${src}&limit=100`;
    const r = await fetch(url);
    const d = await r.json();
    if (!d.results?.length) { box.innerHTML = '<div class="dp-empty">No results</div>'; return; }
    box.innerHTML = d.results.map(l => {
      const icon = SRC_ICONS[l.source_type] || 'LOG';
      const ts = l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '';
      const msg = l.message || JSON.stringify(l).slice(0, 120);
      return `<div class="dl-item ${l.source_type}">
        <div class="dl-row"><span class="da-src">${icon}</span><span class="da-time">${ts}</span>${l.severity ? `<span class="da-sev ${l.severity}">${l.severity}</span>` : ''}</div>
        <div class="dl-msg">${esc(msg)}</div>
      </div>`;
    }).join('');
  } catch (e) { box.innerHTML = '<div class="dp-empty">Search failed</div>'; }
}

export function onDashboardMessage(msg) {
  if (['suricata_alert', 'syslog_event', 'snmp_trap', 'mqtt_message', 'traffic_stats'].includes(msg.type)) {
    clearTimeout(DS._debounce);
    DS._debounce = setTimeout(() => fetchData(), 500);
  }
}

function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ── Topology Tree ──────────────────────────────────────────────────
function renderTopologyTree(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>Network Topology</h3><button class="dp-btn" id="topo-refresh">Refresh</button></div>
    <div id="topo-tree-wrap"><div class="dp-empty">Loading...</div></div>`;
  wrap.appendChild(sec);
  $('#topo-refresh')?.addEventListener('click', fetchTopologyTree);
}

async function fetchTopologyTree() {
  const wrap = document.getElementById('topo-tree-wrap');
  if (!wrap) return;
  try {
    const resp = await fetch('/api/topology');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const devices = data.devices || [];
    const links = data.links || [];
    if (!devices.length) { wrap.innerHTML = '<div class="dp-empty">No topology data</div>'; return; }
    const tree = buildTopoTree(devices, links);
    wrap.innerHTML = tree ? renderTopoNode(tree, 0) : '<div class="dp-empty">No root node found</div>';
    bindTopoToggle(wrap);
  } catch (e) {
    wrap.innerHTML = `<div class="dp-empty">Load failed: ${e.message}</div>`;
  }
}

function buildTopoTree(devices, links) {
  const childIds = new Set(links.map(l => l.to));
  const roots = devices.filter(d => !childIds.has(d.id || d.devMAC));
  if (!roots.length) return null;
  const root = roots[0];
  return buildTopoNode(root, devices, links, new Set());
}

function buildTopoNode(node, devices, links, visited) {
  const id = node.id || node.devMAC;
  if (visited.has(id)) return null;
  visited.add(id);
  const children = links
    .filter(l => l.from === id)
    .map(l => devices.find(d => (d.id || d.devMAC) === l.to))
    .filter(Boolean)
    .map(child => buildTopoNode(child, devices, links, visited))
    .filter(Boolean);
  return {
    id, name: node.devName || node.name || id,
    ip: node.devLastIP || node.ip || '',
    type: node.devType || node.type || '',
    status: node.devStatus || node.status || 'secure',
    children,
  };
}

function renderTopoNode(node, depth) {
  const FSM_C = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
  const c = FSM_C[node.status] || '#5a6e88';
  const hasChildren = node.children && node.children.length > 0;
  const childHtml = hasChildren
    ? `<ul class="topo-children">${node.children.map(ch => renderTopoNode(ch, depth + 1)).join('')}</ul>`
    : '';
  return `<li class="topo-node ${hasChildren ? 'has-children' : ''} ${hasChildren ? '' : 'leaf'}">
    <div class="topo-node-row">
      ${hasChildren ? '<span class="topo-toggle">▶</span>' : '<span class="topo-toggle-leaf">●</span>'}
      <span class="topo-dot" style="background:${c};box-shadow:0 0 4px ${c}"></span>
      <span class="topo-name">${esc(node.name)}</span>
      <span class="topo-type">${esc(node.type)}</span>
      <span class="topo-ip">${esc(node.ip)}</span>
    </div>
    ${childHtml}
  </li>`;
}

function bindTopoToggle(wrap) {
  wrap.querySelectorAll('.topo-node.has-children > .topo-node-row').forEach(row => {
    row.addEventListener('click', () => {
      const node = row.parentElement;
      node.classList.toggle('expanded');
    });
    row.style.cursor = 'pointer';
  });
}
