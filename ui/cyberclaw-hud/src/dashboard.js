import * as echarts from 'echarts';

const DS = {
  alerts: [],
  charts: {},
  refreshMs: 30000,
  autoRefresh: true,
  _timer: null,
};

const $ = s => document.querySelector(s);

const SEV_COLORS = { critical: '#ff2244', high: '#f97316', warning: '#eab308', medium: '#f59e0b', low: '#00bbff', info: '#64748b' };
const FSM_COLORS = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
const SRC_ICONS = { syslog: 'SYS', snmp: 'SNP', mqtt: 'MQT', suricata: 'IDS', scenario: 'SCE' };
const PROTO_COLORS = {
  HTTP: '#2563eb', HTTPS: '#3b82f6',
  MQTT: '#0891b2', COAP: '#06b6d4',
  MODBUS: '#f59e0b', S7COMM: '#f97316', PROFINET: '#fb923c',
  SSH: '#6366f1', SNMP: '#8b5cf6',
  TCP: '#0ea5e9', UDP: '#64748b', ICMP: '#64748b',
  OTHER: '#64748b',
};

export function initDashboard() {
  const wrap = $('#dashboard-content');
  if (!wrap) return;

  // Row 1: Device status tiles
  const topRow = el('div', 'dp-top-row');
  renderDeviceOverview(topRow);
  wrap.appendChild(topRow);

  // Row 2: Trends + Topology (stacked vertically)
  const bottomRow = el('div', 'dp-bottom-row');
  renderTrendPanel(bottomRow);
  renderTopologyTree(bottomRow);
  wrap.appendChild(bottomRow);

  fetchDeviceOverview();
  fetchTrends();
  // Topology loads lazily when the Dashboard tab becomes visible
  DS._topoLoaded = false;
  DS._timer = setInterval(() => { if (DS.autoRefresh) { fetchDeviceOverview(); fetchTrends(); } }, DS.refreshMs);
}

// Lazy-load topology when Dashboard tab becomes visible (container has dimensions)
window.addEventListener('dashboard-visible', () => {
  if (!DS._topoLoaded) {
    DS._topoLoaded = true;
    fetchTopologyTree();
  }
});

// ── Toast notification helper ────────────────────────────────────
function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const colors = {
    info: 'rgba(0,187,255,.15)', success: 'rgba(0,255,136,.15)',
    warning: 'rgba(234,179,8,.15)', error: 'rgba(255,34,68,.15)',
  };
  const borders = {
    info: 'rgba(0,187,255,.4)', success: 'rgba(0,255,136,.4)',
    warning: 'rgba(234,179,8,.4)', error: 'rgba(255,34,68,.4)',
  };
  const el = document.createElement('div');
  el.style.cssText = `
    background:${colors[type] || colors.info}; border:1px solid ${borders[type] || borders.info};
    color:#cbd5e1; padding:8px 16px; border-radius:6px; font-size:12px; margin-bottom:6px;
    opacity:0; transition:opacity .3s; pointer-events:none;
  `;
  el.textContent = msg;
  container.appendChild(el);
  requestAnimationFrame(() => el.style.opacity = '1');
  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }, 2000);
}

function renderTrendPanel(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>安全趋势</h3><button class="dp-btn" id="dt-refresh">刷新</button></div>
    <div class="dp-charts-grid">
      <div id="dt-alert-count" class="dp-chart"></div>
      <div id="dt-protocol" class="dp-chart"></div>
    </div>`;
  wrap.appendChild(sec);
  $('#dt-refresh')?.addEventListener('click', fetchTrends);
}

// ── Device Overview Tiles ──────────────────────────────────────────
function renderDeviceOverview(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>设备状态</h3><button class="dp-btn" id="do-refresh">刷新</button></div>
    <div class="do-tiles" id="do-tiles"></div>`;
  wrap.appendChild(sec);
  $('#do-refresh')?.addEventListener('click', fetchDeviceOverview);
}

async function fetchDeviceOverview() {
  try {
    const devResp = await fetch('/api/dashboard/db/devices');
    const devData = devResp.ok ? await devResp.json() : { devices: [] };
    renderDeviceTiles(devData.devices || []);
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

  const total = devices.length || 1;
  wrap.innerHTML = states.map(s => `
    <div class="do-tile" style="--tile-color: ${FSM_COLORS[s]}">
      <div class="do-tile-icon">${icons[s]}</div>
      <div class="do-tile-count">${counts[s]}</div>
      <div class="do-tile-label">${s}</div>
      <div class="do-tile-pct">${Math.round(counts[s] / total * 100)}%</div>
    </div>
  `).join('');
}

async function fetchTrends() {
  // Dispose orphaned device-status chart if it exists from a previous render
  if (DS.charts['#dt-device-status']) {
    DS.charts['#dt-device-status'].dispose();
    delete DS.charts['#dt-device-status'];
  }
  try {
    const [ac, pt] = await Promise.all([
      fetch('/api/dashboard/trends/alert-count?hours=24').then(r => r.json()),
      fetch('/api/dashboard/trends/protocol-traffic').then(r => r.json()),
    ]);
    renderAlertCountChart(ac);
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
  const labels = (d.labels || []).map(l => l.slice(-5));
  c.setOption({
    title: { text: '告警/小时', left: 'center', textStyle: { color: '#64748b', fontSize:13 } },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(0,15,25,0.95)',
      borderColor: 'rgba(0,187,255,0.3)',
      borderWidth: 1,
      textStyle: { color: '#64748b', fontSize:13 },
    },
    legend: {
      data: ['critical', 'high', 'warning', 'medium', 'low', 'info'],
      top: 0, right: 0,
      textStyle: { color: '#64748b', fontSize:12 },
      itemWidth: 12, itemHeight: 8,
    },
    grid: { left: 40, right: 16, top: 48, bottom: 28 },
    xAxis: {
      type: 'category', data: labels,
      axisLabel: {
        color: '#64748b', fontSize:11,
        interval: labels.length > 16 ? 2 : labels.length > 10 ? 1 : 0,
      },
      axisLine: { lineStyle: { color: '#94a3b8' } },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#94a3b8' } },
    },
    series: ['critical', 'high', 'warning', 'medium', 'low', 'info'].map(k => ({
      name: k, type: 'line', stack: 'total', smooth: true,
      areaStyle: { opacity: 0.25 },
      data: d.series?.[k] || [],
      itemStyle: { color: SEV_COLORS[k] },
      symbol: 'circle', symbolSize: 4, showSymbol: false,
      emphasis: { focus: 'series' },
    })),
  });
}

function renderProtocolChart(d) {
  const c = getChart('#dt-protocol');
  if (!c) return;

  // Build {name, value} pairs from API data, sort descending
  const raw = (d.labels || []).map((l, i) => ({
    name: l.toUpperCase(),
    value: d.data?.[i] || 0,
  }));
  raw.sort((a, b) => b.value - a.value);

  // Top 8 + aggregate rest as "Other"
  const top = raw.slice(0, 8);
  const rest = raw.slice(8);
  if (rest.length > 0) {
    top.push({
      name: 'OTHER',
      value: rest.reduce((s, r) => s + r.value, 0),
    });
  }

  const names = top.map(t => t.name);
  const values = top.map(t => t.value);
  const colors = top.map(t => PROTO_COLORS[t.name] || '#64748b');

  c.setOption({
    title: {
      text: '协议分布',
      left: 'center',
      textStyle: { color: '#64748b', fontSize:13 },
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: 'rgba(0,15,25,0.95)',
      borderColor: 'rgba(0,187,255,0.3)',
      borderWidth: 1,
      textStyle: { color: '#64748b', fontSize:13 },
    },
    grid: { left: 72, right: 48, top: 32, bottom: 12 },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', fontSize:11 },
      splitLine: { lineStyle: { color: '#94a3b8' } },
    },
    yAxis: {
      type: 'category',
      data: names,
      axisLabel: { color: '#64748b', fontSize:12 },
      axisLine: { lineStyle: { color: '#94a3b8' } },
      axisTick: { show: false },
    },
    series: [{
      type: 'bar',
      data: values.map((v, i) => ({
        value: v,
        itemStyle: {
          color: colors[i],
          borderRadius: [0, 4, 4, 0],
        },
      })),
      barWidth: 14,
      label: {
        show: true,
        position: 'right',
        color: '#64748b',
        fontSize:12,
      },
    }],
  });
}

export function onDashboardMessage(msg) {
  // Real-time collector/IDS events
  const realtimeTypes = ['suricata_alert', 'syslog_event', 'snmp_trap', 'mqtt_message', 'traffic_stats'];
  // Scenario demo events (attack_detected, port_scan, vulnerability_found, etc.)
  const scenarioTypes = [
    'attack_detected', 'scan_started', 'port_scan', 'vulnerability_found',
    'bruteforce', 'lateral_movement', 'c2_detected', 'device_isolated',
    'analysis_complete', 'isolation_request', 'threat_resolved',
    'system_ready', 'scenario_start', 'scenario_complete', 'heartbeat',
  ];
  if (realtimeTypes.includes(msg.type) || scenarioTypes.includes(msg.type)) {
    clearTimeout(DS._debounce);
    DS._debounce = setTimeout(() => { fetchTrends(); fetchDeviceOverview(); }, 500);
  }
  // Topology-changing events: only actual device status changes, NOT heartbeat
  const topoTypes = ['device_isolated', 'attack_detected', 'scan_started',
    'vulnerability_found', 'threat_resolved', 'scenario_start', 'scenario_complete'];
  if (topoTypes.includes(msg.type)) {
    clearTimeout(DS._topoDebounce);
    DS._topoDebounce = setTimeout(() => fetchTopologyTree(), 800);
  }
}

function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ── Topology Treeviz (referenced from NetAlertX network-tree.js) ───
const TOPO_ICONS = {
  internet: '<i class="fa-solid fa-globe" style="color:#00bbff"></i>',
  switch:   '<i class="fa-solid fa-network-wired" style="color:#00e5ff"></i>',
  firewall: '<i class="fa-solid fa-shield-halved" style="color:#f97316"></i>',
  gateway:  '<i class="fa-solid fa-server" style="color:#22c55e"></i>',
  ap:       '<i class="fa-solid fa-wifi" style="color:#7c3aed"></i>',
  router:   '<i class="fa-solid fa-route" style="color:#00bbff"></i>',
  camera:   '<i class="fa-solid fa-video" style="color:#94a3b8"></i>',
  plc:      '<i class="fa-solid fa-microchip" style="color:#f97316"></i>',
  lock:     '<i class="fa-solid fa-lock" style="color:#eab308"></i>',
  sensor:   '<i class="fa-solid fa-temperature-half" style="color:#22c55e"></i>',
  bulb:     '<i class="fa-solid fa-lightbulb" style="color:#eab308"></i>',
  plug:     '<i class="fa-solid fa-plug" style="color:#64748b"></i>',
  hmi:      '<i class="fa-solid fa-display" style="color:#7c3aed"></i>',
  nas:      '<i class="fa-solid fa-hard-drive" style="color:#00bbff"></i>',
};
const TOPO_NET_TYPES = new Set(['internet','switch','firewall','gateway','ap','router']);

function renderTopologyTree(wrap) {
  const sec = el('section', 'dashboard-panel');
  sec.innerHTML = `
    <div class="dp-header"><h3>网络拓扑</h3><button class="dp-btn" id="topo-refresh">刷新</button></div>
    <div id="topo-tree-wrap" class="topo-tree-container"><div class="dp-empty">加载中...</div></div>`;
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
    if (!devices.length) { wrap.innerHTML = '<div class="dp-empty">暂无拓扑数据</div>'; return; }
    const hierarchy = buildTopoHierarchy(devices, links);
    if (!hierarchy) { wrap.innerHTML = '<div class="dp-empty">未找到根节点</div>'; return; }
    DS._topoData = { devices, links };
    // Wait for DOM layout to complete before Treeviz renders
    requestAnimationFrame(() => requestAnimationFrame(() => initTopoTree(hierarchy)));
  } catch (e) {
    wrap.innerHTML = `<div class="dp-empty">加载失败: ${e.message}</div>`;
  }
}

// Build hierarchical tree from flat device+link data
// (adapted from NetAlertX getChildren / getHierarchy)
function buildTopoHierarchy(devices, links) {
  const normLinks = links.map(l => ({ from: l.from || l.from_, to: l.to }));
  const childIds = new Set(normLinks.map(l => l.to));
  const roots = devices.filter(d => !childIds.has(d.id || d.devMAC));
  if (!roots.length) return null;

  // Build parent map: childId → parentId
  const parentOf = {};
  normLinks.forEach(l => { parentOf[l.to] = l.from; });
  const devMap = {};
  devices.forEach(d => { devMap[d.id || d.devMAC] = d; });

  // Start from root, recursively build children
  const root = roots[0];
  return buildTopoNode(root, devMap, normLinks, parentOf, new Set());
}

function buildTopoNode(node, devMap, links, parentOf, visited) {
  const id = node.id || node.devMAC;
  if (visited.has(id)) return null;
  visited.add(id);

  const name = node.name || node.devName || id;
  const ip = node.ip || node.devLastIP || '';
  const type = node.type || node.devType || '';
  const status = node.status || node.devStatus || 'secure';
  const online = node.online !== undefined ? node.online : true;
  const isNet = TOPO_NET_TYPES.has(type);

  // Find children of this node
  const childLinks = links.filter(l => l.from === id);
  const children = childLinks
    .map(l => devMap[l.to])
    .filter(Boolean)
    .map(child => buildTopoNode(child, devMap, links, parentOf, visited))
    .filter(Boolean);

  return {
    id, name, ip, type, status, online, isNet,
    hasChildren: children.length > 0,
    collapsed: DS._topoCollapsed && DS._topoCollapsed.has(id),
    children: (DS._topoCollapsed && DS._topoCollapsed.has(id)) ? [] : children,
  };
}

// Initialize or refresh Treeviz (adapted from NetAlertX initTree)
function initTopoTree(hierarchy) {
  if (typeof Treeviz === 'undefined') {
    const wrap = document.getElementById('topo-tree-wrap');
    if (wrap) wrap.innerHTML = '<div class="dp-empty">拓扑库加载失败</div>';
    return;
  }

  const container = document.getElementById('topo-tree-wrap');
  if (!container) return;

  // Calculate node sizes based on container
  const treeHeight = container.offsetHeight || 380;
  const treeWidth = container.offsetWidth || 800;

  // Count leaves/parents for sizing
  let leaves = 0, parents = 0;
  function count(n) {
    // Count all children, even collapsed ones, for sizing
    const realChildren = n.hasChildren ? (n.children.length || 1) : 0;
    if (!n.hasChildren) { leaves++; }
    else { parents++; if (n.children.length) n.children.forEach(count); }
  }
  count(hierarchy);
  leaves = Math.max(leaves, 1);

  const nodeHeight = Math.min(Math.max(Math.floor(treeHeight / (leaves + 1)), 26), 40);
  const nodeWidth = Math.min(Math.max(Math.floor(treeWidth / (parents + 2)), 100), 180);

  container.innerHTML = '';
  container.style.height = '380px';
  container.style.width = '100%';

  const treeInstance = Treeviz.create({
    htmlId: 'topo-tree-wrap',
    renderNode: function(nodeData) {
      return renderTopoNodeHtml(nodeData);
    },
    mainAxisNodeSpacing: 'auto',
    nodeHeight: nodeHeight,
    nodeWidth: nodeWidth,
    marginTop: 6,
    marginLeft: 12,
    marginRight: 12,
    isHorizontal: true,
    hasZoom: true,
    hasPan: true,
    idKey: 'id',
    hasFlatData: false,
    relationnalField: 'children',
    linkWidth: function() { return 1.5; },
    linkColor: function(nodeData) {
      const s = nodeData.data.status;
      if (s === 'attacked') return '#ff2244';
      if (s === 'vulnerable') return '#ffaa00';
      if (s === 'scanning') return '#00bbff';
      if (s === 'isolated') return '#5a6e88';
      return 'rgba(0,187,255,0.25)';
    },
    linkShape: 'quadraticBeziers',
  });

  treeInstance.refresh(hierarchy);
  DS._topoTree = treeInstance;
}

// Render individual node HTML (adapted from NetAlertX renderNode)
function renderTopoNodeHtml(nodeData) {
  const d = nodeData.data;
  const icon = TOPO_ICONS[d.type] || '<i class="fa-solid fa-circle-nodes" style="color:#64748b"></i>';
  const isNet = d.isNet || TOPO_NET_TYPES.has(d.type);
  const isOffline = d.online === false;

  // Status badge (only show for non-secure non-root nodes)
  let badgeHtml = '';
  if (isOffline) {
    badgeHtml = '<span class="topo-node-badge offline">OFFLINE</span>';
  } else if (d.status !== 'secure' && d.type !== 'internet') {
    badgeHtml = `<span class="topo-node-badge ${d.status}">${d.status}</span>`;
  }

  // Network device marker
  const netMarker = isNet ? '<span class="topo-net-marker"></span>' : '';

  // Collapse/expand toggle
  let toggleHtml = '';
  if (d.hasChildren) {
    const sym = d.collapsed ? '+' : '−';
    toggleHtml = `<span class="topo-toggle-btn" data-topo-id="${d.id}">${sym}</span>`;
  }

  return `<div class="topo-node ${isOffline ? 'status-offline' : 'status-' + d.status}" style="position:relative"
               data-topo-id="${d.id}" data-topo-name="${esc(d.name)}"
               data-topo-ip="${d.ip}" data-topo-type="${d.type}"
               data-topo-status="${d.status}" data-topo-net="${isNet}">
    <span class="topo-node-icon">${icon}</span>
    <span class="topo-node-name">${esc(d.name)}</span>
    <span class="topo-node-ip">${esc(d.ip)}</span>
    ${badgeHtml}
    ${toggleHtml}
    ${netMarker}
  </div>`;
}

// Handle toggle click (delegated)
document.addEventListener('click', function(e) {
  const toggle = e.target.closest('.topo-toggle-btn');
  if (!toggle) return;
  e.stopPropagation();
  const nodeId = toggle.dataset.topoId;
  if (!nodeId) return;
  if (!DS._topoCollapsed) DS._topoCollapsed = new Set();
  if (DS._topoCollapsed.has(nodeId)) {
    DS._topoCollapsed.delete(nodeId);
  } else {
    DS._topoCollapsed.add(nodeId);
  }
  // Rebuild with updated collapse state
  if (DS._topoData) {
    const hierarchy = buildTopoHierarchy(DS._topoData.devices, DS._topoData.links);
    if (hierarchy) {
      DS._topoTree = null;
      initTopoTree(hierarchy);
    }
  }
});

// Tooltip on hover (delegated)
document.addEventListener('mouseover', function(e) {
  const node = e.target.closest('.topo-node');
  let tip = document.getElementById('topo-tooltip');
  if (!node) {
    if (tip) tip.style.display = 'none';
    return;
  }
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'topo-tooltip';
    tip.style.cssText = 'display:none;position:fixed;z-index:1000;background:rgba(0,15,25,.95);border:1px solid rgba(0,187,255,.3);border-radius:6px;padding:8px 12px;font-size:11px;pointer-events:none;min-width:160px;box-shadow:0 4px 16px rgba(0,0,0,.5)';
    document.body.appendChild(tip);
  }
  const name = node.dataset.topoName || '';
  const ip = node.dataset.topoIp || '';
  const type = node.dataset.topoType || '';
  const status = node.dataset.topoStatus || 'secure';
  const sc = FSM_COLORS[status] || '#5a6e88';
  tip.innerHTML = `<div style="font-weight:600;color:#e0f5ec;margin-bottom:4px">${name}</div>
    <div style="color:#64748b;font-family:Share Tech Mono,monospace">${ip}</div>
    <div style="color:#94a3b8;margin-top:2px">${type}</div>
    <div style="color:${sc};font-weight:600;margin-top:4px;font-size:10px;text-transform:uppercase">${status}</div>`;
  const rect = node.getBoundingClientRect();
  tip.style.display = 'block';
  tip.style.left = Math.min(rect.right + 10, window.innerWidth - 200) + 'px';
  tip.style.top = rect.top + 'px';
});
document.addEventListener('mouseout', function(e) {
  if (e.target.closest('.topo-node')) {
    const tip = document.getElementById('topo-tooltip');
    if (tip) tip.style.display = 'none';
  }
});
