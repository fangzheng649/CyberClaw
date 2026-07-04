import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { ShaderPass } from 'three/addons/postprocessing/ShaderPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { GlitchPass } from 'three/addons/postprocessing/GlitchPass.js';
import { VignetteShader } from 'three/addons/shaders/VignetteShader.js';
import { CSS2DRenderer, CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import gsap from 'gsap';
import { saveState, loadState, onStateChange, KEYS } from '../shared/state-sync.js';

// ═══════════════════════════════════════════════════════════════════
// CyberClaw — "Digital Immune System" Security HUD
// ═══════════════════════════════════════════════════════════════════

// ── Security State Colors ────────────────────────────────────────
const STATUS_COLORS = {
  secure:     new THREE.Color(0x00ff88),
  scanning:   new THREE.Color(0x00bbff),
  vulnerable: new THREE.Color(0xffaa00),
  attacked:   new THREE.Color(0xff2244),
  isolated:   new THREE.Color(0x5a6e88),
  offline:    new THREE.Color(0x555555),
};

const STATUS_GLOW = {
  secure: 0.15, scanning: 0.35, vulnerable: 0.55, attacked: 0.9, isolated: 0.08, offline: 0.02,
};

// ── Quality Modes ────────────────────────────────────────────────
const QUALITY_MODES = ['focus', 'balanced', 'broadcast'];
const QUALITY_LABELS = { focus: 'FOCUS', balanced: 'BALANCED', broadcast: 'BROADCAST' };

// ── App State ────────────────────────────────────────────────────
const state = {
  scene: null, camera: null, renderer: null, labels: null,
  composer: null, controls: null,
  glitchPass: null, bloomPass: null, vignettePass: null,
  qualityMode: 'balanced',
  socket: null, clock: new THREE.Clock(),
  mouse: new THREE.Vector2(), raycaster: new THREE.Raycaster(),
  hovered: null, selected: null,
  devices: [],       // { id, mesh, halo, label, group, payload, beamLine }
  links: [],         // { line, fromId, toId }
  beams: [],         // attack beam pool
  shields: [],       // defense shield pool
  alerts: [],
  deviceEvents: {},   // { deviceId: [events] }
  eventCount: 0,
  fps: { frames: 0, lastTime: performance.now(), value: 0 },
  frameCount: 0,
  stats: { secure: 0, scanning: 0, vulnerable: 0, attacked: 0, isolated: 0 },
  scenarioRunning: false,
  scenarioStep: 0, totalSteps: 0,
  envUniforms: null,
  // MCP tool data
  toolRunning: null,       // { tool, task_id }
  deviceScanData: {},      // { deviceId: { ports, vulns, cves, fingerprint } }
  baselineData: {},        // { deviceId: { score, pass, fail, critical_failures } }
  baselineOverall: null,   // { profile, overall_score, summary }
};

// ── DOM References ───────────────────────────────────────────────
const dom = {
  loading: document.getElementById('loading'),
  loadingProgress: document.getElementById('loading-progress'),
  loadingText: document.getElementById('loading-text'),
  alertList: document.getElementById('alert-list'),
  detailPanel: document.getElementById('detail-panel'),
  tooltip: document.getElementById('tooltip'),
  footerSocket: document.getElementById('footer-socket'),
  footerFps: document.getElementById('footer-fps'),
  footerEvents: document.getElementById('footer-events'),
  sidebarLeft: document.getElementById('sidebar-left'),
  sidebarRight: document.getElementById('sidebar-right'),
  footerPanel: document.getElementById('footer-panel'),
  toggleLeft: document.getElementById('toggle-left'),
  toggleRight: document.getElementById('toggle-right'),
  toggleFooter: document.getElementById('toggle-footer'),
  reopenLeft: document.getElementById('reopen-left'),
  reopenRight: document.getElementById('reopen-right'),
  reopenFooter: document.getElementById('reopen-footer'),
  valThreat: document.getElementById('val-threat'),
  valInfected: document.getElementById('val-infected'),
  valAlerts: document.getElementById('val-alerts'),
  valIsolated: document.getElementById('val-isolated'),
  valScenario: document.getElementById('val-scenario'),
  btnStart: document.getElementById('btn-start-demo'),
  btnStop: document.getElementById('btn-stop-demo'),
  btnReset: document.getElementById('btn-reset'),
  progressBar: document.getElementById('demo-progress-bar'),
  progressText: document.getElementById('demo-progress-text'),
};

// ── Shared Geometries (optimized poly count) ────────────────────
const _geo = {
  router:   new THREE.OctahedronGeometry(1.4, 0),
  switch:   new THREE.BoxGeometry(2.2, 0.6, 1.4),
  camera:   new THREE.ConeGeometry(0.7, 1.2, 8),
  sensor:   new THREE.TetrahedronGeometry(0.8, 0),
  plug:     new THREE.CylinderGeometry(0.45, 0.45, 0.7, 8),
  pc:       new THREE.BoxGeometry(1.0, 0.8, 0.5),
  attacker: new THREE.OctahedronGeometry(1.2, 0),
  server:   new THREE.BoxGeometry(1.2, 1.8, 0.8),
  gateway:  new THREE.TorusGeometry(0.9, 0.3, 8, 16),
  access:   new THREE.BoxGeometry(1.0, 1.4, 0.6),
  halo:     new THREE.RingGeometry(1.6, 1.8, 24),
};

// ── Shared Materials ─────────────────────────────────────────────
function makeDeviceMaterial(status) {
  return new THREE.MeshStandardMaterial({
    color: 0x0d2218,
    emissive: STATUS_COLORS[status],
    emissiveIntensity: STATUS_GLOW[status],
    metalness: 0.7,
    roughness: 0.5,
    transparent: true,
    opacity: 0.72,
  });
}

// ── Loading Progress ─────────────────────────────────────────────
function setLoading(pct, text) {
  dom.loadingProgress.style.width = `${pct}%`;
  dom.loadingText.textContent = text;
}

// ═══════════════════════════════════════════════════════════════════
// SCENE INIT
// ═══════════════════════════════════════════════════════════════════

function initScene() {
  const root = document.getElementById('scene-root');

  state.scene = new THREE.Scene();
  state.scene.fog = new THREE.FogExp2(0x030508, 0.008);

  state.camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 300);
  state.camera.position.set(2, 24, 42);

  state.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  state.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  state.renderer.setSize(window.innerWidth, window.innerHeight);
  state.renderer.toneMapping = THREE.ACESFilmicToneMapping;
  state.renderer.toneMappingExposure = 1.1;
  root.appendChild(state.renderer.domElement);

  state.labels = new CSS2DRenderer();
  state.labels.setSize(window.innerWidth, window.innerHeight);
  state.labels.domElement.style.position = 'fixed';
  state.labels.domElement.style.inset = '0';
  state.labels.domElement.style.pointerEvents = 'none';
  root.appendChild(state.labels.domElement);

  // ── Post-processing (lightweight 5-pass pipeline) ────────────
  const sz = new THREE.Vector2(window.innerWidth, window.innerHeight);
  state.composer = new EffectComposer(state.renderer);
  state.composer.addPass(new RenderPass(state.scene, state.camera));
  state.bloomPass = new UnrealBloomPass(sz, 0.7, 0.4, 0.6);
  state.composer.addPass(state.bloomPass);
  state.vignettePass = new ShaderPass(VignetteShader);
  state.vignettePass.uniforms.offset.value = 0.92;
  state.vignettePass.uniforms.darkness.value = 1.4;
  state.composer.addPass(state.vignettePass);
  state.glitchPass = new GlitchPass();
  state.glitchPass.enabled = false;
  state.composer.addPass(state.glitchPass);
  state.composer.addPass(new OutputPass());

  // ── Controls ──────────────────────────────────────────────────
  state.controls = new OrbitControls(state.camera, state.renderer.domElement);
  state.controls.enableDamping = true;
  state.controls.dampingFactor = 0.06;
  state.controls.minDistance = 10;
  state.controls.maxDistance = 100;
  state.controls.maxPolarAngle = Math.PI * 0.48;
  state.controls.target.set(2, 0, 0);

  // ── Lighting ──────────────────────────────────────────────────
  state.scene.add(new THREE.AmbientLight(0x2a5a4a, 0.45));

  const keyLight = new THREE.SpotLight(0x00ff88, 3.0, 120, Math.PI * 0.4, 0.4, 1.2);
  keyLight.position.set(0, 28, 10);
  state.scene.add(keyLight);

  const warmLight = new THREE.SpotLight(0xff4444, 1.5, 80, Math.PI * 0.5, 0.5, 1.5);
  warmLight.position.set(-24, -4, -12);
  state.scene.add(warmLight);

  const rimLight = new THREE.SpotLight(0x00bbff, 1.2, 80, Math.PI * 0.4, 0.3, 1.4);
  rimLight.position.set(16, 8, -20);
  state.scene.add(rimLight);

  addEnvironment();
}

function addEnvironment() {
  // Ground grid
  const grid = new THREE.GridHelper(160, 40, 0x0a2a1a, 0x071a12);
  grid.position.y = -1.5;
  grid.material.transparent = true;
  grid.material.opacity = 0.25;
  grid.matrixAutoUpdate = false;
  grid.updateMatrix();
  state.scene.add(grid);

  // Pulsing ground rings (reduced count)
  const ringUniforms = { uTime: { value: 0 } };
  for (let i = 1; i <= 3; i++) {
    const ringMat = new THREE.ShaderMaterial({
      uniforms: { ...ringUniforms, uIndex: { value: i } },
      vertexShader: `varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }`,
      fragmentShader: `
        uniform float uTime, uIndex;
        varying vec2 vUv;
        void main() {
          float a = atan(vUv.y-0.5, vUv.x-0.5);
          float s = sin(a*2.0 + uTime*0.6 + uIndex*1.5)*0.5+0.5;
          float alpha = 0.06 + s*0.1;
          vec3 c = mod(uIndex,2.0)>0.5 ? vec3(0.0,0.5,0.25) : vec3(0.0,0.3,0.5);
          gl_FragColor = vec4(c, alpha);
        }`,
      transparent: true, side: THREE.DoubleSide, depthWrite: false,
    });
    const ring = new THREE.Mesh(new THREE.RingGeometry(7*i-0.05, 7*i+0.05, 48), ringMat);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = -5.98;
    ring.matrixAutoUpdate = false; ring.updateMatrix();
    ring.userData.ringUniforms = ringUniforms;
    state.scene.add(ring);
  }

  // Starfield
  const STAR_N = 600;
  const sPos = new Float32Array(STAR_N * 3);
  const sPh = new Float32Array(STAR_N);
  const sSz = new Float32Array(STAR_N);
  for (let i = 0; i < STAR_N; i++) {
    sPos[i*3]   = (Math.random()-0.5)*260;
    sPos[i*3+1] = (Math.random()-0.15)*160;
    sPos[i*3+2] = (Math.random()-0.5)*260;
    sPh[i] = Math.random()*6.28;
    sSz[i] = 0.6 + Math.random()*1.8;
  }
  const sGeo = new THREE.BufferGeometry();
  sGeo.setAttribute('position', new THREE.BufferAttribute(sPos, 3));
  sGeo.setAttribute('aPhase', new THREE.BufferAttribute(sPh, 1));
  sGeo.setAttribute('aSize', new THREE.BufferAttribute(sSz, 1));
  const sMat = new THREE.ShaderMaterial({
    uniforms: { uTime: { value: 0 } },
    vertexShader: `
      attribute float aPhase, aSize;
      uniform float uTime;
      varying float vAlpha;
      void main() {
        vAlpha = 0.3 + 0.4*sin(uTime*0.9 + aPhase);
        vec4 mv = modelViewMatrix * vec4(position,1.0);
        gl_PointSize = aSize * (60.0 / -mv.z);
        gl_Position = projectionMatrix * mv;
      }`,
    fragmentShader: `
      varying float vAlpha;
      void main() {
        float d = length(gl_PointCoord-0.5)*2.0;
        if(d>1.0) discard;
        gl_FragColor = vec4(0.4,0.9,0.7, vAlpha*smoothstep(1.0,0.3,d));
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
  });
  const stars = new THREE.Points(sGeo, sMat);
  stars.matrixAutoUpdate = false; stars.updateMatrix();
  state.scene.add(stars);
  state.envUniforms = { starTime: sMat.uniforms.uTime, ringTime: ringUniforms.uTime };
}

// ═══════════════════════════════════════════════════════════════════
// DEVICE & LINK BUILDERS
// ═══════════════════════════════════════════════════════════════════

function getGeometry(type) {
  return _geo[type] || _geo.camera;
}

function buildDevice(payload) {
  const group = new THREE.Group();
  const pos = payload.pos || [0, 0, 0];
  group.position.set(pos[0], pos[1], pos[2]);

  const status = payload.online === false ? 'offline' : (payload.status || 'secure');
  const statusColor = STATUS_COLORS[status];

  // Scale by device type for better visual distinction
  const typeScale = {
    router: 1.1, switch: 1.0, camera: 0.9, sensor: 0.8,
    plug: 0.7, pc: 0.85, attacker: 1.3, server: 1.0, gateway: 1.0,
    access: 0.85,
  };

  // Solid mesh — dark base
  const mat = makeDeviceMaterial(status);
  const geo = getGeometry(payload.type);
  const mesh = new THREE.Mesh(geo, mat);
  const s = typeScale[payload.type] || 1;
  mesh.scale.set(s, s, s);
  group.add(mesh);

  // Wireframe edges — primary visual identity
  const edges = new THREE.EdgesGeometry(geo);
  const edgeMat = new THREE.LineBasicMaterial({
    color: statusColor,
    transparent: true,
    opacity: 0.7,
    depthWrite: false,
  });
  const wireframe = new THREE.LineSegments(edges, edgeMat);
  wireframe.scale.set(s * 1.01, s * 1.01, s * 1.01);
  group.add(wireframe);

  // Halo ring
  const haloMat = new THREE.MeshBasicMaterial({
    color: statusColor,
    transparent: true, opacity: 0.12, side: THREE.DoubleSide, depthWrite: false,
  });
  const halo = new THREE.Mesh(_geo.halo, haloMat);
  halo.rotation.x = -Math.PI / 2;
  halo.position.y = -0.5;
  group.add(halo);

  // Label
  const labelEl = document.createElement('div');
  labelEl.className = 'device-label';
  const statusColorCSS = getStatusCSS(status);
  labelEl.innerHTML = `<span class="status-indicator" style="background:${statusColorCSS};box-shadow:0 0 6px ${statusColorCSS}"></span>${payload.name}<span class="ip-text">${payload.ip}</span>`;
  const label = new CSS2DObject(labelEl);
  label.position.set(0, 2.2, 0);
  group.add(label);

  state.scene.add(group);

  const entry = {
    id: payload.id, mesh, wireframe, halo, label, group, payload,
    mat, edgeMat, haloMat, labelEl, status, typeScale: s,
  };
  state.devices.push(entry);

  // ── Apply initial status visual effects (shrink + shield for isolated) ──
  if (status === 'isolated') {
    mesh.scale.set(s * 0.7, s * 0.7, s * 0.7);
    wireframe.scale.set(s * 0.71, s * 0.71, s * 0.71);
    spawnShield(entry);
  }

  return entry;
}

function buildLink(fromDev, toDev) {
  const from = fromDev.group.position;
  const to = toDev.group.position;

  const points = [from.clone(), to.clone()];
  const geo = new THREE.BufferGeometry().setFromPoints(points);
  const mat = new THREE.LineBasicMaterial({
    color: 0x00ff88, transparent: true, opacity: 0.15, depthWrite: false,
  });
  const line = new THREE.Line(geo, mat);
  state.scene.add(line);

  const entry = { line, fromId: fromDev.id, toId: toDev.id, mat, fromDev, toDev };
  state.links.push(entry);
  return entry;
}

function buildTopology(data) {
  // Clear existing — dispose everything properly
  state.devices.forEach(d => {
    // CSS2DObject 彻底清理：先断 element 引用 + 从 group 摘除，再移除 DOM 节点。
    // 否则 CSS2DRenderer 遍历窗口仍持有引用 → mock 设备 label DOM 残留（用户看到的"没清掉"）。
    if (d.label) { d.label.element = null; d.group.remove(d.label); }
    d.wireframe?.geometry?.dispose();   // EdgesGeometry（每设备独有，非共享 _geo）
    d.labelEl?.remove();
    d.mat?.dispose();
    d.edgeMat?.dispose();
    d.haloMat?.dispose();
    state.scene.remove(d.group);
    // 注意：不 dispose mesh.geometry / halo.geometry —— 它们是全局共享 _geo
  });
  state.links.forEach(l => {
    l.mat?.dispose();
    l.line.geometry?.dispose();
    state.scene.remove(l.line);
  });
  // Clean up beams and shields
  state.beams.forEach(b => { b.mat?.dispose(); b.line.geometry?.dispose(); state.scene.remove(b.line); });
  state.shields.forEach(s => { s.mat?.dispose(); s.mesh.geometry?.dispose(); state.scene.remove(s.mesh); });
  state.beams = [];
  state.shields = [];
  state.devices = [];
  state.links = [];

  // Build devices
  const deviceMap = {};
  (data.devices || []).forEach(d => {
    const entry = buildDevice(d);
    deviceMap[d.id] = entry;
  });

  // Build links
  (data.links || []).forEach(l => {
    const fromKey = l.from || l.from_;
    if (deviceMap[fromKey] && deviceMap[l.to]) {
      buildLink(deviceMap[fromKey], deviceMap[l.to]);
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// INCREMENTAL DEVICE ADD/REMOVE + MODE INDICATOR (GSAP)
// buildDevice() already scene.add + state.devices.push, so these are thin
// animation wrappers. All GSAP tweens use onComplete to guarantee correct
// final state + resource cleanup (prevents the opacity=0 / zombie-mesh
//残留 that crashed stage-10 reactive switching).
// ═══════════════════════════════════════════════════════════════════
function addDeviceToScene(dev) {
  if (!dev || !dev.id) return;
  if (state.devices.some(d => d.id === dev.id)) return;  // already present
  const entry = buildDevice(dev);
  entry.group.scale.set(0.01, 0.01, 0.01);
  gsap.to(entry.group.scale, { x: 1, y: 1, z: 1, duration: 0.8, ease: 'back.out(1.7)' });
}

function removeDeviceFromScene(deviceId) {
  const idx = state.devices.findIndex(d => d.id === deviceId);
  if (idx < 0) return;
  const entry = state.devices[idx];
  gsap.to(entry.group.scale, {
    x: 0.01, y: 0.01, z: 0.01, duration: 0.6, ease: 'power2.in',
    onComplete: () => {
      entry.labelEl?.remove();
      entry.mat?.dispose();
      entry.edgeMat?.dispose();
      entry.haloMat?.dispose();
      state.scene.remove(entry.group);
      const cur = state.devices.findIndex(d => d.id === deviceId);  // re-find (list may shift)
      if (cur >= 0) state.devices.splice(cur, 1);
    },
  });
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY STATE FSM
// ═══════════════════════════════════════════════════════════════════

function getStatusCSS(status) {
  const map = { secure: '#00ff88', scanning: '#00bbff', vulnerable: '#ffaa00', attacked: '#ff2244', isolated: '#5a6e88' };
  return map[status] || '#00ff88';
}

function updateDeviceStatus(deviceId, newStatus) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry || entry.status === newStatus) return;

  entry.status = newStatus;
  entry.payload.status = newStatus;

  const color = STATUS_COLORS[newStatus];
  const glow = STATUS_GLOW[newStatus];

  // Animate solid mesh emissive
  gsap.to(entry.mat.emissive, { r: color.r, g: color.g, b: color.b, duration: 0.8, ease: 'power2.inOut' });
  gsap.to(entry.mat, { emissiveIntensity: glow, duration: 0.8, ease: 'power2.inOut' });

  // Animate wireframe edge color
  gsap.to(entry.edgeMat.color, { r: color.r, g: color.g, b: color.b, duration: 0.8, ease: 'power2.inOut' });

  // Animate halo
  gsap.to(entry.haloMat.color, { r: color.r, g: color.g, b: color.b, duration: 0.8, ease: 'power2.inOut' });
  gsap.to(entry.haloMat, { opacity: newStatus === 'attacked' ? 0.4 : 0.15, duration: 0.5 });

  // Update label
  const cssColor = getStatusCSS(newStatus);
  const dot = entry.labelEl.querySelector('.status-indicator');
  if (dot) {
    dot.style.background = cssColor;
    dot.style.boxShadow = `0 0 6px ${cssColor}`;
  }

  // Attacked pulse effect — scale relative to type scale
  if (newStatus === 'attacked') {
    const ts = entry.typeScale || 1;
    gsap.to(entry.mesh.scale, { x: ts * 1.08, y: ts * 1.08, z: ts * 1.08, duration: 0.4, yoyo: true, repeat: 2, ease: 'sine.inOut' });
    gsap.to(entry.wireframe.scale, { x: ts * 1.1, y: ts * 1.1, z: ts * 1.1, duration: 0.4, yoyo: true, repeat: 2, ease: 'sine.inOut' });
    triggerGlitch();
  }

  // Scanning spin
  if (newStatus === 'scanning') {
    gsap.to(entry.group.rotation, { y: entry.group.rotation.y + Math.PI * 2, duration: 2, ease: 'power2.inOut' });
  }

  // Isolated shrink
  if (newStatus === 'isolated') {
    const ts = entry.typeScale || 1;
    gsap.to(entry.mesh.scale, { x: ts * 0.7, y: ts * 0.7, z: ts * 0.7, duration: 0.6, ease: 'power2.in' });
    gsap.to(entry.wireframe.scale, { x: ts * 0.7, y: ts * 0.7, z: ts * 0.7, duration: 0.6, ease: 'power2.in' });
    spawnShield(entry);
  }

  // ── Persist device statuses to localStorage ──
  const statuses = {};
  state.devices.forEach(d => { statuses[d.id] = d.status; });
  saveState(KEYS.hudDeviceStatuses, statuses);
}

// ═══════════════════════════════════════════════════════════════════
// ATTACK BEAM EFFECTS
// ═══════════════════════════════════════════════════════════════════

function fireAttackBeam(fromId, toId, color = 0xff2244) {
  const from = state.devices.find(d => d.id === fromId);
  const to = state.devices.find(d => d.id === toId);
  if (!from || !to) return;

  const fromPos = from.group.position;
  const toPos = to.group.position;

  // Build arc curve
  const points = [];
  for (let i = 0; i <= 30; i++) {
    const t = i / 30;
    const p = new THREE.Vector3().lerpVectors(fromPos, toPos, t);
    p.y += Math.sin(t * Math.PI) * 2.5;
    points.push(p);
  }
  const curve = new THREE.CatmullRomCurve3(points);

  // Glowing tube beam (bloom-friendly)
  const tubeGeo = new THREE.TubeGeometry(curve, 40, 0.12, 6, false);
  const tubeMat = new THREE.MeshBasicMaterial({
    color, transparent: true, opacity: 0,
  });
  const tube = new THREE.Mesh(tubeGeo, tubeMat);
  state.scene.add(tube);

  // Outer glow tube (wider, dimmer)
  const glowGeo = new THREE.TubeGeometry(curve, 40, 0.35, 6, false);
  const glowMat = new THREE.MeshBasicMaterial({
    color, transparent: true, opacity: 0,
  });
  const glowMesh = new THREE.Mesh(glowGeo, glowMat);
  state.scene.add(glowMesh);

  // Animate beam
  gsap.to(tubeMat, { opacity: 0.9, duration: 0.3, ease: 'power2.out' });
  gsap.to(glowMat, { opacity: 0.25, duration: 0.3, ease: 'power2.out' });
  gsap.to(tubeMat, { opacity: 0, duration: 0.8, delay: 1.5, ease: 'power2.in' });
  gsap.to(glowMat, { opacity: 0, duration: 0.8, delay: 1.5, ease: 'power2.in', onComplete: () => {
    state.scene.remove(tube);
    state.scene.remove(glowMesh);
    tubeGeo.dispose(); tubeMat.dispose();
    glowGeo.dispose(); glowMat.dispose();
  }});

  // Animate the link line
  const link = state.links.find(l =>
    (l.fromId === fromId && l.toId === toId) || (l.fromId === toId && l.toId === fromId)
  );
  if (link) {
    const origOpacity = link.mat.opacity;
    gsap.to(link.mat, { opacity: 0.6, duration: 0.3 });
    gsap.to(link.mat.color, { r: new THREE.Color(color).r, g: new THREE.Color(color).g, b: new THREE.Color(color).b, duration: 0.3 });
    gsap.to(link.mat, { opacity: origOpacity, delay: 2, duration: 0.5 });
    gsap.to(link.mat.color, { r: 0, g: 1, b: 0.53, delay: 2, duration: 0.5 });
  }

  state.beams.push({ line: tube, mat: tubeMat });
}

// ── Defense Shield ───────────────────────────────────────────────

function spawnShield(deviceEntry) {
  const shieldGeo = new THREE.IcosahedronGeometry(2.5, 1);
  const shieldMat = new THREE.MeshBasicMaterial({
    color: 0x00bbff,
    wireframe: true,
    transparent: true,
    opacity: 0,
    depthWrite: false,
  });
  const shield = new THREE.Mesh(shieldGeo, shieldMat);
  shield.position.copy(deviceEntry.group.position);
  state.scene.add(shield);

  shield.scale.set(0.01, 0.01, 0.01);
  gsap.to(shield.scale, { x: 1, y: 1, z: 1, duration: 0.8, ease: 'back.out(1.5)' });
  gsap.to(shieldMat, { opacity: 0.25, duration: 0.5 });
  gsap.to(shieldMat, { opacity: 0.08, delay: 2, duration: 1 });

  state.shields.push({ mesh: shield, mat: shieldMat });
}

// ── Glitch Burst ─────────────────────────────────────────────────

function triggerGlitch() {
  if (state.glitchPass) {
    state.glitchPass.enabled = true;
    setTimeout(() => { state.glitchPass.enabled = false; }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════════
// SCAN WAVE EFFECT
// ═══════════════════════════════════════════════════════════════════

function triggerScanWave(sourceId, targetIds) {
  const source = state.devices.find(d => d.id === sourceId);
  if (!source) return;

  const srcPos = source.group.position;
  const waveGeo = new THREE.RingGeometry(0.5, 1, 32);
  const waveMat = new THREE.MeshBasicMaterial({
    color: 0x00bbff, transparent: true, opacity: 0.4, side: THREE.DoubleSide, depthWrite: false,
  });
  const wave = new THREE.Mesh(waveGeo, waveMat);
  wave.rotation.x = -Math.PI / 2;
  wave.position.copy(srcPos);
  state.scene.add(wave);

  gsap.to(wave.scale, { x: 30, y: 30, z: 30, duration: 2, ease: 'power2.out' });
  gsap.to(waveMat, { opacity: 0, duration: 2, ease: 'power2.in', onComplete: () => {
    state.scene.remove(wave);
    waveGeo.dispose();
    waveMat.dispose();
  }});
}

function triggerDiscoveryWave(deviceId) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry) return;
  const pos = entry.group.position;
  // 单环收敛波纹：聚焦"这台设备被发现"，让位设备自身的 back.out 入场动画。
  // 区别于扫描波纹(大范围 scale 30)：起点小、scale 7、opacity 0.45、1.2s。
  const geo = new THREE.RingGeometry(0.15, 0.35, 32);
  const mat = new THREE.MeshBasicMaterial({
    color: 0x00ffaa, transparent: true, opacity: 0.45,
    side: THREE.DoubleSide, depthWrite: false,
  });
  const wave = new THREE.Mesh(geo, mat);
  wave.rotation.x = -Math.PI / 2;
  wave.position.copy(pos);
  wave.position.y += 0.1;            // 略离地，避免 z-fight
  state.scene.add(wave);
  gsap.to(wave.scale, { x: 7, y: 7, z: 7, duration: 1.2, ease: 'power2.out' });
  gsap.to(mat, { opacity: 0, duration: 1.2, ease: 'power2.in', onComplete: () => {
    state.scene.remove(wave); geo.dispose(); mat.dispose();
  }});
}

// ═══════════════════════════════════════════════════════════════════
// UI UPDATES
// ═══════════════════════════════════════════════════════════════════

function updateMetrics(stats) {
  state.stats = { ...state.stats, ...stats };

  const total = Object.values(state.stats).reduce((a, b) => a + b, 0);
  const infected = state.stats.attacked;
  const isolated = state.stats.isolated;

  // Threat level
  const threatEl = dom.valThreat;
  if (infected > 2) { threatEl.textContent = 'CRITICAL'; threatEl.className = 'metric-value critical'; }
  else if (infected > 0) { threatEl.textContent = 'HIGH'; threatEl.className = 'metric-value critical'; }
  else if (state.stats.vulnerable > 0) { threatEl.textContent = 'MEDIUM'; threatEl.className = 'metric-value warning'; }
  else if (state.stats.scanning > 0) { threatEl.textContent = 'LOW'; threatEl.className = 'metric-value info'; }
  else { threatEl.textContent = 'LOW'; threatEl.className = 'metric-value secure'; }

  dom.valInfected.textContent = `${infected} / ${total}`;
  dom.valAlerts.textContent = state.alerts.filter(a => a.severity === 'critical').length;
  dom.valIsolated.textContent = isolated;
}

function updateScenarioProgress(step, total) {
  const pct = total > 0 ? (step / total) * 100 : 0;
  dom.progressBar.style.width = `${pct}%`;
  dom.progressText.textContent = state.scenarioRunning ? `Step ${step}/${total}` : 'Ready';
  dom.valScenario.textContent = state.scenarioRunning ? `${pct.toFixed(0)}%` : 'READY';
}

function showNotificationToast(data) {
  // Accept either a full data object or individual args for backward compat
  let title, message, severity, hasDetail, guid;
  if (typeof data === 'object' && data !== null) {
    title = data.title || '';
    message = data.message || '';
    severity = data.severity || 'info';
    hasDetail = data.has_detail;
    guid = data.guid;
  } else {
    title = arguments[0] || '';
    message = arguments[1] || '';
    severity = arguments[2] || 'info';
    hasDetail = false;
  }

  const container = document.getElementById('notification-toast-container') || (() => {
    const c = document.createElement('div');
    c.id = 'notification-toast-container';
    c.style.cssText = 'position:fixed;top:20px;right:20px;z-index:10000;display:flex;flex-direction:column;gap:8px;max-width:400px;';
    document.body.appendChild(c);
    return c;
  })();

  const colors = { critical: '#ff4444', warning: '#ff9800', info: '#2196f3', discovery: '#00ffaa' };
  const bg = colors[severity] || colors.info;

  // "查看详情" button — opens Chat page where detail modal is available
  const detailBtn = hasDetail
    ? `<button onclick="window.open('/chat/', 'cyberclaw-chat')" style="margin-top:6px;padding:3px 10px;background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.2);border-radius:4px;color:#00ff88;font-size:10px;cursor:pointer;font-family:monospace;">查看详情</button>`
    : '';

  const toast = document.createElement('div');
  toast.style.cssText = `background:${bg}22;border:1px solid ${bg};border-radius:8px;padding:12px 16px;color:#fff;font-size:13px;animation:toast-in 0.3s ease;backdrop-filter:blur(8px);`;
  toast.innerHTML = `<div style="font-weight:600;margin-bottom:4px;">${title}</div><div style="opacity:0.85;line-height:1.4;">${message}</div>${detailBtn}`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.5s';
    setTimeout(() => toast.remove(), 500);
  }, 5000);
}

function addAlert(event) {
  state.alerts.unshift(event);
  if (state.alerts.length > 50) state.alerts.pop();

  // Track per-device events
  const devIds = [event.target, event.source].filter(Boolean);
  devIds.forEach(id => {
    if (!state.deviceEvents[id]) state.deviceEvents[id] = [];
    state.deviceEvents[id].unshift({ ...event, time: new Date().toLocaleTimeString('zh-CN', { hour12: false }) });
    if (state.deviceEvents[id].length > 20) state.deviceEvents[id].pop();
  });

  // Refresh detail panel if selected device is involved
  if (state.selected && devIds.includes(state.selected.id)) {
    updateDetailPanel(state.selected);
  }

  const card = document.createElement('div');
  card.className = 'alert-card';
  card.dataset.severity = event.severity || 'info';

  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  card.innerHTML = `
    <span class="alert-time">${time}</span>
    <span class="alert-severity ${event.severity || 'info'}">${event.severity || 'info'}</span>
    <div class="alert-msg">${event.message || event.type}</div>
  `;

  // Click to focus on device
  if (event.target || event.source) {
    card.addEventListener('click', () => {
      const devId = event.target || event.source;
      focusDevice(devId);
    });
  }

  dom.alertList.insertBefore(card, dom.alertList.firstChild);

  // Limit visible alerts
  while (dom.alertList.children.length > 40) {
    dom.alertList.removeChild(dom.alertList.lastChild);
  }

  state.eventCount++;
  dom.footerEvents.textContent = state.eventCount;

  // ── Persist alerts & device events to localStorage ──
  saveState(KEYS.hudAlerts, state.alerts);
  saveState(KEYS.hudDeviceEvents, state.deviceEvents);
}

function focusDevice(deviceId) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry) return;

  // Update detail panel
  updateDetailPanel(entry);

  // Animate camera to device
  const target = entry.group.position.clone();
  gsap.to(state.controls.target, { x: target.x, y: target.y, z: target.z, duration: 1, ease: 'power2.inOut' });
  gsap.to(state.camera.position, {
    x: target.x + 8, y: target.y + 12, z: target.z + 12,
    duration: 1, ease: 'power2.inOut',
  });

  state.selected = entry;
}

function updateDetailPanel(entry) {
  const p = entry.payload;
  const cssColor = getStatusCSS(entry.status);
  const statusLabel = { secure: 'SECURE', scanning: 'SCANNING', vulnerable: 'VULNERABLE', attacked: 'ATTACKED', isolated: 'ISOLATED', offline: 'OFFLINE' };
  const onlineStatus = p.online === false ? '<span style="color:#888;font-size:11px"> ● OFFLINE</span>' : '';

  // Connected neighbors
  const neighbors = state.links
    .filter(l => l.fromId === entry.id || l.toId === entry.id)
    .map(l => l.fromId === entry.id ? l.toId : l.fromId);

  // Device events
  const events = state.deviceEvents[entry.id] || [];
  const eventHtml = events.slice(0, 8).map(e => `
    <div class="detail-event">
      <span class="detail-event-time">${e.time}</span>
      <span class="detail-event-severity ${e.severity || 'info'}">${e.severity || 'info'}</span>
      <span class="detail-event-msg">${e.message || e.type}</span>
    </div>
  `).join('');

  // MCP tool data
  const scanData = state.deviceScanData[entry.id] || {};
  const baselineData = state.baselineData[entry.id] || null;

  // Open ports section
  const ports = scanData.ports || [];
  const portsHtml = ports.length ? `
    <div class="detail-section">
      <p class="detail-section-title">Open Ports (${ports.length})</p>
      <div class="detail-ports">${ports.map(p => {
        const danger = [23, 445, 3389, 21].includes(p.port);
        const warn = [80, 8080, 554].includes(p.port);
        const cls = danger ? 'danger' : warn ? 'warning' : 'safe';
        return `<span class="port-chip ${cls}">${p.port}/${p.protocol || 'tcp'} ${p.service || ''}</span>`;
      }).join('')}</div>
    </div>
  ` : '';

  // CVE section
  const cves = scanData.cves || [];
  const cvesHtml = cves.length ? `
    <div class="detail-section">
      <p class="detail-section-title">Vulnerabilities (${cves.length})</p>
      <div class="detail-vulns">${cves.map(c => {
        const sev = (c.severity || '').toLowerCase();
        const cls = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
        return `<div class="vuln-card ${cls}">
          <span class="vuln-id">${c.cve_id}</span>
          <span class="vuln-cvss">CVSS ${c.cvss || '?'}</span>
          <span class="vuln-desc">${(c.description || '').substring(0, 60)}…</span>
        </div>`;
      }).join('')}</div>
    </div>
  ` : '';

  // Compliance score section
  const baselineHtml = baselineData ? `
    <div class="detail-section">
      <p class="detail-section-title">Compliance Score</p>
      <div class="compliance-bar">
        <div class="compliance-fill ${baselineData.score < 60 ? 'low' : baselineData.score < 80 ? 'mid' : 'high'}" style="width:${baselineData.score}%"></div>
        <span class="compliance-value">${baselineData.score}/100</span>
      </div>
      <div class="compliance-detail">${baselineData.pass} pass / ${baselineData.fail} fail${baselineData.critical_failures > 0 ? ` / ${baselineData.critical_failures} critical` : ''}</div>
    </div>
  ` : (state.baselineOverall ? `
    <div class="detail-section">
      <p class="detail-section-title">Overall Compliance</p>
      <div class="compliance-bar">
        <div class="compliance-fill ${state.baselineOverall.overall_score < 60 ? 'low' : state.baselineOverall.overall_score < 80 ? 'mid' : 'high'}" style="width:${state.baselineOverall.overall_score}%"></div>
        <span class="compliance-value">${state.baselineOverall.overall_score}/100</span>
      </div>
    </div>
  ` : '');

  dom.detailPanel.innerHTML = `
    <h2 style="margin:0 0 8px;font-size:16px;">${p.name}</h2>
    <div class="detail-status-badge ${p.online === false ? 'offline' : entry.status}">
      <span class="status-dot"></span>
      ${statusLabel[p.online === false ? 'offline' : entry.status] || entry.status.toUpperCase()}${onlineStatus}
    </div>
    <div class="detail-grid">
      <div class="detail-row"><span class="label">IP</span><span class="value">${p.ip}</span></div>
      <div class="detail-row"><span class="label">MAC</span><span class="value">${p.mac}</span></div>
      <div class="detail-row"><span class="label">Type</span><span class="value">${p.type}</span></div>
      ${p.vendor ? `<div class="detail-row"><span class="label">Vendor</span><span class="value">${p.vendor}</span></div>` : ''}
      ${p.model ? `<div class="detail-row"><span class="label">Model</span><span class="value">${p.model}</span></div>` : ''}
      ${p.firmware_version ? `<div class="detail-row"><span class="label">Firmware</span><span class="value">${p.firmware_version}</span></div>` : ''}
      ${p.last_seen ? `<div class="detail-row"><span class="label">Last Seen</span><span class="value">${p.last_seen}</span></div>` : ''}
      ${p.protocols && p.protocols.length ? `<div class="detail-row"><span class="label">Protocols</span><span class="value">${p.protocols.map(pr => `<span class="proto-tag">${pr}</span>`).join(' ')}</span></div>` : ''}
      <div class="detail-row"><span class="label">Links</span><span class="value">${neighbors.length} connections</span></div>
    </div>
    ${portsHtml}
    ${cvesHtml}
    ${baselineHtml}
    <div class="detail-actions">
      <button class="action-btn scan" data-device="${entry.id}">SCAN</button>
      <button class="action-btn cve" data-device="${entry.id}" data-vendor="${p.vendor || ''}" data-model="${p.model || ''}">CVE CHECK</button>
      ${entry.status !== 'isolated' ? `<button class="action-btn isolate" data-device="${entry.id}" data-ip="${p.ip}">ISOLATE</button>` : `<button class="action-btn restore" data-device="${entry.id}" data-ip="${p.ip}">RESTORE</button>`}
      <button class="action-btn baseline" data-device="${entry.id}">BASELINE</button>
    </div>
    ${neighbors.length ? `
      <div class="detail-section">
        <p class="detail-section-title">Connected Devices</p>
        <div class="detail-neighbors">${neighbors.map(nId => {
          const dev = state.devices.find(d => d.id === nId);
          const nCss = dev ? getStatusCSS(dev.status) : '#888';
          return `<span class="neighbor-chip" data-device="${nId}" style="border-color:${nCss};color:${nCss}">${dev ? dev.payload.name : nId}</span>`;
        }).join('')}</div>
      </div>
    ` : ''}
    ${events.length ? `
      <div class="detail-section">
        <p class="detail-section-title">Security Events (${events.length})</p>
        <div class="detail-events">${eventHtml}</div>
      </div>
    ` : ''}
  `;

  // Click neighbor chips to focus
  dom.detailPanel.querySelectorAll('.neighbor-chip').forEach(chip => {
    chip.addEventListener('click', () => focusDevice(chip.dataset.device));
  });

  // Action button handlers
  dom.detailPanel.querySelector('.action-btn.scan')?.addEventListener('click', () => triggerDeviceScan(entry.id));
  dom.detailPanel.querySelector('.action-btn.cve')?.addEventListener('click', (e) => triggerCveCheck(entry.id, e.currentTarget.dataset.vendor, e.currentTarget.dataset.model));
  dom.detailPanel.querySelector('.action-btn.isolate')?.addEventListener('click', () => triggerDeviceIsolation(entry.id));
  dom.detailPanel.querySelector('.action-btn.restore')?.addEventListener('click', () => triggerDeviceRestore(entry.id));
  dom.detailPanel.querySelector('.action-btn.baseline')?.addEventListener('click', () => triggerBaseline(entry.id));
}

// ═══════════════════════════════════════════════════════════════════
// QUALITY MODE
// ═══════════════════════════════════════════════════════════════════

function setQualityMode(mode) {
  state.qualityMode = mode;
  const isFocus = mode === 'focus';
  const isBroadcast = mode === 'broadcast';
  if (state.bloomPass) state.bloomPass.strength = isFocus ? 0.4 : isBroadcast ? 1.0 : 0.7;
  document.getElementById('quality-toggle').textContent = QUALITY_LABELS[mode];
}

// ═══════════════════════════════════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════════════════════════════════

let wsReconnectDelay = 1000;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    wsReconnectDelay = 1000;
    dom.footerSocket.textContent = 'CONNECTED';
    dom.footerSocket.style.color = '#00ff88';
  };

  ws.onclose = () => {
    dom.footerSocket.textContent = 'RECONNECTING';
    dom.footerSocket.style.color = '#ffaa00';
    setTimeout(connectWS, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, 30000);
  };

  ws.onerror = () => {
    ws.close();
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      handleWSMessage(msg);
    } catch (err) { /* ignore */ }
  };

  state.socket = ws;
}

function _countDeviceStatuses(devices) {
  const counts = { secure: 0, scanning: 0, vulnerable: 0, attacked: 0, isolated: 0, offline: 0 };
  (devices || []).forEach(d => {
    const s = (d.online === false) ? 'offline' : (d.status || 'secure');
    if (counts[s] !== undefined) counts[s]++;
  });
  return counts;
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'init':
      buildTopology(msg);
      if (msg.devices) {
        updateMetrics(_countDeviceStatuses(msg.devices));
      }
      break;

    case 'scenario_start':
      state.scenarioRunning = true;
      state.scenarioStep = 0;
      state.alerts = [];
      state.deviceEvents = {};
      dom.alertList.innerHTML = '';
      dom.btnStart.disabled = true;
      dom.btnStop.disabled = false;
      buildTopology(msg);
      if (msg.devices) {
        updateMetrics(_countDeviceStatuses(msg.devices));
      }
      break;

    case 'scenario_complete':
      state.scenarioRunning = false;
      dom.btnStart.disabled = false;
      dom.btnStop.disabled = true;
      updateScenarioProgress(state.totalSteps, state.totalSteps);
      break;

    case 'scenario_stop':
      state.scenarioRunning = false;
      state.alerts = [];
      state.deviceEvents = {};
      dom.alertList.innerHTML = '';
      dom.btnStart.disabled = false;
      dom.btnStop.disabled = true;
      buildTopology(msg);
      if (msg.devices) {
        updateMetrics(_countDeviceStatuses(msg.devices));
      }
      updateScenarioProgress(0, state.totalSteps);
      break;

    case 'scenario_reset':
      state.scenarioRunning = false;
      state.scenarioStep = 0;
      state.alerts = [];
      state.deviceEvents = {};
      dom.alertList.innerHTML = '';
      dom.btnStart.disabled = false;
      dom.btnStop.disabled = true;
      buildTopology(msg);
      if (msg.devices) {
        updateMetrics(_countDeviceStatuses(msg.devices));
      }
      updateScenarioProgress(0, state.totalSteps);
      break;

    case 'system_ready':
      addAlert(msg);
      break;

    case 'scan_started':
      msg.targets?.forEach(t => updateDeviceStatus(t, 'scanning'));
      triggerScanWave(msg.source, msg.targets);
      addAlert(msg);
      break;

    case 'port_scan':
      updateDeviceStatus(msg.target, 'vulnerable');
      addAlert(msg);
      break;

    case 'vuln_found':
      updateDeviceStatus(msg.target, 'vulnerable');
      fireAttackBeam(msg.source || 'firewall', msg.target, 0xffaa00);
      addAlert(msg);
      break;

    case 'brute_force':
      updateDeviceStatus(msg.target, 'attacked');
      fireAttackBeam(msg.source, msg.target, 0xff6600);
      addAlert(msg);
      break;

    case 'attack_detected':
      updateDeviceStatus(msg.target, 'attacked');
      fireAttackBeam(msg.source, msg.target, 0xff2244);
      addAlert(msg);
      break;

    case 'lateral_movement':
      updateDeviceStatus(msg.target, 'attacked');
      fireAttackBeam(msg.source, msg.target, 0xff2244);
      addAlert(msg);
      break;

    case 'c2_detected':
      triggerGlitch();
      addAlert(msg);
      break;

    case 'analysis_complete':
      addAlert(msg);
      break;

    case 'isolation_request':
      addAlert(msg);
      break;

    case 'device_isolated':
      updateDeviceStatus(msg.target, 'isolated');
      addAlert(msg);
      showNotificationToast({
        title: '设备已隔离',
        message: msg.message || `设备 ${msg.target} 已隔离，防护盾已激活`,
        severity: 'warning',
      });
      break;

    case 'threat_resolved':
      if (msg.target) updateDeviceStatus(msg.target, 'secure');
      addAlert(msg);
      break;

    case 'heartbeat':
      if (msg.stats) {
        updateMetrics(msg.stats);
      }
      if (msg.scenarioRunning !== undefined) {
        state.scenarioRunning = msg.scenarioRunning;
        state.scenarioStep = msg.step || 0;
        state.totalSteps = msg.totalSteps || state.totalSteps;
        updateScenarioProgress(state.scenarioStep, state.totalSteps);
      }
      break;

    // ── Mode switch (mock↔real) → 主动重建场景，无需刷新页面 ──────
    case 'mode_changed': {
      buildTopology({ devices: msg.devices || [], links: msg.links || [] });
      if (msg.devices) updateMetrics(_countDeviceStatuses(msg.devices));
      showNotificationToast({
        title: msg.mode === 'real' ? '切换到真实模式' : '切换到演示模式',
        message: msg.reason === 'esp32_arrival' ? '检测到 ESP32 接入'
          : msg.reason === 'no_real_devices' ? '无真实设备在线'
          : '拓扑已刷新',
        severity: msg.mode === 'real' ? 'discovery' : 'info',
      });
      break;
    }

    // ── MCP Tool Events ─────────────────────────────────────────
    case 'tool_started':
      state.toolRunning = { tool: msg.tool, task_id: msg.task_id };
      addAlert({ severity: 'info', message: msg.message || `Tool ${msg.tool} started`, type: msg.type });
      if (msg.target_device) updateDeviceStatus(msg.target_device, 'scanning');
      break;

    case 'scan_result': {
      const scanDevices = msg.devices || [];
      scanDevices.forEach(d => {
        if (!state.deviceScanData[d.device_id]) state.deviceScanData[d.device_id] = {};
        state.deviceScanData[d.device_id].ports = d.ports || [];
        state.deviceScanData[d.device_id].vendor = d.vendor || '';
        if (d.fingerprint) state.deviceScanData[d.device_id].fingerprint = d.fingerprint;
      });
      // Update device status based on scan type
      scanDevices.forEach(d => {
        const hasVulnPorts = (d.ports || []).some(p => [23, 445, 3389].includes(p.port));
        updateDeviceStatus(d.device_id, hasVulnPorts ? 'vulnerable' : 'secure');
      });
      if (state.selected && scanDevices.find(d => d.device_id === state.selected.id)) {
        updateDetailPanel(state.selected);
      }
      addAlert({
        severity: 'info',
        message: `Scan complete: ${scanDevices.length} devices, ${msg.total_hosts || 0} hosts found`,
        type: msg.scan_type,
      });
      saveState(KEYS.hudScanData, state.deviceScanData);
      break;
    }

    case 'vuln_result': {
      const vDevs = msg.vulnerabilities || [];
      const devId = msg.device_id;
      if (devId) {
        if (!state.deviceScanData[devId]) state.deviceScanData[devId] = {};
        state.deviceScanData[devId].vulns = vDevs;
        if (vDevs.length > 0) updateDeviceStatus(devId, 'vulnerable');
      }
      if (state.selected && state.selected.id === devId) updateDetailPanel(state.selected);
      if (vDevs.length > 0) {
        addAlert({ severity: 'critical', target: devId, message: `${vDevs.length} vulnerabilities found`, type: 'vuln_result' });
      }
      saveState(KEYS.hudScanData, state.deviceScanData);
      break;
    }

    case 'cve_result': {
      const cves = msg.cves || [];
      const cveDevId = msg.device_id;
      if (cveDevId) {
        if (!state.deviceScanData[cveDevId]) state.deviceScanData[cveDevId] = {};
        state.deviceScanData[cveDevId].cves = cves;
      }
      if (state.selected && state.selected.id === cveDevId) updateDetailPanel(state.selected);
      addAlert({
        severity: (msg.critical || 0) > 0 ? 'critical' : 'warning',
        target: cveDevId,
        message: `CVE check: ${msg.total_cves || 0} CVEs (${msg.critical || 0} critical, ${msg.high || 0} high)`,
        type: 'cve_result',
      });
      saveState(KEYS.hudScanData, state.deviceScanData);
      break;
    }

    case 'baseline_result': {
      const bDevs = msg.devices || [];
      bDevs.forEach(d => {
        state.baselineData[d.device_id] = { score: d.score, pass: d.pass, fail: d.fail, critical_failures: d.critical_failures, failed_rules: d.failed_rules || [] };
      });
      state.baselineOverall = { profile: msg.profile, overall_score: msg.overall_score, summary: msg.summary };
      if (state.selected) updateDetailPanel(state.selected);
      addAlert({
        severity: msg.overall_score < 60 ? 'critical' : msg.overall_score < 80 ? 'warning' : 'info',
        message: `Baseline audit: score ${msg.overall_score}/100`,
        type: 'baseline_result',
      });
      saveState(KEYS.hudBaselineData, state.baselineData);
      saveState(KEYS.hudBaselineOverall, state.baselineOverall);
      break;
    }

    case 'device_restored': {
      const rDevId = msg.target;
      if (rDevId) updateDeviceStatus(rDevId, 'secure');
      addAlert({ severity: 'info', target: rDevId, message: msg.message || `Device restored`, type: 'device_restored' });
      break;
    }

    case 'tool_complete':
      state.toolRunning = null;
      break;

    case 'tool_error':
      state.toolRunning = null;
      addAlert({ severity: 'critical', message: msg.message || 'Tool error', type: 'tool_error' });
      break;

    case 'tool_result':
      addAlert({ severity: 'info', message: `Tool result: ${msg.tool}`, type: 'tool_result' });
      break;

    // ── Real-time syslog events from collector ───────────────────
    case 'syslog_event': {
      const evt = msg.event || {};
      const sevMap = { emergency: 'critical', alert: 'critical', critical: 'critical',
                       error: 'warning', warning: 'warning', notice: 'info', info: 'info', debug: 'info' };
      const alertSev = sevMap[evt.severity] || 'info';

      // Find device by hostname (IP)
      const hostDev = state.devices.find(d => (d.ip || d.payload?.ip) === evt.hostname);
      if (hostDev && ['critical', 'alert', 'emergency'].includes(evt.severity)) {
        updateDeviceStatus(hostDev.id, 'attacked');
      }

      addAlert({
        severity: alertSev,
        source: evt.hostname,
        message: evt.message || 'Syslog event',
        type: 'syslog_event',
      });
      break;
    }

    // ── SNMP trap events ─────────────────────────────────────────
    case 'snmp_trap': {
      const trap = msg.trap || {};
      addAlert({
        severity: 'warning',
        source: trap.source,
        message: `SNMP Trap from ${trap.source} (${trap.raw_length || 0} bytes)`,
        type: 'snmp_trap',
      });
      break;
    }

    // ── MQTT message events ──────────────────────────────────────
    case 'mqtt_message': {
      const mqttMsg = msg.message || {};
      // Only alert on potentially anomalous messages
      if (mqttMsg.payload && mqttMsg.payload.length > 200) {
        addAlert({
          severity: 'info',
          message: `MQTT ${mqttMsg.topic}: ${mqttMsg.payload.substring(0, 60)}...`,
          type: 'mqtt_message',
        });
      }
      break;
    }

    // ── Device discovered / reconnected / offline (scan or MQTT) ──
    case 'device_discovered':
    case 'device_back_online': {
      const dev = msg.device || {};
      const verb = msg.type === 'device_back_online' ? 'reconnected' : 'discovered';
      addAlert({
        severity: 'info',
        message: `Device ${verb}: ${dev.name || dev.ip || dev.mac} (${dev.device_type || dev.type || 'unknown'})`,
        type: msg.type,
      });
      addDeviceToScene(dev);
      // 设备发现波纹（设备位置双环扩散）+ 右上角 toast 通知
      requestAnimationFrame(() => triggerDiscoveryWave(dev.id));
      showNotificationToast({
        title: `${dev.name || dev.ip || dev.mac} 已发现`,
        message: `${dev.device_type || dev.type || 'device'} · ${dev.vendor || ''} ${dev.model || ''}`.trim(),
        severity: 'discovery',
      });
      break;
    }
    case 'device_offline': {
      const dev = msg.device || {};
      addAlert({
        severity: 'warning',
        message: `Device offline: ${dev.name || dev.ip || dev.mac}`,
        type: 'device_offline',
      });
      if (dev.id) removeDeviceFromScene(dev.id);
      break;
    }
    case 'suricata_alert': {
      const evt = msg.event || {};
      addAlert({
        severity: evt.severity || 'high',
        message: evt.message || 'Suricata alert',
        type: 'suricata_alert',
      });
      if (evt.fsm_state && evt.target) {
        const entry = state.devices.find(d => d.payload?.ip === evt.target);
        if (entry) updateDeviceStatus(entry.id, evt.fsm_state);
      }
      break;
    }
    case 'traffic_stats': {
      break;
    }

    // ── Notification from scheduler/security events ────────────────
    case 'notification': {
      showNotificationToast(msg);
      addAlert({
        severity: msg.severity === 'critical' ? 'critical' : msg.severity === 'warning' ? 'warning' : 'info',
        message: `${msg.title}: ${msg.message}`,
        type: 'notification',
      });
      break;
    }

    // ── CyberSense: 多源关联判定(syslog+snmp+ids 三源命中同一设备) ──
    case 'cybersense_verdict': {
      const v = msg;
      // 设备变色(幂等: 与 suricata 单源同状态不冲突)
      if (v.device_id || v.device_ip) {
        const entry = state.devices.find(d => d.id === v.device_id)
          || state.devices.find(d => d.payload?.ip === v.device_ip);
        if (entry) updateDeviceStatus(entry.id, v.fsm_state || 'attacked');
      }
      const srcLabel = (v.sources_hit || []).join(' + ');
      const conf = Math.round((v.confidence || 0) * 100);
      showNotificationToast({
        title: `🛡 CyberSense 多源关联: ${v.device_name || v.device_ip}`,
        message: `判定 ${v.verdict || 'compromised'} · 置信度 ${conf}% · ${v.sources_count} 源: ${srcLabel}`,
        severity: v.verdict === 'compromised' ? 'critical' : 'warning',
      });
      addAlert({
        severity: v.verdict === 'compromised' ? 'critical' : 'warning',
        message: `[CyberSense] ${v.device_name || v.device_ip} ${v.verdict || ''} (${conf}%, ${srcLabel})`,
        type: 'cybersense_verdict',
      });
      break;
    }
  }

  // Update step counter
  if (msg.step !== undefined) {
    state.scenarioStep = msg.step;
    updateScenarioProgress(msg.step, state.totalSteps);
  }

  // Sync all device statuses from server
  if (msg.devices) {
    msg.devices.forEach(d => {
      const entry = state.devices.find(e => e.id === d.id);
      if (entry && entry.status !== d.status) {
        updateDeviceStatus(d.id, d.status);
      }
    });
  }

}

// ═══════════════════════════════════════════════════════════════════
// INTERACTION
// ═══════════════════════════════════════════════════════════════════

function setupInteraction() {
  const canvas = state.renderer.domElement;

  canvas.addEventListener('mousemove', (e) => {
    state.mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
    state.mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
  });

  canvas.addEventListener('click', () => {
    if (state.hovered) {
      focusDevice(state.hovered.id);
    }
  });

  // Panel toggles
  dom.toggleLeft.addEventListener('click', () => togglePanel('left'));
  dom.toggleRight.addEventListener('click', () => togglePanel('right'));
  dom.toggleFooter.addEventListener('click', () => togglePanel('footer'));
  dom.reopenLeft.addEventListener('click', () => reopenPanel('left'));
  dom.reopenRight.addEventListener('click', () => reopenPanel('right'));
  dom.reopenFooter.addEventListener('click', () => reopenPanel('footer'));

  // Quality toggle
  document.getElementById('quality-toggle').addEventListener('click', () => {
    const idx = QUALITY_MODES.indexOf(state.qualityMode);
    setQualityMode(QUALITY_MODES[(idx + 1) % QUALITY_MODES.length]);
  });

  // Demo controls
  dom.btnStart.addEventListener('click', () => {
    if (state.socket) state.socket.send(JSON.stringify({ action: 'start_scenario' }));
  });
  dom.btnStop.addEventListener('click', () => {
    if (state.socket) state.socket.send(JSON.stringify({ action: 'stop_scenario' }));
  });
  dom.btnReset.addEventListener('click', () => {
    if (state.socket) state.socket.send(JSON.stringify({ action: 'reset' }));
  });

  // Alert filters
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      document.querySelectorAll('.alert-card').forEach(card => {
        card.style.display = (filter === 'all' || card.dataset.severity === filter) ? '' : 'none';
      });
    });
  });

  // Collector controls
  document.getElementById('btn-collector-start').addEventListener('click', () => startCollector());
  document.getElementById('btn-collector-stop').addEventListener('click', () => stopCollector());

  // Nav: open Chat in new window (preserves HUD state)
  document.getElementById('nav-chat')?.addEventListener('click', () => {
    window.open('/chat/', 'cyberclaw-chat');
  });

  // Resize
  window.addEventListener('resize', onResize);
}

function togglePanel(side) {
  if (side === 'left') {
    dom.sidebarLeft.classList.toggle('collapsed');
    dom.reopenLeft.classList.toggle('visible', dom.sidebarLeft.classList.contains('collapsed'));
  } else if (side === 'right') {
    dom.sidebarRight.classList.toggle('collapsed');
    dom.reopenRight.classList.toggle('visible', dom.sidebarRight.classList.contains('collapsed'));
  } else {
    dom.footerPanel.classList.toggle('collapsed');
    dom.reopenFooter.classList.toggle('visible', dom.footerPanel.classList.contains('collapsed'));
  }
}

function reopenPanel(side) {
  if (side === 'left') { dom.sidebarLeft.classList.remove('collapsed'); dom.reopenLeft.classList.remove('visible'); }
  else if (side === 'right') { dom.sidebarRight.classList.remove('collapsed'); dom.reopenRight.classList.remove('visible'); }
  else { dom.footerPanel.classList.remove('collapsed'); dom.reopenFooter.classList.remove('visible'); }
}

function onResize() {
  state.camera.aspect = window.innerWidth / window.innerHeight;
  state.camera.updateProjectionMatrix();
  state.renderer.setSize(window.innerWidth, window.innerHeight);
  state.labels.setSize(window.innerWidth, window.innerHeight);
  state.composer.setSize(window.innerWidth, window.innerHeight);
}

// ═══════════════════════════════════════════════════════════════════
// MCP TOOL TRIGGERS
// ═══════════════════════════════════════════════════════════════════

async function triggerDeviceScan(deviceId) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry) return;
  updateDeviceStatus(deviceId, 'scanning');
  try {
    await fetch('/api/tools/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: entry.payload.ip, scan_type: 'network' }),
    });
  } catch (e) { console.error('Scan failed:', e); }
}

async function triggerCveCheck(deviceId, vendor, model) {
  try {
    await fetch('/api/tools/cve-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vendor: vendor || '', model: model || '', device_id: deviceId }),
    });
  } catch (e) { console.error('CVE check failed:', e); }
}

async function triggerDeviceIsolation(deviceId) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry) return;
  // 防重复点击：禁用按钮 + 显示隔离中（隔离成功后由 device_isolated 广播刷新面板，按钮自动变 RESTORE）
  const btn = dom.detailPanel.querySelector('.action-btn.isolate');
  const restoreBtn = () => {
    const b = dom.detailPanel.querySelector('.action-btn.isolate');
    if (b && b.disabled) { b.disabled = false; b.classList.remove('is-busy'); b.textContent = 'ISOLATE'; }
  };
  if (btn) { btn.disabled = true; btn.classList.add('is-busy'); btn.textContent = 'ISOLATING...'; }
  try {
    await fetch('/api/tools/isolate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, device_ip: entry.payload.ip }),
    });
    // 兜底：8s 后若按钮仍处于 disabled（广播丢失/未刷新面板），恢复可点击
    setTimeout(restoreBtn, 8000);
  } catch (e) {
    console.error('Isolation failed:', e);
    restoreBtn();
  }
}

async function triggerDeviceRestore(deviceId) {
  const entry = state.devices.find(d => d.id === deviceId);
  if (!entry) return;
  try {
    await fetch('/api/tools/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, device_ip: entry.payload.ip }),
    });
  } catch (e) { console.error('Restore failed:', e); }
}

async function triggerBaseline(deviceId) {
  try {
    await fetch('/api/tools/baseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile: 'iot-default', target: 'all' }),
    });
  } catch (e) { console.error('Baseline failed:', e); }
}

async function startCollector() {
  try {
    const resp = await fetch('/api/tools/collector/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: 8514 }),
    });
    const status = await resp.json();
    const el = document.getElementById('collector-status');
    if (el) el.textContent = status.is_running ? `Running on :${status.port}` : 'Stopped';
    addAlert({ severity: 'info', message: `Syslog collector started on UDP :${status.port}`, type: 'collector' });
    return status;
  } catch (e) { console.error('Collector start failed:', e); }
}

async function stopCollector() {
  try {
    const resp = await fetch('/api/tools/collector/stop', { method: 'POST' });
    const status = await resp.json();
    const el = document.getElementById('collector-status');
    if (el) el.textContent = 'Stopped';
    addAlert({ severity: 'info', message: 'Syslog collector stopped', type: 'collector' });
    return status;
  } catch (e) { console.error('Collector stop failed:', e); }
}

async function getCollectorEvents(limit = 50) {
  try {
    const resp = await fetch(`/api/tools/collector/events?limit=${limit}`);
    return await resp.json();
  } catch (e) { console.error('Get events failed:', e); return { events: [] }; }
}

// ═══════════════════════════════════════════════════════════════════
// RAYCASTING (hover/select)
// ═══════════════════════════════════════════════════════════════════

function updateRaycast() {
  state.raycaster.setFromCamera(state.mouse, state.camera);
  const meshes = state.devices.map(d => d.mesh);
  const hits = state.raycaster.intersectObjects(meshes);

  // Reset previous hover
  if (state.hovered) {
    const h = state.hovered;
    gsap.to(h.mat, { emissiveIntensity: STATUS_GLOW[h.status], duration: 0.3 });
    gsap.to(h.edgeMat, { opacity: 0.85, duration: 0.3 });
    dom.tooltip.classList.remove('visible');
  }

  if (hits.length > 0) {
    const hitMesh = hits[0].object;
    const entry = state.devices.find(d => d.mesh === hitMesh);
    if (entry) {
      state.hovered = entry;
      const hoverGlow = Math.min(STATUS_GLOW[entry.status] + 0.2, 0.7);
      gsap.to(entry.mat, { emissiveIntensity: hoverGlow, duration: 0.25 });
      gsap.to(entry.edgeMat, { opacity: 1, duration: 0.25 });
      gsap.to(entry.haloMat, { opacity: 0.3, duration: 0.25 });
      state.renderer.domElement.style.cursor = 'pointer';

      // Show tooltip
      dom.tooltip.textContent = `${entry.payload.name} (${entry.payload.ip}) — ${entry.status.toUpperCase()}`;
      dom.tooltip.style.left = `${(state.mouse.x * 0.5 + 0.5) * window.innerWidth + 16}px`;
      dom.tooltip.style.top = `${(-state.mouse.y * 0.5 + 0.5) * window.innerHeight - 10}px`;
      dom.tooltip.classList.add('visible');
    }
  } else {
    state.hovered = null;
    state.renderer.domElement.style.cursor = 'default';
  }
}

// ═══════════════════════════════════════════════════════════════════
// ANIMATION LOOP
// ═══════════════════════════════════════════════════════════════════

function animate() {
  requestAnimationFrame(animate);

  const t = state.clock.getElapsedTime();
  const dt = state.clock.getDelta();

  // FPS counter
  state.fps.frames++;
  const now = performance.now();
  if (now - state.fps.lastTime >= 1000) {
    state.fps.value = state.fps.frames;
    state.fps.frames = 0;
    state.fps.lastTime = now;
    dom.footerFps.textContent = state.fps.value;
  }

  // Environment uniforms
  if (state.envUniforms) {
    state.envUniforms.starTime.value = t;
    state.envUniforms.ringTime.value = t;
  }

  // Device idle animations
  state.devices.forEach((entry, i) => {
    const bob = Math.sin(t * 0.8 + i * 0.7) * 0.06;
    entry.group.position.y = (entry.payload.pos?.[1] || 0) + bob;
    const baseX = entry.payload.pos?.[0] || 0;

    // Attacked pulse (smooth, not flashy)
    if (entry.status === 'attacked') {
      entry.group.position.x = baseX;
      const pulse = STATUS_GLOW.attacked + Math.sin(t * 3 + i) * 0.15;
      entry.mat.emissiveIntensity = pulse;
      entry.edgeMat.opacity = 0.75 + Math.sin(t * 3 + i) * 0.15;
      entry.haloMat.opacity = 0.25 + Math.sin(t * 2) * 0.1;
    }

    // Vulnerable warning oscillation (side-to-side wobble + emissive pulse)
    else if (entry.status === 'vulnerable') {
      entry.group.position.x = baseX + Math.sin(t * 2.5 + i * 0.5) * 0.14;
      entry.mat.emissiveIntensity = STATUS_GLOW.vulnerable + Math.sin(t * 4 + i) * 0.12;
    }

    else {
      entry.group.position.x = baseX;
    }

    // Scanning rotate
    if (entry.status === 'scanning') {
      entry.mesh.rotation.y += 0.015;
      entry.wireframe.rotation.y = entry.mesh.rotation.y;
    }
  });

  // Shield rotation
  state.shields.forEach(s => {
    s.mesh.rotation.y += 0.005;
    s.mesh.rotation.x += 0.003;
  });

  // Raycast (every 3 frames to save CPU)
  state.frameCount++;
  if (state.frameCount % 3 === 0) updateRaycast();

  // Controls
  state.controls.update();

  // Render
  state.composer.render();
  state.labels.render(state.scene, state.camera);
}

// ═══════════════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════════════

async function boot() {
  setLoading(10, 'Initializing 3D engine...');
  initScene();

  setLoading(30, 'Loading IoT topology...');

  // ── Restore persisted state from localStorage ────────────────
  setLoading(45, 'Restoring previous session...');
  // Restore alert timeline — directly fill state & DOM without saveState calls
  const savedAlerts = loadState(KEYS.hudAlerts, []);
  if (savedAlerts.length > 0) {
    state.alerts = savedAlerts;
    state.deviceEvents = loadState(KEYS.hudDeviceEvents, {});
    // Rebuild alert cards in DOM
    savedAlerts.slice().reverse().forEach(a => {
      const card = document.createElement('div');
      card.className = 'alert-card';
      card.dataset.severity = a.severity || 'info';
      const time = a.time || new Date().toLocaleTimeString('zh-CN', { hour12: false });
      card.innerHTML = `
        <span class="alert-time">${time}</span>
        <span class="alert-severity ${a.severity || 'info'}">${a.severity || 'info'}</span>
        <div class="alert-msg">${a.message || a.type}</div>
      `;
      if (a.target || a.source) {
        card.addEventListener('click', () => focusDevice(a.target || a.source));
      }
      dom.alertList.insertBefore(card, dom.alertList.firstChild);
    });
    // Trim DOM if needed
    while (dom.alertList.children.length > 40) {
      dom.alertList.removeChild(dom.alertList.lastChild);
    }
    state.eventCount = savedAlerts.length;
    dom.footerEvents.textContent = state.eventCount;
  }
  // Restore device scan/CVE/baseline data (in-memory only, no DOM yet)
  state.deviceScanData = loadState(KEYS.hudScanData, {});
  state.baselineData = loadState(KEYS.hudBaselineData, {});
  state.baselineOverall = loadState(KEYS.hudBaselineOverall, null);
  if (!state.deviceEvents || Object.keys(state.deviceEvents).length === 0) {
    state.deviceEvents = loadState(KEYS.hudDeviceEvents, {});
  }

  setLoading(60, 'Establishing real-time link...');
  connectWS();

  setLoading(80, 'Calibrating threat sensors...');
  setupInteraction();

  // ── Listen for state changes from Chat page ─────────────────
  onStateChange((changedKey) => {
    // If Chat page triggers a scan or other action, the WS will
    // push results here too — no special handling needed.
  });

  // ── Listen for isolation events from Chat via BroadcastChannel ──
  try {
    const _isoBC = new BroadcastChannel('cyberclaw-sync');
    _isoBC.addEventListener('message', (e) => {
      const d = e.data;
      if (d?.key === 'cc_isolation_event' && d.deviceIp) {
        // Find device by IP and update status
        const entry = state.devices.find(dev => {
          const ip = dev.payload?.ip || dev.payload?.devLastIP || '';
          return ip === d.deviceIp;
        });
        if (entry) {
          updateDeviceStatus(entry.id, 'isolated');
          addAlert({
            severity: 'high',
            message: `Device ${d.deviceIp} isolated via CyberAgent`,
            type: 'chat_isolation',
          });
        }
      }
    });
  } catch {}

  setLoading(100, 'CyberClaw online. All systems nominal.');
  setTimeout(() => {
    dom.loading.style.display = 'none';
    dom.loading.remove();
  }, 600);

  // Start render loop
  animate();
  onResize();
  window.addEventListener('resize', onResize);
}

boot();
