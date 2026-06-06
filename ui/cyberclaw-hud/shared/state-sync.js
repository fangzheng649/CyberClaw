// ═══════════════════════════════════════════════════════════════════
// CyberClaw — Cross-Page State Sync via localStorage + BroadcastChannel
// ═══════════════════════════════════════════════════════════════════
// Shared between HUD (src/main.js) and Chat (chat/main.js).
// Both pages stay independent; this module bridges state changes.

const CHANNEL_NAME = 'cyberclaw-sync';

// ── localStorage Key Constants ─────────────────────────────────────
export const KEYS = {
  chatMessages:       'cc_chat_messages',
  hudAlerts:          'cc_hud_alerts',
  hudDeviceEvents:    'cc_hud_device_events',
  hudScanData:        'cc_hud_scan_data',
  hudBaselineData:    'cc_hud_baseline_data',
  hudBaselineOverall: 'cc_hud_baseline_overall',
  hudDeviceStatuses:  'cc_hud_device_statuses',
};

// ── BroadcastChannel (real-time, same-origin) ─────────────────────
let bc = null;
try {
  bc = new BroadcastChannel(CHANNEL_NAME);
} catch {
  // Fallback: BroadcastChannel not supported; rely on storage event only
}

// ── Save ───────────────────────────────────────────────────────────
export function saveState(key, data) {
  try {
    localStorage.setItem(key, JSON.stringify(data));
    // Notify other page(s) immediately
    bc?.postMessage({ key, timestamp: Date.now() });
  } catch (e) {
    console.warn('[state-sync] saveState failed:', e);
  }
}

// ── Load ───────────────────────────────────────────────────────────
export function loadState(key, defaultValue = null) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : defaultValue;
  } catch {
    return defaultValue;
  }
}

// ── Listen for changes from other page ─────────────────────────────
// Callback receives the changed key name.
export function onStateChange(callback) {
  // 1. BroadcastChannel — fast, same-origin
  if (bc) {
    bc.addEventListener('message', (e) => {
      if (e.data?.key) callback(e.data.key);
    });
  }

  // 2. storage event — fires in OTHER tabs/windows on same origin
  window.addEventListener('storage', (e) => {
    if (e.key && e.key.startsWith('cc_')) {
      callback(e.key);
    }
  });
}

// ── Clear all CyberClaw state ──────────────────────────────────────
export function clearAllState() {
  Object.values(KEYS).forEach(key => {
    try { localStorage.removeItem(key); } catch {}
  });
}
