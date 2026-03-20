/**
 * control.js — Contrôle Snort (start/stop/restart, mode IDS/IPS, interfaces)
 */
'use strict';

// ── État ──────────────────────────────────────────────────────────────────────

let currentMode       = 'ids';
let availableIfaces   = [];
let autoRefreshTimer  = null;

// ── Init ──────────────────────────────────────────────────────────────────────

(async function init() {
  await Promise.all([refreshStatus(), loadInterfaces(), loadSettings()]);
  setupAutoRefresh();
})();

// ── Statut Snort ─────────────────────────────────────────────────────────────

async function refreshStatus() {
  try {
    const r    = await fetch('/api/snort/status');
    const data = await r.json();
    renderStatus(data);
  } catch (e) {
    renderStatus({ running: false, error: e.message });
  }
  document.getElementById('lastUpdate').textContent =
    `Mis à jour : ${new Date().toLocaleTimeString()}`;
}

function renderStatus(data) {
  const dot      = document.getElementById('statusDot');
  const dotInner = document.getElementById('statusDotInner');
  const statEl   = document.getElementById('statStatus');

  if (data.running) {
    dot.className      = 'absolute w-16 h-16 rounded-full bg-green-500 ping-slow opacity-30';
    dotInner.className = 'relative w-10 h-10 rounded-full bg-green-500 flex items-center justify-center text-xl';
    dotInner.textContent = '▶';
    statEl.className   = 'text-xl font-bold mt-1 text-green-400';
    statEl.textContent = 'En cours';
  } else {
    dot.className      = 'absolute w-16 h-16 rounded-full bg-red-700 ping-slow opacity-30';
    dotInner.className = 'relative w-10 h-10 rounded-full bg-red-700 flex items-center justify-center text-xl';
    dotInner.textContent = '■';
    statEl.className   = 'text-xl font-bold mt-1 text-red-400';
    statEl.textContent = 'Arrêté';
  }

  document.getElementById('statPid').textContent    = data.pid    || '—';
  document.getElementById('statUptime').textContent = data.uptime || '—';
  document.getElementById('statMem').textContent    = data.mem    || '—';

  // Mode badge
  const modeEl = document.getElementById('statMode');
  currentMode  = data.mode || 'ids';
  if (currentMode === 'ips') {
    modeEl.className   = 'px-4 py-2 rounded-lg text-sm font-bold bg-red-900/40 text-red-300 border border-red-800/40';
    modeEl.textContent = 'IPS — Inline';
  } else {
    modeEl.className   = 'px-4 py-2 rounded-lg text-sm font-bold bg-blue-900/40 text-blue-300 border border-blue-800/40';
    modeEl.textContent = 'IDS — Passif';
  }

  updateModeButtons(currentMode);

  // Sortie brute
  document.getElementById('rawOutput').textContent = data.rawOutput || '';
}

// ── Boutons contrôle ──────────────────────────────────────────────────────────

['start','stop','restart'].forEach(action => {
  document.getElementById(`btn${action.charAt(0).toUpperCase() + action.slice(1)}`)
    .addEventListener('click', async () => {
      showToast(`${action}...`, 'info');
      try {
        const r = await fetch(`/api/snort/${action}`, { method: 'POST' });
        const d = await r.json();
        if (d.success) {
          showToast(`Snort ${action === 'start' ? 'démarré' : action === 'stop' ? 'arrêté' : 'redémarré'}`, 'ok');
          setTimeout(refreshStatus, 1500); // laisser le temps au service
        } else {
          showToast(`✖ ${d.error}`, 'err');
        }
      } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
    });
});

document.getElementById('btnReload').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/reload', { method: 'POST' });
    const d = await r.json();
    showToast(d.success ? 'Règles rechargées (SIGHUP)' : `✖ ${d.error}`, d.success ? 'ok' : 'err');
  } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
});

// ── Mode IDS / IPS ────────────────────────────────────────────────────────────

document.getElementById('btnModeIds').addEventListener('click', () => selectMode('ids'));
document.getElementById('btnModeIps').addEventListener('click', () => selectMode('ips'));

function selectMode(mode) {
  currentMode = mode;
  updateModeButtons(mode);
  updateGeneratedCmd();
}

function updateModeButtons(mode) {
  const btnIds = document.getElementById('btnModeIds');
  const btnIps = document.getElementById('btnModeIps');
  const cfgIds = document.getElementById('configIds');
  const cfgIps = document.getElementById('configIps');

  if (mode === 'ids') {
    btnIds.className = 'flex-1 py-4 rounded-xl border-2 border-blue-500 bg-blue-900/30 text-blue-300 text-sm font-bold transition-all';
    btnIps.className = 'flex-1 py-4 rounded-xl border-2 border-gray-700 bg-transparent text-gray-500 text-sm font-bold transition-all';
    cfgIds.classList.remove('hidden');
    cfgIps.classList.add('hidden');
  } else {
    btnIps.className = 'flex-1 py-4 rounded-xl border-2 border-red-500 bg-red-900/30 text-red-300 text-sm font-bold transition-all';
    btnIds.className = 'flex-1 py-4 rounded-xl border-2 border-gray-700 bg-transparent text-gray-500 text-sm font-bold transition-all';
    cfgIps.classList.remove('hidden');
    cfgIds.classList.add('hidden');
  }
  updateGeneratedCmd();
}

// ── Interfaces ────────────────────────────────────────────────────────────────

async function loadInterfaces() {
  try {
    const r    = await fetch('/api/snort/interfaces');
    const data = await r.json();
    availableIfaces = data.interfaces || [];
    populateIfaceSelects(availableIfaces);
    renderIfaceList(availableIfaces);
  } catch (e) {
    document.getElementById('ifaceList').innerHTML =
      `<p class="p-6 text-xs text-red-400">✖ ${e.message}</p>`;
  }
}

function populateIfaceSelects(ifaces) {
  const selects = ['ifaceIds','ifaceIps1','ifaceIps2'];
  selects.forEach(id => {
    const sel = document.getElementById(id);
    const cur = sel.value;
    sel.innerHTML = '<option value="">— Sélectionner —</option>';
    ifaces.forEach(i => {
      const opt = document.createElement('option');
      opt.value = i.name;
      opt.textContent = `${i.name}  (${i.state})${i.mac ? '  ' + i.mac : ''}`;
      if (i.name === cur) opt.selected = true;
      sel.appendChild(opt);
    });
  });
  updateGeneratedCmd();
}

const STATE_COLORS = {
  UP:      'bg-green-900/40 text-green-300',
  DOWN:    'bg-red-900/40 text-red-300',
  UNKNOWN: 'bg-gray-800 text-gray-400',
  LOWERLAYERDOWN: 'bg-orange-900/40 text-orange-300'
};

function renderIfaceList(ifaces) {
  const container = document.getElementById('ifaceList');
  if (!ifaces.length) {
    container.innerHTML = '<p class="p-6 text-xs text-gray-600">Aucune interface détectée.</p>';
    return;
  }
  container.innerHTML = ifaces.map(i => {
    const state  = (i.state || 'UNKNOWN').toUpperCase();
    const color  = STATE_COLORS[state] || STATE_COLORS.UNKNOWN;
    return `
      <div class="px-6 py-3 flex items-center gap-4">
        <span class="font-mono text-sm text-gray-200 w-24 shrink-0">${i.name}</span>
        <span class="px-2 py-0.5 rounded text-xs font-medium ${color}">${state}</span>
        <span class="text-xs text-gray-500 font-mono">${i.mac || ''}</span>
        <span class="text-xs text-gray-600 ml-auto">MTU ${i.mtu || '?'}</span>
      </div>`;
  }).join('');
}

// ── Commande générée ──────────────────────────────────────────────────────────

['ifaceIds','ifaceIps1','ifaceIps2'].forEach(id => {
  document.getElementById(id).addEventListener('change', updateGeneratedCmd);
});

function updateGeneratedCmd() {
  const cmdEl = document.getElementById('generatedCmd');
  const iface1 = document.getElementById('ifaceIds').value  || 'eth0';
  const iface2 = document.getElementById('ifaceIps1').value || 'eth0';
  const iface3 = document.getElementById('ifaceIps2').value || 'eth1';

  if (currentMode === 'ids') {
    cmdEl.textContent = `/usr/local/bin/snort \\\n  -c /usr/local/etc/snort/snort.lua \\\n  --daq pcap \\\n  -i ${iface1} \\\n  -l /var/log/snort \\\n  -D`;
  } else {
    cmdEl.textContent = `/usr/local/bin/snort \\\n  -c /usr/local/etc/snort/snort.lua \\\n  --daq afpacket \\\n  -i ${iface2}:${iface3} \\\n  -Q \\\n  -l /var/log/snort \\\n  -D`;
  }
}

window.copyCmd = () => {
  const text = document.getElementById('generatedCmd').textContent;
  navigator.clipboard.writeText(text).then(() => showToast('Commande copiée', 'ok'));
};

// ── Appliquer le mode ─────────────────────────────────────────────────────────

document.getElementById('btnApplyMode').addEventListener('click', async () => {
  const btn = document.getElementById('btnApplyMode');
  btn.disabled = true;
  btn.textContent = 'Application en cours…';

  const body = {
    mode:          currentMode,
    interfaceIds:  document.getElementById('ifaceIds').value,
    interfaceIps1: document.getElementById('ifaceIps1').value,
    interfaceIps2: document.getElementById('ifaceIps2').value
  };

  try {
    const r = await fetch('/api/snort/set-mode', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body)
    });
    const d = await r.json();
    if (d.success) {
      showToast(`Mode ${d.mode.toUpperCase()} appliqué — Snort redémarre…`, 'ok');
      setTimeout(refreshStatus, 3000);
    } else {
      showToast(`✖ ${d.error}`, 'err');
    }
  } catch (e) {
    showToast(`✖ ${e.message}`, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Appliquer le mode et redémarrer Snort';
  }
});

// ── Charger les settings pour pré-remplir les interfaces ──────────────────────

async function loadSettings() {
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    if (s.interfaceIds)  document.getElementById('ifaceIds').value  = s.interfaceIds;
    if (s.interfaceIps1) document.getElementById('ifaceIps1').value = s.interfaceIps1;
    if (s.interfaceIps2) document.getElementById('ifaceIps2').value = s.interfaceIps2;
    updateGeneratedCmd();
  } catch (_) {}
}

// ── Auto-refresh ──────────────────────────────────────────────────────────────

function setupAutoRefresh() {
  const chk = document.getElementById('chkAutoRefresh');
  const start = () => { autoRefreshTimer = setInterval(refreshStatus, 5000); };
  const stop  = () => { clearInterval(autoRefreshTimer); };
  if (chk.checked) start();
  chk.addEventListener('change', () => chk.checked ? start() : stop());
}

// ── Sortie brute toggle ───────────────────────────────────────────────────────

document.getElementById('btnToggleOutput').addEventListener('click', () => {
  const w   = document.getElementById('outputWrapper');
  const btn = document.getElementById('btnToggleOutput');
  w.classList.toggle('hidden');
  btn.textContent = w.classList.contains('hidden') ? 'Afficher ▾' : 'Masquer ▴';
});

// ── Utilities ─────────────────────────────────────────────────────────────────

function showToast(msg, type = 'ok') {
  const colors = {
    ok:   'bg-green-800 text-green-200',
    err:  'bg-red-900 text-red-200',
    warn: 'bg-yellow-800 text-yellow-200',
    info: 'bg-blue-900 text-blue-200'
  };
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.add('hidden'), 3500);
}
