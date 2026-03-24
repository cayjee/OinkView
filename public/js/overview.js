/**
 * overview.js — Vue globale de la configuration Snort en cours
 */
'use strict';

const ACTION_COLORS = {
  alert:   { bg: 'bg-red-900/40',    text: 'text-red-300'    },
  drop:    { bg: 'bg-orange-900/40', text: 'text-orange-300' },
  pass:    { bg: 'bg-green-900/40',  text: 'text-green-300'  },
  reject:  { bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
};

// ── Chargement principal ──────────────────────────────────────────────────────

async function load() {
  // Remettre les sections en état "chargement" avant la requête
  document.getElementById('globalStats').innerHTML    = '<p class="text-gray-600 text-xs col-span-4">Chargement…</p>';
  document.getElementById('variablesGrid').innerHTML  = '<p class="text-gray-600 text-xs col-span-2">Chargement…</p>';
  document.getElementById('modulesList').innerHTML    = '<p class="text-gray-600 text-xs">Chargement…</p>';
  document.getElementById('ruleFilesList').innerHTML  = '<p class="p-6 text-gray-600 text-xs">Chargement…</p>';

  try {
    const r = await fetch('/api/snort/overview');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    renderGlobalStats(data.globalStats, data.ruleFiles.length);
    renderVariables(data.luaParsed, data.luaError, data.snortConfig);
    renderModules(data.luaParsed);
    renderRuleFiles(data.ruleFiles);
    loadLuaRaw();
  } catch (e) {
    const msg = `Erreur de chargement : ${e.message}`;
    document.getElementById('globalStats').innerHTML   = `<p class="text-red-400 text-xs col-span-4">✖ ${msg}</p>`;
    document.getElementById('variablesGrid').innerHTML = `<p class="text-red-400 text-xs col-span-2">✖ ${msg}</p>`;
    document.getElementById('modulesList').innerHTML   = `<p class="text-red-400 text-xs">✖ ${msg}</p>`;
    document.getElementById('ruleFilesList').innerHTML = `<p class="p-6 text-red-400 text-xs">✖ ${msg}</p>`;
    showToast(`✖ ${e.message}`, 'err');
  }
}

// ── Stats globales ─────────────────────────────────────────────────────────────

function renderGlobalStats(stats, fileCount) {
  const container = document.getElementById('globalStats');

  const cards = [
    { label: 'Règles totales',   value: stats.total,    color: 'text-blue-300',   bg: 'bg-blue-900/20',   border: 'border-blue-800/40' },
    { label: 'Règles actives',   value: stats.total - stats.disabled, color: 'text-green-300', bg: 'bg-green-900/20', border: 'border-green-800/40' },
    { label: 'Désactivées',      value: stats.disabled, color: 'text-gray-400',   bg: 'bg-gray-800/40',   border: 'border-gray-700/40' },
    { label: 'Fichiers inclus',  value: fileCount,      color: 'text-orange-300', bg: 'bg-orange-900/20', border: 'border-orange-800/40' },
  ];

  container.innerHTML = cards.map(c => `
    <div class="rounded-xl border ${c.border} ${c.bg} p-5 flex flex-col gap-1">
      <span class="text-3xl font-bold ${c.color}">${c.value ?? 0}</span>
      <span class="text-xs text-gray-500 uppercase tracking-widest">${c.label}</span>
    </div>
  `).join('');

  // Ajout des stats par action si présentes
  const actionCards = ['alert','drop','pass','reject']
    .filter(a => stats[a] > 0)
    .map(a => {
      const c = ACTION_COLORS[a] || { bg: 'bg-gray-800/40', text: 'text-gray-300' };
      return `
        <div class="rounded-xl border border-gray-700/40 ${c.bg} p-4 flex flex-col gap-1">
          <span class="text-2xl font-bold ${c.text}">${stats[a]}</span>
          <span class="text-xs text-gray-500 uppercase tracking-widest">${a}</span>
        </div>`;
    });

  if (actionCards.length) container.innerHTML += actionCards.join('');
}

// ── Variables réseau ──────────────────────────────────────────────────────────

function renderVariables(lua, error, configPath) {
  const grid   = document.getElementById('variablesGrid');
  const status = document.getElementById('luaStatus');

  if (error) {
    status.textContent = `✖ ${error}`;
    status.className = 'text-xs text-red-400';
    grid.innerHTML = `<p class="text-gray-600 text-xs col-span-2">
      Configurez le chemin vers <code class="text-orange-300">snort.lua</code> dans les
      <a href="settings.html" class="text-orange-400 underline">Paramètres</a>.
    </p>`;
    return;
  }

  status.textContent = configPath;
  status.className = 'text-xs text-gray-500 font-mono';

  if (!lua.variables.length) {
    grid.innerHTML = '<p class="text-gray-600 text-xs col-span-2">Aucune variable réseau détectée.</p>';
    return;
  }

  grid.innerHTML = lua.variables.map(v => `
    <div class="flex items-start gap-3 bg-gray-800/50 rounded-lg p-3">
      <span class="text-orange-300 font-semibold text-xs shrink-0 w-40 truncate" title="${esc(v.name)}">${esc(v.name)}</span>
      <span class="text-gray-300 text-xs font-mono break-all">${esc(v.value)}</span>
    </div>
  `).join('');
}

// ── Modules ───────────────────────────────────────────────────────────────────

function renderModules(lua) {
  const container = document.getElementById('modulesList');
  if (!lua || !lua.modules.length) {
    container.innerHTML = '<p class="text-gray-600 text-xs">Aucun module détecté ou snort.lua non configuré.</p>';
    return;
  }

  // Colorier les modules connus
  const known = {
    ips: 'bg-blue-900/40 text-blue-300 border-blue-800/40',
    alert_fast: 'bg-green-900/40 text-green-300 border-green-800/40',
    alert_json: 'bg-green-900/40 text-green-300 border-green-800/40',
    stream: 'bg-purple-900/40 text-purple-300 border-purple-800/40',
    stream_tcp: 'bg-purple-900/40 text-purple-300 border-purple-800/40',
    stream_udp: 'bg-purple-900/40 text-purple-300 border-purple-800/40',
    http_inspect: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
    ssl: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
    ftp_telnet: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
  };

  container.innerHTML = lua.modules.map(m => {
    const cls = known[m] || 'bg-gray-800/40 text-gray-400 border-gray-700/40';
    return `<span class="px-2.5 py-1 rounded-md border text-xs font-medium ${cls}">${esc(m)}</span>`;
  }).join('');
}

// ── Fichiers de règles ────────────────────────────────────────────────────────

function renderRuleFiles(files) {
  const container = document.getElementById('ruleFilesList');

  if (!files.length) {
    container.innerHTML = '<p class="p-6 text-gray-600 text-xs">Aucun fichier de règles trouvé.</p>';
    return;
  }

  container.innerHTML = files.map((f, idx) => {
    const active = f.stats.total - f.stats.disabled;
    return `
    <div class="px-6 py-4">
      <!-- Header ligne fichier -->
      <div class="flex items-center gap-3 cursor-pointer" onclick="toggleFileRules(${idx})">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            ${f.readable
              ? '<span class="w-2 h-2 rounded-full bg-green-500 shrink-0"></span>'
              : '<span class="w-2 h-2 rounded-full bg-red-500 shrink-0"></span>'}
            <span class="text-sm text-gray-200 font-mono truncate" title="${esc(f.filePath)}">${esc(f.filePath)}</span>
          </div>
          ${!f.readable ? `<p class="text-xs text-red-400 mt-1 ml-4">${esc(f.error)}</p>` : ''}
        </div>
        <!-- Mini stats -->
        <div class="flex items-center gap-2 shrink-0">
          <span class="px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 text-xs">${f.stats.total} règles</span>
          <span class="px-2 py-0.5 rounded bg-green-900/40 text-green-300 text-xs">${active} actives</span>
          ${f.stats.disabled > 0 ? `<span class="px-2 py-0.5 rounded bg-gray-800 text-gray-500 text-xs">${f.stats.disabled} off</span>` : ''}
          ${f.stats.alert  > 0 ? `<span class="px-2 py-0.5 rounded bg-red-900/40 text-red-300 text-xs">${f.stats.alert} alert</span>` : ''}
          ${f.stats.drop   > 0 ? `<span class="px-2 py-0.5 rounded bg-orange-900/40 text-orange-300 text-xs">${f.stats.drop} drop</span>` : ''}
          <svg class="w-4 h-4 text-gray-500 transition-transform" id="chevron-${idx}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
          </svg>
        </div>
      </div>

      <!-- Règles dépliables -->
      <div id="rules-${idx}" class="hidden mt-3 overflow-auto max-h-72 rounded-lg border border-gray-800">
        <table class="w-full text-xs border-collapse">
          <thead class="bg-gray-800 text-gray-500 uppercase tracking-wider sticky top-0">
            <tr>
              <th class="px-3 py-2 text-left">Action</th>
              <th class="px-3 py-2 text-left">SID</th>
              <th class="px-3 py-2 text-left">Message</th>
              <th class="px-3 py-2 text-left">Statut</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800/60">
            ${f.rules.length
              ? f.rules.map(r => {
                  const c = ACTION_COLORS[r.action] || { text: 'text-gray-400' };
                  return `<tr class="${r.disabled ? 'opacity-40' : ''} hover:bg-gray-800/40">
                    <td class="px-3 py-2 font-semibold ${c.text}">${esc(r.action)}</td>
                    <td class="px-3 py-2 text-orange-300">${r.sid ? '#'+r.sid : '—'}</td>
                    <td class="px-3 py-2 text-gray-300 max-w-xs truncate" title="${esc(r.msg)}">${esc(r.msg)}</td>
                    <td class="px-3 py-2">${r.disabled
                      ? '<span class="px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">off</span>'
                      : '<span class="px-1.5 py-0.5 rounded bg-green-900/40 text-green-400">on</span>'}</td>
                  </tr>`;
                }).join('')
              : '<tr><td colspan="4" class="px-3 py-4 text-center text-gray-600">Aucune règle dans ce fichier.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>`;
  }).join('');
}

window.toggleFileRules = (idx) => {
  const panel   = document.getElementById(`rules-${idx}`);
  const chevron = document.getElementById(`chevron-${idx}`);
  panel.classList.toggle('hidden');
  chevron.style.transform = panel.classList.contains('hidden') ? '' : 'rotate(180deg)';
};

// ── snort.lua raw ─────────────────────────────────────────────────────────────

async function loadLuaRaw() {
  const btn     = document.getElementById('btnToggleLua');
  const wrapper = document.getElementById('luaRawWrapper');
  const pre     = document.getElementById('luaRaw');

  btn.addEventListener('click', async () => {
    if (!wrapper.classList.contains('hidden')) {
      wrapper.classList.add('hidden');
      btn.textContent = 'Afficher ▾';
      return;
    }
    try {
      const r    = await fetch('/api/snort/config-raw');
      const data = await r.json();
      pre.textContent = data.content || data.error || 'Fichier vide.';
    } catch (e) {
      pre.textContent = `Erreur : ${e.message}`;
    }
    wrapper.classList.remove('hidden');
    btn.textContent = 'Masquer ▴';
  });
}

document.getElementById('btnRefresh').addEventListener('click', load);

// ── Utilities ─────────────────────────────────────────────────────────────────

function esc(str) {
  return String(str ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg, type = 'ok') {
  const toast  = document.getElementById('toast');
  const colors = { ok: 'bg-green-800 text-green-200', err: 'bg-red-900 text-red-200' };
  toast.textContent = msg;
  toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3500);
}

// ── Init ──────────────────────────────────────────────────────────────────────
load();
