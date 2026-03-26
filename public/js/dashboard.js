/**
 * dashboard.js — Console temps réel avec stats, filtres, export, géo locale
 */
'use strict';

const socket        = io({ auth: { token: localStorage.getItem('oinkview_token') || '' } });
const logConsole    = document.getElementById('logConsole');
const liveStatus    = document.getElementById('liveStatus');
const liveIndicator = document.getElementById('liveIndicator');
const chkAutoscroll = document.getElementById('chkAutoscroll');
const btnClear      = document.getElementById('btnClear');

let alertCount = 0;
let dropCount  = 0;
const MAX_LINES = 5000; // augmenté — les plus vieilles lignes sont retirées du DOM

// ── Stats en mémoire ──────────────────────────────────────────────────────────

const stats = {
  perMinute:      {},
  sidCounts:      {},
  ipCounts:       {},
  ipGeo:          {},
  protoCounts:    { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  priorityCounts: { '1': 0, '2': 0, '3': 0 }
};

// ── Parser ligne Snort fast-alert ─────────────────────────────────────────────

function parseLine(text) {
  const tsM    = text.match(/^(\d+)\/(\d+)-(\d+):(\d+):(\d+)\.(\d+)/);
  const sidM   = text.match(/\[(\d+):(\d+):(\d+)\]/);
  const msgM   = text.match(/\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]/);
  const clsM   = text.match(/\[Classification:\s*([^\]]+)\]/);
  const prioM  = text.match(/\[Priority:\s*(\d+)\]/);
  const protoM = text.match(/\{(\w+)\}/);
  const ipM    = text.match(/(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+->\s+(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/);
  const lower  = text.toLowerCase();
  let action = 'info';
  if (lower.includes('[drop]') || lower.includes('[reject]')) action = 'drop';
  else if (lower.includes('[alert]') || sidM) action = 'alert';

  // Construire un timestamp ISO depuis le timestamp Snort (sans année → année courante)
  let isoTs = null;
  if (tsM) {
    const now = new Date();
    isoTs = new Date(
      now.getFullYear(),
      parseInt(tsM[1]) - 1,
      parseInt(tsM[2]),
      parseInt(tsM[3]),
      parseInt(tsM[4]),
      parseInt(tsM[5])
    ).toISOString();
  }

  return {
    raw:            text,
    isoTs,
    gid:            sidM   ? sidM[1]            : null,
    sid:            sidM   ? sidM[2]            : null,
    rev:            sidM   ? sidM[3]            : null,
    msg:            msgM   ? msgM[1]            : null,
    classification: clsM   ? clsM[1].trim()    : null,
    priority:       prioM  ? prioM[1]           : null,
    proto:          protoM ? protoM[1].toUpperCase() : null,
    srcIp:          ipM    ? ipM[1]             : null,
    srcPort:        ipM    ? ipM[2]             : null,
    dstIp:          ipM    ? ipM[3]             : null,
    dstPort:        ipM    ? ipM[4]             : null,
    action
  };
}

// ── Tracking stats ────────────────────────────────────────────────────────────

function trackStats(parsed) {
  if (parsed.action === 'info') return;

  const now = new Date();
  const key = now.getFullYear() + '-' +
    String(now.getMonth() + 1).padStart(2, '0') + '-' +
    String(now.getDate()).padStart(2, '0') + 'T' +
    String(now.getHours()).padStart(2, '0') + ':' +
    String(now.getMinutes()).padStart(2, '0');
  stats.perMinute[key] = (stats.perMinute[key] || 0) + 1;

  if (parsed.sid) {
    if (!stats.sidCounts[parsed.sid]) stats.sidCounts[parsed.sid] = { count: 0, msg: '' };
    stats.sidCounts[parsed.sid].count++;
    if (parsed.msg && !stats.sidCounts[parsed.sid].msg) stats.sidCounts[parsed.sid].msg = parsed.msg;
  }

  if (parsed.srcIp) {
    stats.ipCounts[parsed.srcIp] = (stats.ipCounts[parsed.srcIp] || 0) + 1;
    queueGeo(parsed.srcIp);
  }

  const p = parsed.proto;
  if (p === 'TCP' || p === 'UDP' || p === 'ICMP') stats.protoCounts[p]++;
  else if (p) stats.protoCounts.OTHER++;

  if (parsed.priority && stats.priorityCounts[parsed.priority] !== undefined)
    stats.priorityCounts[parsed.priority]++;
}

// ── Géolocalisation locale (/api/geo/batch — aucune requête internet) ──────────

const GEO_QUEUE = new Set();
let geoTimer = null;

function isPrivateIp(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/.test(ip);
}

function queueGeo(ip) {
  if (!ip || isPrivateIp(ip) || stats.ipGeo[ip] !== undefined) return;
  stats.ipGeo[ip] = null;
  GEO_QUEUE.add(ip);
  if (!geoTimer) geoTimer = setTimeout(flushGeo, 2000);
}

async function flushGeo() {
  geoTimer = null;
  const ips = Array.from(GEO_QUEUE).slice(0, 100);
  GEO_QUEUE.clear();
  if (!ips.length) return;
  try {
    const r    = await fetch('/api/geo/batch', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ips })
    });
    const data = await r.json();
    if (data.results) {
      ips.forEach(ip => {
        stats.ipGeo[ip] = data.results[ip] || { country: '', countryCode: '', city: '' };
      });
    }
    renderTopIps();
  } catch (_) {}
}

// ── Mini graphique (Canvas) ───────────────────────────────────────────────────

function drawChart() {
  const canvas = document.getElementById('chartCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const now    = new Date();
  const values = [];
  const labels = [];
  for (var i = 14; i >= 0; i--) {
    const d   = new Date(now - i * 60000);
    const key = d.getFullYear() + '-' +
      String(d.getMonth() + 1).padStart(2, '0') + '-' +
      String(d.getDate()).padStart(2, '0') + 'T' +
      String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0');
    values.push(stats.perMinute[key] || 0);
    labels.push(String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'));
  }

  const maxVal = Math.max.apply(null, values.concat([1]));
  const pL = 24, pR = 4, pT = 6, pB = 16;
  const cW = W - pL - pR, cH = H - pT - pB;
  const bW = cW / values.length;

  ctx.strokeStyle = '#374151'; ctx.lineWidth = 0.5;
  for (var g = 0; g <= 3; g++) {
    const y = pT + cH - (cH * g / 3);
    ctx.beginPath(); ctx.moveTo(pL, y); ctx.lineTo(W - pR, y); ctx.stroke();
    ctx.fillStyle = '#4b5563'; ctx.font = '7px monospace';
    ctx.fillText(Math.round(maxVal * g / 3), 1, y + 3);
  }

  values.forEach(function(v, i) {
    const bh   = (v / maxVal) * cH;
    const x    = pL + i * bW;
    const y    = pT + cH - bh;
    const grad = ctx.createLinearGradient(0, y, 0, pT + cH);
    grad.addColorStop(0, '#f97316');
    grad.addColorStop(1, '#7c2d12');
    ctx.fillStyle = grad;
    ctx.fillRect(x + 1, y, bW - 2, bh);
  });

  ctx.fillStyle = '#6b7280'; ctx.font = '7px monospace';
  labels.forEach(function(l, i) {
    if (i === 0 || i === 7 || i === 14) ctx.fillText(l, pL + i * bW, H - 2);
  });
}

setInterval(drawChart, 15000);

// ── Top SIDs ──────────────────────────────────────────────────────────────────

function renderTopSids() {
  const el = document.getElementById('topSids');
  if (!el) return;
  const sorted = Object.entries(stats.sidCounts)
    .sort(function(a, b) { return b[1].count - a[1].count; })
    .slice(0, 8);
  if (!sorted.length) {
    el.innerHTML = '<p class="text-gray-600 text-xs p-2">Aucune alerte</p>';
    return;
  }
  el.innerHTML = sorted.map(function(entry) {
    const sid = entry[0], d = entry[1];
    return '<div class="flex items-center gap-2 px-3 py-1.5 border-b border-gray-800 last:border-0">' +
      '<span class="text-orange-400 font-mono text-xs w-10 shrink-0 text-right">' + d.count + 'x</span>' +
      '<span class="text-gray-300 text-xs truncate" title="SID ' + sid + '">' + (d.msg || 'SID ' + sid) + '</span>' +
      '</div>';
  }).join('');
}

// ── Top IPs ───────────────────────────────────────────────────────────────────

function renderTopIps() {
  const el = document.getElementById('topIps');
  if (!el) return;
  const sorted = Object.entries(stats.ipCounts)
    .sort(function(a, b) { return b[1] - a[1]; })
    .slice(0, 8);
  if (!sorted.length) {
    el.innerHTML = '<p class="text-gray-600 text-xs p-2">Aucune IP</p>';
    return;
  }
  el.innerHTML = sorted.map(function(entry) {
    const ip   = entry[0], count = entry[1];
    const geo  = stats.ipGeo[ip];
    const priv = isPrivateIp(ip);
    let geoStr;
    if (priv) {
      geoStr = '<span class="text-gray-600">Réseau local</span>';
    } else if (geo && geo.country) {
      const loc = [geo.countryCode, geo.city].filter(Boolean).join(' · ');
      geoStr = '<span class="text-gray-400 font-mono">' + loc + '</span>';
    } else {
      geoStr = '<span class="text-gray-600">…</span>';
    }
    return '<div class="flex items-center gap-2 px-3 py-1.5 border-b border-gray-800 last:border-0">' +
      '<span class="text-orange-400 font-mono text-xs w-8 shrink-0 text-right">' + count + '</span>' +
      '<span class="font-mono text-xs text-cyan-400 w-24 shrink-0">' + ip + '</span>' +
      '<span class="text-xs truncate flex-1">' + geoStr + '</span>' +
      '</div>';
  }).join('');
}

setInterval(function() { renderTopSids(); renderTopIps(); drawChart(); }, 5000);

// ── IP highlighting ───────────────────────────────────────────────────────────

function highlightLine(text) {
  const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return escaped.replace(/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g,
    '<span class="text-cyan-400 font-semibold">$1</span>');
}

// ── Filtres ───────────────────────────────────────────────────────────────────

const filters = { text: '', proto: '', priority: '', action: '', ip: '', timeStart: null, timeEnd: null };

function getFilters() {
  filters.text      = document.getElementById('fText').value.trim().toLowerCase();
  filters.proto     = document.getElementById('fProto').value;
  filters.priority  = document.getElementById('fPriority').value;
  filters.action    = document.getElementById('fAction').value;
  filters.ip        = document.getElementById('fIp').value.trim();
  const tsEl        = document.getElementById('fTimeStart');
  const teEl        = document.getElementById('fTimeEnd');
  filters.timeStart = tsEl && tsEl.value ? new Date(tsEl.value).getTime() : null;
  filters.timeEnd   = teEl && teEl.value ? new Date(teEl.value).getTime() : null;
}

function lineMatchesFilters(text, isoTs) {
  const lower = text.toLowerCase();
  if (filters.text     && !lower.includes(filters.text))                            return false;
  if (filters.proto    && !lower.includes('{' + filters.proto.toLowerCase() + '}')) return false;
  if (filters.priority && !lower.includes('priority: ' + filters.priority))         return false;
  if (filters.ip       && !lower.includes(filters.ip.toLowerCase()))                return false;
  if (filters.action) {
    const isDrop  = lower.includes('[drop]') || lower.includes('[reject]');
    const isAlert = lower.includes('[alert]') || /\[\d+:\d+:\d+\]/.test(text);
    if (filters.action === 'alert' && !isAlert) return false;
    if (filters.action === 'drop'  && !isDrop)  return false;
  }
  if (isoTs) {
    const ts = new Date(isoTs).getTime();
    if (filters.timeStart && ts < filters.timeStart) return false;
    if (filters.timeEnd   && ts > filters.timeEnd)   return false;
  }
  return true;
}

function applyFilters() {
  getFilters();
  logConsole.querySelectorAll('div[data-raw]').forEach(function(div) {
    const gs      = div.dataset.gidsid;
    const muted   = gs && mutedSids[gs] !== undefined;
    if (muted && !showMuted) {
      div.style.display = 'none';
      div.classList.remove('muted-alert');
      return;
    }
    const visible = lineMatchesFilters(div.dataset.raw, div.dataset.ts);
    div.style.display = visible ? '' : 'none';
    div.classList.toggle('muted-alert', muted && visible);
  });
}

['fText', 'fProto', 'fPriority', 'fAction', 'fIp', 'fTimeStart', 'fTimeEnd'].forEach(function(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener('input',  applyFilters);
  el.addEventListener('change', applyFilters);
});

document.getElementById('btnResetFilters').addEventListener('click', function() {
  ['fText', 'fIp'].forEach(function(id) { document.getElementById(id).value = ''; });
  ['fProto', 'fPriority', 'fAction'].forEach(function(id) { document.getElementById(id).value = ''; });
  const tsEl = document.getElementById('fTimeStart');
  const teEl = document.getElementById('fTimeEnd');
  if (tsEl) tsEl.value = '';
  if (teEl) teEl.value = '';
  applyFilters();
});

// ── Stats panel toggle ────────────────────────────────────────────────────────

document.getElementById('btnToggleStats').addEventListener('click', function() {
  const panel = document.getElementById('statsPanel');
  const btn   = document.getElementById('btnToggleStats');
  panel.classList.toggle('hidden');
  btn.textContent = panel.classList.contains('hidden') ? '▶ Stats' : '◀ Stats';
});

// ── Noise filter — GID:SID mute list ─────────────────────────────────────────

let mutedSids = {};  // { "116:444": "IPv4 option set", ... }
let showMuted = false;

async function loadMutedSids() {
  try {
    const r = await fetch('/api/muted-sids');
    mutedSids = await r.json();
    renderMutedList();
    updateMutedCounter();
  } catch (_) {}
}

async function muteGidSid(gidSid, label) {
  try {
    await fetch('/api/muted-sids', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ gidSid, label })
    });
    mutedSids[gidSid] = label || gidSid;
    applyFilters();
    renderMutedList();
    updateMutedCounter();
    showToast('🔇 ' + gidSid + ' masqué', 'ok');
  } catch (e) { showToast('Erreur: ' + e.message, 'err'); }
}

window.unmuteGidSid = async function(gidSid) {
  try {
    await fetch('/api/muted-sids/' + encodeURIComponent(gidSid), { method: 'DELETE' });
    delete mutedSids[gidSid];
    applyFilters();
    renderMutedList();
    updateMutedCounter();
    showToast('🔔 ' + gidSid + ' réactivé', 'ok');
  } catch (e) { showToast('Erreur: ' + e.message, 'err'); }
};

function renderMutedList() {
  const el = document.getElementById('mutedList');
  if (!el) return;
  const entries = Object.entries(mutedSids);
  if (!entries.length) {
    el.innerHTML = '<p class="text-gray-600 text-xs px-3 py-1">Aucun filtre actif</p>';
    return;
  }
  el.innerHTML = entries.map(function(entry) {
    const gidSid = entry[0], label = entry[1];
    const safeGs  = gidSid.replace(/'/g, "\\'");
    const safeL   = String(label).replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return '<div class="flex items-center gap-1 px-3 py-1.5 border-b border-gray-800/50 last:border-0">' +
      '<span class="font-mono text-orange-400/60 text-xs w-14 shrink-0">' + gidSid + '</span>' +
      '<span class="text-gray-500 text-xs truncate flex-1" title="' + safeL + '">' + safeL + '</span>' +
      '<button onclick="unmuteGidSid(\'' + safeGs + '\')" ' +
              'class="text-gray-600 hover:text-red-400 text-xs shrink-0 px-1" title="Réactiver">✕</button>' +
      '</div>';
  }).join('');
}

function updateMutedCounter() {
  const btn = document.getElementById('btnToggleMuted');
  if (!btn) return;
  const n = Object.keys(mutedSids).length;
  if (showMuted) {
    btn.textContent = '🔔 Afficher tout';
    btn.className = btn.className.replace('bg-yellow-900/50','bg-gray-800') || btn.className;
  } else {
    btn.textContent = n ? '🔇 Bruit (' + n + ')' : '🔇 Bruit';
  }
  btn.classList.toggle('bg-yellow-900/50', n > 0 && !showMuted);
  btn.classList.toggle('text-yellow-300',  n > 0 && !showMuted);
  btn.classList.toggle('bg-gray-800',      n === 0 || showMuted);
  btn.classList.toggle('text-gray-300',    n === 0 || showMuted);
}

document.getElementById('btnToggleMuted').addEventListener('click', function() {
  showMuted = !showMuted;
  applyFilters();
  updateMutedCounter();
});

// ── Alert detail modal ────────────────────────────────────────────────────────

const alertModal      = document.getElementById('alertModal');
const alertModalClose = document.getElementById('alertModalClose');

function showAlertDetail(parsed) {
  const fields = [
    ['Timestamp',       parsed.isoTs ? parsed.isoTs.replace('T', ' ').replace('Z', '') : '—'],
    ['GID:SID:Rev',     [parsed.gid, parsed.sid, parsed.rev].filter(Boolean).join(':') || '—'],
    ['Message',         parsed.msg || '—'],
    ['Classification',  parsed.classification || '—'],
    ['Priorité',        parsed.priority || '—'],
    ['Protocole',       parsed.proto || '—'],
    ['IP Source',       parsed.srcIp ? (parsed.srcIp + (parsed.srcPort ? ':' + parsed.srcPort : '')) : '—'],
    ['IP Destination',  parsed.dstIp ? (parsed.dstIp + (parsed.dstPort ? ':' + parsed.dstPort : '')) : '—'],
    ['Action',          parsed.action],
  ];

  document.getElementById('alertModalContent').innerHTML = fields.map(([k, v]) =>
    '<div class="bg-gray-800/50 rounded p-2"><span class="text-gray-500 block text-xs mb-0.5">' + k + '</span>' +
    '<span class="text-gray-100 font-mono break-all">' + String(v).replace(/</g,'&lt;') + '</span></div>'
  ).join('');
  document.getElementById('alertModalRaw').textContent = parsed.raw;

  // Mute button
  const gidSid     = (parsed.gid && parsed.sid) ? parsed.gid + ':' + parsed.sid : null;
  const actionsEl  = document.getElementById('alertModalActions');
  if (actionsEl) {
    if (gidSid) {
      const alreadyMuted = mutedSids[gidSid] !== undefined;
      const btn = document.createElement('button');
      btn.className   = 'px-3 py-1.5 rounded text-xs transition-colors ' +
        (alreadyMuted
          ? 'bg-yellow-900/40 hover:bg-yellow-800 text-yellow-300'
          : 'bg-gray-700 hover:bg-gray-600 text-gray-300');
      btn.textContent = alreadyMuted
        ? '🔔 Réactiver [' + gidSid + ']'
        : '🔇 Masquer ce type [' + gidSid + ']';
      btn.addEventListener('click', function() {
        alertModal.classList.add('hidden');
        if (alreadyMuted) unmuteGidSid(gidSid);
        else muteGidSid(gidSid, parsed.msg || gidSid);
      });
      actionsEl.innerHTML = '';
      actionsEl.appendChild(btn);
    } else {
      actionsEl.innerHTML = '';
    }
  }

  alertModal.classList.remove('hidden');
}

alertModalClose.addEventListener('click', () => alertModal.classList.add('hidden'));
alertModal.addEventListener('click', (e) => { if (e.target === alertModal) alertModal.classList.add('hidden'); });

// ── Socket events ─────────────────────────────────────────────────────────────

socket.on('connect', function() {
  liveStatus.textContent = 'Connecté';
  liveIndicator.classList.remove('bg-gray-600', 'bg-red-600');
  liveIndicator.classList.add('bg-green-500');
});

socket.on('disconnect', function() {
  liveStatus.textContent = 'Déconnecté';
  liveIndicator.classList.remove('bg-green-500');
  liveIndicator.classList.add('bg-red-600');
});

socket.on('log:reset', function(data) {
  const msg = data && data.reason ? data.reason : 'Fichier de log réinitialisé.';
  const div = document.createElement('div');
  div.className = 'text-yellow-400 italic py-1 border-t border-yellow-600/30';
  div.textContent = '⟳ ' + msg;
  logConsole.prepend(div);
  if (chkAutoscroll.checked) logConsole.scrollTop = 0;
});

socket.on('log:line', function(line) {
  const parsed = parseLine(line);
  trackStats(parsed);
  appendLine(line, parsed);
  updateCounters(parsed);
});

// ── Render ────────────────────────────────────────────────────────────────────

function appendLine(text, parsed) {
  const placeholder = logConsole.querySelector('.italic');
  if (placeholder) placeholder.remove();

  const allLines = logConsole.querySelectorAll('div[data-raw]');
  if (allLines.length >= MAX_LINES) {
    const last = allLines[allLines.length - 1];
    if (last) last.remove();
  }

  getFilters();
  const gidSid  = (parsed.gid && parsed.sid) ? parsed.gid + ':' + parsed.sid : '';
  const muted   = gidSid && mutedSids[gidSid] !== undefined;
  const cls     = parsed.action === 'drop' ? 'log-drop' : parsed.action === 'alert' ? 'log-alert' : 'log-info';
  const div     = document.createElement('div');
  div.className        = cls + ' cursor-pointer hover:bg-white/5 rounded px-1';
  div.dataset.raw      = text;
  div.dataset.gidsid   = gidSid;
  if (parsed.isoTs) div.dataset.ts = parsed.isoTs;
  div.innerHTML        = highlightLine(text);

  if (muted && !showMuted) {
    div.style.display = 'none';
  } else {
    div.style.display = lineMatchesFilters(text, parsed.isoTs) ? '' : 'none';
    if (muted) div.classList.add('muted-alert');
  }

  div.addEventListener('click', function() { showAlertDetail(parsed); });
  logConsole.prepend(div);

  if (chkAutoscroll.checked) logConsole.scrollTop = 0;
}

function updateCounters(parsed) {
  if (parsed.action === 'drop') {
    dropCount++;
    document.getElementById('cntDrop').textContent = dropCount + ' drop';
  } else if (parsed.action === 'alert') {
    alertCount++;
    document.getElementById('cntAlert').textContent = alertCount + ' alert';
  }
}

// ── Controls ──────────────────────────────────────────────────────────────────

function resetStats() {
  stats.perMinute      = {};
  stats.sidCounts      = {};
  stats.ipCounts       = {};
  stats.ipGeo          = {};
  stats.protoCounts    = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
  stats.priorityCounts = { '1': 0, '2': 0, '3': 0 };
}

btnClear.addEventListener('click', function() {
  fetch('/api/reset/dashboard', { method: 'POST' }).catch(function() {});
  logConsole.innerHTML = '<p class="text-gray-600 italic">Console vidée.</p>';
  alertCount = 0; dropCount = 0;
  document.getElementById('cntAlert').textContent = '0 alert';
  document.getElementById('cntDrop').textContent  = '0 drop';
  resetStats();
  renderTopSids(); renderTopIps(); drawChart();
});

// ── Export ────────────────────────────────────────────────────────────────────

document.getElementById('btnExportTxt').addEventListener('click', function() {
  const lines = Array.from(logConsole.querySelectorAll('div[data-raw]'))
    .filter(function(d) { return d.style.display !== 'none'; })
    .map(function(d) { return d.dataset.raw; });
  downloadBlob(lines.join('\n'), 'oinkview-' + timestamp() + '.txt', 'text/plain');
  showToast('Export TXT téléchargé', 'ok');
});

document.getElementById('btnExportCsv').addEventListener('click', function() {
  const header = 'timestamp,action,gid,sid,rev,msg,classification,priority,proto,src_ip,src_port,dst_ip,dst_port\n';
  const rows = Array.from(logConsole.querySelectorAll('div[data-raw]'))
    .filter(function(d) { return d.style.display !== 'none'; })
    .map(function(d) {
      const p = parseLine(d.dataset.raw);
      return [
        p.isoTs || '', p.action || '', p.gid || '', p.sid || '', p.rev || '',
        p.msg ? '"' + p.msg.replace(/"/g, '""') + '"' : '',
        p.classification ? '"' + p.classification.replace(/"/g, '""') + '"' : '',
        p.priority || '', p.proto || '',
        p.srcIp || '', p.srcPort || '', p.dstIp || '', p.dstPort || ''
      ].join(',');
    }).join('\n');
  downloadBlob(header + rows, 'oinkview-' + timestamp() + '.csv', 'text/csv');
  showToast('Export CSV téléchargé', 'ok');
});

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function timestamp() {
  return new Date().toISOString().slice(0, 19).replace(/:/g, '-');
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(msg, type) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ' +
    (type === 'ok' ? 'bg-green-800 text-green-200' : 'bg-red-900 text-red-200');
  toast.classList.remove('hidden');
  setTimeout(function() { toast.classList.add('hidden'); }, 3500);
}

document.getElementById('btnResetAll').addEventListener('click', async function() {
  await fetch('/api/reset/dashboard', { method: 'POST' });
  logConsole.innerHTML = '<p class="text-gray-600 italic">Console réinitialisée.</p>';
  alertCount = 0; dropCount = 0;
  document.getElementById('cntAlert').textContent = '0 alert';
  document.getElementById('cntDrop').textContent  = '0 drop';
  resetStats();
  renderTopSids(); renderTopIps(); drawChart();
  showToast('Dashboard réinitialisé', 'ok');
});

// ── Init ──────────────────────────────────────────────────────────────────────
drawChart();
renderTopSids();
renderTopIps();
loadMutedSids();
