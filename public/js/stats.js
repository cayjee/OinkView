/**
 * stats.js — Page Statistiques OinkView
 */
'use strict';

var ipGeoCache = {};

// ── Chargement principal ───────────────────────────────────────────────────────

async function loadStats() {
  try {
    const r    = await fetch('/api/stats');
    const data = await r.json();
    if (data.error) { showErr(data.error); return; }
    renderCards(data);
    drawTimeChart(data.perMinute);
    drawPie('protoChart', 'protoLegend',
      [
        { label: 'TCP',   value: data.protoCounts.TCP   || 0, color: '#3b82f6' },
        { label: 'UDP',   value: data.protoCounts.UDP   || 0, color: '#10b981' },
        { label: 'ICMP',  value: data.protoCounts.ICMP  || 0, color: '#f59e0b' },
        { label: 'Autre', value: data.protoCounts.OTHER || 0, color: '#8b5cf6' }
      ]
    );
    drawPie('prioChart', 'prioLegend',
      [
        { label: 'Priorite 1', value: data.priorityCounts['1'] || 0, color: '#ef4444' },
        { label: 'Priorite 2', value: data.priorityCounts['2'] || 0, color: '#f97316' },
        { label: 'Priorite 3', value: data.priorityCounts['3'] || 0, color: '#facc15' }
      ]
    );
    renderTopSids(data.sidCounts);
    renderTopIps(data.ipCounts, ipGeoCache);
    loadGeo(Object.keys(data.ipCounts), data.ipCounts);
  } catch (e) {
    showErr(e.message);
  }
}

// ── Cartes ─────────────────────────────────────────────────────────────────────

function renderCards(data) {
  document.getElementById('statTotal').textContent = data.total || 0;
  document.getElementById('statTcp').textContent   = data.protoCounts ? (data.protoCounts.TCP  || 0) : 0;
  document.getElementById('statUdp').textContent   = data.protoCounts ? (data.protoCounts.UDP  || 0) : 0;
  document.getElementById('statIcmp').textContent  = data.protoCounts ? (data.protoCounts.ICMP || 0) : 0;
}

// ── Graphique activite (Canvas) ────────────────────────────────────────────────

function drawTimeChart(perMinute) {
  var canvas = document.getElementById('timeChart');
  if (!canvas) return;
  // Set actual pixel width
  canvas.width = canvas.offsetWidth || 600;
  var ctx = canvas.getContext('2d');
  var W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  var now    = new Date();
  var values = [];
  var labels = [];
  for (var i = 59; i >= 0; i--) {
    var d   = new Date(now - i * 60000);
    var key = d.getFullYear() + '-' +
      String(d.getMonth() + 1).padStart(2, '0') + '-' +
      String(d.getDate()).padStart(2, '0') + 'T' +
      String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0');
    values.push(perMinute[key] || 0);
    labels.push(String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'));
  }

  var maxVal = 1;
  for (var j = 0; j < values.length; j++) { if (values[j] > maxVal) maxVal = values[j]; }

  var pL = 32, pR = 8, pT = 8, pB = 20;
  var cW = W - pL - pR, cH = H - pT - pB;
  var bW = cW / values.length;

  // Grid
  ctx.strokeStyle = '#374151'; ctx.lineWidth = 0.5;
  for (var g = 0; g <= 4; g++) {
    var gy = pT + cH - (cH * g / 4);
    ctx.beginPath(); ctx.moveTo(pL, gy); ctx.lineTo(W - pR, gy); ctx.stroke();
    ctx.fillStyle = '#4b5563'; ctx.font = '9px monospace';
    ctx.fillText(Math.round(maxVal * g / 4), 2, gy + 3);
  }

  // Bars
  for (var k = 0; k < values.length; k++) {
    var bh   = (values[k] / maxVal) * cH;
    var bx   = pL + k * bW;
    var by   = pT + cH - bh;
    var grad = ctx.createLinearGradient(0, by, 0, pT + cH);
    grad.addColorStop(0, '#f97316');
    grad.addColorStop(1, '#7c2d12');
    ctx.fillStyle = grad;
    ctx.fillRect(bx + 0.5, by, Math.max(bW - 1, 1), bh);
  }

  // X labels every 10 min
  ctx.fillStyle = '#6b7280'; ctx.font = '8px monospace';
  for (var l = 0; l < labels.length; l++) {
    if (l % 10 === 0) ctx.fillText(labels[l], pL + l * bW, H - 4);
  }
}

// ── Pie chart SVG ──────────────────────────────────────────────────────────────

function drawPie(svgId, legendId, slices) {
  var svg    = document.getElementById(svgId);
  var legend = document.getElementById(legendId);
  if (!svg || !legend) return;

  var total = 0;
  for (var i = 0; i < slices.length; i++) total += slices[i].value;

  if (total === 0) {
    svg.innerHTML = '<text x="60" y="65" fill="#4b5563" text-anchor="middle" font-size="10">Aucune donnee</text>';
    legend.innerHTML = '';
    return;
  }

  var cx = 60, cy = 60, r = 52;
  var angle = -Math.PI / 2;
  var paths = '';

  for (var j = 0; j < slices.length; j++) {
    if (!slices[j].value) continue;
    var frac       = slices[j].value / total;
    var startAngle = angle;
    angle += frac * 2 * Math.PI;
    var endAngle   = angle;
    var x1 = cx + r * Math.cos(startAngle);
    var y1 = cy + r * Math.sin(startAngle);
    var x2 = cx + r * Math.cos(endAngle);
    var y2 = cy + r * Math.sin(endAngle);
    var large = frac > 0.5 ? 1 : 0;
    paths += '<path d="M' + cx + ',' + cy + ' L' + x1.toFixed(2) + ',' + y1.toFixed(2) +
      ' A' + r + ',' + r + ' 0 ' + large + ',1 ' + x2.toFixed(2) + ',' + y2.toFixed(2) +
      ' Z" fill="' + slices[j].color + '" opacity="0.85"/>';
  }

  svg.innerHTML = paths;

  var legendHtml = '';
  for (var k = 0; k < slices.length; k++) {
    var pct = total > 0 ? Math.round(slices[k].value / total * 100) : 0;
    legendHtml += '<div class="flex items-center gap-2">' +
      '<span class="w-3 h-3 rounded-sm shrink-0" style="background:' + slices[k].color + '"></span>' +
      '<span class="text-gray-300">' + slices[k].label + '</span>' +
      '<span class="text-gray-500 ml-auto">' + pct + '%</span>' +
      '</div>';
  }
  legend.innerHTML = legendHtml;
}

// ── Top SIDs ───────────────────────────────────────────────────────────────────

function renderTopSids(sidCounts) {
  var tbody = document.getElementById('tableSids');
  if (!tbody) return;

  var entries = Object.keys(sidCounts).map(function(sid) {
    return { sid: sid, count: sidCounts[sid].count, msg: sidCounts[sid].msg || '' };
  });
  entries.sort(function(a, b) { return b.count - a.count; });
  entries = entries.slice(0, 10);

  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="px-6 py-4 text-gray-600 text-xs">Aucune regle declenchee</td></tr>';
    return;
  }

  tbody.innerHTML = entries.map(function(e) {
    return '<tr class="hover:bg-gray-800/50">' +
      '<td class="px-6 py-3"><span class="px-2 py-0.5 rounded bg-orange-900/40 text-orange-300 font-mono text-xs">' + e.sid + '</span></td>' +
      '<td class="px-6 py-3 text-gray-300 text-sm max-w-xs truncate" title="' + e.msg + '">' + (e.msg || '—') + '</td>' +
      '<td class="px-6 py-3 text-right"><span class="px-2 py-0.5 rounded-full bg-gray-800 text-gray-300 text-xs font-mono">' + e.count + '</span></td>' +
      '</tr>';
  }).join('');
}

// ── Top IPs ────────────────────────────────────────────────────────────────────

function isPrivateIp(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)/.test(ip);
}

function renderTopIps(ipCounts, geoData) {
  var tbody = document.getElementById('tableIps');
  if (!tbody) return;

  var entries = Object.keys(ipCounts).map(function(ip) {
    return { ip: ip, count: ipCounts[ip] };
  });
  entries.sort(function(a, b) { return b.count - a.count; });
  entries = entries.slice(0, 10);

  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-gray-600 text-xs">Aucune IP detectee</td></tr>';
    return;
  }

  tbody.innerHTML = entries.map(function(e, idx) {
    var geo     = geoData[e.ip];
    var priv    = isPrivateIp(e.ip);
    var country = '—';
    var city    = '—';
    if (priv) {
      country = 'Local (privé)';
    } else if (geo) {
      country = (geo.countryCode ? '[' + geo.countryCode + '] ' : '') + (geo.country || '—');
      city    = geo.city || '—';
    }
    return '<tr class="hover:bg-gray-800/50">' +
      '<td class="px-6 py-3 text-gray-500 text-xs">' + (idx + 1) + '</td>' +
      '<td class="px-6 py-3 font-mono text-cyan-400 text-sm">' + e.ip + '</td>' +
      '<td class="px-6 py-3 text-gray-300 text-sm">' + country + '</td>' +
      '<td class="px-6 py-3 text-gray-400 text-sm">' + city + '</td>' +
      '<td class="px-6 py-3 text-right"><span class="px-2 py-0.5 rounded-full bg-gray-800 text-orange-300 text-xs font-mono">' + e.count + '</span></td>' +
      '</tr>';
  }).join('');
}

// ── Geo lookup ─────────────────────────────────────────────────────────────────

async function loadGeo(allIps, ipCounts) {
  var ips = allIps.filter(function(ip) { return !isPrivateIp(ip) && !ipGeoCache[ip]; }).slice(0, 100);
  if (!ips.length) return;
  try {
    var r    = await fetch('/api/geo/batch', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ips: ips })
    });
    var data = await r.json();
    if (data.results) {
      Object.keys(data.results).forEach(function(ip) { ipGeoCache[ip] = data.results[ip]; });
    }
    renderTopIps(ipCounts, ipGeoCache);
  } catch (_) {}
}

// ── Toast / err ────────────────────────────────────────────────────────────────

function showToast(msg, type) {
  var toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ' +
    (type === 'ok' ? 'bg-green-800 text-green-200' : 'bg-red-900 text-red-200');
  toast.classList.remove('hidden');
  setTimeout(function() { toast.classList.add('hidden'); }, 3500);
}

function showErr(msg) {
  showToast('Erreur: ' + msg, 'err');
}

// ── Events ─────────────────────────────────────────────────────────────────────

document.getElementById('btnRefresh').addEventListener('click', function() { loadStats(); });

document.getElementById('btnReset').addEventListener('click', async function() {
  await fetch('/api/reset/stats', { method: 'POST' });
  ipGeoCache = {};
  document.getElementById('statTotal').textContent = '0';
  document.getElementById('statTcp').textContent   = '0';
  document.getElementById('statUdp').textContent   = '0';
  document.getElementById('statIcmp').textContent  = '0';
  document.getElementById('tableSids').innerHTML   = '<tr><td colspan="3" class="px-6 py-4 text-gray-600 text-xs">Reinitialise.</td></tr>';
  document.getElementById('tableIps').innerHTML    = '<tr><td colspan="5" class="px-6 py-4 text-gray-600 text-xs">Reinitialise.</td></tr>';
  document.getElementById('protoChart').innerHTML  = '';
  document.getElementById('prioChart').innerHTML   = '';
  document.getElementById('protoLegend').innerHTML = '';
  document.getElementById('prioLegend').innerHTML  = '';
  var canvas = document.getElementById('timeChart');
  if (canvas) canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
  showToast('Stats réinitialisées — les anciennes données sont masquées', 'ok');
  loadStats();
});

// ── Init ───────────────────────────────────────────────────────────────────────
loadStats();
