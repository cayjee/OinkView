/**
 * rules.js — Rule Builder & Rules List
 * Implements Snort 3 rule syntax generation.
 */
'use strict';

// ── DOM refs ──────────────────────────────────────────────────────────────────

const ruleType      = document.getElementById('ruleType');
const ruleAction    = document.getElementById('ruleAction');
const ruleProto     = document.getElementById('ruleProto');
const ruleDir       = document.getElementById('ruleDir');
const ruleSrcIp     = document.getElementById('ruleSrcIp');
const ruleSrcPort   = document.getElementById('ruleSrcPort');
const ruleDstIp     = document.getElementById('ruleDstIp');
const ruleDstPort   = document.getElementById('ruleDstPort');
const ruleService   = document.getElementById('ruleService');
const ruleMsg       = document.getElementById('ruleMsg');
const ruleBuffer    = document.getElementById('ruleBuffer');
const ruleContent   = document.getElementById('ruleContent');
const modNocase     = document.getElementById('modNocase');
const modFastPattern = document.getElementById('modFastPattern');
const ruleFlow      = document.getElementById('ruleFlow');
const ruleSid       = document.getElementById('ruleSid');
const ruleRev       = document.getElementById('ruleRev');
const ruleRem       = document.getElementById('ruleRem');
const rulePreview   = document.getElementById('rulePreview');
const btnSave       = document.getElementById('btnSave');
const btnRefreshRules = document.getElementById('btnRefreshRules');
const btnReload     = document.getElementById('btnReload');
const rulesTbody    = document.getElementById('rulesTbody');
const searchRules   = document.getElementById('searchRules');
const rulesCount    = document.getElementById('rulesCount');
const modal         = document.getElementById('modal');
const modalContent  = document.getElementById('modalContent');
const modalClose    = document.getElementById('modalClose');

// ── State ─────────────────────────────────────────────────────────────────────

let allRules = [];       // règles locales
let communityRules = []; // règles communautaires
let mergedRules = [];    // toutes les règles fusionnées

// ── Init ─────────────────────────────────────────────────────────────────────

(async function init() {
  // Charger le nom du fichier de règles depuis les settings
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    if (s.rulesFile) {
      const filename = s.rulesFile.split('/').pop();
      const el = document.getElementById('btnSaveFilename');
      if (el) el.textContent = filename;
    }
  } catch (_) {}

  await fetchNextSid();
  await Promise.all([loadRules(), loadCategories()]);
  updatePreview();
})();

// ── Rule type toggle ──────────────────────────────────────────────────────────

ruleType.addEventListener('change', () => {
  const type = ruleType.value;
  document.getElementById('traditionalFields').classList.toggle('hidden', type !== 'traditional');
  document.getElementById('serviceField').classList.toggle('hidden', type !== 'service');
  updatePreview();
});

// ── Live preview: update on any input change ──────────────────────────────────

[ruleType, ruleAction, ruleProto, ruleDir, ruleSrcIp, ruleSrcPort,
 ruleDstIp, ruleDstPort, ruleService, ruleMsg, ruleBuffer, ruleContent,
 modNocase, modFastPattern, ruleFlow, ruleRev, ruleRem
].forEach(el => el.addEventListener('input', updatePreview));

[ruleType, ruleAction, ruleProto, ruleDir, ruleService, ruleFlow
].forEach(el => el.addEventListener('change', updatePreview));

// ── Rule generation ───────────────────────────────────────────────────────────

/**
 * Assembles a valid Snort 3 rule string from the form values.
 */
function buildRule() {
  const type   = ruleType.value;
  const action = ruleAction.value;
  const msg    = ruleMsg.value.trim().replace(/"/g, '\\"') || 'New Rule';
  const sid    = ruleSid.value || '1000001';
  const rev    = ruleRev.value || '1';

  // ── Header ──────────────────────────────────────────────────────────────────
  let header;
  if (type === 'traditional') {
    const proto    = ruleProto.value;
    const dir      = ruleDir.value;
    const srcIp    = ruleSrcIp.value.trim()   || 'any';
    const srcPort  = ruleSrcPort.value.trim() || 'any';
    const dstIp    = ruleDstIp.value.trim()   || 'any';
    const dstPort  = ruleDstPort.value.trim() || 'any';
    header = `${action} ${proto} ${srcIp} ${srcPort} ${dir} ${dstIp} ${dstPort}`;
  } else if (type === 'service') {
    header = `${action} ${ruleService.value}`;
  } else {
    // file rule
    header = `${action} file`;
  }

  // ── Options ─────────────────────────────────────────────────────────────────
  const opts = [];

  opts.push(`msg:"${msg}"`);

  // Flow
  const flowVal = ruleFlow.value;
  if (flowVal) opts.push(flowVal.replace(/;$/, ''));

  // Payload: sticky buffer + content + modifiers
  const buf     = ruleBuffer.value;
  const content = ruleContent.value.trim();
  if (content) {
    if (buf) opts.push(buf);  // Snort 3 sticky buffer (no value, just keyword+semicolon)
    let contentOpt = `content:"${content.replace(/"/g, '\\"')}"`;
    if (modFastPattern.checked) contentOpt += ', fast_pattern';
    if (modNocase.checked)      contentOpt += ', nocase';
    opts.push(contentOpt);
  }

  opts.push(`sid:${sid}`);
  opts.push(`rev:${rev}`);

  const rem = ruleRem.value.trim().replace(/"/g, '\\"');
  if (rem) opts.push(`rem:"${rem}"`);

  return `${header} ( ${opts.join('; ')}; )`;
}

function updatePreview() {
  rulePreview.textContent = buildRule();
}

// ── SID management ────────────────────────────────────────────────────────────

async function fetchNextSid() {
  try {
    const r = await fetch('/api/rules/next-sid');
    const { sid } = await r.json();
    ruleSid.value = sid;
  } catch (_) {
    ruleSid.value = 1000001;
  }
}

// ── Save rule ─────────────────────────────────────────────────────────────────

btnSave.addEventListener('click', async () => {
  const rule = buildRule();
  if (!ruleMsg.value.trim()) return showToast('⚠ Champ "msg" requis.', 'warn');

  btnSave.disabled = true;
  try {
    const r    = await fetch('/api/rules', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rule })
    });
    const data = await r.json();
    if (data.success) {
      showToast('✔ Règle ajoutée dans local.rules', 'ok');
      await fetchNextSid();
      updatePreview();
      await loadRules();
    } else {
      showToast(`✖ ${data.error}`, 'err');
    }
  } catch (e) {
    showToast(`✖ ${e.message}`, 'err');
  } finally {
    btnSave.disabled = false;
  }
});

// ── Load rules list ───────────────────────────────────────────────────────────

async function loadRules() {
  try {
    // Charger les règles locales et communautaires en parallèle
    const [localRes, commRes] = await Promise.all([
      fetch('/api/rules'),
      fetch('/api/rules/community')
    ]);
    const localData = await localRes.json();
    const commData  = await commRes.json();

    allRules       = localData.rules   || [];
    communityRules = commData.rules    || [];
    mergedRules    = [...allRules, ...communityRules];
    applyFilters();
    rulesCount.textContent = `${allRules.length} locale(s) · ${communityRules.length} communautaire(s)`;
  } catch (e) {
    showToast(`✖ ${e.message}`, 'err');
  }
}

btnRefreshRules.addEventListener('click', () => { loadRules(); loadCategories(); });

// ── Catégories ────────────────────────────────────────────────────────────────

async function loadCategories() {
  try {
    const r    = await fetch('/api/rules/categories');
    const data = await r.json();

    const catSel  = document.getElementById('filterCategory');
    const clsSel  = document.getElementById('filterClasstype');

    // Peupler catégories (préfixes msg)
    data.categories.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c; opt.textContent = c;
      catSel.appendChild(opt);
    });

    // Peupler classtypes
    data.classtypes.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c; opt.textContent = c;
      clsSel.appendChild(opt);
    });
  } catch (_) {}
}

document.getElementById('filterCategory').addEventListener('change', applyFilters);
document.getElementById('filterClasstype').addEventListener('change', applyFilters);
document.getElementById('btnResetFilters').addEventListener('click', () => {
  document.getElementById('searchRules').value      = '';
  document.getElementById('filterSource').value     = 'all';
  document.getElementById('filterCategory').value   = '';
  document.getElementById('filterClasstype').value  = '';
  applyFilters();
});

// ── Search filter ─────────────────────────────────────────────────────────────

searchRules.addEventListener('input', applyFilters);
document.getElementById('filterSource').addEventListener('change', applyFilters);

function applyFilters() {
  const q         = searchRules.value.toLowerCase();
  const source    = document.getElementById('filterSource').value;
  const category  = document.getElementById('filterCategory').value;
  const classtype = document.getElementById('filterClasstype').value;

  let base = mergedRules;
  if (source === 'local')     base = allRules;
  if (source === 'community') base = communityRules;

  const filtered = base.filter(rule => {
    if (category  && rule.category  !== category)  return false;
    if (classtype && rule.classtype !== classtype)  return false;
    if (q && !(
      (rule.sid      && rule.sid.includes(q)) ||
      (rule.msg      && rule.msg.toLowerCase().includes(q)) ||
      (rule.action   && rule.action.includes(q)) ||
      (rule.filePath && rule.filePath.toLowerCase().includes(q)) ||
      rule.raw.toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderRules(filtered);
  rulesCount.textContent = `${filtered.length} affiché(s) · ${allRules.length} locale(s) · ${communityRules.length} communautaire(s)`;
}

// ── Render rules table ────────────────────────────────────────────────────────

const ACTION_COLORS = {
  alert:   'text-red-400',
  drop:    'text-orange-400',
  pass:    'text-green-400',
  reject:  'text-yellow-400',
  unknown: 'text-gray-400'
};

function renderRules(rules) {
  if (!rules.length) {
    rulesTbody.innerHTML = '<tr><td colspan="5" class="px-4 py-8 text-center text-gray-600 text-xs">Aucune règle trouvée.</td></tr>';
    return;
  }

  rulesTbody.innerHTML = rules.map(rule => {
    const color   = ACTION_COLORS[rule.action] || ACTION_COLORS.unknown;
    const opacity = rule.disabled ? 'opacity-40' : '';
    const sidText = rule.sid ? `#${rule.sid}` : '—';
    const isLocal     = rule.editable !== false;
    const sourceBadge = isLocal
      ? '<span class="px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-300">locale</span>'
      : `<span class="px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 truncate max-w-[80px] inline-block" title="${escHtml(rule.filePath || '')}">${escHtml(rule.filePath || 'communauté')}</span>`;

    // Encodage sûr de la règle brute pour passer en attribut HTML
    const rawEncoded = encodeURIComponent(rule.raw);

    return `
      <tr class="hover:bg-gray-900/50 transition-colors ${opacity}" data-sid="${rule.sid || ''}">
        <td class="px-4 py-2.5 font-semibold text-xs ${color}">${rule.action}</td>
        <td class="px-4 py-2.5 text-orange-300 text-xs">${sidText}</td>
        <td class="px-4 py-2.5 text-gray-300 text-xs max-w-xs truncate" title="${escHtml(rule.msg)}">${escHtml(rule.msg)}</td>
        <td class="px-4 py-2.5 text-xs">${sourceBadge}</td>
        <td class="px-4 py-2.5 text-xs">
          ${rule.disabled
            ? '<span class="px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">désactivée</span>'
            : '<span class="px-1.5 py-0.5 rounded bg-green-900/40 text-green-400">active</span>'}
        </td>
        <td class="px-4 py-2.5 text-right space-x-1">
          <button onclick="loadIntoBuilder('${rawEncoded}')" title="Charger dans l'éditeur"
                  class="px-2 py-1 rounded bg-orange-900/40 hover:bg-orange-800 text-orange-300 text-xs transition-colors">✎ éditer</button>
          <button onclick="showRaw('${rule.sid}')" title="Voir la règle brute"
                  class="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs transition-colors">⊞</button>
          ${!isLocal ? `
          <button onclick="copyToLocal('${rawEncoded}')" title="Copier vers local.rules"
                  class="px-2 py-1 rounded bg-green-900/40 hover:bg-green-900 text-green-300 text-xs transition-colors">+ local</button>
          ` : `
          <button onclick="toggleRule('${rule.sid}')" title="${rule.disabled ? 'Activer' : 'Désactiver'}"
                  class="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs transition-colors">
            ${rule.disabled ? '▶' : '⏸'}
          </button>
          <button onclick="deleteRule('${rule.sid}')" title="Supprimer"
                  class="px-2 py-1 rounded bg-red-900/40 hover:bg-red-900 text-red-300 text-xs transition-colors">✕</button>
          `}
        </td>
      </tr>`;
  }).join('');
}

// ── Rule actions (global for onclick handlers) ────────────────────────────────

window.showRaw = (sid) => {
  const rule = mergedRules.find(r => r.sid === String(sid));
  if (!rule) return;
  modalContent.textContent = rule.raw;
  modal.classList.remove('hidden');
};

/**
 * Parse une règle Snort brute et remplit le formulaire de l'éditeur.
 * Le SID est remplacé par le prochain SID disponible (nouvelle règle).
 */
window.loadIntoBuilder = async (rawEncoded) => {
  const raw = decodeURIComponent(rawEncoded).trim().replace(/^#\s*/, '');

  // ── 1. Header : action + type ────────────────────────────────────────────
  const headerMatch = raw.match(/^(alert|drop|pass|reject|rewrite)\s+(\S+)/);
  if (!headerMatch) return showToast('Format de règle non reconnu', 'warn');

  const action  = headerMatch[1];
  const second  = headerMatch[2]; // proto, service name, ou "file"

  ruleAction.value = action;

  // Déterminer le type
  const services    = ['http','ftp','smtp','ssl','ssh','dns','dce_http_proxy','dce_http_server'];
  const protocols   = ['tcp','udp','icmp','ip'];

  let type;
  if (second === 'file') {
    type = 'file';
  } else if (services.includes(second)) {
    type = 'service';
    ruleService.value = second;
  } else {
    type = 'traditional';
    ruleProto.value = second;
  }

  // Mettre à jour le sélecteur de type et afficher/masquer les champs
  ruleType.value = type;
  document.getElementById('traditionalFields').classList.toggle('hidden', type !== 'traditional');
  document.getElementById('serviceField').classList.toggle('hidden', type !== 'service');

  // ── 2. Header traditionnel : src/dir/dst ─────────────────────────────────
  if (type === 'traditional') {
    // Format : action proto srcIp srcPort direction dstIp dstPort ( ... )
    const trad = raw.match(/^\S+\s+\S+\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\(/);
    if (trad) {
      ruleSrcIp.value   = trad[1];
      ruleSrcPort.value = trad[2];
      ruleDir.value     = trad[3];
      ruleDstIp.value   = trad[4];
      ruleDstPort.value = trad[5];
    }
  }

  // ── 3. Options ────────────────────────────────────────────────────────────
  const optsMatch = raw.match(/\((.+)\)\s*$/s);
  const opts      = optsMatch ? optsMatch[1] : '';

  // msg
  const msgM = opts.match(/\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"/);
  ruleMsg.value = msgM ? msgM[1].replace(/\\"/g, '"') : '';

  // flow
  const flowM = opts.match(/\bflow\s*:\s*([^;]+);/);
  if (flowM) {
    const flowVal = `flow:${flowM[1].trim()};`;
    const flowOpt = document.getElementById('ruleFlow');
    // Chercher l'option correspondante
    const match = [...flowOpt.options].find(o => o.value === flowVal);
    flowOpt.value = match ? flowVal : '';
  } else {
    ruleFlow.value = '';
  }

  // Sticky buffer + content
  const buffers = ['http_uri','http_header','http_method','http_client_body','http_raw_uri','file_data','pkt_data'];
  let foundBuffer = '';
  buffers.forEach(b => { if (opts.includes(b + ';') || opts.includes(b + ',')) foundBuffer = b; });
  ruleBuffer.value = foundBuffer;

  const contentM = opts.match(/\bcontent\s*:\s*"((?:[^"\\]|\\.)*)"/);
  ruleContent.value = contentM ? contentM[1].replace(/\\"/g, '"') : '';

  modNocase.checked      = /\bnocase\b/.test(opts);
  modFastPattern.checked = /\bfast_pattern\b/.test(opts);

  // rev
  const revM = opts.match(/\brev\s*:\s*(\d+)\s*;/);
  ruleRev.value = revM ? revM[1] : '1';

  // rem
  const remM = opts.match(/\brem\s*:\s*"((?:[^"\\]|\\.)*)"/);
  ruleRem.value = remM ? remM[1] : '';

  // ── 4. Nouveau SID (ne pas réutiliser l'ancien) ───────────────────────────
  await fetchNextSid();

  // ── 5. Scroll vers le haut + aperçu ──────────────────────────────────────
  updatePreview();
  document.querySelector('section').scrollTo({ top: 0, behavior: 'smooth' });
  showToast('Règle chargée dans l\'éditeur — SID mis à jour', 'ok');
};

window.copyToLocal = async (rawEncoded) => {
  const rule = decodeURIComponent(rawEncoded);
  try {
    const r = await fetch('/api/rules/copy-to-local', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rule })
    });
    const d = await r.json();
    if (d.success) {
      showToast(`Copiée dans local.rules (nouveau SID: ${d.newSid})`, 'ok');
      await fetchNextSid();
      await loadRules();
    } else {
      showToast(`✖ ${d.error}`, 'err');
    }
  } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
};

window.toggleRule = async (sid) => {
  try {
    const r = await fetch(`/api/rules/${sid}/toggle`, { method: 'PATCH' });
    const d = await r.json();
    if (d.success) { await loadRules(); showToast('Statut modifié', 'ok'); }
    else showToast(`✖ ${d.error}`, 'err');
  } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
};

window.deleteRule = async (sid) => {
  if (!confirm(`Supprimer la règle SID ${sid} ? Cette action est irréversible.`)) return;
  try {
    const r = await fetch(`/api/rules/${sid}`, { method: 'DELETE' });
    const d = await r.json();
    if (d.success) { await loadRules(); showToast('✔ Règle supprimée', 'ok'); }
    else showToast(`✖ ${d.error}`, 'err');
  } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
};

modalClose.addEventListener('click', () => modal.classList.add('hidden'));
modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });

// ── Reload Snort ──────────────────────────────────────────────────────────────

btnReload.addEventListener('click', async () => {
  btnReload.disabled = true;
  try {
    const r = await fetch('/api/reload', { method: 'POST' });
    const d = await r.json();
    showToast(d.success ? '✔ Snort rechargé' : `✖ ${d.error}`, d.success ? 'ok' : 'err');
  } catch (e) { showToast(`✖ ${e.message}`, 'err'); }
  finally { btnReload.disabled = false; }
});

// ── Utilities ─────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type = 'ok') {
  const toast = document.getElementById('toast');
  const colors = { ok: 'bg-green-800 text-green-200', err: 'bg-red-900 text-red-200', warn: 'bg-yellow-800 text-yellow-200' };
  toast.textContent = msg;
  toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3500);
}
