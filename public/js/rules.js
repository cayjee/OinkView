/**
 * rules.js — Rule Builder & Rules List
 * Snort 3 full rule syntax support.
 */
'use strict';

// ── DOM refs ──────────────────────────────────────────────────────────────────

const ruleType        = document.getElementById('ruleType');
const ruleAction      = document.getElementById('ruleAction');
const ruleProto       = document.getElementById('ruleProto');
const ruleDir         = document.getElementById('ruleDir');
const ruleSrcIp       = document.getElementById('ruleSrcIp');
const ruleSrcPort     = document.getElementById('ruleSrcPort');
const ruleDstIp       = document.getElementById('ruleDstIp');
const ruleDstPort     = document.getElementById('ruleDstPort');
const ruleService     = document.getElementById('ruleService');
const ruleMsg         = document.getElementById('ruleMsg');
const rulePcre        = document.getElementById('rulePcre');
const ruleFlow        = document.getElementById('ruleFlow');
const ruleClasstype   = document.getElementById('ruleClasstype');
const rulePriority    = document.getElementById('rulePriority');
const ruleRefType     = document.getElementById('ruleRefType');
const ruleRefId       = document.getElementById('ruleRefId');
const ruleMetadata    = document.getElementById('ruleMetadata');
const ruleItype       = document.getElementById('ruleItype');
const ruleIcode       = document.getElementById('ruleIcode');
const ruleDsize       = document.getElementById('ruleDsize');
const ruleTtl         = document.getElementById('ruleTtl');
const ruleTos         = document.getElementById('ruleTos');
const ruleIpId        = document.getElementById('ruleIpId');
const ruleWindow      = document.getElementById('ruleWindow');
const ruleIpProto     = document.getElementById('ruleIpProto');
const ruleByteTest    = document.getElementById('ruleByteTest');
const ruleByteJump    = document.getElementById('ruleByteJump');
const ruleByteExtract = document.getElementById('ruleByteExtract');
const ruleByteMath    = document.getElementById('ruleByteMath');
const threshType      = document.getElementById('threshType');
const threshTrack     = document.getElementById('threshTrack');
const threshCount     = document.getElementById('threshCount');
const threshSeconds   = document.getElementById('threshSeconds');
const dfTrack         = document.getElementById('dfTrack');
const dfCount         = document.getElementById('dfCount');
const dfSeconds       = document.getElementById('dfSeconds');
const ruleSid         = document.getElementById('ruleSid');
const ruleRev         = document.getElementById('ruleRev');
const ruleRem         = document.getElementById('ruleRem');
const rulePreview     = document.getElementById('rulePreview');
const btnSave         = document.getElementById('btnSave');
const btnRefreshRules = document.getElementById('btnRefreshRules');
const rulesTbody      = document.getElementById('rulesTbody');
const searchRules     = document.getElementById('searchRules');
const rulesCount      = document.getElementById('rulesCount');
const modal           = document.getElementById('modal');
const modalContent    = document.getElementById('modalContent');
const modalClose      = document.getElementById('modalClose');

// ── State ─────────────────────────────────────────────────────────────────────

let allRules       = [];
let communityRules = [];
let mergedRules    = [];
let contentEntries = []; // [{id, buffer, content, nocase, fastPattern, offset, depth, distance, within}]

// ── Sticky buffer list ────────────────────────────────────────────────────────

const STICKY_BUFFERS = [
  // HTTP
  'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header',
  'http_method', 'http_client_body', 'http_raw_body',
  'http_cookie', 'http_raw_cookie',
  'http_stat_code', 'http_stat_msg', 'http_version', 'http_true_ip',
  // File / packet
  'file_data', 'pkt_data', 'raw_data',
  // DNS
  'dns_query',
  // SSL/TLS
  'ssl_state', 'ssl_version',
  // SMTP
  'smtp_from_addr', 'smtp_rcpt_addr', 'smtp_filename', 'smtp_header', 'smtp_body',
  // SIP
  'sip_body', 'sip_header', 'sip_method', 'sip_stat_code', 'sip_uri',
  // SSH
  'ssh_proto', 'ssh_server_version', 'ssh_client_version',
];

function bufferOptions(selected) {
  const opts = STICKY_BUFFERS.map(b =>
    `<option value="${b}" ${selected === b ? 'selected' : ''}>${b}</option>`
  ).join('');
  return `<option value="" ${!selected ? 'selected' : ''}>— aucun buffer —</option>${opts}`;
}

// ── Content entries management ────────────────────────────────────────────────

function addContentEntry(opts = {}) {
  const id = Date.now() + Math.random();
  contentEntries.push({
    id,
    buffer:      opts.buffer      || '',
    content:     opts.content     || '',
    nocase:      opts.nocase      || false,
    fastPattern: opts.fastPattern || false,
    offset:      opts.offset      || '',
    depth:       opts.depth       || '',
    distance:    opts.distance    || '',
    within:      opts.within      || '',
  });
  renderContentEntries();
}

window.removeContentEntry = function(id) {
  contentEntries = contentEntries.filter(e => e.id !== id);
  renderContentEntries();
};

window.updateEntry = function(id, field, value) {
  const entry = contentEntries.find(e => e.id === id);
  if (entry) { entry[field] = value; updatePreview(); }
};

function renderContentEntries() {
  const container = document.getElementById('contentEntriesContainer');
  if (!contentEntries.length) {
    container.innerHTML = '<p class="text-xs text-gray-600 italic">Aucun content — cliquez sur "+ Ajouter content"</p>';
    updatePreview();
    return;
  }

  container.innerHTML = contentEntries.map((entry, idx) => `
    <div class="border border-gray-700 rounded-lg p-3 space-y-2 bg-gray-900/50" data-ceid="${entry.id}">
      <div class="flex items-center gap-2">
        <span class="text-xs text-gray-600 shrink-0">#${idx + 1}</span>
        <select class="form-select flex-1 text-xs" onchange="updateEntry(${entry.id}, 'buffer', this.value)">
          ${bufferOptions(entry.buffer)}
        </select>
        <button onclick="removeContentEntry(${entry.id})"
                class="px-2 py-1 text-red-500 hover:text-red-300 text-xs shrink-0">✕</button>
      </div>
      <input type="text" class="form-input w-full text-xs font-mono"
             placeholder='Valeur du content (ex: /admin.php)'
             value="${escHtml(entry.content)}"
             oninput="updateEntry(${entry.id}, 'content', this.value)"/>
      <div class="flex gap-4 text-xs text-gray-300">
        <label class="flex items-center gap-1 cursor-pointer">
          <input type="checkbox" class="accent-orange-500" ${entry.nocase ? 'checked' : ''}
                 onchange="updateEntry(${entry.id}, 'nocase', this.checked)"> nocase
        </label>
        <label class="flex items-center gap-1 cursor-pointer">
          <input type="checkbox" class="accent-orange-500" ${entry.fastPattern ? 'checked' : ''}
                 onchange="updateEntry(${entry.id}, 'fastPattern', this.checked)"> fast_pattern
        </label>
      </div>
      <div class="grid grid-cols-4 gap-1.5">
        <div>
          <label class="text-xs text-gray-600">offset</label>
          <input type="text" class="form-input text-xs" placeholder="—"
                 value="${escHtml(entry.offset)}"
                 oninput="updateEntry(${entry.id}, 'offset', this.value)"/>
        </div>
        <div>
          <label class="text-xs text-gray-600">depth</label>
          <input type="text" class="form-input text-xs" placeholder="—"
                 value="${escHtml(entry.depth)}"
                 oninput="updateEntry(${entry.id}, 'depth', this.value)"/>
        </div>
        <div>
          <label class="text-xs text-gray-600">distance</label>
          <input type="text" class="form-input text-xs" placeholder="—"
                 value="${escHtml(entry.distance)}"
                 oninput="updateEntry(${entry.id}, 'distance', this.value)"/>
        </div>
        <div>
          <label class="text-xs text-gray-600">within</label>
          <input type="text" class="form-input text-xs" placeholder="—"
                 value="${escHtml(entry.within)}"
                 oninput="updateEntry(${entry.id}, 'within', this.value)"/>
        </div>
      </div>
    </div>
  `).join('');
  updatePreview();
}

document.getElementById('btnAddContent').addEventListener('click', () => addContentEntry());

// ── Init ──────────────────────────────────────────────────────────────────────

(async function init() {
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    if (s.rulesFile) {
      const el = document.getElementById('btnSaveFilename');
      if (el) el.textContent = s.rulesFile.split('/').pop();
    }
  } catch (_) {}

  await fetchNextSid();
  await Promise.all([loadRules(), loadCategories()]);
  renderContentEntries();
  updatePreview();
})();

// ── Rule type toggle ──────────────────────────────────────────────────────────

ruleType.addEventListener('change', () => {
  const type = ruleType.value;
  document.getElementById('traditionalFields').classList.toggle('hidden', type !== 'traditional');
  document.getElementById('serviceField').classList.toggle('hidden', type !== 'service');
  updatePreview();
});

// ── Live preview: watch all simple fields ─────────────────────────────────────

[ruleType, ruleAction, ruleProto, ruleDir, ruleSrcIp, ruleSrcPort,
 ruleDstIp, ruleDstPort, ruleService, ruleMsg, rulePcre,
 ruleFlow, ruleClasstype, rulePriority, ruleRefType, ruleRefId,
 ruleMetadata, ruleItype, ruleIcode, ruleDsize, ruleTtl, ruleTos,
 ruleIpId, ruleWindow, ruleIpProto,
 ruleByteTest, ruleByteJump, ruleByteExtract, ruleByteMath,
 threshType, threshTrack, threshCount, threshSeconds,
 dfTrack, dfCount, dfSeconds,
 ruleRev, ruleRem,
 document.getElementById('flagsMod'), document.getElementById('fragMod'),
].forEach(el => { if (el) el.addEventListener('input', updatePreview); });

[ruleType, ruleAction, ruleProto, ruleDir, ruleService, ruleFlow,
 ruleClasstype, threshType, threshTrack, dfTrack,
 document.getElementById('flagsMod'), document.getElementById('fragMod'),
].forEach(el => { if (el) el.addEventListener('change', updatePreview); });

// TCP flags checkboxes
['flagS','flagA','flagF','flagR','flagP','flagU','flagC','flagE',
 'fragM','fragD','fragR',
].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', updatePreview);
});

// ── Rule builder ──────────────────────────────────────────────────────────────

function buildRule() {
  const type   = ruleType.value;
  const action = ruleAction.value;
  const msg    = ruleMsg.value.trim().replace(/"/g, '\\"') || 'New Rule';
  const sid    = ruleSid.value || '1000001';
  const rev    = ruleRev.value || '1';

  // ── Header ──────────────────────────────────────────────────────────────────
  let header;
  if (type === 'traditional') {
    const proto   = ruleProto.value;
    const dir     = ruleDir.value;
    const srcIp   = ruleSrcIp.value.trim()   || 'any';
    const srcPort = ruleSrcPort.value.trim() || 'any';
    const dstIp   = ruleDstIp.value.trim()   || 'any';
    const dstPort = ruleDstPort.value.trim() || 'any';
    header = `${action} ${proto} ${srcIp} ${srcPort} ${dir} ${dstIp} ${dstPort}`;
  } else if (type === 'service') {
    header = `${action} ${ruleService.value}`;
  } else {
    header = `${action} file`;
  }

  // ── Options ──────────────────────────────────────────────────────────────────
  const opts = [];

  opts.push(`msg:"${msg}"`);

  // classtype
  if (ruleClasstype.value) opts.push(`classtype:${ruleClasstype.value}`);

  // priority
  if (rulePriority.value) opts.push(`priority:${rulePriority.value}`);

  // reference
  if (ruleRefId.value.trim()) opts.push(`reference:${ruleRefType.value},${ruleRefId.value.trim()}`);

  // flow
  const flowVal = ruleFlow.value;
  if (flowVal) opts.push(flowVal.replace(/;$/, ''));

  // TCP flags
  const flagLetters = ['S','A','F','R','P','U','C','E']
    .filter(f => document.getElementById('flag' + f)?.checked)
    .join('');
  if (flagLetters) {
    const mod = document.getElementById('flagsMod').value;
    opts.push(`flags:${mod}${flagLetters}`);
  }

  // itype / icode
  if (ruleItype.value.trim()) opts.push(`itype:${ruleItype.value.trim()}`);
  if (ruleIcode.value.trim()) opts.push(`icode:${ruleIcode.value.trim()}`);

  // dsize
  if (ruleDsize.value.trim()) opts.push(`dsize:${ruleDsize.value.trim()}`);

  // TTL / TOS / IP ID
  if (ruleTtl.value.trim())    opts.push(`ttl:${ruleTtl.value.trim()}`);
  if (ruleTos.value.trim())    opts.push(`tos:${ruleTos.value.trim()}`);
  if (ruleIpId.value.trim())   opts.push(`id:${ruleIpId.value.trim()}`);

  // window
  if (ruleWindow.value.trim()) opts.push(`window:${ruleWindow.value.trim()}`);

  // ip_proto
  if (ruleIpProto.value.trim()) opts.push(`ip_proto:${ruleIpProto.value.trim()}`);

  // fragbits
  const fragLetters = ['M','D','R']
    .filter(f => document.getElementById('frag' + f)?.checked)
    .join('');
  if (fragLetters) {
    const mod = document.getElementById('fragMod').value;
    opts.push(`fragbits:${mod}${fragLetters}`);
  }

  // ── Content entries ──────────────────────────────────────────────────────────
  contentEntries.forEach(entry => {
    if (!entry.content.trim()) return;
    if (entry.buffer) opts.push(entry.buffer);
    let co = `content:"${entry.content.replace(/"/g, '\\"')}"`;
    if (entry.fastPattern) co += ', fast_pattern';
    if (entry.nocase)      co += ', nocase';
    opts.push(co);
    if (entry.offset.trim())   opts.push(`offset:${entry.offset.trim()}`);
    if (entry.depth.trim())    opts.push(`depth:${entry.depth.trim()}`);
    if (entry.distance.trim()) opts.push(`distance:${entry.distance.trim()}`);
    if (entry.within.trim())   opts.push(`within:${entry.within.trim()}`);
  });

  // pcre
  if (rulePcre.value.trim()) opts.push(`pcre:"${rulePcre.value.trim().replace(/"/g, '\\"')}"`);

  // byte operations
  if (ruleByteTest.value.trim())    opts.push(`byte_test:${ruleByteTest.value.trim()}`);
  if (ruleByteJump.value.trim())    opts.push(`byte_jump:${ruleByteJump.value.trim()}`);
  if (ruleByteExtract.value.trim()) opts.push(`byte_extract:${ruleByteExtract.value.trim()}`);
  if (ruleByteMath.value.trim())    opts.push(`byte_math:${ruleByteMath.value.trim()}`);

  // threshold
  if (threshType.value && threshCount.value && threshSeconds.value) {
    opts.push(`threshold:type ${threshType.value}, track ${threshTrack.value}, count ${threshCount.value}, seconds ${threshSeconds.value}`);
  }

  // detection_filter
  if (dfTrack.value && dfCount.value && dfSeconds.value) {
    opts.push(`detection_filter:track ${dfTrack.value}, count ${dfCount.value}, seconds ${dfSeconds.value}`);
  }

  opts.push(`sid:${sid}`);
  opts.push(`rev:${rev}`);

  if (ruleMetadata.value.trim()) opts.push(`metadata:${ruleMetadata.value.trim()}`);

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
  if (!ruleMsg.value.trim()) return showToast('Champ "msg" requis.', 'warn');

  btnSave.disabled = true;
  try {
    const r = await fetch('/api/rules', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rule })
    });
    const data = await r.json();
    if (data.success) {
      showToast('Règle ajoutée dans local.rules', 'ok');
      await fetchNextSid();
      updatePreview();
      await loadRules();
    } else {
      showToast(`Erreur: ${data.error}`, 'err');
    }
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'err');
  } finally {
    btnSave.disabled = false;
  }
});

// ── Load rules list ───────────────────────────────────────────────────────────

async function loadRules() {
  try {
    const [localRes, commRes] = await Promise.all([
      fetch('/api/rules'),
      fetch('/api/rules/community')
    ]);
    const localData = await localRes.json();
    const commData  = await commRes.json();

    allRules       = localData.rules  || [];
    communityRules = commData.rules   || [];
    mergedRules    = [...allRules, ...communityRules];
    applyFilters();
    rulesCount.textContent = `${allRules.length} locale(s) · ${communityRules.length} communautaire(s)`;
  } catch (e) {
    showToast(`Erreur: ${e.message}`, 'err');
  }
}

btnRefreshRules.addEventListener('click', () => { loadRules(); loadCategories(); });

// ── Categories ────────────────────────────────────────────────────────────────

async function loadCategories() {
  try {
    const r    = await fetch('/api/rules/categories');
    const data = await r.json();
    const catSel = document.getElementById('filterCategory');
    const clsSel = document.getElementById('filterClasstype');

    // Clear existing options (keep first)
    while (catSel.options.length > 1) catSel.remove(1);
    while (clsSel.options.length > 1) clsSel.remove(1);

    data.categories.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c; opt.textContent = c;
      catSel.appendChild(opt);
    });
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
  document.getElementById('searchRules').value     = '';
  document.getElementById('filterSource').value    = 'all';
  document.getElementById('filterCategory').value  = '';
  document.getElementById('filterClasstype').value = '';
  applyFilters();
});

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
  rewrite: 'text-blue-400',
  unknown: 'text-gray-400'
};

function renderRules(rules) {
  if (!rules.length) {
    rulesTbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-gray-600 text-xs">Aucune règle trouvée.</td></tr>';
    return;
  }

  rulesTbody.innerHTML = rules.map(rule => {
    const color      = ACTION_COLORS[rule.action] || ACTION_COLORS.unknown;
    const opacity    = rule.disabled ? 'opacity-40' : '';
    const sidText    = rule.sid ? `#${rule.sid}` : '—';
    const isLocal    = rule.editable !== false;
    const rawEncoded = encodeURIComponent(rule.raw);
    const isChecked  = rule.sid && selectedSids.has(rule.sid) ? 'checked' : '';
    const sourceBadge = isLocal
      ? '<span class="px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-300">locale</span>'
      : `<span class="px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 truncate max-w-[80px] inline-block" title="${escHtml(rule.filePath || '')}">${escHtml(rule.filePath ? rule.filePath.split('/').pop() : 'communauté')}</span>`;

    const inLocalCell = !isLocal
      ? (rule.inLocal
          ? '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-green-900/60 text-green-400 text-xs font-bold" title="Copiée dans local.rules">✓</span>'
          : '<span class="text-gray-700 text-xs" title="Pas encore dans local.rules">○</span>')
      : '<span class="text-gray-800 text-xs">—</span>';

    return `
      <tr class="hover:bg-gray-900/50 transition-colors ${opacity}" data-sid="${rule.sid || ''}">
        <td class="px-3 py-2.5">
          ${rule.sid ? `<input type="checkbox" class="rule-chk accent-orange-500" data-sid="${rule.sid}" ${isChecked} onchange="onRuleChkChange(this)"/>` : ''}
        </td>
        <td class="px-4 py-2.5 font-semibold text-xs ${color}">${rule.action}</td>
        <td class="px-4 py-2.5 text-orange-300 text-xs">${sidText}</td>
        <td class="px-4 py-2.5 text-gray-300 text-xs max-w-xs truncate" title="${escHtml(rule.msg)}">${escHtml(rule.msg)}</td>
        <td class="px-4 py-2.5 text-xs">${sourceBadge}</td>
        <td class="px-4 py-2.5 text-center">${inLocalCell}</td>
        <td class="px-4 py-2.5 text-xs">
          ${rule.disabled
            ? '<span class="px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">désactivée</span>'
            : '<span class="px-1.5 py-0.5 rounded bg-green-900/40 text-green-400">active</span>'}
        </td>
        <td class="px-4 py-2.5 text-right space-x-1">
          <button onclick="loadIntoBuilder('${rawEncoded}')" title="Charger dans l'éditeur"
                  class="px-2 py-1 rounded bg-orange-900/40 hover:bg-orange-800 text-orange-300 text-xs transition-colors">✎</button>
          <button onclick="showRaw('${rule.sid}')" title="Voir la règle brute"
                  class="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs transition-colors">⊞</button>
          ${!isLocal ? `
          <button onclick="copyToLocal('${rawEncoded}')" title="Copier vers local.rules"
                  class="px-2 py-1 rounded bg-green-900/40 hover:bg-green-900 text-green-300 text-xs transition-colors">+local</button>
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

window.onRuleChkChange = function(chk) {
  const sid = chk.dataset.sid;
  if (chk.checked) selectedSids.add(sid);
  else             selectedSids.delete(sid);
  updateBulkToolbar();
};

// ── Rule actions ──────────────────────────────────────────────────────────────

window.showRaw = (sid) => {
  const rule = mergedRules.find(r => r.sid === String(sid));
  if (!rule) return;
  modalContent.textContent = rule.raw;
  modal.classList.remove('hidden');
};

/**
 * Parse une règle brute Snort 3 et remplit tous les champs du formulaire.
 */
window.loadIntoBuilder = async (rawEncoded) => {
  const raw = decodeURIComponent(rawEncoded).trim().replace(/^#\s*/, '');

  // ── 1. Header ────────────────────────────────────────────────────────────────
  const headerMatch = raw.match(/^(alert|drop|pass|reject|rewrite)\s+(\S+)/);
  if (!headerMatch) return showToast('Format de règle non reconnu', 'warn');

  const action = headerMatch[1];
  const second = headerMatch[2];

  ruleAction.value = action;

  const SERVICES  = ['http','ftp','smtp','ssl','ssh','dns','dce_http_proxy','dce_http_server',
                     'sip','imap','pop3','telnet','dcerpc','netbios-ssn'];
  const PROTOCOLS = ['tcp','udp','icmp','ip'];

  let type;
  if (second === 'file') {
    type = 'file';
  } else if (SERVICES.includes(second)) {
    type = 'service';
    ruleService.value = second;
  } else if (PROTOCOLS.includes(second)) {
    type = 'traditional';
    ruleProto.value = second;
  } else {
    type = 'traditional';
  }

  ruleType.value = type;
  document.getElementById('traditionalFields').classList.toggle('hidden', type !== 'traditional');
  document.getElementById('serviceField').classList.toggle('hidden', type !== 'service');

  // ── 2. Traditional header ────────────────────────────────────────────────────
  if (type === 'traditional') {
    const trad = raw.match(/^\S+\s+\S+\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\(/);
    if (trad) {
      ruleSrcIp.value   = trad[1];
      ruleSrcPort.value = trad[2];
      ruleDir.value     = trad[3];
      ruleDstIp.value   = trad[4];
      ruleDstPort.value = trad[5];
    }
  }

  // ── 3. Options block ─────────────────────────────────────────────────────────
  const optsMatch = raw.match(/\((.+)\)\s*$/s);
  const opts      = optsMatch ? optsMatch[1] : '';

  // msg
  const msgM = opts.match(/\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"/);
  ruleMsg.value = msgM ? msgM[1].replace(/\\"/g, '"') : '';

  // classtype
  const ctM = opts.match(/\bclasstype\s*:\s*([^;]+);/);
  ruleClasstype.value = ctM ? ctM[1].trim() : '';

  // priority
  const prioM = opts.match(/\bpriority\s*:\s*(\d+)\s*;/);
  rulePriority.value = prioM ? prioM[1] : '';

  // reference
  const refM = opts.match(/\breference\s*:\s*([^,]+),([^;]+);/);
  if (refM) {
    ruleRefType.value = refM[1].trim();
    ruleRefId.value   = refM[2].trim();
  } else {
    ruleRefType.value = 'cve';
    ruleRefId.value   = '';
  }

  // metadata
  const metaM = opts.match(/\bmetadata\s*:\s*([^;]+);/);
  ruleMetadata.value = metaM ? metaM[1].trim() : '';

  // flow
  const flowM = opts.match(/\bflow\s*:\s*([^;]+);/);
  if (flowM) {
    const flowVal = `flow:${flowM[1].trim()};`;
    const match   = [...ruleFlow.options].find(o => o.value === flowVal);
    ruleFlow.value = match ? flowVal : '';
  } else {
    ruleFlow.value = '';
  }

  // TCP flags
  const flagsM = opts.match(/\bflags\s*:\s*([!*+]?)([SAFRPUCE]+)\s*;/i);
  ['flagS','flagA','flagF','flagR','flagP','flagU','flagC','flagE'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.checked = false;
  });
  if (flagsM) {
    const mod   = flagsM[1];
    const flags = flagsM[2].toUpperCase();
    document.getElementById('flagsMod').value = mod;
    for (const f of flags) {
      const el = document.getElementById('flag' + f);
      if (el) el.checked = true;
    }
  }

  // itype / icode
  const itypeM = opts.match(/\bitype\s*:\s*([^;]+);/);
  ruleItype.value = itypeM ? itypeM[1].trim() : '';
  const icodeM = opts.match(/\bicode\s*:\s*([^;]+);/);
  ruleIcode.value = icodeM ? icodeM[1].trim() : '';

  // dsize
  const dsizeM = opts.match(/\bdsize\s*:\s*([^;]+);/);
  ruleDsize.value = dsizeM ? dsizeM[1].trim() : '';

  // ttl / tos / id
  const ttlM = opts.match(/\bttl\s*:\s*([^;]+);/);
  ruleTtl.value = ttlM ? ttlM[1].trim() : '';
  const tosM = opts.match(/\btos\s*:\s*([^;]+);/);
  ruleTos.value = tosM ? tosM[1].trim() : '';
  const ipIdM = opts.match(/\bid\s*:\s*([^;]+);/);
  ruleIpId.value = ipIdM ? ipIdM[1].trim() : '';

  // window
  const winM = opts.match(/\bwindow\s*:\s*([^;]+);/);
  ruleWindow.value = winM ? winM[1].trim() : '';

  // ip_proto
  const ipProtoM = opts.match(/\bip_proto\s*:\s*([^;]+);/);
  ruleIpProto.value = ipProtoM ? ipProtoM[1].trim() : '';

  // fragbits
  const fragM = opts.match(/\bfragbits\s*:\s*([!*+]?)([MDR]+)\s*;/i);
  ['fragM','fragD','fragR'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.checked = false;
  });
  if (fragM) {
    const mod   = fragM[1];
    const frags = fragM[2].toUpperCase();
    document.getElementById('fragMod').value = mod;
    for (const f of frags) {
      const el = document.getElementById('frag' + f);
      if (el) el.checked = true;
    }
  }

  // ── Content entries ──────────────────────────────────────────────────────────
  contentEntries = [];
  // Parse all content occurrences with their preceding sticky buffer
  const contentRe = /(?:([\w]+);[^;]*?)?content\s*:\s*"((?:[^"\\]|\\.)*)"\s*([^;]*)?;/g;
  // Simpler approach: tokenize options
  const tokens = opts.split(/;/).map(t => t.trim()).filter(Boolean);
  let currentBuffer = '';
  let i = 0;
  while (i < tokens.length) {
    const tok = tokens[i];
    // Check if it's a known sticky buffer (keyword without value)
    const bufName = tok.trim();
    if (STICKY_BUFFERS.includes(bufName)) {
      currentBuffer = bufName;
      i++; continue;
    }
    // content
    const cM = tok.match(/^content\s*:\s*"((?:[^"\\]|\\.)*)"(.*)?$/);
    if (cM) {
      const entry = {
        id: Date.now() + Math.random(),
        buffer:      currentBuffer,
        content:     cM[1].replace(/\\"/g, '"'),
        nocase:      false,
        fastPattern: false,
        offset:      '',
        depth:       '',
        distance:    '',
        within:      '',
      };
      currentBuffer = ''; // consumed
      // Look ahead for modifiers
      let j = i + 1;
      while (j < tokens.length) {
        const mod = tokens[j].trim();
        if (mod === 'nocase')                          { entry.nocase = true; j++; }
        else if (mod === 'fast_pattern')               { entry.fastPattern = true; j++; }
        else if (/^offset\s*:\s*/.test(mod))           { entry.offset   = mod.replace(/^offset\s*:\s*/, ''); j++; }
        else if (/^depth\s*:\s*/.test(mod))            { entry.depth    = mod.replace(/^depth\s*:\s*/, ''); j++; }
        else if (/^distance\s*:\s*/.test(mod))         { entry.distance = mod.replace(/^distance\s*:\s*/, ''); j++; }
        else if (/^within\s*:\s*/.test(mod))           { entry.within   = mod.replace(/^within\s*:\s*/, ''); j++; }
        else break;
      }
      i = j;
      contentEntries.push(entry);
      continue;
    }
    i++;
  }
  renderContentEntries();

  // pcre
  const pcreM = opts.match(/\bpcre\s*:\s*"((?:[^"\\]|\\.)*)"/);
  rulePcre.value = pcreM ? pcreM[1].replace(/\\"/g, '"') : '';

  // byte operations
  const btM = opts.match(/\bbyte_test\s*:\s*([^;]+);/);
  ruleByteTest.value = btM ? btM[1].trim() : '';
  const bjM = opts.match(/\bbyte_jump\s*:\s*([^;]+);/);
  ruleByteJump.value = bjM ? bjM[1].trim() : '';
  const beM = opts.match(/\bbyte_extract\s*:\s*([^;]+);/);
  ruleByteExtract.value = beM ? beM[1].trim() : '';
  const bmM = opts.match(/\bbyte_math\s*:\s*([^;]+);/);
  ruleByteMath.value = bmM ? bmM[1].trim() : '';

  // threshold
  const thM = opts.match(/\bthreshold\s*:\s*type\s+(\w+),\s*track\s+(\w+),\s*count\s+(\d+),\s*seconds\s+(\d+)/);
  if (thM) {
    threshType.value    = thM[1];
    threshTrack.value   = thM[2];
    threshCount.value   = thM[3];
    threshSeconds.value = thM[4];
  } else {
    threshType.value = threshCount.value = threshSeconds.value = '';
    threshTrack.value = 'by_src';
  }

  // detection_filter
  const dfM = opts.match(/\bdetection_filter\s*:\s*track\s+(\w+),\s*count\s+(\d+),\s*seconds\s+(\d+)/);
  if (dfM) {
    dfTrack.value   = dfM[1];
    dfCount.value   = dfM[2];
    dfSeconds.value = dfM[3];
  } else {
    dfTrack.value = dfCount.value = dfSeconds.value = '';
  }

  // rev / rem
  const revM = opts.match(/\brev\s*:\s*(\d+)\s*;/);
  ruleRev.value = revM ? revM[1] : '1';
  const remM = opts.match(/\brem\s*:\s*"((?:[^"\\]|\\.)*)"/);
  ruleRem.value = remM ? remM[1] : '';

  // ── 4. New SID ───────────────────────────────────────────────────────────────
  await fetchNextSid();

  updatePreview();
  document.querySelector('section').scrollTo({ top: 0, behavior: 'smooth' });
  showToast('Règle chargée dans l\'éditeur', 'ok');
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
      showToast(`Copiée dans local.rules (SID: ${d.newSid})`, 'ok');
      await fetchNextSid();
      await loadRules();
    } else {
      showToast(`Erreur: ${d.error}`, 'err');
    }
  } catch (e) { showToast(`Erreur: ${e.message}`, 'err'); }
};

window.toggleRule = async (sid) => {
  try {
    const r = await fetch(`/api/rules/${sid}/toggle`, { method: 'PATCH' });
    const d = await r.json();
    if (d.success) { await loadRules(); showToast('Statut modifié', 'ok'); }
    else showToast(`Erreur: ${d.error}`, 'err');
  } catch (e) { showToast(`Erreur: ${e.message}`, 'err'); }
};

window.deleteRule = async (sid) => {
  if (!confirm(`Supprimer la règle SID ${sid} ? Action irréversible.`)) return;
  try {
    const r = await fetch(`/api/rules/${sid}`, { method: 'DELETE' });
    const d = await r.json();
    if (d.success) { await loadRules(); showToast('Règle supprimée', 'ok'); }
    else showToast(`Erreur: ${d.error}`, 'err');
  } catch (e) { showToast(`Erreur: ${e.message}`, 'err'); }
};

modalClose.addEventListener('click', () => modal.classList.add('hidden'));
modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });

// ── Validate (test Snort config) ──────────────────────────────────────────────

const validateModal      = document.getElementById('validateModal');
const validateOutput     = document.getElementById('validateOutput');
const validateModalClose = document.getElementById('validateModalClose');

validateModalClose.addEventListener('click', () => validateModal.classList.add('hidden'));
validateModal.addEventListener('click', e => { if (e.target === validateModal) validateModal.classList.add('hidden'); });

document.getElementById('btnValidate').addEventListener('click', async () => {
  validateOutput.textContent = 'Test en cours…';
  validateModal.classList.remove('hidden');
  try {
    const r = await fetch('/api/rules/validate', { method: 'POST' });
    const d = await r.json();
    if (d.success) {
      validateOutput.className = 'bg-gray-950 rounded-lg p-4 text-xs text-green-300 whitespace-pre-wrap break-all overflow-auto max-h-96';
      validateOutput.textContent = '✔ Configuration valide\n\n' + (d.output || '');
    } else {
      validateOutput.className = 'bg-gray-950 rounded-lg p-4 text-xs text-red-300 whitespace-pre-wrap break-all overflow-auto max-h-96';
      validateOutput.textContent = '✖ Erreurs détectées\n\n' + (d.output || d.error || '');
    }
  } catch (e) {
    validateOutput.className = 'bg-gray-950 rounded-lg p-4 text-xs text-red-300 whitespace-pre-wrap break-all overflow-auto max-h-96';
    validateOutput.textContent = `Erreur: ${e.message}`;
  }
});

// ── Bulk selection ────────────────────────────────────────────────────────────

let selectedSids = new Set();

function getSelectedLocalSids() {
  return [...selectedSids].filter(sid => {
    const rule = mergedRules.find(r => r.sid === sid);
    return rule && rule.editable !== false;
  });
}

function updateBulkToolbar() {
  const toolbar = document.getElementById('bulkToolbar');
  const count   = document.getElementById('bulkCount');
  if (selectedSids.size > 0) {
    toolbar.classList.remove('hidden');
    count.textContent = `${selectedSids.size} sélectionnée(s)`;
  } else {
    toolbar.classList.add('hidden');
  }
}

document.getElementById('chkSelectAll').addEventListener('change', function() {
  const checkboxes = document.querySelectorAll('.rule-chk');
  checkboxes.forEach(chk => {
    chk.checked = this.checked;
    const sid = chk.dataset.sid;
    if (this.checked) selectedSids.add(sid);
    else              selectedSids.delete(sid);
  });
  updateBulkToolbar();
});

document.getElementById('btnBulkCancel').addEventListener('click', () => {
  selectedSids.clear();
  document.querySelectorAll('.rule-chk').forEach(chk => chk.checked = false);
  document.getElementById('chkSelectAll').checked = false;
  updateBulkToolbar();
});

document.getElementById('btnBulkEnable').addEventListener('click', async () => {
  const sids = getSelectedLocalSids();
  if (!sids.length) return showToast('Aucune règle locale sélectionnée', 'warn');
  await bulkAction('enable', sids);
});

document.getElementById('btnBulkDisable').addEventListener('click', async () => {
  const sids = getSelectedLocalSids();
  if (!sids.length) return showToast('Aucune règle locale sélectionnée', 'warn');
  await bulkAction('disable', sids);
});

document.getElementById('btnBulkDelete').addEventListener('click', async () => {
  const sids = getSelectedLocalSids();
  if (!sids.length) return showToast('Aucune règle locale sélectionnée', 'warn');
  if (!confirm(`Supprimer ${sids.length} règle(s) ? Cette action est irréversible.`)) return;
  await bulkAction('delete', sids);
});

async function bulkAction(action, sids) {
  try {
    const r = await fetch('/api/rules/bulk', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ action, sids })
    });
    const d = await r.json();
    if (d.success) {
      showToast(`${d.affected} règle(s) ${action === 'delete' ? 'supprimée(s)' : action === 'enable' ? 'activée(s)' : 'désactivée(s)'}`, 'ok');
      selectedSids.clear();
      document.getElementById('chkSelectAll').checked = false;
      updateBulkToolbar();
      await loadRules();
    } else {
      showToast(`Erreur: ${d.error}`, 'err');
    }
  } catch (e) { showToast(`Erreur: ${e.message}`, 'err'); }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type = 'ok') {
  const toast  = document.getElementById('toast');
  const colors = { ok: 'bg-green-800 text-green-200', err: 'bg-red-900 text-red-200', warn: 'bg-yellow-800 text-yellow-200' };
  toast.textContent = msg;
  toast.className   = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3500);
}
