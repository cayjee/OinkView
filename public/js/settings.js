/**
 * settings.js — Load & save application settings
 */
'use strict';

// Champs en lecture seule — affichés mais non modifiables (définis dans .env)
const readonlyFields = ['rulesFile', 'logFile', 'communityRulesDir', 'snortConfig', 'snortBin'];
// Champs éditables — sauvegardés dans settings.json
const fields = ['rulesFile', 'logFile', 'logFormat', 'tailLines', 'snortConfig', 'communityRulesDir', 'snortBin', 'snortInterface', 'authEnabled'];

// ── Load settings on page start ───────────────────────────────────────────────

(async function load() {
  try {
    const r    = await fetch('/api/settings');
    const data = await r.json();
    fields.forEach(key => {
      const el = document.getElementById(key);
      if (!el) return;
      if (el.type === 'checkbox') { el.checked = !!data[key]; }
      else if (data[key] !== undefined) { el.value = data[key]; }
    });
    updatePermissions();
    updateSnortCommands();
  } catch (e) {
    showToast(`✖ Chargement échoué : ${e.message}`, 'err');
  }
})();

// ── Save settings ─────────────────────────────────────────────────────────────

document.getElementById('btnSave').addEventListener('click', async () => {
  const payload = {};
  fields.forEach(key => {
    if (readonlyFields.includes(key)) return; // ne pas sauvegarder les chemins .env
    const el = document.getElementById(key);
    if (!el) return;
    if (el.type === 'checkbox')    payload[key] = el.checked;
    else if (el.type === 'number') payload[key] = parseInt(el.value, 10);
    else                           payload[key] = el.value;
  });
  // authPassword is optional — only send if filled
  const pwEl = document.getElementById('authPassword');
  if (pwEl && pwEl.value.trim()) payload.authPassword = pwEl.value.trim();

  try {
    const r    = await fetch('/api/settings', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload)
    });
    const data = await r.json();
    if (data.success) {
      showToast('✔ Paramètres sauvegardés', 'ok');
      document.getElementById('saveStatus').textContent = `Sauvegardé à ${new Date().toLocaleTimeString()}`;
    } else {
      showToast(`✖ ${data.error}`, 'err');
    }
  } catch (e) {
    showToast(`✖ ${e.message}`, 'err');
  }
});

// ── Test file path ────────────────────────────────────────────────────────────

window.testPath = async (inputId) => {
  const el         = document.getElementById(inputId);
  const statusEl   = document.getElementById(inputId + 'Status');
  const filePath   = el.value.trim();
  if (!filePath) return;

  statusEl.textContent = 'Test en cours…';
  statusEl.className   = 'text-xs mt-1 text-gray-400';

  try {
    const r    = await fetch('/api/settings/test-path', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ filePath })
    });
    const data = await r.json();
    if (data.ok) {
      statusEl.textContent = '✔ Accessible';
      statusEl.className   = 'text-xs mt-1 text-green-400';
    } else {
      statusEl.textContent = `✖ ${data.error}`;
      statusEl.className   = 'text-xs mt-1 text-red-400';
    }
  } catch (e) {
    statusEl.textContent = `✖ ${e.message}`;
    statusEl.className   = 'text-xs mt-1 text-red-400';
  }
};

// ── Permissions dynamiques ────────────────────────────────────────────────────

function updatePermissions() {
  const rules     = document.getElementById('rulesFile').value     || '/etc/snort/rules/local.rules';
  const log       = document.getElementById('logFile').value       || '/var/log/snort/alert_fast.txt';
  const community = document.getElementById('communityRulesDir').value || '';

  // Références inline
  const pRules = document.getElementById('perm-rules');
  const pLog   = document.getElementById('perm-log');
  if (pRules) pRules.textContent = rules;
  if (pLog)   pLog.textContent   = log;

  // Bloc 1 : droits fichiers hôte
  const cmdFiles = document.getElementById('cmd-files');
  if (cmdFiles) cmdFiles.textContent =
`# Rendre les fichiers accessibles au container (hôte)
sudo chmod 664 ${rules}
sudo chmod 644 ${log}`;

  // Bloc 2 : volumes docker-compose
  const cmdSudo = document.getElementById('cmd-sudo');
  if (cmdSudo) cmdSudo.textContent =
`volumes:
  - ./config:/app/config
  - ${rules}:${rules}
  - ${log}:${log}:ro`;

  // Bloc 3 : dossier communautaire (masqué si vide)
  const communityBlock = document.getElementById('perm-community-block');
  const cmdCommunity   = document.getElementById('cmd-community');
  if (communityBlock) communityBlock.style.display = community ? '' : 'none';
  if (cmdCommunity && community) cmdCommunity.textContent =
`# Ajouter dans docker-compose.yml → volumes :
  - ${community}:${community}:ro`;
}

// Mettre à jour les permissions quand un champ change
['rulesFile','logFile','communityRulesDir'].forEach(function(id) {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', updatePermissions);
});

// ── Commandes Snort ───────────────────────────────────────────────────────────

function updateSnortCommands() {
  const bin   = document.getElementById('snortBin').value       || '/usr/local/bin/snort';
  const cfg   = document.getElementById('snortConfig').value    || '/usr/local/etc/snort/snort.lua';
  const log   = document.getElementById('logFile').value        || '/var/log/snort/alert_fast.txt';
  const iface = document.getElementById('snortInterface').value || 'eth0';
  const logDir = log.substring(0, log.lastIndexOf('/')) || '/var/log/snort';

  const set = function(id, txt) { const el = document.getElementById(id); if (el) el.textContent = txt; };

  set('cmd-start-ids',
    'sudo ' + bin + ' \\\n' +
    '  -c ' + cfg + ' \\\n' +
    '  --daq pcap \\\n' +
    '  -i ' + iface + ' \\\n' +
    '  -l ' + logDir + ' \\\n' +
    '  -D'
  );

  set('cmd-test',
    'sudo ' + bin + ' -c ' + cfg + ' -T'
  );

  set('cmd-stop',
    'sudo pkill -f snort\n# ou :\nsudo kill $(cat /var/run/snort/snort.pid)'
  );

  set('cmd-reload',
    '# Rechargement à chaud des règles (envoie SIGHUP à Snort 3)\n' +
    'sudo kill -SIGHUP $(pidof snort)\n' +
    '# ou :\n' +
    'sudo pkill -HUP snort\n' +
    '# si installé en service systemd :\n' +
    'sudo systemctl restart snort3'
  );

  set('cmd-tail',
    'tail -f ' + log
  );

  set('cmd-status',
    'ps aux | grep snort | grep -v grep'
  );

  set('cmd-version',
    bin + ' --version'
  );
}

['snortBin', 'snortConfig', 'logFile', 'snortInterface'].forEach(function(id) {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', updateSnortCommands);
});

// Copier un bloc de commandes dans le presse-papier
window.copyBlock = (blockId) => {
  const el = document.getElementById(blockId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    showToast('Commandes copiées dans le presse-papier', 'ok');
  }).catch(() => {
    showToast('Erreur de copie', 'err');
  });
};

// ── Utilities ─────────────────────────────────────────────────────────────────

function showToast(msg, type = 'ok') {
  const toast  = document.getElementById('toast');
  const colors = { ok: 'bg-green-800 text-green-200', err: 'bg-red-900 text-red-200', warn: 'bg-yellow-800 text-yellow-200' };
  toast.textContent = msg;
  toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3500);
}
