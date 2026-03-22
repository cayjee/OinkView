'use strict';

const CATEGORIES = {
  scan:        'Scan réseau',
  ddos:        'DDoS / Flood',
  exploit:     'Exploitation',
  malware:     'Malware / C2',
  injection:   'Injection',
  bruteforce:  'Brute force',
  exfiltration:'Exfiltration',
  mitm:        'MITM / ARP',
  other:       'Autre'
};

// ── Drop zone ─────────────────────────────────────────────────────────────────

const dropZone  = document.getElementById('dropZone');
const fileInput = document.getElementById('pcapFile');

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('border-orange-500');
  dropZone.classList.remove('border-gray-700');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('border-orange-500');
  dropZone.classList.add('border-gray-700');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('border-orange-500');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

let selectedFile = null;

function setFile(file) {
  if (!file.name.match(/\.(pcap|cap|pcapng)$/i)) {
    showToast('Fichier invalide — seuls .pcap, .cap et .pcapng sont acceptés', 'err');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    showToast('Fichier trop volumineux (max 50 Mo)', 'err');
    return;
  }
  selectedFile = file;
  document.getElementById('dropText').textContent =
    `${file.name}  (${(file.size / 1024).toFixed(1)} Ko)`;
  dropZone.classList.add('border-green-500');
  dropZone.classList.remove('border-gray-700', 'border-orange-500');
}

// ── Lancer le test ────────────────────────────────────────────────────────────

document.getElementById('btnRunTest').addEventListener('click', async () => {
  const category    = document.getElementById('pcapCategory').value;
  const description = document.getElementById('pcapDescription').value.trim();

  if (!category)              { showToast('Sélectionnez une catégorie', 'err'); return; }
  if (description.length < 10){ showToast('Description trop courte (min. 10 caractères)', 'err'); return; }
  if (!selectedFile)          { showToast('Sélectionnez un fichier PCAP', 'err'); return; }

  const btn    = document.getElementById('btnRunTest');
  const status = document.getElementById('testStatus');
  btn.disabled = true;
  status.textContent = 'Lecture du fichier…';

  try {
    const pcapBase64 = await toBase64(selectedFile);
    status.textContent = 'Envoi à Snort…';

    const r = await fetch('/api/pcap/test', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ pcapBase64, description, category })
    });
    const data = await r.json();

    if (!r.ok) {
      showToast(`Erreur : ${data.error}`, 'err');
      status.textContent = '';
      return;
    }

    status.textContent = 'Terminé.';
    renderResults(data);
  } catch (e) {
    showToast(`Erreur : ${e.message}`, 'err');
    status.textContent = '';
  } finally {
    btn.disabled = false;
  }
});

function toBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = () => resolve(reader.result.split(',')[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// ── Afficher les résultats ────────────────────────────────────────────────────

function renderResults(data) {
  document.getElementById('resultsSection').classList.remove('hidden');

  const alertCount = data.alertCount || 0;
  const sids = new Set();
  (data.alerts || []).forEach(l => {
    const m = l.match(/\[\d+:(\d+):\d+\]/);
    if (m) sids.add(m[1]);
  });

  document.getElementById('statAlerts').textContent = alertCount;
  document.getElementById('statSids').textContent   = sids.size;
  document.getElementById('badgeCategory').textContent =
    CATEGORIES[data.category] || data.category;
  document.getElementById('resultDescription').textContent =
    `"${data.description}"`;

  // Verdict
  const verdictBox  = document.getElementById('statVerdict');
  const verdictText = document.getElementById('statVerdictText');
  if (alertCount > 0) {
    verdictText.textContent  = 'DÉTECTÉ';
    verdictBox.className     = 'bg-green-900/40 rounded-lg p-4 text-center';
    verdictText.className    = 'text-3xl font-bold text-green-400';
  } else {
    verdictText.textContent  = 'NON DÉTECTÉ';
    verdictBox.className     = 'bg-red-900/40 rounded-lg p-4 text-center';
    verdictText.className    = 'text-3xl font-bold text-red-400';
  }

  // Liste des alertes
  const tableEl = document.getElementById('alertsTable');
  tableEl.innerHTML = '';
  if (data.alerts && data.alerts.length > 0) {
    data.alerts.forEach(line => {
      const div = document.createElement('div');
      div.className   = line.includes('[**]') ? 'text-red-400 py-0.5' : 'text-gray-500 py-0.5';
      div.textContent = line;
      tableEl.appendChild(div);
    });
    document.getElementById('alertsTableSection').classList.remove('hidden');
  } else {
    document.getElementById('alertsTableSection').classList.add('hidden');
  }

  // Sortie brute
  document.getElementById('rawOutput').textContent = data.output || '(aucune sortie)';

  document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

// ── Reload Snort ──────────────────────────────────────────────────────────────

document.getElementById('btnReload').addEventListener('click', async () => {
  const btn = document.getElementById('btnReload');
  btn.disabled = true;
  try {
    const r = await fetch('/api/reload', { method: 'POST' });
    const d = await r.json();
    showToast(d.success ? '✔ Snort rechargé' : `✖ ${d.error}`, d.success ? 'ok' : 'err');
  } catch (e) {
    showToast(`✖ ${e.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
});

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(msg, type = 'ok') {
  const toast  = document.getElementById('toast');
  const colors = { ok: 'bg-green-800 text-green-200', err: 'bg-red-900 text-red-200' };
  toast.textContent = msg;
  toast.className   = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg ${colors[type] || colors.ok}`;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 3500);
}
