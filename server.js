/**
 * OinkView — Snort 3 GUI Manager
 * Backend Express + Socket.io
 */

'use strict';

const express  = require('express');
const http     = require('http');
const crypto   = require('crypto');
const { Server } = require('socket.io');
const fs       = require('fs');
const path     = require('path');
const { exec } = require('child_process');
const chokidar = require('chokidar');
const geoip    = require('geoip-lite');

// ─── État global ─────────────────────────────────────────────────────────────

let dashResetTime  = 0; // timestamp ms — filtre les lignes du dashboard
let statsResetTime = 0; // timestamp ms — filtre les stats

// ─── Sessions auth ────────────────────────────────────────────────────────────
const sessions = new Set(); // tokens actifs en mémoire

// Parse le timestamp Snort "MM/DD-HH:MM:SS.usec" → ms epoch (année courante)
function parseSnortTs(line) {
  const m = line.match(/^(\d+)\/(\d+)-(\d+):(\d+):\d+/);
  if (!m) return Date.now(); // ligne sans timestamp = considérée récente
  const now = new Date();
  return new Date(now.getFullYear(), parseInt(m[1]) - 1, parseInt(m[2]),
    parseInt(m[3]), parseInt(m[4])).getTime();
}

// ─── Bootstrap ───────────────────────────────────────────────────────────────

const app    = express();
const server = http.createServer(app);
const io     = new Server(server);
const PORT   = process.env.PORT || 3000;

const CONFIG_DIR   = path.join(__dirname, 'config');
const SETTINGS_FILE = path.join(CONFIG_DIR, 'settings.json');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });

const DEFAULT_SETTINGS = {
  rulesFile:          '/etc/snort/rules/local.rules',
  logFile:            '/var/log/snort/alert_fast.txt',
  logFormat:          'fast',
  reloadCommand:      'systemctl reload snort3',
  snortPidFile:       '/var/run/snort/snort.pid',
  snortConfig:        '/usr/local/etc/snort/snort.lua',
  communityRulesDir:  '',
  tailLines:          200,
  snortBin:           '/usr/local/bin/snort',
  snortInterface:     'eth0',
  authEnabled:        false,
  authPassword:       ''
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE))
      return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) };
  } catch (_) {}
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(data) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2));
}

/**
 * Parse a rules file and return an array of rule objects.
 * Lines starting with '#' are treated as comments/disabled rules.
 */
function parseRules(content) {
  const rules = [];
  content.split('\n').forEach((raw, idx) => {
    const line = raw.trim();
    if (!line) return;

    const disabled  = line.startsWith('#');
    const effective = disabled ? line.slice(1).trim() : line;

    const sidMatch  = effective.match(/\bsid\s*:\s*(\d+)\s*;/);
    const msgMatch  = effective.match(/\bmsg\s*:\s*"([^"]+)"\s*;/);
    const actMatch  = effective.match(/^(alert|drop|pass|reject|rewrite)\s+/);

    // Ignorer les lignes qui ne ressemblent pas à des règles Snort
    if (!actMatch && !disabled) return;
    if (disabled && !effective.match(/^(alert|drop|pass|reject|rewrite)\s+/)) return;

    const msgText      = msgMatch ? msgMatch[1] : '(no message)';
    const classtypeMatch = effective.match(/\bclasstype\s*:\s*([\w-]+)\s*;/);
    // Préfixe du msg = premier mot en majuscules avant un espace (ex: "MALWARE-CNC foo" → "MALWARE-CNC")
    const msgPrefixM   = msgText.match(/^([A-Z0-9][A-Z0-9_-]+)/);
    const msgPrefix    = msgPrefixM ? msgPrefixM[1] : null;

    rules.push({
      lineNumber: idx + 1,
      sid:        sidMatch ? sidMatch[1] : null,
      msg:        msgText,
      action:     actMatch ? actMatch[1] : (effective.match(/^(alert|drop|pass|reject|rewrite)\s+/) || ['','unknown'])[1],
      classtype:  classtypeMatch ? classtypeMatch[1] : null,
      category:   msgPrefix,
      disabled,
      raw
    });
  });
  return rules;
}

/**
 * Determine the next available SID (≥ 1 000 001).
 */
function nextSid(content) {
  const MIN_SID = 1_000_001;
  let max = MIN_SID - 1;
  const re = /\bsid\s*:\s*(\d+)\s*;/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const n = parseInt(m[1], 10);
    if (n > max) max = n;
  }
  return max + 1;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const settings = loadSettings();
  if (!settings.authEnabled) return next();
  // req.path is relative to the mount point '/api' → '/auth/login', not '/api/auth/login'
  if (req.path === '/auth/login' || req.path === '/auth/check' || req.path === '/auth/logout') return next();
  const token = req.headers['x-auth-token'] || '';
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Non autorisé' });
  next();
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', authMiddleware);

// ─── API — Auth ───────────────────────────────────────────────────────────────

app.get('/api/auth/check', (req, res) => {
  const settings = loadSettings();
  if (!settings.authEnabled) return res.json({ authRequired: false, ok: true });
  const token = req.headers['x-auth-token'] || '';
  res.json({ authRequired: true, ok: sessions.has(token) });
});

app.post('/api/auth/login', (req, res) => {
  const settings = loadSettings();
  if (!settings.authEnabled) return res.json({ ok: true, token: '' });
  const { password } = req.body;
  if (password !== settings.authPassword) return res.status(401).json({ error: 'Mot de passe incorrect' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.add(token);
  res.json({ ok: true, token });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'] || '';
  sessions.delete(token);
  res.json({ ok: true });
});

// ─── API — Settings ───────────────────────────────────────────────────────────

app.get('/api/settings', (_req, res) => {
  const s = loadSettings();
  const safe = { ...s };
  if (safe.authPassword) safe.authPassword = ''; // never send password to client
  res.json(safe);
});

app.post('/api/settings', (req, res) => {
  try {
    saveSettings({ ...loadSettings(), ...req.body });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Test whether a file path is readable
app.post('/api/settings/test-path', (req, res) => {
  const { filePath } = req.body;
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ─── API — Rules ──────────────────────────────────────────────────────────────

app.get('/api/rules', (_req, res) => {
  const { rulesFile } = loadSettings();
  try {
    const content = fs.existsSync(rulesFile) ? fs.readFileSync(rulesFile, 'utf8') : '';
    res.json({ content, rules: parseRules(content) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET règles communautaires depuis un dossier (tous les .rules sauf local.rules)
app.get('/api/rules/community', (_req, res) => {
  const { communityRulesDir, rulesFile } = loadSettings();
  if (!communityRulesDir) return res.json({ rules: [], files: [], error: 'Dossier non configuré' });

  try {
    if (!fs.existsSync(communityRulesDir))
      return res.status(404).json({ rules: [], files: [], error: 'Dossier introuvable' });

    // Lister tous les .rules du dossier (non récursif)
    const files = fs.readdirSync(communityRulesDir)
      .filter(f => f.endsWith('.rules'))
      .filter(f => path.join(communityRulesDir, f) !== rulesFile.trim()); // exclure local.rules

    let allRules = [];
    const fileStats = [];

    files.forEach(file => {
      const filePath = path.join(communityRulesDir, file);
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const rules   = parseRules(content).map(r => ({
          ...r, source: 'community', editable: false, filePath: file
        }));
        fileStats.push({ file, count: rules.length });
        allRules = allRules.concat(rules);
      } catch (e) {
        fileStats.push({ file, count: 0, error: e.message });
      }
    });

    res.json({ rules: allRules, files: fileStats, total: allRules.length });
  } catch (e) {
    res.status(500).json({ rules: [], files: [], error: e.message });
  }
});

// GET toutes les catégories disponibles (classtype + préfixes msg)
app.get('/api/rules/categories', (_req, res) => {
  const { communityRulesDir, rulesFile } = loadSettings();
  const classtypes = new Set();
  const categories = new Set();

  const readAndExtract = (filePath) => {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      parseRules(content).forEach(r => {
        if (r.classtype) classtypes.add(r.classtype);
        if (r.category)  categories.add(r.category);
      });
    } catch (_) {}
  };

  // Lire local.rules
  if (rulesFile && fs.existsSync(rulesFile)) readAndExtract(rulesFile);

  // Lire les fichiers communautaires
  if (communityRulesDir && fs.existsSync(communityRulesDir)) {
    fs.readdirSync(communityRulesDir)
      .filter(f => f.endsWith('.rules'))
      .forEach(f => readAndExtract(path.join(communityRulesDir, f)));
  }

  res.json({
    classtypes: [...classtypes].sort(),
    categories: [...categories].sort()
  });
});

// POST copier une règle communautaire vers local.rules (avec nouveau SID)
app.post('/api/rules/copy-to-local', (req, res) => {
  const { rulesFile } = loadSettings();
  const { rule } = req.body;
  if (!rule) return res.status(400).json({ error: 'Règle manquante' });

  try {
    const content = fs.existsSync(rulesFile) ? fs.readFileSync(rulesFile, 'utf8') : '';
    const newSid  = nextSid(content);

    // Remplacer le SID existant par le nouveau SID local
    const localRule = rule.replace(/\bsid\s*:\s*\d+\s*;/, `sid:${newSid};`)
                          .replace(/\brev\s*:\s*\d+\s*;/, 'rev:1;');

    const sep = content && !content.endsWith('\n') ? '\n' : '';
    fs.appendFileSync(rulesFile, sep + localRule + '\n');
    res.json({ success: true, newSid });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Toutes les règles : local.rules (éditables) + fichiers inclus dans snort.lua (lecture seule)
app.get('/api/rules/all', (_req, res) => {
  const { rulesFile, snortConfig } = loadSettings();

  // 1. Règles locales (éditables)
  let localContent = '';
  try { localContent = fs.existsSync(rulesFile) ? fs.readFileSync(rulesFile, 'utf8') : ''; } catch (_) {}
  const localRules = parseRules(localContent).map(r => ({ ...r, source: 'local', editable: true, filePath: rulesFile }));

  // 2. Règles communautaires depuis les fichiers inclus dans snort.lua
  let communityRules = [];
  if (snortConfig && fs.existsSync(snortConfig)) {
    try {
      const luaContent = fs.readFileSync(snortConfig, 'utf8');
      const luaParsed  = parseSnortLua(luaContent);
      luaParsed.ruleIncludes
        .filter(p => p.trim() !== rulesFile.trim()) // exclure local.rules déjà chargé
        .forEach(filePath => {
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const rules   = parseRules(content).map(r => ({
              ...r, source: 'community', editable: false,
              filePath: filePath.split('/').pop() // juste le nom du fichier
            }));
            communityRules = communityRules.concat(rules);
          } catch (_) {}
        });
    } catch (_) {}
  }

  res.json({
    local:     localRules,
    community: communityRules,
    total:     localRules.length + communityRules.length
  });
});

// Return the next available SID
app.get('/api/rules/next-sid', (_req, res) => {
  const { rulesFile } = loadSettings();
  try {
    const content = fs.existsSync(rulesFile) ? fs.readFileSync(rulesFile, 'utf8') : '';
    res.json({ sid: nextSid(content) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Append a new rule
app.post('/api/rules', (req, res) => {
  const { rulesFile } = loadSettings();
  const { rule } = req.body;
  if (!rule || typeof rule !== 'string')
    return res.status(400).json({ error: 'Missing rule string' });
  try {
    // Ensure there's a newline at end of file before appending
    let sep = '\n';
    if (fs.existsSync(rulesFile)) {
      const tail = fs.readFileSync(rulesFile, 'utf8').slice(-1);
      if (tail === '\n') sep = '';
    }
    fs.appendFileSync(rulesFile, sep + rule + '\n');
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Toggle rule enabled/disabled (comment/uncomment)
app.patch('/api/rules/:sid/toggle', (req, res) => {
  const { rulesFile } = loadSettings();
  const { sid } = req.params;
  try {
    const content = fs.readFileSync(rulesFile, 'utf8');
    const re = new RegExp(`(^|\\n)(#?\\s*(?:alert|drop|pass|reject|rewrite)[^\\n]*\\bsid\\s*:\\s*${sid}\\s*;[^\\n]*)`, 'g');
    let found = false;
    const updated = content.replace(re, (_full, pre, line) => {
      found = true;
      const toggled = line.trimStart().startsWith('#')
        ? pre + line.replace(/^(\s*)#\s?/, '$1')
        : pre + '# ' + line;
      return toggled;
    });
    if (!found) return res.status(404).json({ error: 'SID not found' });
    fs.writeFileSync(rulesFile, updated);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete a rule by SID
app.delete('/api/rules/:sid', (req, res) => {
  const { rulesFile } = loadSettings();
  const { sid } = req.params;
  try {
    const content = fs.readFileSync(rulesFile, 'utf8');
    const lines = content.split('\n').filter(line => {
      // Remove any line (even commented) that contains this SID
      return !line.match(new RegExp(`\\bsid\\s*:\\s*${sid}\\s*;`));
    });
    fs.writeFileSync(rulesFile, lines.join('\n'));
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── API — Snort Reload ───────────────────────────────────────────────────────

app.post('/api/reload', (_req, res) => {
  const { reloadCommand, snortPidFile } = loadSettings();

  // If a PID file is provided and the command contains 'SIGHUP', use kill approach
  let cmd = reloadCommand;
  if (!cmd && snortPidFile && fs.existsSync(snortPidFile)) {
    const pid = fs.readFileSync(snortPidFile, 'utf8').trim();
    cmd = `kill -SIGHUP ${pid}`;
  }

  exec(cmd, { timeout: 10_000 }, (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: stderr || error.message, stdout });
    res.json({ success: true, output: stdout || '(no output)' });
  });
});

// ─── API — Snort Config Overview ─────────────────────────────────────────────

/**
 * Parse snort.lua (texte Lua) de façon légère :
 * - Extrait les variables réseau (HOME_NET, etc.)
 * - Extrait les chemins de fichiers de règles inclus (include = '...')
 * - Extrait les plugins/modules activés (alert_fast, alert_json, etc.)
 */
function parseSnortLua(content) {
  const result = {
    variables:    [],
    ruleIncludes: [],
    modules:      [],
    rawContent:   content
  };

  // Variables réseau : HOME_NET = '...', EXTERNAL_NET = '...', etc.
  const varRe = /^\s*([\w_]+)\s*=\s*['"]([^'"]+)['"]/gm;
  let m;
  const netKeywords = ['NET', 'SERVER', 'PORT', 'ADDR', 'RULE_PATH', 'LOG_DIR'];
  while ((m = varRe.exec(content)) !== null) {
    if (netKeywords.some(k => m[1].toUpperCase().includes(k))) {
      result.variables.push({ name: m[1], value: m[2] });
    }
  }

  // Fichiers de règles inclus dans le bloc ips { include = '...' }
  // Snort 3 : include peut être une string ou une table
  const includeRe = /include\s*=\s*['"]([^'"]+)['"]/g;
  while ((m = includeRe.exec(content)) !== null) {
    const p = m[1];
    // Filtrer uniquement les fichiers .rules
    if (p.endsWith('.rules') || p.includes('rules')) {
      result.ruleIncludes.push(p);
    }
  }

  // Modules activés : lignes du type "alert_fast = {" ou "ips = {"
  const moduleRe = /^([\w_]+)\s*=\s*\{/gm;
  while ((m = moduleRe.exec(content)) !== null) {
    result.modules.push(m[1]);
  }

  return result;
}

/**
 * Lit un fichier de règles et retourne ses règles parsées + statistiques.
 */
function readRuleFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const rules   = parseRules(content);
    const stats   = rules.reduce((acc, r) => {
      if (!r.disabled) acc[r.action] = (acc[r.action] || 0) + 1;
      acc.total++;
      acc.disabled += r.disabled ? 1 : 0;
      return acc;
    }, { total: 0, disabled: 0 });
    return { filePath, readable: true, rules, stats };
  } catch (e) {
    return { filePath, readable: false, error: e.message, rules: [], stats: { total: 0, disabled: 0 } };
  }
}

// GET vue d'ensemble de la configuration Snort
app.get('/api/snort/overview', (_req, res) => {
  const { snortConfig, rulesFile } = loadSettings();

  // 1. Lire et parser snort.lua
  let luaParsed = null;
  let luaError  = null;
  if (snortConfig && fs.existsSync(snortConfig)) {
    try {
      const content = fs.readFileSync(snortConfig, 'utf8');
      luaParsed = parseSnortLua(content);
    } catch (e) { luaError = e.message; }
  } else {
    luaError = snortConfig ? 'Fichier introuvable' : 'Chemin non configuré';
  }

  // 2. Collecter tous les fichiers de règles à lire :
  //    - ceux inclus dans snort.lua
  //    - + local.rules configuré dans OinkView
  const includesFromLua = luaParsed ? luaParsed.ruleIncludes : [];
  const allPaths = [...new Set([...includesFromLua, rulesFile])].filter(Boolean);

  const ruleFiles = allPaths.map(readRuleFile);

  // 3. Stats globales agrégées
  const globalStats = ruleFiles.reduce((acc, f) => {
    acc.total    += f.stats.total;
    acc.disabled += f.stats.disabled;
    Object.entries(f.stats).forEach(([k, v]) => {
      if (!['total','disabled'].includes(k)) acc[k] = (acc[k] || 0) + v;
    });
    return acc;
  }, { total: 0, disabled: 0 });

  res.json({
    snortConfig,
    luaParsed,
    luaError,
    ruleFiles,
    globalStats
  });
});

// GET contenu brut de snort.lua
app.get('/api/snort/config-raw', (_req, res) => {
  const { snortConfig } = loadSettings();
  try {
    const content = fs.readFileSync(snortConfig, 'utf8');
    res.json({ content });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── API — Géolocalisation locale (geoip-lite, aucune requête internet) ───────

app.post('/api/geo/batch', (req, res) => {
  const { ips } = req.body;
  if (!Array.isArray(ips)) return res.status(400).json({ error: 'ips array required' });
  const results = {};
  ips.forEach(ip => {
    const geo = geoip.lookup(ip);
    if (geo) {
      results[ip] = {
        country:     geo.country || '',
        countryCode: geo.country || '',
        city:        geo.city    || '',
        region:      geo.region  || ''
      };
    }
  });
  res.json({ results });
});

// ─── API — Validation config Snort ────────────────────────────────────────────

app.post('/api/rules/validate', (_req, res) => {
  const { snortBin, snortConfig } = loadSettings();
  if (!snortBin || !snortConfig)
    return res.status(400).json({ ok: false, output: 'snortBin ou snortConfig non configuré dans les Paramètres.' });
  exec(`${snortBin} -c ${snortConfig} -T 2>&1`, { timeout: 30000 }, (error, stdout, stderr) => {
    const output  = (stdout + stderr).trim();
    const success = output.includes('successfully validated');
    res.json({ success, output });
  });
});

// ─── API — Test PCAP contre les règles Snort ─────────────────────────────────

app.post('/api/pcap/test', (req, res) => {
  const { snortBin, snortConfig } = loadSettings();
  const { pcapBase64, description, category } = req.body;

  if (!pcapBase64)
    return res.status(400).json({ error: 'Fichier PCAP manquant' });
  if (!description || !description.trim())
    return res.status(400).json({ error: 'Description requise' });
  if (!category)
    return res.status(400).json({ error: 'Catégorie requise' });
  if (!snortBin || !snortConfig)
    return res.status(400).json({ error: 'snortBin et snortConfig non configurés dans Paramètres' });

  const tmpId   = crypto.randomBytes(8).toString('hex');
  const tmpPcap = `/tmp/oinkview-${tmpId}.pcap`;
  const tmpLog  = `/tmp/oinkview-log-${tmpId}`;

  try {
    fs.writeFileSync(tmpPcap, Buffer.from(pcapBase64, 'base64'));
    fs.mkdirSync(tmpLog, { recursive: true });
  } catch (e) {
    return res.status(500).json({ error: `Erreur fichier temporaire : ${e.message}` });
  }

  const cmd = `${snortBin} -r ${tmpPcap} -c ${snortConfig} -l ${tmpLog} 2>&1`;
  exec(cmd, { timeout: 60000 }, (error, stdout, stderr) => {
    const output = (stdout + (stderr || '')).trim();

    // Lire les fichiers d'alertes générés dans tmpLog
    let alertLines = [];
    try {
      fs.readdirSync(tmpLog).forEach(f => {
        if (f.startsWith('alert')) {
          fs.readFileSync(path.join(tmpLog, f), 'utf8')
            .split('\n').filter(Boolean)
            .forEach(l => alertLines.push(l));
        }
      });
    } catch (_) {}

    // Fallback : parser stdout pour les lignes d'alertes
    if (alertLines.length === 0) {
      output.split('\n').forEach(line => {
        if (line.includes('[**]') || line.includes('[Priority:')) alertLines.push(line);
      });
    }

    // Nettoyage fichiers temporaires
    try { fs.unlinkSync(tmpPcap); } catch (_) {}
    try { fs.rmSync(tmpLog, { recursive: true, force: true }); } catch (_) {}

    const alertCount = alertLines.filter(l => l.includes('[**]')).length;
    res.json({ success: true, alertCount, alerts: alertLines, output, description, category });
  });
});

// ─── API — Opérations bulk sur les règles ─────────────────────────────────────

app.post('/api/rules/bulk', (req, res) => {
  const { rulesFile } = loadSettings();
  const { action, sids } = req.body;
  if (!action || !Array.isArray(sids) || !sids.length)
    return res.status(400).json({ error: 'action et sids requis' });
  try {
    let content = fs.readFileSync(rulesFile, 'utf8');
    if (action === 'delete') {
      const lines = content.split('\n').filter(line =>
        !sids.some(sid => line.match(new RegExp(`\\bsid\\s*:\\s*${sid}\\s*;`)))
      );
      content = lines.join('\n');
    } else {
      sids.forEach(sid => {
        const re = new RegExp(`(^|\\n)(#?\\s*(?:alert|drop|pass|reject|rewrite)[^\\n]*\\bsid\\s*:\\s*${sid}\\s*;[^\\n]*)`, 'g');
        content = content.replace(re, (_full, pre, line) => {
          const isDisabled = line.trimStart().startsWith('#');
          if (action === 'enable'  && isDisabled)  return pre + line.replace(/^(\s*)#\s?/, '$1');
          if (action === 'disable' && !isDisabled) return pre + '# ' + line;
          return _full;
        });
      });
    }
    fs.writeFileSync(rulesFile, content);
    res.json({ success: true, count: sids.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── API — Reset dashboard / stats ───────────────────────────────────────────

app.post('/api/reset/dashboard', (_req, res) => {
  dashResetTime = Date.now();
  res.json({ success: true, resetTime: dashResetTime });
});

app.post('/api/reset/stats', (_req, res) => {
  statsResetTime = Date.now();
  res.json({ success: true, resetTime: statsResetTime });
});

app.get('/api/reset/times', (_req, res) => {
  res.json({ dashResetTime, statsResetTime });
});

// ─── API — Statistiques log ───────────────────────────────────────────────────

app.get('/api/stats', (_req, res) => {
  const { logFile } = loadSettings();
  if (!logFile || !fs.existsSync(logFile)) {
    return res.json({ perMinute: {}, sidCounts: {}, ipCounts: {}, protoCounts: { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 }, priorityCounts: { '1': 0, '2': 0, '3': 0 }, total: 0 });
  }
  try {
    const lines = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
    const perMinute     = {};
    const sidCounts     = {};
    const ipCounts      = {};
    const protoCounts   = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    const priorityCounts = { '1': 0, '2': 0, '3': 0 };
    let total = 0;

    lines.forEach(function processLine(line) {
      if (statsResetTime && parseSnortTs(line) < statsResetTime) return;
      const tsM = line.match(/^(\d+)\/(\d+)-(\d+):(\d+):\d+/);
      if (tsM) {
        const now = new Date();
        const key = now.getFullYear() + '-' + tsM[1].padStart(2,'0') + '-' + tsM[2].padStart(2,'0') + 'T' + tsM[3] + ':' + tsM[4];
        perMinute[key] = (perMinute[key] || 0) + 1;
      }
      const sidM = line.match(/\[(\d+):(\d+):(\d+)\]/);
      const msgM = line.match(/\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]/);
      if (sidM) {
        const sid = sidM[2];
        if (!sidCounts[sid]) sidCounts[sid] = { count: 0, msg: msgM ? msgM[1] : '' };
        sidCounts[sid].count++;
        total++;
      }
      const ipM = line.match(/(\d+\.\d+\.\d+\.\d+)(?::\d+)?\s+->/);
      if (ipM) ipCounts[ipM[1]] = (ipCounts[ipM[1]] || 0) + 1;

      const protoM = line.match(/\{(\w+)\}/);
      if (protoM) {
        const p = protoM[1].toUpperCase();
        if (p === 'TCP' || p === 'UDP' || p === 'ICMP') protoCounts[p]++;
        else protoCounts.OTHER++;
      }
      const prioM = line.match(/\[Priority:\s*(\d+)\]/);
      if (prioM && priorityCounts[prioM[1]] !== undefined) priorityCounts[prioM[1]]++;
    });

    res.json({ perMinute, sidCounts, ipCounts, protoCounts, priorityCounts, total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── WebSocket — Auth + Real-time log streaming ──────────────────────────────

io.use((socket, next) => {
  const settings = loadSettings();
  if (!settings.authEnabled) return next();
  const token = socket.handshake.auth.token || '';
  if (!token || !sessions.has(token)) return next(new Error('Unauthorized'));
  next();
});

io.on('connection', (socket) => {
  const settings = loadSettings();
  const logFile  = settings.logFile;
  const tailN    = settings.tailLines || 200;

  console.log(`[ws] client connected: ${socket.id}`);

  // Send the last N lines immediately on connect
  if (fs.existsSync(logFile)) {
    try {
      const lines = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
      lines.slice(-tailN).forEach(function(l) {
        if (!dashResetTime || parseSnortTs(l) >= dashResetTime) socket.emit('log:line', l);
      });
    } catch (_) {}
  }

  // Watch for new data appended to the log file
  let currentSize = fs.existsSync(logFile) ? fs.statSync(logFile).size : 0;

  const watcher = chokidar.watch(logFile, {
    persistent:       true,
    usePolling:       false,
    awaitWriteFinish: { stabilityThreshold: 100, pollInterval: 50 }
  });

  watcher.on('change', (p) => {
    try {
      const newSize = fs.statSync(p).size;

      if (newSize < currentSize) {
        // Log was rotated / truncated — reset
        currentSize = 0;
      }

      if (newSize > currentSize) {
        const buf = Buffer.alloc(newSize - currentSize);
        const fd  = fs.openSync(p, 'r');
        fs.readSync(fd, buf, 0, buf.length, currentSize);
        fs.closeSync(fd);
        currentSize = newSize;

        buf.toString('utf8')
          .split('\n')
          .filter(Boolean)
          .forEach(line => socket.emit('log:line', line));
      }
    } catch (_) {}
  });

  // Log file deleted (Snort restart / rotation)
  watcher.on('unlink', () => {
    currentSize = 0;
    socket.emit('log:reset', { reason: 'Fichier de log supprimé — Snort redémarre ?' });
  });

  // Log file recreated after deletion
  watcher.on('add', (p) => {
    currentSize = 0;
    socket.emit('log:reset', { reason: 'Nouveau fichier de log détecté — Snort redémarré.' });
    // Stream the initial tail of the new file
    try {
      const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
      lines.slice(-tailN).forEach(l => socket.emit('log:line', l));
      currentSize = fs.statSync(p).size;
    } catch (_) {}
  });

  socket.on('disconnect', () => {
    console.log(`[ws] client disconnected: ${socket.id}`);
    watcher.close();
  });

  // Allow client to request a refresh of settings (path may have changed)
  socket.on('settings:reload', () => {
    watcher.close();
    // Reconnect will handle the rest; just acknowledge
    socket.emit('settings:reloaded');
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n  OinkView running → http://localhost:${PORT}\n`);
});
