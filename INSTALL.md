# OinkView — Guide d'installation

OinkView est une interface web locale pour gérer votre installation Snort 3.
Elle tourne entièrement en local (Node.js) et lit/écrit directement dans les fichiers Snort.

---

## Prérequis

| Outil   | Version minimale |
|---------|-----------------|
| Node.js | 18 LTS          |
| npm     | 9+              |
| Snort   | 3.x             |
| OS      | Linux (Debian/Ubuntu/RHEL) ou WSL |

---

## 1. Installation des dépendances

```bash
cd /opt/oinkview          # ou le répertoire de votre choix
npm install
```

Dépendances installées :

| Paquet    | Rôle |
|-----------|------|
| express   | serveur HTTP |
| socket.io | WebSocket pour le flux de logs en temps réel |
| chokidar  | surveillance des fichiers (file watcher) |
| cors      | headers CORS si besoin d'accès cross-origin |

---

## 2. Gestion des permissions Linux

Le processus Node.js doit accéder aux fichiers Snort sans être root.
La méthode recommandée est d'utiliser le groupe `snort`.

### 2.1 Fichier de règles locales

```bash
# S'assurer que le groupe snort existe
sudo groupadd -f snort

# Assigner la propriété et les droits
sudo chown root:snort /etc/snort/rules/local.rules
sudo chmod 664 /etc/snort/rules/local.rules   # rw-rw-r--

# Ajouter l'utilisateur courant au groupe snort
sudo usermod -aG snort $USER
newgrp snort                                   # appliquer sans logout
```

### 2.2 Fichier de logs d'alertes

```bash
# Pour alert_fast ou alert_json
sudo chown root:snort /var/log/snort/alert_fast.txt
sudo chmod 640 /var/log/snort/alert_fast.txt  # rw-r-----

# Ou, si Snort tourne en tant qu'utilisateur 'snort' :
sudo chown snort:snort /var/log/snort/alert_fast.txt
sudo chmod 644 /var/log/snort/alert_fast.txt
```

### 2.3 Commande de rechargement sans mot de passe sudo

```bash
# Créer un fichier sudoers dédié à OinkView
echo "$USER ALL=(ALL) NOPASSWD: /bin/systemctl reload snort3" \
  | sudo tee /etc/sudoers.d/oinkview
sudo chmod 440 /etc/sudoers.d/oinkview
```

Testez avec :
```bash
sudo systemctl reload snort3
```

Si vous préférez la méthode SIGHUP :
```bash
echo "$USER ALL=(ALL) NOPASSWD: /bin/kill" \
  | sudo tee /etc/sudoers.d/oinkview
```
Et configurez dans OinkView → Paramètres :
```
kill -SIGHUP $(cat /var/run/snort/snort.pid)
```

---

## 3. Démarrage

```bash
# Mode production
npm start

# Mode développement (rechargement automatique)
npm run dev
```

Ouvrir dans le navigateur : **http://localhost:3000**

---

## 4. Configuration initiale

1. Aller dans **Paramètres** (Settings)
2. Renseigner le chemin vers `local.rules` et le fichier de log
3. Cliquer sur **Tester** pour vérifier les accès
4. Sauvegarder

---

## 5. Configuration Snort recommandée

### Activer alert_fast dans snort.lua

```lua
-- snort.lua
alert_fast =
{
    file = true,
    packet = false,
    limit = 10,        -- Mo
}
```

### Inclure local.rules

```lua
ips =
{
    include = '/etc/snort/rules/local.rules',
    variables = default_variables
}
```

---

## 6. Arborescence du projet

```
OinkView/
├── config/
│   └── settings.json       ← chemins des fichiers (créé automatiquement)
├── public/
│   ├── index.html          ← Dashboard / console de logs temps réel
│   ├── rules.html          ← Générateur et liste des règles
│   ├── settings.html       ← Paramètres
│   └── js/
│       ├── dashboard.js    ← WebSocket + affichage logs
│       ├── rules.js        ← Constructeur de règles Snort 3
│       └── settings.js     ← Formulaire de paramètres
├── package.json
├── server.js               ← Backend Express + Socket.io
└── INSTALL.md
```

---

## 7. Lancer comme service systemd (optionnel)

```ini
# /etc/systemd/system/oinkview.service
[Unit]
Description=OinkView - Snort 3 GUI Manager
After=network.target

[Service]
Type=simple
User=VOTRE_USER
WorkingDirectory=/opt/oinkview
ExecStart=/usr/bin/node server.js
Restart=on-failure
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now oinkview
```
