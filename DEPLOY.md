# OinkView — Guide de Déploiement

Guide complet pour déployer et gérer OinkView sur une VM Snort via Hyper-V.

---

## Prérequis

| Côté Windows (poste local) | Côté VM Linux (Snort) |
|---|---|
| PowerShell 5+ | Node.js 18 LTS + npm |
| OpenSSH client (`ssh`, `scp`) | Snort 3 installé |
| Accès réseau à la VM | nvm (recommandé) |

### Vérifier que SSH fonctionne

```powershell
ssh snort@<IP-VM>
```

Si la connexion est refusée, activer SSH sur la VM :

```bash
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
```

---

## Fichier de déploiement — `deploy.ps1`

Le script `deploy.ps1` automatise entièrement le déploiement depuis Windows vers la VM.

### Configuration du script

Ouvrir `deploy.ps1` et ajuster les 4 variables en haut :

```powershell
$VM_USER = "snort"           # Utilisateur SSH sur la VM
$VM_IP   = "192.168.1.100"  # IP de la VM Hyper-V
$VM_PATH = "/home/snort/OinkView"  # Répertoire cible sur la VM
$LOCAL   = "D:/CODAGE/OinkView"    # Répertoire source local
```

### Ce que fait le script (3 étapes)

1. **Copie SCP** — transfère `server.js`, `package.json` et `public/` vers la VM
2. **npm install** — installe/met à jour les dépendances Node sur la VM
3. **Redémarrage** — tue l'ancien process OinkView et relance avec `nohup`

### Lancer le déploiement

```powershell
.\deploy.ps1
```

À la fin, le script affiche l'URL d'accès :

```
OK - Deploye sur http://192.168.1.100:3000
```

---

## Trouver l'IP de la VM

### Depuis Windows (PowerShell)

```powershell
Get-VM | Select-Object Name, @{N='IP';E={($_.NetworkAdapters | Select-Object -Expand IPAddresses)[0]}}
```

### Depuis la VM

```bash
hostname -I
# ou
ip a | grep 'inet ' | grep -v 127
```

---

## Accéder à l'application

Ouvrir dans le navigateur depuis Windows :

```
http://<IP-VM>:3000
```

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Console d'alertes temps réel |
| Règles | `/rules.html` | Éditeur de règles Snort 3 |
| Statistiques | `/stats.html` | Graphiques et top IPs |
| Vue globale | `/overview.html` | Parsing de snort.lua |
| Paramètres | `/settings.html` | Chemins, API keys |

---

## Gérer OinkView sur la VM

### Vérifier si le process tourne

```bash
ps aux | grep node
```

### Démarrer manuellement

```bash
cd ~/OinkView
nohup node server.js > logs/oinkview.log 2>&1 &
echo "PID: $!"
```

### Arrêter OinkView

```bash
pkill -f 'node server.js'
```

### Voir les logs en direct

```bash
tail -f ~/OinkView/logs/oinkview.log
```

### Démarrer automatiquement au boot (systemd)

Créer le service :

```bash
sudo nano /etc/systemd/system/oinkview.service
```

Contenu :

```ini
[Unit]
Description=OinkView - Snort 3 GUI Manager
After=network.target

[Service]
Type=simple
User=snort
WorkingDirectory=/home/snort/OinkView
ExecStart=/usr/bin/env node server.js
Restart=on-failure
RestartSec=5
StandardOutput=append:/home/snort/OinkView/logs/oinkview.log
StandardError=append:/home/snort/OinkView/logs/oinkview.log

[Install]
WantedBy=multi-user.target
```

Activer et démarrer :

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now oinkview
sudo systemctl status oinkview
```

Avec systemd, plus besoin de `nohup` — OinkView redémarre automatiquement après un crash ou un reboot.

---

## Dépannage

### L'app ne répond plus après un restart de Snort

OinkView gère automatiquement le restart de Snort (détection de suppression/recréation du fichier de log). Si le stream s'interrompt, un message jaune apparaît dans la console :

> `⟳ Nouveau fichier de log détecté — Snort redémarré.`

Si l'app elle-même est morte :

```bash
ps aux | grep node   # vérifier
.\deploy.ps1         # redéployer depuis Windows
```

### Page inaccessible depuis le navigateur

1. Vérifier que node tourne : `ps aux | grep node`
2. Vérifier le port : `ss -tlnp | grep 3000`
3. Vérifier le firewall : `sudo ufw status`
4. Ouvrir le port si nécessaire : `sudo ufw allow 3000/tcp`

### Erreur de connexion SSH/SCP dans deploy.ps1

Vérifier que OpenSSH est installé sur Windows :

```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```

Installer si absent :

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

### Node.js introuvable sur la VM

Si nvm est utilisé, sourcer le profil avant de lancer node :

```bash
source ~/.bashrc && nvm use 20
```

Le script `deploy.ps1` le fait automatiquement via `source ~/.bashrc`.

### Vérifier la version Node

```bash
node --version   # doit être >= 18
npm --version    # doit être >= 9
```

---

## Structure des fichiers déployés

```
~/OinkView/
├── server.js              ← Backend Express + Socket.io
├── package.json           ← Dépendances npm
├── public/
│   ├── index.html         ← Dashboard
│   ├── rules.html         ← Éditeur de règles
│   ├── stats.html         ← Statistiques
│   ├── overview.html      ← Vue globale snort.lua
│   ├── settings.html      ← Paramètres
│   ├── style.css
│   └── js/
│       ├── dashboard.js
│       ├── rules.js
│       ├── stats.js
│       ├── overview.js
│       ├── settings.js
│       └── control.js
├── config/
│   └── settings.json      ← Config persistante (chemins, API keys)
└── logs/
    └── oinkview.log       ← Logs du serveur Node
```

> **Note :** `config/settings.json` et `logs/` ne sont pas écrasés par `deploy.ps1` — tes paramètres sont préservés à chaque déploiement.
