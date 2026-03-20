# OinkView — Snort 3 GUI Manager

> Interface web locale pour gérer, surveiller et analyser les alertes **Snort 3** en temps réel.

![Node.js](https://img.shields.io/badge/Node.js-20-green?logo=node.js)
![Express](https://img.shields.io/badge/Express-4.x-lightgrey?logo=express)
![Socket.io](https://img.shields.io/badge/Socket.io-4.x-black?logo=socket.io)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Aperçu

OinkView est une interface web légère qui se connecte directement à vos fichiers Snort 3 (fichier de règles, fichier de logs) pour vous offrir :

- Une **console d'alertes en temps réel** avec filtres avancés
- Un **éditeur de règles** (activer/désactiver/créer/supprimer) avec support des règles communautaires
- Des **statistiques détaillées** : top IPs, top SIDs, distribution des protocoles et priorités
- Une **géolocalisation** automatique des IPs sources
- Une intégration **VirusTotal** pour identifier les IPs malveillantes
- Des **exports TXT/CSV** des alertes filtrées

---

## Captures d'écran

| Dashboard temps réel | Page Statistiques | Éditeur de règles |
|---|---|---|
| Console filtrée + mini-graphique | Top IPs/SIDs + camemberts | Toggle, création, suppression |

---

## Fonctionnalités

### Dashboard (`/`)
- Flux en temps réel des alertes Snort via **WebSocket** (Socket.io)
- Mise en évidence des adresses IP (cyan)
- Filtres par texte, IP, protocole (TCP/UDP/ICMP), priorité, action (alert/drop)
- Panneau latéral avec **graphique d'activité sur 15 min**, top 8 SIDs, top 8 IPs sources
- Boutons **Export TXT / Export CSV** des lignes visibles
- **Réinitialisation** serveur (les alertes antérieures restent masquées même après navigation)

### Vue Globale (`/overview.html`)
- Aperçu de la configuration `snort.lua`
- Variables réseau (HOME_NET, EXTERNAL_NET, …)
- Modules actifs, fichiers de règles inclus
- Statut du processus Snort (PID, uptime)

### Règles (`/rules.html`)
- Liste de toutes les règles (locales + communautaires)
- Filtrage par catégorie, classtype, SID, message
- **Activer / désactiver** une règle (commentaire `#`)
- **Créer** une nouvelle règle avec auto-incrémentation du SID (≥ 1 000 001)
- **Supprimer** une règle
- Copier une règle communautaire dans `local.rules` avec nouveau SID
- Rechargement de Snort via `Reload Snort` (configurable)

### Statistiques (`/stats.html`)
- Compteurs : total alertes, TCP, UDP, ICMP
- **Graphique d'activité sur 60 minutes** (Canvas)
- Camemberts SVG : répartition protocoles / priorités
- **Top 10 IPs sources** avec pays, ville, drapeau et bouton **VirusTotal**
- **Top 10 règles déclenchées** (SID + message + compteur)
- Réinitialisation des statistiques (persistante entre navigations)

### Paramètres (`/settings.html`)
- Chemins des fichiers (rules, log, config Snort, dossier communautaire)
- Format du log (fast / json)
- Commande de rechargement Snort
- Clé API VirusTotal
- **Commandes Snort prêtes à copier** (démarrage IDS, test config, arrêt, logs, statut, version) générées dynamiquement depuis les chemins configurés
- Instructions de permissions Linux (groupes, sudoers)

---

## Architecture

```
oinkview/
├── server.js              # Backend Express + Socket.io + API REST
├── public/
│   ├── index.html         # Dashboard
│   ├── overview.html      # Vue globale Snort
│   ├── rules.html         # Éditeur de règles
│   ├── stats.html         # Statistiques
│   ├── settings.html      # Paramètres
│   ├── style.css          # Styles globaux (dark theme)
│   └── js/
│       ├── dashboard.js   # Temps réel, filtres, stats, geo, VT
│       ├── overview.js    # Parsing snort.lua
│       ├── rules.js       # Gestion des règles
│       ├── stats.js       # Graphiques, top IPs/SIDs, VT
│       └── settings.js    # Sauvegarde, commandes dynamiques
├── config/
│   └── settings.json      # Configuration persistante (gitignored)
├── Dockerfile
├── docker-compose.yml
└── package.json
```

### API REST

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/settings` | Lire la configuration |
| POST | `/api/settings` | Sauvegarder la configuration |
| POST | `/api/settings/test-path` | Vérifier l'accessibilité d'un fichier |
| GET | `/api/rules` | Lire `local.rules` |
| POST | `/api/rules` | Ajouter une règle |
| PATCH | `/api/rules/:sid/toggle` | Activer/désactiver une règle |
| DELETE | `/api/rules/:sid` | Supprimer une règle |
| GET | `/api/rules/community` | Lire les règles du dossier communautaire |
| GET | `/api/rules/all` | Toutes les règles (local + community) |
| GET | `/api/rules/next-sid` | Prochain SID disponible |
| POST | `/api/reload` | Recharger Snort |
| GET | `/api/overview` | Vue globale snort.lua |
| GET | `/api/logs` | Dernières N lignes du log |
| GET | `/api/stats` | Statistiques parsées depuis le log |
| POST | `/api/reset/dashboard` | Réinitialiser le dashboard |
| POST | `/api/reset/stats` | Réinitialiser les statistiques |
| GET | `/api/reset/times` | Timestamps de réinitialisation |
| GET | `/api/vt/ip/:ip` | Vérification VirusTotal (avec cache 1h) |

### WebSocket (Socket.io)

| Événement | Direction | Description |
|---|---|---|
| `log:line` | Serveur → Client | Nouvelle ligne du fichier de log |

---

## Installation

### Prérequis

- **Node.js ≥ 18** (ou Docker)
- Snort 3 installé sur la machine hôte
- Accès en lecture au fichier de log Snort (`alert_fast.txt`)
- Accès en lecture/écriture au fichier de règles (`local.rules`)

### Installation manuelle

```bash
git clone https://github.com/VOTRE_USERNAME/OinkView.git
cd OinkView
npm install
npm start
```

Ouvrir [http://localhost:3000](http://localhost:3000)

### Configuration initiale

Aller dans **Paramètres** et renseigner :
- **Fichier de règles** : `/etc/snort/rules/local.rules`
- **Fichier de logs** : `/var/log/snort/alert_fast.txt`
- **Config Snort** : `/usr/local/etc/snort/snort.lua` *(optionnel)*
- **Commande de rechargement** : `systemctl reload snort3` *(ou `kill -SIGHUP $(cat /var/run/snort/snort.pid)`)*

### Permissions Linux

OinkView doit pouvoir lire le log et modifier les règles :

```bash
# Créer le groupe snort et y ajouter l'utilisateur courant
sudo groupadd -f snort
sudo usermod -aG snort $USER

# Droits sur local.rules (lecture + écriture)
sudo chown root:snort /etc/snort/rules/local.rules
sudo chmod 664 /etc/snort/rules/local.rules

# Droits sur le log (lecture seule)
sudo chown root:snort /var/log/snort/alert_fast.txt
sudo chmod 640 /var/log/snort/alert_fast.txt

# Permettre le rechargement sans mot de passe
echo "$USER ALL=(ALL) NOPASSWD: /bin/systemctl" \
  | sudo tee /etc/sudoers.d/oinkview
sudo chmod 440 /etc/sudoers.d/oinkview
```

> Les commandes exactes adaptées à votre configuration sont disponibles dans l'onglet **Paramètres** de l'interface.

---

## Déploiement Docker

### Build & Run rapide

```bash
# Build l'image
docker build -t oinkview .

# Lancer avec les volumes nécessaires
docker run -d \
  --name oinkview \
  --restart unless-stopped \
  -p 3000:3000 \
  -v $(pwd)/config:/app/config \
  -v /etc/snort/rules/local.rules:/etc/snort/rules/local.rules \
  -v /var/log/snort/alert_fast.txt:/var/log/snort/alert_fast.txt:ro \
  oinkview
```

### Avec Docker Compose

```bash
# Éditer docker-compose.yml si besoin (chemins de volumes)
docker compose up -d

# Voir les logs
docker compose logs -f

# Arrêter
docker compose down
```

### Volumes

| Volume | Type | Description |
|---|---|---|
| `./config` | Lecture/écriture | Persistance de `settings.json` |
| `/etc/snort/rules/local.rules` | Lecture/écriture | Fichier de règles Snort |
| `/var/log/snort/alert_fast.txt` | Lecture seule | Log des alertes |
| `/usr/local/etc/snort/snort.lua` | Lecture seule | Config Snort (optionnel) |

> **Note** : Le `docker-compose.yml` utilise `network_mode: host` pour que la géolocalisation via [ip-api.com](http://ip-api.com) fonctionne correctement depuis le conteneur.

---

## VirusTotal

OinkView peut vérifier la réputation des IPs sources détectées via l'API VirusTotal v3.

1. Créer un compte gratuit sur [virustotal.com](https://www.virustotal.com)
2. Récupérer votre clé API dans *My API Key*
3. La renseigner dans **Paramètres → VirusTotal API Key**

Les résultats sont mis en cache côté serveur pendant **1 heure** pour économiser les requêtes. La clé n'est jamais exposée au navigateur.

---

## Format de log supporté

OinkView supporte le format **Snort fast-alert** :

```
MM/DD-HH:MM:SS.usec [**] [gen:sid:rev] message [**] [Classification: ...] [Priority: N] {PROTO} srcIP:srcPort -> dstIP:dstPort
```

Exemple :
```
03/20-14:32:11.123456 [**] [1:1000001:1] MALWARE-CNC Suspicious outbound [**] [Priority: 1] {TCP} 192.168.1.50:54321 -> 203.0.113.1:443
```

---

## Développement

```bash
npm install
npm run dev   # nodemon — rechargement automatique
```

L'application écoute sur [http://localhost:3000](http://localhost:3000).

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Node.js 20 + Express 4 |
| Temps réel | Socket.io 4 + Chokidar |
| Frontend | HTML5 + Tailwind CSS (CDN) |
| Graphiques | Canvas API + SVG |
| Géolocalisation | [ip-api.com](http://ip-api.com) (batch, gratuit) |
| Threat Intel | VirusTotal API v3 |
| Police | JetBrains Mono |

---

## Licence

MIT — Utilisation libre, y compris en environnement professionnel.

---

*OinkView — parce que gérer Snort ne devrait pas être compliqué.*
