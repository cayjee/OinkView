# OinkView — Snort 3 GUI Manager

> Interface web locale pour gérer, surveiller et analyser les alertes **Snort 3** en temps réel.

![Node.js](https://img.shields.io/badge/Node.js-20-green?logo=node.js)
![Express](https://img.shields.io/badge/Express-4.x-lightgrey?logo=express)
![Socket.io](https://img.shields.io/badge/Socket.io-4.x-black?logo=socket.io)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Aperçu

OinkView est une interface web légère qui se connecte directement à vos fichiers Snort 3 pour vous offrir :

- Une **console d'alertes en temps réel** avec filtres avancés
- Un **éditeur de règles** (activer/désactiver/créer/supprimer) avec support des règles communautaires
- Des **statistiques détaillées** : top IPs, top SIDs, distribution des protocoles et priorités
- Une **géolocalisation offline** des IPs sources (aucune requête internet)
- Des **exports TXT/CSV** des alertes filtrées

> Fonctionne entièrement hors-ligne — aucune donnée ne quitte votre réseau.

---

## Installation

Voir **[INSTALL.md](INSTALL.md)** pour le guide complet.

### Démarrage rapide

```bash
git clone https://github.com/cayjee/OinkView.git
cd OinkView
cp .env.example .env
nano .env                        # adapter les chemins Snort
sudo docker compose up -d --build
```

Ouvrir : **http://localhost:3000**

---

## Fonctionnalités

### Dashboard (`/`)
- Flux en temps réel des alertes Snort via **WebSocket**
- Filtres : texte, IP, protocole, priorité, action, plage horaire
- Modal de détail au clic sur une alerte
- Panneau latéral : graphique d'activité, top SIDs, top IPs avec pays
- Export **TXT / CSV** des alertes filtrées

### Vue Globale (`/overview.html`)
- Parsing de `snort.lua` : variables réseau, modules actifs, fichiers de règles inclus

### Règles (`/rules.html`)
- Liste locale + règles communautaires
- Activer / désactiver / supprimer (avec confirmation)
- Sélection **bulk** : activer/désactiver/supprimer plusieurs règles
- Générateur de règles Snort 3 complet (32 sticky buffers, PCRE, rate limiting…)
- **Validation** de la configuration Snort (`snort -c snort.lua -T`)
- Copier une règle communautaire dans `local.rules` avec nouveau SID

### Statistiques (`/stats.html`)
- Graphique 60 min, camemberts protocoles/priorités
- Top 10 IPs sources avec géolocalisation offline
- Top 10 règles déclenchées

### Paramètres (`/settings.html`)
- Chemins des fichiers Snort (règles, log, config, binaire)
- Authentification par mot de passe (optionnelle)
- Commandes Snort générées dynamiquement

---

## Architecture

```
OinkView/
├── .env.example           ← Modèle de configuration des chemins Snort
├── server.js              ← Backend Express + Socket.io + API REST
├── public/
│   ├── index.html         ← Dashboard
│   ├── overview.html      ← Vue globale
│   ├── rules.html         ← Éditeur de règles
│   ├── stats.html         ← Statistiques
│   ├── settings.html      ← Paramètres
│   └── js/
├── config/
│   └── settings.json      ← Configuration persistante (gitignored)
├── Dockerfile
└── docker-compose.yml
```

### API REST

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/settings` | Lire la configuration |
| POST | `/api/settings` | Sauvegarder la configuration |
| GET | `/api/rules` | Lire `local.rules` |
| POST | `/api/rules` | Ajouter une règle |
| PATCH | `/api/rules/:sid/toggle` | Activer/désactiver une règle |
| DELETE | `/api/rules/:sid` | Supprimer une règle |
| POST | `/api/rules/bulk` | Actions bulk sur plusieurs SIDs |
| POST | `/api/rules/validate` | Valider la config Snort |
| GET | `/api/rules/community` | Règles du dossier communautaire |
| POST | `/api/reload` | Recharger Snort |
| GET | `/api/snort/overview` | Vue globale snort.lua |
| GET | `/api/stats` | Statistiques parsées |
| POST | `/api/geo/batch` | Géolocalisation offline (geoip-lite) |

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Node.js 20 + Express 4 |
| Temps réel | Socket.io 4 + Chokidar |
| Frontend | HTML5 + Tailwind CSS (CDN) |
| Graphiques | Canvas API + SVG |
| Géolocalisation | geoip-lite (offline, embarqué) |
| Déploiement | Docker + Docker Compose |
| Police | JetBrains Mono |

---

## Licence

MIT — Utilisation libre, y compris en environnement professionnel.

---

*OinkView — parce que gérer Snort ne devrait pas être compliqué.*
