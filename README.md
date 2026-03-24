# OinkView — Snort 3 Management Interface

> L'interface de gestion Snort 3 que votre SIEM ne peut pas remplacer.

![Node.js](https://img.shields.io/badge/Node.js-20-green?logo=node.js)
![Express](https://img.shields.io/badge/Express-4.x-lightgrey?logo=express)
![Socket.io](https://img.shields.io/badge/Socket.io-4.x-black?logo=socket.io)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Pourquoi OinkView ?

Un SIEM ingère vos logs Snort, les corrèle, génère des alertes — mais il ne peut pas **modifier une règle**, **désactiver un faux positif**, **créer une signature** ou **valider votre configuration** sans que vous ouvriez un terminal SSH.

OinkView comble ce manque : c'est l'interface de **gestion opérationnelle de Snort 3**, conçue pour l'analyste qui veut agir sur son IDS directement depuis son navigateur.

```
Flux de travail typique sans OinkView :
  Alerte SIEM → SSH sur la sonde → vi local.rules → snort -c -T → SIGHUP

Flux de travail avec OinkView :
  Alerte → OinkView → modifier/désactiver la règle → copier la commande → terminé
```

> Fonctionne entièrement **hors-ligne** — aucune donnée ne quitte votre réseau.

---

## Ce qu'OinkView fait que votre SIEM ne fait pas

| Fonctionnalité | SIEM | OinkView |
|---|:---:|:---:|
| Visualiser les alertes en temps réel | ✅ | ✅ |
| Créer une règle Snort 3 | ❌ | ✅ |
| Activer / désactiver une règle | ❌ | ✅ |
| Modifier les règles communautaires | ❌ | ✅ |
| Valider la configuration Snort (`-T`) | ❌ | ✅ |
| Voir les variables réseau de snort.lua | ❌ | ✅ |
| Géolocalisation offline des IPs | ➖ | ✅ |
| Déploiement en 3 commandes | ➖ | ✅ |

---

## Fonctionnalités

### Dashboard — Console alertes temps réel
- Flux live via WebSocket, nouvelles alertes en haut
- Filtres : texte, IP, protocole, priorité, action, plage horaire
- Clic sur une alerte → modal de détail complet
- Panneau statistiques : graphique d'activité, top SIDs, top IPs géolocalisées
- Export **TXT / CSV** des alertes filtrées

### Règles — Éditeur complet
- Liste locale + règles communautaires (lecture seule)
- Activer / désactiver / supprimer avec confirmation
- Sélection **bulk** : appliquer une action sur plusieurs règles en un clic
- **Générateur de règles** Snort 3 : 32 sticky buffers, PCRE, rate limiting, byte ops
- **Validation** de la configuration (`snort -c snort.lua -T`) avec résultat inline
- Copier une règle communautaire dans `local.rules` pour la personnaliser

### Vue Globale
- Parsing de `snort.lua` : variables réseau (`HOME_NET`, `HTTP_PORTS`…), modules actifs, fichiers de règles chargés

### Statistiques
- Graphique 60 min, camemberts protocoles/priorités
- Top 10 IPs sources avec géolocalisation offline
- Top 10 règles déclenchées

### Paramètres
- Configuration des chemins Snort (règles, log, config, binaire)
- Commandes Snort générées dynamiquement (démarrer, tester, arrêter, recharger les règles)
- Authentification par mot de passe (optionnelle)

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

## Pour qui ?

| Profil | Usage |
|---|---|
| Analyste SOC avec Snort standalone | Gestion des règles sans SSH, monitoring live |
| Équipe avec SIEM | Complément pour la gestion opérationnelle de la sonde |
| Administrateur réseau | Surveillance du trafic, ajustement des règles |
| Étudiant / formation cybersécurité | Prise en main de Snort 3 sans ligne de commande |

---

## Architecture

```
OinkView/
├── server.js              ← Backend Express + Socket.io + API REST
├── public/
│   ├── index.html         ← Dashboard
│   ├── overview.html      ← Vue globale
│   ├── rules.html         ← Éditeur de règles
│   ├── stats.html         ← Statistiques
│   ├── settings.html      ← Paramètres
│   └── js/
├── config/
│   ├── settings.json      ← Configuration persistante (gitignored)
│   └── reset_times.json   ← Timestamps de réinitialisation (gitignored)
├── Dockerfile
└── docker-compose.yml
```

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Node.js 20 + Express 4 |
| Temps réel | Socket.io 4 + Chokidar |
| Frontend | HTML5 + Tailwind CSS |
| Graphiques | Canvas API |
| Géolocalisation | geoip-lite (offline, embarqué) |
| Déploiement | Docker + Docker Compose |

---

## Licence

MIT — Utilisation libre, y compris en environnement professionnel.

---

*OinkView — parce que gérer Snort ne devrait pas nécessiter un terminal.*
