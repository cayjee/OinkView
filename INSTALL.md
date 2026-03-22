# OinkView — Guide d'installation

OinkView est une interface web locale pour gérer votre installation Snort 3.
Elle se déploie via Docker et accède directement aux fichiers Snort de l'hôte.

---

## Prérequis

| Outil          | Version minimale |
|----------------|-----------------|
| Docker         | 20+             |
| Docker Compose | v2 (`docker compose`) |
| Snort          | 3.x             |
| OS             | Linux (Debian/Ubuntu/RHEL) |

---

## 1. Cloner le dépôt

```bash
git clone https://github.com/cayjee/OinkView.git
cd OinkView
```

---

## 2. Placer vos fichiers Snort

OinkView utilise une structure de dossiers fixe. Placez vos fichiers aux emplacements suivants :

```
OinkView/
├── rules/
│   ├── local.rules          ← vos règles locales
│   └── community/           ← vos règles communautaires (.rules)
└── logs/
    └── alert_fast.txt       ← fichier de log Snort (symlink ou copie)
```

### Règles locales

Le fichier `rules/local.rules` est déjà présent (vide). OinkView le gère directement.

### Règles communautaires

Copiez vos fichiers `.rules` dans `rules/community/` :

```bash
cp snort3-community.rules rules/community/
```

### Logs

Créez un lien symbolique vers votre fichier de log Snort :

```bash
ln -s /var/log/snort/alert_fast.txt logs/alert_fast.txt
```

---

## 3. Lancer le container

```bash
sudo docker compose up -d --build
```

Ouvrir dans le navigateur : **http://localhost:3000**

Les chemins sont préconfigurés — aucune modification nécessaire dans Paramètres.

---

## 4. Configuration Snort recommandée

### Activer alert_fast dans snort.lua

```lua
alert_fast =
{
    file = true,
    packet = false,
    limit = 10,
}
```

### Inclure local.rules

```lua
ips =
{
    include = '/snort/rules/local.rules',
    variables = default_variables
}
```

---

## 5. Commandes utiles

```bash
# Voir les logs du container
sudo docker logs -f oinkview

# Redémarrer
sudo docker compose restart

# Arrêter
sudo docker compose down

# Mettre à jour
git pull && sudo docker compose up -d --build
```

---

## 6. Arborescence du projet

```
OinkView/
├── rules/
│   ├── local.rules          ← règles locales (géré par OinkView)
│   └── community/           ← règles communautaires (lecture seule)
├── logs/                    ← fichier de log Snort
├── config/                  ← settings.json persistant (volume Docker)
├── public/
│   ├── index.html           ← Dashboard temps réel
│   ├── rules.html           ← Éditeur de règles Snort 3
│   ├── pcap.html            ← Test PCAP contre les règles
│   ├── stats.html           ← Statistiques
│   ├── overview.html        ← Vue globale
│   └── settings.html        ← Paramètres
├── server.js                ← Backend Express + Socket.io
├── Dockerfile
└── docker-compose.yml
```
