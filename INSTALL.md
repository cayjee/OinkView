# OinkView — Guide d'installation

OinkView est une interface web locale pour gérer votre installation Snort 3.
Elle se déploie via Docker et accède directement aux fichiers Snort de l'hôte.

---

## Prérequis

| Outil          | Version minimale |
|----------------|-----------------|
| Docker         | 20+             |
| Docker Compose | 1.29+ / v2      |
| Snort          | 3.x             |
| OS             | Linux (Debian/Ubuntu/RHEL) |

---

## 1. Cloner le dépôt

```bash
git clone https://github.com/cayjee/OinkView.git
cd OinkView
```

---

## 2. Adapter les volumes

Éditer `docker-compose.yml` pour pointer vers vos fichiers Snort :

```yaml
volumes:
  - ./config:/app/config
  - /etc/snort/rules/local.rules:/etc/snort/rules/local.rules
  - /var/log/snort/alert_fast.txt:/var/log/snort/alert_fast.txt:ro
```

Ajuster les chemins selon votre installation Snort.

---

## 3. Lancer le container

```bash
docker-compose up -d --build
```

Ouvrir dans le navigateur : **http://localhost:3000**

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
    include = '/etc/snort/rules/local.rules',
    variables = default_variables
}
```

---

## 5. Commandes utiles

```bash
# Voir les logs du container
docker logs -f oinkview

# Redémarrer
docker-compose restart

# Arrêter
docker-compose down

# Mettre à jour
git pull && docker-compose up -d --build
```

---

## 6. Arborescence du projet

```
OinkView/
├── config/                     ← settings.json persistant (volume)
├── public/
│   ├── index.html              ← Dashboard temps réel
│   ├── rules.html              ← Éditeur de règles Snort 3
│   ├── stats.html              ← Statistiques
│   ├── overview.html           ← Vue globale
│   ├── settings.html           ← Paramètres
│   └── js/
├── server.js                   ← Backend Express + Socket.io
├── Dockerfile
└── docker-compose.yml
```
