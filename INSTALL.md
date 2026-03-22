# OinkView — Guide d'installation

OinkView est une interface web locale pour gérer votre installation Snort 3.
Elle se déploie via Docker et se connecte directement aux dossiers Snort de votre système.

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

## 2. Configurer les chemins Snort

```bash
cp .env.example .env
```

**Installation standard Snort 3 → rien à modifier.** Le `.env` pointe déjà vers les chemins par défaut :

| Variable | Chemin par défaut | Description |
|---|---|---|
| `SNORT_RULES_DIR` | `/etc/snort/rules` | Dossier des règles |
| `SNORT_CONFIG_DIR` | `/usr/local/etc/snort` | Dossier de configuration |
| `SNORT_BIN` | `/usr/local/bin/snort` | Binaire Snort |
| `SNORT_LOG_DIR` | `/var/log/snort` | Dossier des logs |

**Installation non-standard** → éditer `.env` avec vos chemins réels :

```bash
nano .env
```

> Pour trouver vos chemins :
> ```bash
> which snort
> find / -name "snort.lua" 2>/dev/null
> find / -name "local.rules" 2>/dev/null
> ```

---

## 3. Lancer le container

```bash
sudo docker compose up -d --build
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
├── .env.example         ← Chemins Snort 3 par défaut (copier en .env)
├── .env                 ← Votre configuration locale (non commité)
├── config/              ← settings.json persistant (volume Docker)
├── public/
│   ├── index.html       ← Dashboard temps réel
│   ├── rules.html       ← Éditeur de règles Snort 3
│   ├── pcap.html        ← Test PCAP contre les règles
│   ├── stats.html       ← Statistiques
│   ├── overview.html    ← Vue globale
│   └── settings.html    ← Paramètres
├── server.js            ← Backend Express + Socket.io
├── Dockerfile
└── docker-compose.yml
```
