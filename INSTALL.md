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

Ouvrir le fichier `.env` inclus dans le dépôt :

```bash
nano .env
```

**Installation standard Snort 3 → rien à modifier.** Les chemins par défaut sont déjà corrects :

| Variable | Chemin par défaut | Description |
|---|---|---|
| `SNORT_LOCAL_RULES` | `/etc/snort/rules/local.rules` | Fichier des règles locales (rw) |
| `SNORT_COMMUNITY_DIR` | `/etc/snort/rules` | Dossier des règles communautaires (ro) |
| `SNORT_CONFIG_DIR` | `/usr/local/etc/snort` | Dossier de configuration |
| `SNORT_BIN` | `/usr/local/bin/snort` | Binaire Snort |
| `SNORT_LOG_DIR` | `/var/log/snort` | Dossier des logs |

**Installation non-standard** → remplacer les valeurs par vos chemins réels.

> Pour trouver vos chemins :
> ```bash
> which snort
> find / -name "snort.lua" 2>/dev/null
> find / -name "local.rules" 2>/dev/null
> ```

---

## 3. Préparer les fichiers Snort

Docker monte les fichiers Snort comme volumes. Si un fichier n'existe pas encore sur l'hôte, Docker crée un **dossier** à sa place, ce qui provoque une erreur. Créez tous les fichiers nécessaires avant de lancer le container :

```bash
# Fichier de règles locales
sudo mkdir -p /etc/snort/rules
sudo touch /etc/snort/rules/local.rules
sudo chmod 664 /etc/snort/rules/local.rules

# Fichier de log Snort
sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert_fast.txt
sudo chmod 644 /var/log/snort/alert_fast.txt
```

> Si vous avez modifié les chemins dans `.env`, adaptez les commandes ci-dessus.

---

## 4. Lancer le container

```bash
sudo docker compose up -d --build
```

Ouvrir dans le navigateur : **http://localhost:3000**

---

## 5. Configuration Snort recommandée

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

## 6. Commandes utiles

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

## 7. Arborescence du projet

```
OinkView/
├── .env                 ← Chemins Snort 3 (modifier si installation non-standard)
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
