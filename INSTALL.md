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

## 2. Configurer les chemins Snort

OinkView a besoin d'accéder aux fichiers Snort de votre hôte.
Les chemins dépendent de votre installation — configurez-les dans le fichier `.env`.

```bash
cp .env.example .env
nano .env
```

Contenu à adapter :

```env
# Dossier des règles (contient local.rules et les règles communautaires)
SNORT_RULES_DIR=/etc/snort/rules

# Dossier de configuration (contient snort.lua)
SNORT_CONFIG_DIR=/usr/local/etc/snort

# Binaire Snort
SNORT_BIN=/usr/local/bin/snort

# Dossier des logs (contient alert_fast.txt)
SNORT_LOG_DIR=/var/log/snort
```

> **Où trouver mes fichiers Snort ?**
> ```bash
> find / -name "snort.lua" 2>/dev/null
> find / -name "snort" -type f 2>/dev/null
> find / -name "local.rules" 2>/dev/null
> ```

---

## 3. Lancer le container

```bash
sudo docker compose up -d --build
```

Ouvrir dans le navigateur : **http://localhost:3000**

---

## 4. Configurer OinkView

Aller dans **Paramètres** et renseigner les mêmes chemins que dans `.env` :

| Champ | Exemple |
|-------|---------|
| Fichier de règles locales | `/etc/snort/rules/local.rules` |
| Fichier de logs | `/var/log/snort/alert_fast.txt` |
| Fichier de configuration (snort.lua) | `/usr/local/etc/snort/snort.lua` |
| Binaire Snort | `/usr/local/bin/snort` |

Cliquer **Sauvegarder**.

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
├── .env.example            ← Modèle de configuration des chemins Snort
├── .env                    ← Votre configuration locale (non commité)
├── config/                 ← settings.json persistant (volume Docker)
├── public/
│   ├── index.html          ← Dashboard temps réel
│   ├── rules.html          ← Éditeur de règles Snort 3
│   ├── pcap.html           ← Test PCAP contre les règles
│   ├── stats.html          ← Statistiques
│   ├── overview.html       ← Vue globale
│   ├── settings.html       ← Paramètres
│   └── js/
├── server.js               ← Backend Express + Socket.io
├── Dockerfile
└── docker-compose.yml
```
