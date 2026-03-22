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

## 2. Copier vos fichiers Snort

OinkView utilise des dossiers fixes inclus dans le dépôt.
Copiez vos fichiers Snort dans ces dossiers avant de démarrer.

### Règles locales

```bash
cp /chemin/vers/votre/local.rules rules/local.rules
```

### Règles communautaires (optionnel)

```bash
cp /chemin/vers/snort3-community.rules rules/community/
# ou tous les fichiers .rules d'un dossier :
cp /chemin/vers/vos/regles/*.rules rules/community/
```

### Logs Snort

Configurer Snort pour écrire ses alertes dans le dossier `logs/` d'OinkView :

```lua
-- Dans snort.lua
alert_fast =
{
    file = true,
    -- pointer vers le dossier logs/ d'OinkView
    -- ex : /home/utilisateur/OinkView/logs/alert_fast.txt
}
```

Ou créer un lien symbolique :

```bash
ln -s /var/log/snort/alert_fast.txt logs/alert_fast.txt
```

---

## 3. Lancer le container

```bash
sudo docker compose up -d --build
```

Ouvrir dans le navigateur : **http://localhost:3000**

Les chemins sont préconfigurés — aucune modification nécessaire dans Paramètres pour les règles et les logs.

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
