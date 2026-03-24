# OinkView — Guide d'utilisation

Interface web de gestion Snort 3 : installation Docker, référence des menus et générateur de règles complet.

---

## Installation via Docker

### Prérequis

- Docker 20.10+
- Docker Compose v2+
- Snort 3 installé sur la machine hôte

### Démarrage rapide

```bash
git clone https://github.com/cayjee/OinkView.git
cd OinkView
docker compose up -d
```

L'interface est accessible sur : **http://localhost:3000**

### Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `3000` | Port d'écoute du serveur |

### Volumes Docker

Le `docker-compose.yml` monte les répertoires Snort en lecture/écriture :

```yaml
volumes:
  - /etc/snort:/etc/snort          # règles et configuration
  - /var/log/snort:/var/log/snort  # logs d'alertes
```

Adapter ces chemins selon votre installation Snort.

### Commandes utiles

```bash
# Démarrer
docker compose up -d

# Arrêter
docker compose down

# Voir les logs OinkView
docker compose logs -f

# Redémarrer après mise à jour
git pull && docker compose up -d --build
```

---

## Configuration initiale

Au premier lancement, aller dans **Paramètres** et renseigner :

| Champ | Exemple | Description |
|---|---|---|
| Fichier de règles | `/etc/snort/rules/local.rules` | Règles locales (lecture/écriture) |
| Fichier de log | `/var/log/snort/alert_fast.txt` | Log d'alertes Snort |
| Config Snort | `/usr/local/etc/snort/snort.lua` | Fichier de configuration principal |
| Répertoire communautaire | `/usr/local/etc/snort/rules/` | Dossier contenant les fichiers `.rules` communautaires (lecture seule) — placer les fichiers `.rules` téléchargés directement dans ce dossier |
| Binaire Snort | `/usr/local/bin/snort` | Chemin vers l'exécutable Snort |
| Interface réseau | `eth0` | Interface par défaut pour les commandes générées |
| Commande de reload | `systemctl reload snort3` | Commande pour recharger Snort |
| Format du log | `alert_fast` ou `alert_json` | Format du fichier de log Snort |
| Lignes au chargement | `200` | Nombre de lignes historiques chargées au démarrage |

Cliquer sur **Tester** pour vérifier l'accès aux fichiers, puis **Sauvegarder**.

---

## Authentification

OinkView intègre un système d'authentification par token optionnel.

### Activer la protection par mot de passe

1. Aller dans **Paramètres → Authentification**
2. Cocher **Activer l'authentification par mot de passe**
3. Saisir un mot de passe dans le champ prévu
4. Cliquer sur **Sauvegarder les paramètres**
5. Recharger la page — OinkView redirige vers la page de connexion

### Se connecter

Accéder à `/login.html`, saisir le mot de passe et cliquer sur **Se connecter**. Un token de session est stocké dans le navigateur.

### Désactiver l'authentification

Décocher la case dans **Paramètres → Authentification** et sauvegarder.

> L'authentification est désactivée par défaut. Le token est purement en mémoire : il est invalidé à chaque redémarrage du serveur.

---

## Dashboard — Console d'alertes

Menu principal, accessible via **Dashboard**.

### Flux temps réel

Les alertes Snort arrivent en temps réel via WebSocket. L'indicateur en haut à droite affiche l'état de la connexion :
- Point vert clignotant : connecté
- Point gris : déconnecté (reconnexion automatique)

### Compteurs

| Badge | Description |
|---|---|
| `N alert` | Nombre d'alertes depuis le dernier reset |
| `N drop` | Nombre de paquets bloqués (action `drop`) |

### Détail d'une alerte

Cliquer sur une ligne de la console pour ouvrir le modal de détail, qui affiche :
- Timestamp complet
- Action, protocole, GID/SID/Rev
- IP source et destination avec ports
- Classification, priorité
- Message complet
- Ligne brute

### Filtres

| Filtre | Description |
|---|---|
| Recherche texte | Cherche dans toute la ligne |
| IP | Filtre sur l'IP source ou destination |
| Protocole | TCP / UDP / ICMP |
| Priorité | 1, 2 ou 3 |
| Action | `alert` ou `drop` |
| De / À | Plage horaire (datetime-local) |

Cliquer sur **Réinitialiser** pour effacer tous les filtres.

### Boutons d'action

| Bouton | Description |
|---|---|
| **Vider console** | Efface l'affichage (ne supprime pas les données) |
| **Réinitialiser tout** | Remet à zéro les compteurs et le cache geo |
| **Export TXT** | Télécharge les lignes visibles en texte brut |
| **Export CSV** | Télécharge les lignes visibles au format CSV |
| **Autoscroll** | Active/désactive le défilement automatique |
| **◀ Stats** | Affiche/masque le panneau statistiques latéral |
| **Reload Snort** | Envoie la commande de rechargement Snort (confirmation requise) |

### Panneau statistiques latéral

- **Graphique alertes/minute** — mini sparkline temps réel
- **Top règles** — SIDs les plus déclenchés
- **Top IPs sources** — avec géolocalisation hors-ligne (pays, ville)

---

## Vue Globale

Menu **Vue Globale** — vue d'ensemble de la configuration Snort en cours.

| Section | Contenu |
|---|---|
| **Statistiques globales** | Total règles chargées, règles actives/désactivées, nombre de fichiers |
| **Variables Snort** | `HOME_NET`, `EXTERNAL_NET`, `HTTP_PORTS`, etc. extraites de `snort.lua` |
| **Modules actifs** | Liste des plugins/modules chargés dans la configuration |
| **Fichiers de règles** | Liste de tous les fichiers `.rules` chargés avec leur statut |

---

## Statistiques

Menu **Statistiques** — analyse agrégée des alertes.

| Section | Contenu |
|---|---|
| **Cartes** | Total alertes, TCP, UDP, ICMP |
| **Graphique 60 min** | Activité par minute sur la dernière heure |
| **Répartition protocoles** | Camembert TCP/UDP/ICMP/Autre |
| **Répartition priorités** | Camembert priorités 1/2/3 |
| **Top 10 règles** | SIDs les plus déclenchés avec message |
| **Top 10 IPs sources** | Avec pays et ville (géolocalisation hors-ligne) |

Boutons disponibles :
- **Rafraîchir** — recharge les données
- **Réinitialiser** — remet les stats à zéro
- **Reload Snort** — recharge Snort

---

## Règles

Menu **Règles** — éditeur et liste des règles.

### Panneau gauche : Générateur de règles

Le formulaire génère une règle Snort 3 valide en temps réel dans l'aperçu. Deux boutons en bas :

| Bouton | Description |
|---|---|
| **Tester config Snort** | Lance `snort -c snort.lua -T` et affiche le résultat |
| **Sauvegarder** | Ajoute la règle dans `local.rules` avec le prochain SID disponible |

### Panneau droit : Liste des règles

#### Filtres de la liste

| Filtre | Description |
|---|---|
| Recherche | SID, message, action, chemin fichier |
| Source | Toutes / Locales uniquement / Communautaires uniquement |
| Catégorie | Filtre par fichier de règles communautaires |
| Classtype | Filtre par type de menace |

#### Actions sur une règle

| Bouton | Description |
|---|---|
| ✎ | Charge la règle dans l'éditeur (nouveau SID assigné automatiquement) |
| ⊞ | Affiche la règle brute |
| ▶ / ⏸ | Active ou désactive la règle (locales uniquement) |
| ✕ | Supprime la règle (locales uniquement, confirmation requise) |
| +local | Copie une règle communautaire dans `local.rules` pour la modifier |

#### Sélection multiple (bulk)

Cocher plusieurs règles via les cases à gauche, ou utiliser **Tout sélectionner** (en-tête de tableau). La barre d'actions bulk apparaît :

| Bouton | Description |
|---|---|
| **▶ Activer** | Active toutes les règles locales sélectionnées |
| **⏸ Désactiver** | Désactive toutes les règles locales sélectionnées |
| **✕ Supprimer** | Supprime toutes les règles locales sélectionnées (confirmation requise) |
| **Annuler** | Efface la sélection |

> Les règles communautaires ne peuvent pas être modifiées en bulk — les copier en local d'abord via **+local**.

---

## Générateur de règles Snort 3 — Référence complète

### Type de règle

| Type | Syntaxe générée | Usage |
|---|---|---|
| **Traditional** | `action proto src port -> dst port ( ... )` | Règle classique basée sur réseau |
| **Service** | `action service ( ... )` | Basée sur le protocole applicatif détecté |
| **File** | `action file ( ... )` | Inspection de fichiers |

---

### Action

| Action | Description |
|---|---|
| `alert` | Génère une alerte sans bloquer |
| `drop` | Bloque le paquet et génère une alerte |
| `pass` | Ignore le paquet (whitelist) |
| `reject` | Bloque et envoie un reset TCP / ICMP unreachable |
| `rewrite` | Remplace le contenu du paquet (mode inline) |

---

### En-tête réseau (Traditional)

| Champ | Exemples | Description |
|---|---|---|
| **Protocole** | `tcp`, `udp`, `icmp`, `ip` | Protocole de transport |
| **Direction** | `->` unidirectionnel, `<>` bidirectionnel | Sens du trafic |
| **IP Source / Destination** | `any`, `192.168.1.0/24`, `$HOME_NET`, `!10.0.0.0/8`, `[1.2.3.4,5.6.7.8]` | Adresse ou groupe |
| **Port Source / Destination** | `any`, `80`, `443`, `[80,443,8080]`, `1024:65535`, `!22` | Port ou plage |

**Variables Snort disponibles en autocomplétion :**

| Variable IP | Variable Port |
|---|---|
| `$HOME_NET` | `$HTTP_PORTS` |
| `$EXTERNAL_NET` | `$SHELLCODE_PORTS` |
| `$HTTP_SERVERS` | `$ORACLE_PORTS` |
| `$SQL_SERVERS` | `$SSH_PORTS` |
| `$SMTP_SERVERS` | `$FTP_PORTS` |
| `$DNS_SERVERS` | `$SIP_PORTS` |

---

### Service (Service Rule)

Protocoles applicatifs reconnus par Snort 3 :

`http`, `ftp`, `smtp`, `ssl`, `ssh`, `dns`, `sip`, `imap`, `pop3`, `telnet`, `dcerpc`, `netbios-ssn`, `dce_http_proxy`, `dce_http_server`

---

### Métadonnées

#### `msg`
Message affiché dans les alertes. Obligatoire.

```
msg:"Suspicious HTTP GET to /admin";
```

#### `classtype`
Catégorie de la menace. Influence la priorité par défaut.

| Valeur | Description |
|---|---|
| `attempted-admin` | Tentative d'accès administrateur |
| `attempted-user` | Tentative d'accès utilisateur |
| `web-application-attack` | Attaque applicative web |
| `shellcode-detect` | Détection de shellcode |
| `trojan-activity` | Activité de trojan |
| `denial-of-service` | Déni de service |
| `network-scan` | Scan réseau |
| `policy-violation` | Violation de politique |
| `protocol-command-decode` | Commande protocolaire anormale |
| `suspicious-login` | Tentative de connexion suspecte |
| `misc-attack` | Attaque diverse |
| `misc-activity` | Activité diverse |
| `bad-unknown` | Trafic inconnu suspect |
| `default-login-attempt` | Tentative avec identifiants par défaut |
| `icmp-event` | Événement ICMP |

#### `priority`
Priorité explicite de 1 (critique) à 255 (faible). Écrase la priorité du classtype.

#### `reference`
Lien vers une base de données de vulnérabilités.

| Type | Exemple | Base |
|---|---|---|
| `cve` | `2021-44228` | CVE (MITRE) |
| `url` | `example.com/advisory` | URL arbitraire |
| `bugtraq` | `12345` | SecurityFocus |
| `arachnids` | `328` | Arachnids |
| `nessus` | `10678` | Tenable Nessus |
| `mcafee` | `100210` | McAfee |
| `osvdb` | `12345` | OSVDB |
| `msb` | `MS17-010` | Microsoft Security Bulletin |

#### `metadata`
Paires clé-valeur libres pour documenter la règle.

```
metadata:affected_product Web_Server, created_at 2024, confidence high;
```

---

### Flow

Contrôle l'état de la connexion et le sens du trafic.

| Option | Description |
|---|---|
| `to_server, established` | Vers le serveur, connexion établie — le plus courant pour HTTP |
| `to_client, established` | Vers le client, connexion établie — pour les réponses |
| `from_client, established` | Synonyme de `to_server` |
| `from_server, established` | Synonyme de `to_client` |
| `to_server, not_established` | Paquets SYN / début de connexion |
| `stateless` | Ignore l'état de la connexion |
| `established` | Toute connexion établie |
| `to_server, no_stream` | Paquets non réassemblés uniquement |
| `to_server, only_stream` | Paquets réassemblés uniquement |

---

### Payload Detection

#### Content (plusieurs entrées possibles)

Chaque entrée content peut avoir :

| Champ | Description |
|---|---|
| **Sticky buffer** | Zone du paquet où chercher (voir liste ci-dessous) |
| **Valeur** | Chaîne à rechercher — texte ou hex `\|xx xx\|` |
| `nocase` | Recherche insensible à la casse |
| `fast_pattern` | Utiliser ce content comme pattern principal pour l'optimisation |
| `offset` | Position de départ dans le payload (en octets depuis le début) |
| `depth` | Nombre d'octets maximum à inspecter depuis l'offset |
| `distance` | Offset relatif au match précédent |
| `within` | Limite relative au match précédent |

**Sticky buffers disponibles :**

| Catégorie | Buffers |
|---|---|
| **HTTP** | `http_uri`, `http_raw_uri`, `http_header`, `http_raw_header`, `http_method`, `http_client_body`, `http_raw_body`, `http_cookie`, `http_raw_cookie`, `http_stat_code`, `http_stat_msg`, `http_version`, `http_true_ip` |
| **Fichier / paquet** | `file_data`, `pkt_data`, `raw_data` |
| **DNS** | `dns_query` |
| **SSL/TLS** | `ssl_state`, `ssl_version` |
| **SMTP** | `smtp_from_addr`, `smtp_rcpt_addr`, `smtp_filename`, `smtp_header`, `smtp_body` |
| **SIP** | `sip_body`, `sip_header`, `sip_method`, `sip_stat_code`, `sip_uri` |
| **SSH** | `ssh_proto`, `ssh_server_version`, `ssh_client_version` |

**Exemple — deux content chaînés :**
```
http_uri; content:"/admin"; nocase; content:"passwd"; distance:0; within:50;
```

#### `pcre`
Expression régulière compatible Perl. Inclure les délimiteurs `/pattern/flags`.

| Flag | Description |
|---|---|
| `i` | Insensible à la casse |
| `s` | `.` inclut les sauts de ligne |
| `m` | `^`/`$` correspondent à chaque ligne |
| `x` | Ignorer les espaces et commentaires |
| `R` | Relatif au dernier match |
| `U` | Appliqué au buffer `http_uri` normalisé |

```
pcre:"/^GET\s+\/admin/i";
```

---

### Détection réseau

#### Flags TCP

| Flag | Lettre | Description |
|---|---|---|
| SYN | S | Établissement de connexion |
| ACK | A | Accusé de réception |
| FIN | F | Fin de connexion |
| RST | R | Reset |
| PSH | P | Push data |
| URG | U | Données urgentes |
| CWR | C | Congestion Window Reduced |
| ECE | E | ECN Echo |

**Modificateurs :**
- `+` *(défaut)* — au moins ces flags doivent être présents
- `!` — aucun de ces flags ne doit être présent
- `*` — au moins un de ces flags doit être présent

```
flags:S;          # SYN uniquement
flags:SA;         # SYN + ACK
flags:!SF;        # ni SYN ni FIN
```

#### `itype` / `icode` (ICMP)

| Option | Exemples courants |
|---|---|
| `itype` | `8` (echo request), `0` (echo reply), `3` (unreachable), `11` (time exceeded) |
| `icode` | `0`, `1:3` (plage) |

#### `dsize`
Taille du payload en octets.

```
dsize:>100;          # payload > 100 octets
dsize:100<>200;      # entre 100 et 200 octets
dsize:0;             # payload vide
```

#### `ttl`
Valeur du champ TTL IP.

```
ttl:<64;             # TTL inférieur à 64
ttl:64<>128;         # entre 64 et 128
```

#### `tos`
Valeur du champ Type of Service IP (décimal).

#### `id`
Valeur du champ identification IP (décimal).

```
id:31337;
```

#### `window`
Taille de fenêtre TCP.

```
window:1024;
```

#### `ip_proto`
Numéro de protocole IP (dans le champ Protocol de l'en-tête IP).

```
ip_proto:!6;         # pas TCP
ip_proto:17;         # UDP
```

#### `fragbits`
Bits de fragmentation IP.

| Bit | Lettre | Description |
|---|---|---|
| More Fragments | M | D'autres fragments suivent |
| Don't Fragment | D | Fragmentation interdite |
| Reserved | R | Bit réservé |

Mêmes modificateurs que flags TCP (`+`, `!`, `*`).

```
fragbits:D;          # bit Don't Fragment activé
fragbits:!D;         # bit Don't Fragment non activé
```

---

### Opérations Byte

Ces options permettent d'extraire et tester des valeurs numériques dans le payload.

#### `byte_test`
Teste une valeur numérique extraite du payload.

```
byte_test: bytes, operator, value, offset [,endian] [,string] [,relative];
```

| Paramètre | Description |
|---|---|
| `bytes` | Nombre d'octets à lire (1-4 pour binaire, 1-10 pour string) |
| `operator` | `=`, `!=`, `<`, `>`, `<=`, `>=`, `&` (AND bit), `^` (XOR bit) |
| `value` | Valeur à comparer (décimal ou hex `0x...`) |
| `offset` | Position dans le payload |
| `big` / `little` | Ordre des octets (défaut: big endian) |
| `string` | Lire comme chaîne numérique |
| `relative` | Offset relatif au dernier match |

```
byte_test:4,=,0x50415353,0;    # teste "PASS" en hex
byte_test:2,>,1000,4,big;      # 2 octets à l'offset 4, valeur > 1000
```

#### `byte_jump`
Saute un nombre d'octets dans le payload pour repositionner le curseur.

```
byte_jump: bytes, offset [,relative] [,big/little] [,align] [,from_beginning] [,from_end] [,post_offset N] [,dce];
```

```
byte_jump:2,0,relative,little;   # saute selon la valeur de 2 octets (little endian)
```

#### `byte_extract`
Extrait une valeur numérique dans une variable réutilisable.

```
byte_extract: bytes, offset, name [,relative] [,multiplier N] [,big/little] [,string] [,align];
```

```
byte_extract:2,0,pkt_len;                # extrait 2 octets dans la variable "pkt_len"
content:"DATA"; within:pkt_len;          # réutilise la variable
```

#### `byte_math`
Effectue un calcul arithmétique sur une valeur extraite.

```
byte_math: bytes, offset, operator, rvalue, result [,endian] [,string] [,relative] [,dce];
```

| Opérateur | Description |
|---|---|
| `+` | Addition |
| `-` | Soustraction |
| `*` | Multiplication |
| `/` | Division |
| `<<` | Décalage gauche |
| `>>` | Décalage droit |

```
byte_math:2,0,+,8,result_var,big;   # extrait 2 octets, ajoute 8, stocke dans result_var
```

---

### Rate Limiting

#### `threshold`
Limite la génération d'alertes pour éviter le flood.

| Paramètre | Valeurs | Description |
|---|---|---|
| `type` | `limit` | Déclencher au maximum N alertes par période |
| | `threshold` | Déclencher 1 alerte toutes les N occurrences |
| | `both` | Combiner limit et threshold |
| `track` | `by_src` | Compter par IP source |
| | `by_dst` | Compter par IP destination |
| `count` | entier | Nombre d'occurrences |
| `seconds` | entier | Durée de la fenêtre (secondes) |

```
threshold:type limit, track by_src, count 5, seconds 60;
# → maximum 5 alertes par IP source par minute
```

#### `detection_filter`
Déclenche l'alerte seulement après N occurrences dans une fenêtre de temps.

```
detection_filter:track by_src, count 10, seconds 1;
# → alerte uniquement si > 10 paquets par seconde (détection de brute-force)
```

Différence avec `threshold` : `detection_filter` supprime complètement l'alerte sous le seuil, alors que `threshold:limit` génère les premières N alertes.

---

### SID / Rev / rem

| Champ | Description |
|---|---|
| **SID** | Identifiant unique de la règle. Auto-incrémenté à partir de 1 000 001 pour les règles locales. Non modifiable. |
| **Rev** | Numéro de révision. Incrémenter à chaque modification de la règle. |
| **rem** | Commentaire interne à la règle, non affiché dans les alertes. |

---

## Exemples de règles complètes

### Détection d'un scan SYN

```
alert tcp any any -> $HOME_NET any ( msg:"TCP SYN Scan detected"; flags:S; flow:stateless; threshold:type threshold, track by_src, count 20, seconds 1; classtype:network-scan; sid:1000001; rev:1; )
```

### Détection d'une tentative d'accès à /admin

```
alert http any any -> $HOME_NET 80 ( msg:"HTTP GET /admin attempt"; flow:to_server,established; http_uri; content:"/admin"; nocase; fast_pattern; classtype:web-application-attack; reference:url,owasp.org/Top10; sid:1000002; rev:1; )
```

### Détection d'un ping flood

```
alert icmp any any -> $HOME_NET any ( msg:"ICMP Flood"; itype:8; icode:0; detection_filter:track by_src, count 50, seconds 1; classtype:denial-of-service; sid:1000003; rev:1; )
```

### Extraction et test d'une valeur byte

```
alert tcp any any -> $HOME_NET 9200 ( msg:"Elasticsearch large request body"; flow:to_server,established; byte_test:4,>,65536,0,big; classtype:web-application-attack; sid:1000004; rev:1; )
```

### Règle avec PCRE

```
alert http any any -> $HOME_NET any ( msg:"SQL Injection attempt"; flow:to_server,established; http_uri; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; classtype:web-application-attack; sid:1000005; rev:1; )
```

### Brute-force SSH

```
alert tcp any any -> $HOME_NET $SSH_PORTS ( msg:"SSH Brute Force attempt"; flow:to_server,established; content:"SSH"; detection_filter:track by_src, count 5, seconds 10; classtype:attempted-admin; sid:1000006; rev:1; )
```

---

## Paramètres — Référence

### Fichiers Snort

| Champ | Description |
|---|---|
| Fichier de règles locales | Fichier `local.rules` — lecture et écriture par OinkView |
| Fichier de logs | Log d'alertes Snort lu en temps réel |
| Format du log | `alert_fast` (texte) ou `alert_json` (JSON structuré) |
| Dossier communautaire | Dossier contenant les fichiers `.rules` communautaires — tous les `.rules` présents dans ce dossier sont chargés en lecture seule dans OinkView |
| Fichier de configuration | `snort.lua` — utilisé pour la validation et la vue globale |
| Binaire Snort | Chemin vers l'exécutable `snort` |
| Interface réseau | Interface utilisée dans les commandes générées |
| Lignes au chargement | Historique affiché à l'ouverture du dashboard |

### Rechargement Snort

| Champ | Description |
|---|---|
| Commande de rechargement | Ex: `systemctl reload snort3` ou `kill -SIGHUP $(cat /var/run/snort/snort.pid)` |
| Fichier PID | Utilisé en fallback si la commande est vide |

### Authentification

| Champ | Description |
|---|---|
| Activer l'authentification | Protège toutes les pages par un mot de passe |
| Mot de passe | Laisser vide pour conserver le mot de passe actuel |

### Commandes Snort générées

La section en bas de page génère automatiquement les commandes utiles à partir de vos paramètres :

| Commande | Description |
|---|---|
| Démarrer Snort (IDS passif) | Lance Snort en mode capture |
| Tester la configuration | `snort -c snort.lua -T` |
| Arrêter Snort | `pkill -f snort` |
| Voir les alertes en direct | `tail -f <logfile>` |
| Vérifier que Snort tourne | `ps aux | grep snort` |
| Version de Snort | `snort --version` |

Chaque commande dispose d'un bouton **Copier**.

### Permissions Linux

La section **Permissions Linux requises** génère les commandes `chmod`/`chown` et `sudoers` adaptées à vos chemins configurés.
