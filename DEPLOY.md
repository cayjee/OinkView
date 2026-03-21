# OinkView — Guide d'utilisation

Interface web de gestion Snort 3 : installation Docker et référence complète du générateur de règles.

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
docker compose pull && docker compose up -d
```

---

## Configuration initiale

Au premier lancement, aller dans **Paramètres** et renseigner :

| Champ | Exemple | Description |
|---|---|---|
| Fichier de règles | `/etc/snort/rules/local.rules` | Règles locales (lecture/écriture) |
| Fichier de log | `/var/log/snort/alert_fast.txt` | Log d'alertes Snort |
| Config Snort | `/etc/snort/snort.lua` | Fichier de configuration principal |
| Répertoire communautaire | `/etc/snort/rules/` | Règles communautaires (lecture seule) |
| Commande de reload | `systemctl reload snort3` | Commande pour recharger Snort |

Cliquer sur **Tester** pour vérifier l'accès aux fichiers, puis **Sauvegarder**.

---

## Générateur de règles Snort 3

Accessible via le menu **Règles**. Le formulaire génère une règle Snort 3 valide en temps réel et l'ajoute dans `local.rules`.

---

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
| *(et 13 autres)* | ... |

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

Sélectionner les flags à tester :

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

---

## Gestion des règles

### Activer / Désactiver
Cliquer sur ⏸ pour désactiver une règle (commentée dans le fichier avec `#`). Cliquer sur ▶ pour la réactiver.

### Charger dans l'éditeur
Cliquer sur ✎ pour charger une règle existante dans le générateur. Un nouveau SID est automatiquement assigné.

### Règles communautaires
Les règles communautaires sont en lecture seule. Cliquer sur **+local** pour copier une règle dans `local.rules` avec un nouveau SID, afin de la modifier.

### Reload Snort
Le bouton **Reload Snort** en bas de la sidebar envoie la commande configurée dans Paramètres pour recharger Snort sans interruption de service.
