# Analyseur de logs d'authentification SSH

Ce projet analyse des journaux Linux `auth.log` pour résumer les tentatives de connexion SSH. Il lit les fichiers de
logs, extrait les événements d'authentification, géolocalise les adresses IP et présente les résultats dans le terminal
et dans un dashboard.

## Prérequis

- Python 3.14 ou une version ultérieure
- [uv](https://docs.astral.sh/uv/)
- Une connexion Internet pour géolocaliser les nouvelles adresses IP

## Installation et lancement

À la racine du projet, installez les dépendances puis lancez l'analyse :

```powershell
uv sync
uv run main.py
```

Le programme crée les dossiers `storage/` et `logs/` si nécessaire. Au premier lancement, il lit les fichiers du dossier
`data/`, enregistre les événements dans `storage/events.csv`, puis affiche le rapport et ouvre le dashboard.

Pour relire les journaux et reconstruire les événements :

```powershell
uv run main.py reload
```

Sans `reload`, les événements déjà enregistrés dans `storage/events.csv` sont réutilisés ; les fichiers de `data/` ne
sont donc pas relus à chaque lancement.

## Journaux analysés

Le dossier `data/` doit contenir des fichiers nommés `auth.log.*`, par exemple `auth.log.1` ou `auth.log.2.gz`.
Les fichiers compressés sont reconnus à partir de leur signature gzip. Les autres fichiers, notamment un fichier nommé
simplement `auth.log`, ne sont pas lus.

Seules les lignes `sshd` correspondant aux événements suivants sont extraites :

- `FAILED` : échec d'authentification (par exemple, un mot de passe refusé) ;
- `INVALID` : tentative avec un utilisateur inexistant ;
- `ACCEPTED` : connexion acceptée.

Les répétitions syslog (`message repeated N times`) sont comptabilisées comme N tentatives. Les événements enregistrés
contiennent la date, le type d'événement, l'utilisateur, l'adresse IP, le port et le nombre de tentatives. Comme les dates
syslog ne contiennent pas l'année, celle-ci est fixée à 2026 dans le code.

## Géolocalisation et cache

Le programme sélectionne jusqu'à 100 adresses IP issues des événements `FAILED` et `ACCEPTED`, en donnant la priorité
aux connexions acceptées, puis aux IP les plus actives. Les nouvelles adresses sont recherchées sur
[ipinfo.io](https://ipinfo.io/) et les résultats sont conservés dans `storage/locations.csv`. Une IP déjà présente dans
ce fichier n'est pas interrogée à nouveau, même après une relance avec `reload`.

Un jeton ipinfo.io est facultatif. Pour l'utiliser, créez un fichier `.env` à la racine du projet contenant :

```text
IPINFO_TOKEN=votre_jeton
```

Le fichier `.env` est ignoré par Git. Sans accès au service, les adresses non géolocalisées reçoivent un pays inconnu
(`??`) ; les IP déjà présentes dans le cache restent disponibles.

## Résultats

Le rapport du terminal présente les totaux, les connexions acceptées, les principales IP et les noms d'utilisateur les
plus souvent testés. Le dashboard Matplotlib affiche trois graphiques :

1. nombre de tentatives échouées par pays ;
2. nombre de connexions réussies par utilisateur ;
3. tentatives échouées avec un utilisateur inexistant.

Le graphique par pays ne porte que sur les tentatives échouées provenant d'IP géolocalisées.

Les fichiers CSV sont stockés dans `storage/`. Les journaux d'exécution par module sont enregistrés dans `logs/`.

## Structure du projet

```text
main.py                       point d'entrée et orchestration
ingestion/raw.py              lecture des fichiers auth.log.*
process/extract_transform.py  extraction des événements SSH
process/geolocation.py        sélection et géolocalisation des IP
storage/storage.py            persistance CSV des événements et du cache IP
serving/dashboard.py          rapport terminal et dashboard
data/                         journaux à analyser
```

## Dépendances

- `requests` : requêtes vers ipinfo.io ;
- `matplotlib` : dashboard ;
- `pymysql` : déclaré dans le projet, mais non utilisé actuellement.
