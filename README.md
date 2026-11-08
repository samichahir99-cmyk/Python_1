# SSH auth.log analyser

Pipeline d'analyse des logs SSH (`auth.log`) : lecture des fichiers de logs, extraction des événements
d'authentification, géolocalisation des adresses IP, puis affichage d'un rapport dans le terminal et d'un dashboard.

## Structure

```
main.py                          point d'entrée : exécute le pipeline
ingestion/raw.py                 lit tous les fichiers de data/ (texte ou gzip)     -> lignes
process/extract_transform.py     regex sur chaque ligne                              -> événements
process/geolocation.py           ipinfo.io, une requête par IP                       -> pays / ville / organisation
serving/dashboard.py             statistiques, rapport terminal et dashboard matplotlib
data/                            logs à analyser : auth.log.1, auth.log.2, auth.log.3.gz, auth.log.4.gz
```

## Fonctionnement

1. **Ingestion** : `raw.toRows('./data')` lit les fichiers `auth.log.*` (rotation des logs). Les fichiers
   compressés sont détectés par leur signature gzip.
2. **Extraction** : chaque ligne `sshd` est transformée en événement (`happened_at`, `event`, `user`, `ip`, `port`, `count`).
   Trois types d'événements :
   - `FAILED` : `Failed password for ...`
   - `INVALID` : `Invalid user ...` (le compte n'existe pas)
   - `ACCEPTED` : `Accepted ... for ...` (connexion réussie)

   Les lignes `message repeated N times` comptent pour N tentatives. L'année (2026) est fixée dans le code,
   car les logs syslog ne la contiennent pas.
3. **Géolocalisation** : `ips_to_locate` choisit au maximum `LOCATE_LIMIT` IP (100, défini dans `main.py`) :
   d'abord celles qui ont réussi à se connecter, puis les plus actives. Chaque IP est interrogée sur ipinfo.io, l'une après l'autre (une centaine de requêtes : quelques secondes à quelques minutes selon la connexion).
4. **Restitution** : `dashboard.stats` calcule les statistiques, `dashboard.report` affiche le résumé dans le terminal
   et `dashboard.dashboard` ouvre le dashboard.

## Dashboard

| Graphique | Contenu |
|---|---|
| Failed attempts per country | nombre de tentatives échouées par pays |
| Successful attempts per user | nombre de connexions réussies par utilisateur |
| Failed attempts with invalid user | tentatives avec un utilisateur inexistant, par nom d'utilisateur |

Limite : le graphique par pays ne couvre que les IP géolocalisées (100 au maximum). Son titre indique combien
de tentatives échouées ont été localisées sur le total. Sans accès à Internet, aucune IP n'est localisée
et ce graphique est vide.

## Lancer le projet

Prérequis : Python 3.14 et [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run main.py
```

- Une connexion Internet est nécessaire pour la géolocalisation.
- Optionnel : un jeton ipinfo.io dans un fichier `.env` à la racine (`IPINFO_TOKEN=...`) pour lever la limite
  de requêtes du plan gratuit. Ce fichier n'est pas versionné (`.gitignore`).
- Le dossier `.venv` n'est pas versionné : il est recréé par `uv sync`.

## Dépendances

- `matplotlib` : dashboard
- `requests` : appels à ipinfo.io
- bibliothèque standard : `re`, `gzip`, `os`, `datetime`, `math`, `collections`

`pymysql` est déclaré dans `pyproject.toml` mais n'est pas utilisé pour l'instant : le projet ne stocke rien dans une base de données.