# Analyseur de logs d'authentification SSH

Ce programme analyse des journaux Linux `auth.log` pour résumer l'activité SSH. Il extrait les tentatives de connexion, géolocalise certaines adresses IP, enregistre les résultats dans des fichiers CSV, puis affiche un rapport dans le terminal et un dashboard.

## Fonctionnalités

- Lecture des journaux SSH tournés, y compris les fichiers gzip.
- Extraction des échecs de connexion, des tentatives avec un utilisateur inexistant et des connexions acceptées.
- Comptabilisation des messages syslog répétés.
- Conservation des événements et des localisations dans des fichiers CSV.
- Géolocalisation via [ipinfo.io](https://ipinfo.io/), avec cache local.
- Rapport récapitulatif et graphiques Matplotlib.

## Prérequis

- Python 3.14 ou version ultérieure.
- [uv](https://docs.astral.sh/uv/).
- Un accès Internet pour les adresses IP qui ne figurent pas encore dans le cache de géolocalisation.

## Installation et lancement

Depuis la racine du projet, installez les dépendances :

```powershell
uv sync
```

Placez les journaux à analyser dans `data/`, puis lancez le programme :

```powershell
uv run main.py
```

Lors de la première exécution, le programme lit les journaux de `data/` et enregistre les événements dans `storage/events.csv`. Les exécutions suivantes réutilisent ce fichier. Pour relire les journaux et reconstruire les événements :

```powershell
uv run main.py reload
```

Le cache des localisations est conservé dans `storage/locations.csv`, y compris après un lancement avec `reload`.

## Journaux pris en charge

Le dossier `data/` doit contenir des fichiers de journaux tournés dont le nom commence par `auth.log.`, par exemple :

```text
data/
├── auth.log.1
├── auth.log.2
└── auth.log.3.gz
```

Les fichiers compressés sont reconnus grâce à leur signature gzip. Un fichier nommé simplement `auth.log` n'est pas lu.

Le programme extrait les lignes `sshd` correspondant aux événements suivants :

| Événement | Signification |
|---|---|
| `FAILED` | Mot de passe ou méthode d'authentification refusé(e). |
| `INVALID` | Tentative avec un compte inexistant. |
| `ACCEPTED` | Connexion SSH acceptée. |

Les messages `message repeated N times` sont comptés comme N tentatives. Chaque événement enregistré contient sa date, son type, l'utilisateur, l'adresse IP, le port et le nombre de tentatives. Les lignes syslog ne contenant pas l'année, celle-ci est fixée à 2026.

## Géolocalisation des adresses IP

Jusqu'à 100 adresses IP distinctes issues des événements `FAILED` et `ACCEPTED` sont sélectionnées. Les IP ayant eu une connexion acceptée sont prioritaires, puis les IP les plus actives. Les événements `INVALID` ne sont pas inclus dans cette sélection.

Les adresses absentes du cache sont recherchées auprès d'ipinfo.io. Un jeton est facultatif. Pour en fournir un, créez un fichier `.env` à la racine du projet :

```text
IPINFO_TOKEN=votre_jeton
```

Le programme conserve une valeur `IPINFO_TOKEN` déjà définie dans l'environnement du shell, qui est prioritaire sur celle du fichier `.env`. Sans résultat de géolocalisation, le pays est indiqué comme `??`. Les IP locales reconnues par ipinfo.io sont marquées `LAN`.

Les adresses IP non présentes dans le cache sont transmises à ipinfo.io pour la géolocalisation.

## Résultats

Le rapport du terminal présente les totaux d'événements, les connexions acceptées, les tentatives échouées par pays, les utilisateurs les plus testés et les principales IP.

Le dashboard comporte trois graphiques :

1. les tentatives échouées par pays (jusqu'à 15 pays ; seules les IP géolocalisées sont prises en compte) ;
2. les connexions réussies par utilisateur (jusqu'à 15 utilisateurs, en barres verticales) ;
3. la répartition des tentatives avec un utilisateur inexistant (diagramme circulaire ; les 8 principaux utilisateurs sont affichés séparément et les autres sont regroupés sous « Other »).

Les données sont enregistrées dans `storage/events.csv` et `storage/locations.csv`. Les journaux d'exécution des modules sont écrits à la racine du projet (`main.log`, `ingestion.log`, `process.log`, `storage.log` et `serving.log`). Les avertissements et erreurs sont également affichés dans le terminal.

## Structure du projet

```text
main.py                       point d'entrée et orchestration
ingestion/raw.py              lecture des fichiers auth.log.*
process/extract_transform.py  extraction et transformation des événements SSH
process/geolocation.py        sélection et géolocalisation des IP
storage/storage.py            lecture et écriture des fichiers CSV
serving/dashboard.py          rapport terminal, statistiques et graphiques
data/                         journaux à analyser
storage/                      fichiers CSV générés
```

## Dépendances

- `matplotlib` : graphiques du dashboard ;
- `requests` : requêtes vers ipinfo.io ;
- `pymysql` : déclaré dans le projet, mais non utilisé par le code actuel.
