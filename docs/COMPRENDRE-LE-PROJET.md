# Comprendre chaque fichier du projet

Ce guide explique **tout** ce que tu vois dans VS Code : à quoi sert chaque fichier,
qui l'a créé, et ce que tu peux répondre au prof. Lis-le avec VS Code ouvert à côté.

---

## 0. Ouvre le bon dossier

Dans VS Code : **Fichier → Ouvrir le dossier** → choisis
`F:\Ecole\Projet Informatique\sentinelle-fondation\sentinelle-repo`.

Le projet, c'est uniquement `sentinelle-repo`. Le dossier au-dessus
(`sentinelle-fondation`) n'est qu'un emballage, il n'y a rien d'autre dedans.

> Dans VS Code, les noms **en gris** sont des éléments **ignorés par git** : ils
> existent sur ton PC mais ne partent jamais sur GitHub (voir `.gitignore`).

---

## 1. Les éléments créés automatiquement (tu n'as pas à les écrire)

Ils apparaissent tout seuls quand on lance des commandes. Ils sont tous dans
`.gitignore`, donc jamais envoyés sur GitHub.

| Élément | Qui le crée | À quoi il sert | Si je le supprime ? |
|---|---|---|---|
| `.git/` (caché) | `git init` / `git clone` | L'historique de tous les commits et les branches. | ⚠️ **Ne jamais supprimer** : tu perdrais tout l'historique. |
| `.venv/` | `python -m venv .venv` | L'**environnement virtuel** : une copie de Python réservée au projet, avec Flask et pytest installés dedans. Ça évite de mélanger les bibliothèques de tous tes projets. | Rien de grave : on le recrée avec les 2 commandes du README. |
| `.pytest_cache/` | `python -m pytest` | pytest y note quels tests ont échoué la dernière fois, pour aller plus vite. | Rien : il revient au prochain lancement des tests. |
| `__pycache__/` (dans chaque dossier Python) | Python, au lancement | Le code Python déjà « traduit » pour démarrer plus vite. | Rien : il revient tout seul. |
| `instance/sentinelle.db` | `run.py`, au premier lancement | **La base de données SQLite** : un seul fichier qui contient l'historique des analyses de mail. | On perd l'historique des analyses ; une base vide est recréée au prochain lancement. |
| `instance/.gitkeep` | nous | Fichier vide. Git ne sait pas garder un dossier vide : ce fichier force le dossier `instance/` à exister sur GitHub. | Le dossier disparaîtrait de GitHub. |

**Ce que tu dis au prof :** « Ces éléments sont générés par les outils (Python,
pytest, git). Ils ne font pas partie du code source, c'est pour ça qu'ils sont dans
le `.gitignore`. »

---

## 2. Les fichiers à la racine

| Fichier | Rôle |
|---|---|
| `run.py` | **Le point de départ.** `python run.py` lance le serveur web sur `127.0.0.1:5000`. `127.0.0.1` veut dire « seulement ce PC » : personne d'autre sur le réseau ne peut s'y connecter. |
| `requirements.txt` | La liste des bibliothèques à installer : **Flask** (le serveur web) et **pytest** (les tests). `pip install -r requirements.txt` les installe. |
| `.gitignore` | La liste de ce que git doit **ignorer** : `.venv`, la base de données, les caches, et `.env`, qui contient des secrets. |
| `.env.example` | Un **modèle** de configuration. Le vrai fichier `.env` (copie de celui-ci) contient la clé secrète et n'est **jamais** mis sur GitHub. On ne publie jamais un secret. |
| `README.md` | La présentation du projet et la carte des fichiers. C'est la première page qu'on voit sur GitHub. |

---

## 3. `sentinelle/` : le code de l'application

C'est le **paquet Python** de l'appli. Un dossier qui contient un `__init__.py`,
Python le considère comme un « paquet » qu'on peut importer.

### Les fichiers de base

| Fichier | Rôle |
|---|---|
| `__init__.py` | Contient `create_app()` : fabrique l'appli Flask, branche la base de données et **enregistre les routes** (les pages). |
| `config.py` | Les réglages : où est la base, taille maximale d'un mail (2 Mo, pour empêcher quelqu'un de saturer l'appli avec un fichier énorme), dossier des mails d'essai. |
| `models.py` | `MailVerdict` : la « fiche résultat » d'une analyse (verdict, score, raisons, conseil). |
| `db.py` | Ouvre la connexion SQLite et crée la table `analyses` si elle n'existe pas. |
| `repository.py` | **Toutes** les requêtes SQL, et seulement ici. Avantage : un seul endroit à vérifier pour la sécurité (requêtes paramétrées avec `?` contre l'injection SQL). |
| `services.py` | `analyze_and_store()` : analyse un mail puis enregistre **seulement son empreinte** (sha256), jamais son contenu (RGPD). |

### `modules/mail/` : le cœur du projet

| Fichier | Rôle |
|---|---|
| `__init__.py` | La fonction `analyze_eml()` : l'entrée du module. Elle appelle le parser, puis les règles. |
| `parser.py` | **Découpe** le fichier `.eml` : expéditeur, sujet, en-têtes, liens, noms des pièces jointes. |
| `rules.py` | ⭐ **Les règles de détection.** Chaque règle ajoute des points de risque et une raison. Score ≥ 50 = dangereux, ≥ 20 = suspect. **C'est ici qu'on va travailler.** |
| `autotest.py` | Lance l'analyse sur les 20 mails de `samples/` et compte les bonnes réponses. |

`modules/__init__.py` est vide : il sert juste à dire à Python « `modules` est un paquet ».

### `routes/` : les adresses du site

| Fichier | Adresses | Rôle |
|---|---|---|
| `dashboard.py` | `/` | Affiche la console. |
| `mail_routes.py` | `/mail/` | La page « Analyse mail » (formulaire classique). |
| `api.py` | `/api/...` | L'**API JSON** que la console appelle en JavaScript. Contient la protection **CSRF** (en-tête `X-Sentinelle`, explication en haut du fichier). |
| `construction.py` | `/reseau/`, `/alertes/`, `/ia/` | Les pages « en cours de construction ». |

### `templates/` : les pages HTML (Jinja2)

Jinja2 permet de mettre des variables dans le HTML (`{{ verdict.score }}`) et
**échappe automatiquement** le texte, ce qui protège contre le XSS.

| Fichier | Rôle |
|---|---|
| `base.html` | Le squelette commun : en-tête, menu, pied de page. Les autres pages « héritent » de lui (`{% extends "base.html" %}`). |
| `console.html` | La console et l'écran de démarrage. |
| `mail.html` | La page « Analyse mail ». |
| `construction.html` | La page « en cours de construction », réutilisée par Réseau, Alertes et IA. |

### `static/` : fichiers envoyés tels quels au navigateur

| Fichier | Rôle |
|---|---|
| `style.css` | Le design commun : couleurs (variables en haut du fichier), cartes, boutons. |
| `console.css` | Le design propre à la console : 3 colonnes, anneaux animés, écran de démarrage. |
| `console.js` | Le comportement de la console : démarrage, prénom, dépôt de mail. Il n'utilise **jamais** `innerHTML` avec des données (protection XSS). |
| `hud.js` | L'horloge de l'en-tête. |

---

## 4. Les autres dossiers

| Dossier | Contenu |
|---|---|
| `samples/phishing/` | 10 faux mails piégés (marques fictives) qui **doivent** être détectés. |
| `samples/legit/` | 10 mails normaux qui **ne doivent pas** être détectés (sinon c'est un faux positif). |
| `tests/` | Les tests automatiques. `conftest.py` prépare une base de données temporaire pour chaque test, pour ne jamais toucher ta vraie base. |
| `tools/evaluate.py` | Affiche le score de détection : `python tools/evaluate.py -v`. |
| `docs/` | `DECISIONS.md` (chaque choix technique et pourquoi), `RETROSPECTIVES.md` (bilan de sprint), les exercices et ce guide. |

---

## 5. Le trajet d'un mail, de bout en bout

Quand tu déposes un fichier `.eml` dans la console :

1. **`static/console.js`** → `analyzeFile()` vérifie que c'est un `.eml`, puis l'envoie
   au serveur avec `fetch("/api/mail")` et l'en-tête `X-Sentinelle`.
2. **`routes/api.py`** → vérifie d'abord l'en-tête (CSRF), puis l'extension du fichier.
3. **`services.py`** → `analyze_and_store()`.
4. **`modules/mail/parser.py`** → découpe le mail.
5. **`modules/mail/rules.py`** → calcule le score et les raisons.
6. **`repository.py`** → enregistre l'empreinte et le verdict dans `instance/sentinelle.db`.
7. Retour dans **`console.js`** : le résultat s'affiche dans « Informations », le
   compagnon donne le conseil et les compteurs se mettent à jour.

Si tu sais raconter ce trajet, tu sais expliquer le projet.

---

## 6. Questions probables du prof

**« Pourquoi Flask ? »** Léger et simple. L'appli tourne en local, pas besoin d'un gros framework.

**« Où sont stockées les données ? »** Dans un fichier SQLite (`instance/sentinelle.db`).
Seulement l'empreinte du mail et le verdict, jamais le contenu (RGPD : minimisation).
Le prénom reste dans le navigateur (`localStorage`).

**« Comment vous protégez l'appli ? »**
- Elle écoute seulement sur `127.0.0.1` (pas accessible depuis le réseau).
- **Injection SQL** : requêtes paramétrées (`?`) dans `repository.py`.
- **XSS** : Jinja2 échappe le HTML, et `console.js` utilise `textContent`.
- **CSRF** : l'API exige l'en-tête `X-Sentinelle`.
- **Fichiers** : seulement `.eml`, 2 Mo maximum.

**« Comment vous savez que la détection marche ? »** On la mesure avec
`tools/evaluate.py` sur 20 mails d'essai. Aujourd'hui : 4/10 phishings détectés, 0 faux
positif. L'objectif est 8/10 avec au plus 1 faux positif.

**« Et le réseau, l'IA ? »** Prévus, mais on construit bloc par bloc : un module qui
marche vraiment avant de passer au suivant. Leur ancien code est gardé dans la branche
git `sauvegarde-avant-nettoyage`.
