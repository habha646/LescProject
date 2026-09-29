# Sentinelle

Projet ICT Complémentaire — S7. Un compagnon local qui aide un particulier ou petit
entrepreneur à repérer les mails/liens dangereux et à savoir ce qui se passe sur son
réseau domestique, expliqué en langage clair.

Équipe : Harone (fondation, front-end, back-end), David (réseau), Svetoslav (IA).

## Démarrer en 5 minutes

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # copie la config d'exemple, ne modifie jamais .env.example
python run.py
```

Ouvre http://127.0.0.1:5000 — l'app tourne déjà avec des données simulées, sans
rien configurer de plus.

## Lancer les tests

```bash
python -m pytest
```

Lance-les **avant chaque commit**. Un test qui casse = on ne pousse pas sur `main`
tant que ce n'est pas réglé ensemble.

## Comment le projet est organisé

```
sentinelle/
  config.py          config de l'app (variables d'environnement, voir .env.example)
  models.py          ⭐ les structures partagées entre tous les modules (LIRE EN PREMIER)
  db.py               connexion et schéma de la base SQLite
  repository.py       toutes les requêtes SQL (rien d'autre ne doit toucher la base)
  routes/              une page = un fichier ; relie modules + templates
  templates/            les pages HTML (Jinja2)
  static/style.css      le style visuel
  modules/
    network/           ⭐ DAVID — scan du réseau
    ai/                ⭐ SVETOSLAV — explications en langage clair
    mail/              analyse des mails .eml (base commune)
tests/                 les tests automatiques
docs/                  décisions d'équipe, notes de rétrospective
```

## Qui touche à quoi

- **David → `sentinelle/modules/network/`**. Une seule fonction à écrire :
  `scan()` dans `scanner.py`. Tout le reste (garde-fou légal, enregistrement en
  base, création d'alerte, affichage) est déjà branché. Lis
  `sentinelle/modules/network/__init__.py` pour le contrat exact.
- **Svetoslav → `sentinelle/modules/ai/`**. Deux fonctions à écrire dans
  `explainer.py` : `explain_with_llm` et `explain_mail_with_llm`. Le produit
  fonctionne déjà sans IA (texte prédéfini) — ton travail l'améliore, il ne
  bloque jamais l'équipe.
- **Harone → tout le reste** : routes, templates, base de données, module mail,
  intégration.

**Règle d'or : ne modifie jamais les signatures dans `models.py` ou dans les
`__init__.py` des modules sans en parler aux deux autres d'abord.** C'est ce qui
permet à chacun de travailler sans casser le travail des autres.

## Modes de fonctionnement (fichier `.env`)

- `SENTINELLE_NETWORK_MODE=fake` (par défaut) : appareils simulés, pour développer
  sans vrai réseau. Passe à `real` seulement sur un réseau qui t'appartient.
- `SENTINELLE_ALLOWED_SUBNETS` : liste blanche des réseaux qu'on a le droit de
  scanner. **Ne scanne jamais un réseau qui n'est pas le tien.**
- `SENTINELLE_AI_MODE=template` (par défaut) : textes prédéfinis. Passe à
  `ollama` une fois le modèle local branché.

## Garde-fous déjà en place (ne pas contourner)

- Pas d'interception du trafic chiffré (pas de MITM)
- Pas de lecture automatique d'une vraie boîte mail — dépôt manuel de fichiers `.eml`
- Le contenu d'un mail n'est jamais stocké en base, seulement son empreinte (sha256)
  et le verdict — voir `sentinelle/db.py`
- Un scan réseau réel est bloqué si le sous-réseau n'est pas dans la liste
  autorisée (`sentinelle/modules/network/guard.py`)
- L'IA explique et propose ; elle ne décide et n'exécute jamais une action seule

## Workflow Git (à respecter)

1. Une branche par tâche : `git checkout -b feature/nom-de-la-tache`
2. Commits courts et clairs : `git commit -m "réseau: implémente le scan via table ARP"`
3. Pull request vers `main`, même à 3 — ça garde une trace pour le rapport et la défense
4. `main` doit toujours pouvoir se lancer avec `python run.py` sans erreur
