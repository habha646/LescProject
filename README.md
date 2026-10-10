# Sentinelle

Projet ICT Complémentaire (S7). Un compagnon de sécurité local qui aide un particulier
ou un petit entrepreneur à repérer les mails dangereux, expliqué en langage clair.

Équipe : Harone (fondation, front-end, back-end), David (réseau), Svetoslav (IA).

**État actuel : seul le module MAIL fonctionne.** Les pages Réseau, Alertes et
Assistant IA affichent « en cours de construction ». Leur ancien code est gardé dans
la branche git `sauvegarde-avant-nettoyage`.

## Lancer l'appli (PowerShell, depuis ce dossier)

```
python -m venv .venv                 # une seule fois
.venv\Scripts\Activate.ps1
pip install -r requirements.txt      # une seule fois
python run.py
```

Puis ouvre http://127.0.0.1:5000 (`Ctrl+C` dans le terminal pour arrêter).

## Vérifier que tout marche

```
python -m pytest -v            # les tests automatiques
python tools/evaluate.py -v    # le score de détection sur les 20 mails d'essai
```

## Carte du projet : où est quoi

Le trajet d'un mail : **page web → route → services → module mail → base**.

```
run.py                          lance le serveur
sentinelle/
  __init__.py                   crée l'appli Flask et branche les routes
  config.py                     réglages (base de données, taille max d'un mail)
  models.py                     MailVerdict : le résultat d'une analyse
  db.py                         la table "analyses" (SQLite)
  repository.py                 toutes les requêtes SQL
  services.py                   analyser un mail puis enregistrer le verdict
  modules/mail/
    parser.py                   découpe le fichier .eml (expéditeur, liens, pièces jointes)
    rules.py                    ⭐ LES RÈGLES DE DÉTECTION : c'est ici qu'on améliore le score
    autotest.py                 teste le moteur sur samples/
  routes/
    dashboard.py                page d'accueil (la console)
    mail_routes.py              page « Analyse mail »
    api.py                      l'API JSON utilisée par la console
    construction.py             pages « en cours de construction »
  templates/                    les pages HTML
    base.html                   en-tête commun à toutes les pages
    console.html                la console + l'écran de démarrage
    mail.html                   page « Analyse mail »
    construction.html           page « en cours de construction »
  static/
    style.css                   le design commun (couleurs, cartes, boutons)
    console.css                 le design propre à la console
    console.js                  le comportement de la console
    hud.js                      l'horloge de l'en-tête
samples/
  phishing/                     10 mails piégés (doivent être détectés)
  legit/                        10 mails normaux (ne doivent pas être détectés)
tools/evaluate.py               mesure la détection sur samples/
tests/                          les tests automatiques
docs/                           décisions, rétrospectives, exercices
```

## Garde-fous en place

- Pas de lecture automatique d'une vraie boîte mail : dépôt manuel de fichiers `.eml`
- Le contenu d'un mail n'est jamais stocké, seulement son empreinte (sha256) et le verdict
- Le prénom de l'utilisateur reste dans son navigateur, jamais sur le serveur
- Protection CSRF (en-tête `X-Sentinelle`) et XSS (`textContent`) : voir `routes/api.py` et `static/console.js`

## Workflow Git

1. Une branche par tâche : `git checkout -b feature/nom-de-la-tache`
2. Commits courts et clairs : `git commit -m "mail: ajoute la règle Reply-To"`
3. Lance les tests **avant chaque commit**
