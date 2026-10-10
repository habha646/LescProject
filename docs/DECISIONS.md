# Journal des décisions techniques

Une ligne par décision : quoi + pourquoi. Utile pour le rapport et pour la
défense individuelle — chacun doit pouvoir expliquer ces choix.

| Date | Décision | Pourquoi | Qui |
|------|----------|----------|-----|
| 2026-09-29 | Python + Flask + SQLite | Bases déjà connues de l'équipe (HTML/CSS/un peu de Python), pas de serveur à administrer | Harone |
| 2026-09-29 | Analyse de mail par dépôt manuel de fichier .eml, pas de connexion à la vraie boîte mail | Éviter de stocker des identifiants et de lire les mails privés/pro du persona ; RGPD | Harone |
| 2026-09-29 | Toute action de blocage demande confirmation de l'utilisateur | Éviter un faux positif qui coupe un outil de travail ; confiance dans l'outil | Harone |
| 2026-09-29 | IA en mode "template" par défaut, Ollama en option | Le produit doit marcher même si l'IA locale n'est pas encore prête ; coût nul | Harone |
| 2026-10-10 | Page principale = console (JavaScript + API JSON `/api/...`) avec écran de démarrage | Interface type « compagnon » : tout sur un seul écran, mises à jour sans recharger la page | Harone |
| 2026-10-10 | Toute requête POST de l'API exige l'en-tête `X-Sentinelle: 1` | Protection CSRF : un site web étranger ne peut pas déclencher un scan ou une analyse à notre place | Harone |
| 2026-10-10 | Le JavaScript n'utilise jamais `innerHTML` avec des données, seulement `textContent` | Protection XSS : un nom d'appareil ou de fichier piégé ne peut pas exécuter de code | Harone |
| 2026-10-10 | Le prénom de l'utilisateur est gardé dans le navigateur (localStorage), pas dans la base | Démo sur un autre PC sans données personnelles ; aucune donnée perso côté serveur (RGPD : minimisation) | Harone |
| 2026-10-10 | Nettoyage : on garde seulement le module mail ; réseau, alertes et IA passent « en cours de construction » (ancien code dans la branche `sauvegarde-avant-nettoyage`) | Construire bloc par bloc, un module qui marche vraiment avant le suivant | Harone |
| 2026-10-10 | Le parser lit aussi le HTML ; 5 nouvelles règles (Reply-To, IP, lien raccourci, texte de lien trompeur, demande d'infos sensibles) | Les phishings sont surtout en HTML ; passage de 4/10 à 10/10 sur notre jeu d'essai, 0 faux positif | Harone |
| 2026-10-10 | L'interface passe au rouge (dangereux) ou à l'orange (suspect) | Une alerte doit se voir immédiatement ; le rouge n'est jamais utilisé ailleurs | Harone |
| | | | |
