# Journal des décisions techniques

Une ligne par décision : quoi + pourquoi. Utile pour le rapport et pour la
défense individuelle — chacun doit pouvoir expliquer ces choix.

| Date | Décision | Pourquoi | Qui |
|------|----------|----------|-----|
| 2026-09-29 | Python + Flask + SQLite | Bases déjà connues de l'équipe (HTML/CSS/un peu de Python), pas de serveur à administrer | Harone |
| 2026-09-29 | Analyse de mail par dépôt manuel de fichier .eml, pas de connexion à la vraie boîte mail | Éviter de stocker des identifiants et de lire les mails privés/pro du persona ; RGPD | Harone |
| 2026-09-29 | Toute action de blocage demande confirmation de l'utilisateur | Éviter un faux positif qui coupe un outil de travail ; confiance dans l'outil | Harone |
| 2026-09-29 | IA en mode "template" par défaut, Ollama en option | Le produit doit marcher même si l'IA locale n'est pas encore prête ; coût nul | Harone |
| | | | |
