# Exercice 1 — Ta première règle de détection : le Reply-To

> **Mise à jour du 10/10 :** cette règle est maintenant écrite dans `rules.py`
> (`_check_reply_to`). Utilise ce guide pour **comprendre chaque ligne**, ou efface la
> fonction et réécris-la toi-même en suivant les étapes : les tests te diront si c'est bon.

Tu n'es pas nul : personne ne sait écrire une règle de détection la première fois.
On va le faire ensemble, une étape à la fois. Ne saute aucune étape, et **tape le
code toi-même au lieu de le copier-coller** : c'est en tapant qu'on retient.

Durée : 30 à 45 minutes.

---

## Étape 0 — Comprendre l'attaque (5 min, sans coder)

Dans un mail, il y a deux adresses différentes :

- **From** : l'adresse affichée comme expéditeur.
- **Reply-To** : l'adresse qui reçoit ta réponse quand tu cliques sur « Répondre ».

Un escroc peut écrire n'importe quoi dans `From` (par exemple `noreply@banque-lumiere.example`)
et mettre **sa propre adresse** dans `Reply-To`. La victime croit répondre à sa banque,
mais elle envoie ses codes à l'escroc.

👉 Ouvre `samples/phishing/p03_reply_to_different.eml` dans VS Code et regarde les
deux premières lignes. Tu vois le piège ?

Puis ouvre `samples/legit/l08_club_reply_to.eml` : ici aussi le Reply-To est
différent, mais c'est **le même domaine** (`clubphoto.example`). C'est normal, pas une attaque.

**La règle qu'on va écrire :** si le domaine du Reply-To est différent du domaine du From,
on ajoute 30 points de risque.

> Le **domaine**, c'est ce qui est après le `@`. Dans `bureau@clubphoto.example`,
> le domaine est `clubphoto.example`.

---

## Étape 1 — Ouvrir le projet et le terminal

1. Ouvre VS Code.
2. Menu **Fichier → Ouvrir le dossier** → choisis `F:\Ecole\Projet Informatique\sentinelle-fondation\sentinelle-repo`.
3. Menu **Terminal → Nouveau terminal**. Un terminal PowerShell s'ouvre en bas.
4. Active l'environnement Python du projet en tapant :

```
.venv\Scripts\Activate.ps1
```

Tu dois voir `(.venv)` au début de la ligne. Ça veut dire que tu utilises le Python
du projet, avec pytest installé.

> Si PowerShell refuse avec une erreur « l'exécution de scripts est désactivée »,
> tape d'abord `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, réponds `O`, puis recommence.

5. Lance la mesure pour voir le point de départ :

```
python tools/evaluate.py
```

Note le résultat : **4/10 phishings détectés**. La ligne `p03` est marquée `RATE`.

---

## Étape 2 — Ouvrir le fichier des règles

Ouvre `sentinelle/modules/mail/rules.py`. Lis-le en entier, il est court.
Remarque que chaque règle a la même forme :

```python
def _check_quelquechose(m: ParsedMail, reasons: list[str]) -> int:
    # regarde le mail "m"
    # si c'est suspect : ajoute une phrase dans "reasons" et renvoie des points
    # sinon : renvoie 0
```

- `m` contient le mail déjà découpé : `m.from_addr`, `m.subject`, `m.headers`…
- `reasons` est la liste des explications affichées à l'utilisateur.
- Le nombre renvoyé (`int`) est le nombre de points de risque.

---

## Étape 3 — Importer l'outil qui lit une adresse

Une adresse dans un mail ressemble à ça : `"Banque Lumiere" <noreply@banque-lumiere.example>`.
Python a déjà un outil pour séparer le nom et l'adresse : `parseaddr`.

En haut du fichier, juste **au-dessus** de la ligne `from .parser import ParsedMail`, ajoute :

```python
from email.utils import parseaddr
```

**Essaie-le** pour comprendre. Dans le terminal, tape `python`, puis :

```python
>>> from email.utils import parseaddr
>>> parseaddr('"Banque Lumiere" <noreply@banque-lumiere.example>')
('Banque Lumiere', 'noreply@banque-lumiere.example')
```

Il renvoie deux choses : le nom affiché et l'adresse. Tape `exit()` pour sortir.

---

## Étape 4 — Une petite fonction qui donne le domaine

Juste **au-dessus** de `def score_mail(`, tape :

```python
def _domaine(adresse: str) -> str:
    _nom, email_seul = parseaddr(adresse)
    if "@" not in email_seul:
        return ""
    return email_seul.rsplit("@", 1)[1].lower()
```

Ligne par ligne :

| Ligne | Ce qu'elle fait |
|---|---|
| `_nom, email_seul = parseaddr(adresse)` | sépare le nom et l'adresse. On ignore le nom (le `_` devant veut dire « je ne m'en sers pas »). |
| `if "@" not in email_seul: return ""` | si l'adresse est cassée (pas de `@`), on renvoie un texte vide au lieu de planter. Un attaquant peut envoyer des en-têtes mal formés exprès. |
| `email_seul.rsplit("@", 1)[1]` | coupe au **dernier** `@` et garde la partie de droite : le domaine. |
| `.lower()` | met en minuscules, car `Banque.EXAMPLE` et `banque.example` sont le même domaine. Sans ça, un attaquant passerait juste en changeant des majuscules… ou au contraire on créerait de faux positifs. |

---

## Étape 5 — La règle elle-même

Juste en dessous de `_domaine`, tape :

```python
def _check_reply_to(m: ParsedMail, reasons: list[str]) -> int:
    reply_to = m.headers.get("reply_to") or ""
    if not reply_to:
        return 0
    domaine_from = _domaine(m.from_addr)
    domaine_reply = _domaine(reply_to)
    if domaine_reply and domaine_reply != domaine_from:
        reasons.append(f"Les réponses partent vers un autre domaine ({domaine_reply}) que celui de l'expéditeur ({domaine_from}).")
        return 30
    return 0
```

Ligne par ligne :

1. On récupère le Reply-To. `or ""` évite une erreur s'il n'existe pas.
2. Pas de Reply-To → rien de suspect → `0` point.
3. On calcule les deux domaines avec ta fonction de l'étape 4.
4. Si les domaines sont différents → on explique pourquoi (en français, pour l'utilisateur) et on renvoie 30 points.

**Pourquoi 30 ?** Seul, ce signal suffit à passer en « suspect » (seuil 20) mais pas en
« dangereux » (seuil 50). C'est voulu : un Reply-To différent est louche, pas une preuve.

---

## Étape 6 — Brancher la règle

Descends dans `score_mail`. Tu vois les lignes `score += _check_...`.
Ajoute la tienne juste après `score += _check_urgency(m, reasons)` :

```python
    score += _check_reply_to(m, reasons)
```

Attention à l'indentation : 4 espaces, alignée avec les lignes au-dessus.
Enregistre le fichier (`Ctrl+S`).

---

## Étape 7 — Vérifier que ça marche

Dans le terminal :

```
python tools/evaluate.py
```

Tu dois obtenir :

- `p03_reply_to_different.eml` → **OK** (score 30)
- `l08_club_reply_to.eml` → toujours **OK** (pas de faux positif)
- **5/10 phishings détectés, 0 faux positif**

Puis vérifie que tu n'as rien cassé :

```
python -m pytest -v
```

Les 8 tests doivent toujours passer. Si un test échoue, lis le message d'erreur en bas :
il donne le fichier et la ligne. Envoie-le-moi si tu bloques.

---

## Étape 8 — Écrire un test pour ta règle (bonus, mais très « pro »)

Dans `tests/test_mail.py`, ajoute à la fin :

```python
def test_reply_to_autre_domaine_est_suspect():
    raw = b"""From: "Banque" <noreply@banque.example>
Reply-To: pirate@freemail.test
Subject: Mise a jour
Content-Type: text/plain

Repondez avec votre code.
"""
    v = analyze_eml(raw)
    assert v.verdict != "safe"
    assert any("domaine" in r for r in v.reasons)
```

Relance `python -m pytest -v` : tu dois avoir **9 passed**.

Un test, c'est une garantie : si quelqu'un casse ta règle plus tard, le test le dira tout de suite.

---

## Étape 9 — Sauvegarder ton travail avec git

```
git add sentinelle/modules/mail/rules.py tests/test_mail.py
git commit -m "Ajoute la règle de détection Reply-To"
```

Ne fais pas `git push` tant qu'on n'a pas relu ensemble.

---

## Pour aller plus loin (à réfléchir pour la défense)

- Le mail `p09` (fraude au président) a un Reply-To **identique** au From : ta règle ne le
  voit pas. Quel autre indice pourrait-on utiliser ? (Indice : regarde le domaine du From.)
- Un attaquant pourrait-il contourner ta règle avec un sous-domaine, par exemple
  `support.banque.example` contre `banque.example` ? Est-ce un faux positif ou un vrai risque ?
