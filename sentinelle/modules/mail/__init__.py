"""Module MAIL — analyse d'un fichier .eml déposé manuellement.

Le chemin d'un mail : parser.py (découpe le fichier) -> rules.py (calcule le score).

CONTRAT :
    analyze_eml(raw_bytes: bytes) -> MailVerdict
"""
from .parser import parse_eml
from .rules import score_mail
from ...models import MailVerdict


def analyze_eml(raw_bytes: bytes) -> MailVerdict:
    parsed = parse_eml(raw_bytes)
    return score_mail(parsed)
