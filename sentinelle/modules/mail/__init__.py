"""Module MAIL — analyse d'un fichier .eml déposé manuellement.

Base déjà fonctionnelle (règles simples). Peut être enrichi par n'importe qui
(David ou Svetoslav) une fois son propre module avancé — pas de propriétaire unique.

CONTRAT :
    analyze_eml(raw_bytes: bytes) -> MailVerdict
"""
from .parser import parse_eml
from .rules import score_mail
from ...models import MailVerdict


def analyze_eml(raw_bytes: bytes) -> MailVerdict:
    parsed = parse_eml(raw_bytes)
    return score_mail(parsed)
