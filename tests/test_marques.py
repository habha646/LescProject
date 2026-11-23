"""Tests de la règle d'usurpation de marque (sentinelle/modules/mail/marques.py)."""
import pytest

from sentinelle.modules.mail import analyze_eml
from sentinelle.modules.mail.marques import find_impersonated_brand, find_lookalike_domain, normalise_name


def _from(sender: str) -> bytes:
    return f"From: {sender}\nSubject: Information\n\nBonjour.\n".encode("utf-8")


def _brand_reasons(sender: str) -> list[str]:
    v = analyze_eml(_from(sender))
    return [r for r in v.reasons if "usurpation de marque" in r or "imite la marque" in r]


# ---------- doivent être signalés ----------

USURPATIONS = [
    '"PayPal Service Client" <alerte@secure-compte.example>',
    '"Microsoft 365" <no-reply@office-mail.example>',
    '"La Poste" <suivi@colis-livraison.example>',
    '"DHL Express" <dhl@gmail.com>',
    '"Impots - Finances publiques" <remboursement@dgfip-info.example>',
    '"Spuerkeess" <securite@spuerkeess-alerte.example>',
    '"Orange" <facture@orange-paiement.example>',          # marque ambiguë, mais nom seul
    '=?UTF-8?Q?=E1=8E=B7icrosoft_Support?= <a@pirate.example>',   # « Ꮇ » cherokee à la place du M
    '"Ne​tf​lix" <compte@pirate.example>',      # caractères invisibles dans le nom
    '"\U0001d5e3\U0001d5ee\U0001d606\U0001d5e3\U0001d5ee\U0001d5f9" <a@pirate.example>',  # « PayPal » en gras mathématique
]


@pytest.mark.parametrize("sender", USURPATIONS)
def test_brand_impersonation_is_flagged(sender):
    assert _brand_reasons(sender)


def test_lookalike_domain_is_flagged():
    assert find_lookalike_domain("mcafee-renouvellement.com") == "mcafee"
    assert find_lookalike_domain("paypal-securite.fr") == "paypal"


# ---------- ne doivent PAS être signalés ----------

LEGITIMES = [
    '"PayPal" <service@paypal.fr>',
    '"Amazon.fr" <confirmation-commande@amazon.fr>',
    '"Netflix" <info@mailer.netflix.com>',
    '"Microsoft" <account-security-noreply@accountprotection.microsoft.com>',
    '"La Poste - Colissimo" <noreply@notif-colissimo.laposte.fr>',
    '"Impots.gouv" <ne-pas-repondre@dgfip.finances.gouv.fr>',
    '"Facebook" <notification@facebookmail.com>',
    '"Jus d\'orange bio" <contact@verger.example>',        # « orange » n'est pas la marque ici
    '"Weather Outlook Weekly" <news@meteo.example>',       # « outlook » mot anglais courant
    '"Marie Free" <marie.free@example.com>',               # nom de famille
    '"Lucas" <lucas.martin@gmail.com>',
]


@pytest.mark.parametrize("sender", LEGITIMES)
def test_legit_sender_is_not_flagged(sender):
    assert _brand_reasons(sender) == []


def test_owned_domains_are_not_lookalikes():
    assert find_lookalike_domain("microsoftonline.com") is None
    assert find_lookalike_domain("onmicrosoft.com") is None
    assert find_lookalike_domain("publicis.com") is None


def test_normalise_name_defeats_disguises():
    assert normalise_name("Lerοy_Merlin") == "leroy merlin"        # « ο » grec
    assert normalise_name("\U0001d5d8\U0001d5d7\U0001d5d8\U0001d5de\U0001d5d4") == "edeka"   # gras mathématique
    assert normalise_name("Mi​cro​soft") == "microsoft"


def test_empty_sender_is_ignored():
    assert find_impersonated_brand("PayPal", "") is None
