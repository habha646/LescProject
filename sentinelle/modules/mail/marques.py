"""Usurpation de marque : le mail dit venir d'une marque connue, mais pas depuis ses domaines.

L'IDÉE (la même que les règles « Brand impersonation » de Sublime Security, sans leur IA)
    « PayPal <service@paypal-securite.xyz> » : le NOM AFFICHÉ dit PayPal, mais le DOMAINE
    n'appartient pas à PayPal. La victime lit le nom, pas l'adresse. C'est la technique de
    phishing la plus courante.

DEUX VÉRIFICATIONS
    1. Nom affiché = une marque, domaine de l'expéditeur ≠ un domaine de cette marque.
    2. Domaine « sosie » : le nom de la marque est DANS le domaine (« mcafee-renew.com »),
       mais ce n'est pas un vrai domaine de la marque.

LES PIÈGES DE L'ESCROC QU'ON DÉJOUE
    - Lettres déguisées : « Lerοy Merlin » avec un « ο » grec, « Ꮇicrosoft » avec un « Ꮇ »
      cherokee, ou des lettres en gras mathématique « 𝗘𝗗𝗘𝗞𝗔 ». On les ramène aux lettres latines.
    - Caractères invisibles glissés entre les lettres (« Mi​cro​soft ») : on les enlève.

LIMITES (à dire à la soutenance)
    - La liste des marques est écrite à la main : une marque absente n'est pas protégée.
    - Un vrai service peut envoyer au nom d'une marque depuis un autre domaine (prestataire
      d'envoi) : c'est un faux positif possible. C'est pour ça que la règle donne 40 points
      (suspect) et pas 50 (dangereux) : elle s'additionne aux autres indices.

POUR AJOUTER UNE MARQUE
    Ajoute une ligne dans BRANDS : les mots à chercher dans le nom affiché, puis ses vrais
    domaines. Un domaine compte comme « vrai » s'il est dans la liste OU si son nom (avant
    le .com/.fr/.de) est exactement un des « labels » de la marque (paypal.fr, paypal.de...).
"""
from __future__ import annotations

import re
import unicodedata

# Lettres qui RESSEMBLENT à des lettres latines (cyrillique, grec, cherokee).
# NFKC (plus bas) s'occupe déjà des lettres « en gras » ou « double barre » mathématiques.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "Ꭺ": "A", "Ᏼ": "B", "Ꮯ": "C", "Ꭼ": "E", "Ꮐ": "G", "Ꮋ": "H", "Ꭻ": "J", "Ꮶ": "K", "Ꮮ": "L", "Ꮇ": "M",
    "Ꮲ": "P", "Ꮪ": "S", "Ꭲ": "T", "Ꮩ": "V", "Ꮃ": "W", "Ꮓ": "Z",
})

# Mots qu'un escroc ajoute autour du nom de marque : « PayPal Service Client », « Microsoft Team ».
GENERIC_WORDS = {
    "service", "services", "support", "team", "equipe", "client", "clients", "customer", "care",
    "security", "securite", "account", "compte", "billing", "facturation", "notification",
    "notifications", "alert", "alerts", "alerte", "info", "information", "no", "reply", "noreply",
    "official", "officiel", "online", "en", "ligne", "help", "aide", "center", "centre", "de", "la",
    "le", "du", "votre", "your", "the", "mail", "email", "message", "messages",
}

# (mots cherchés dans le nom affiché, labels de domaine légitimes, domaines légitimes en plus,
#  ambigu ?) — « ambigu » = le mot existe aussi dans la langue courante (orange, free, apple...).
# Dans ce cas, le nom affiché ne doit contenir QUE la marque et des mots de GENERIC_WORDS.
BRANDS = [
    # Tech et services en ligne
    (["microsoft", "office 365", "office365", "onedrive", "sharepoint"], {"microsoft"},
     {"office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com", "sharepoint.com",
      "azure.com", "xbox.com", "skype.com", "bing.com", "msn.com"}, False),
    (["outlook"], {"microsoft", "outlook"}, {"office.com", "office365.com", "live.com"}, True),
    (["google", "gmail", "youtube"], {"google"}, {"youtube.com", "googlemail.com"}, False),
    (["apple", "icloud", "itunes", "app store"], {"apple"}, {"icloud.com", "me.com", "itunes.com"}, True),
    (["amazon", "prime video"], {"amazon"}, {"amazonses.com"}, False),
    (["paypal"], {"paypal"}, set(), False),
    (["netflix"], {"netflix"}, set(), False),
    (["facebook"], {"facebook"}, {"facebookmail.com", "meta.com"}, False),
    (["instagram"], {"instagram"}, {"facebookmail.com", "meta.com"}, False),
    (["whatsapp"], {"whatsapp"}, {"facebookmail.com", "meta.com"}, False),
    (["linkedin"], {"linkedin"}, set(), False),
    (["docusign"], {"docusign"}, set(), False),
    (["dropbox"], {"dropbox"}, {"dropboxmail.com"}, False),
    (["adobe"], {"adobe"}, {"adobesign.com", "echosign.com"}, False),
    (["spotify"], {"spotify"}, set(), False),
    (["ebay"], {"ebay"}, set(), False),
    (["vinted"], {"vinted"}, set(), False),
    (["leboncoin"], {"leboncoin"}, set(), False),
    (["airbnb"], {"airbnb"}, set(), False),
    # Sécurité informatique
    (["mcafee"], {"mcafee"}, set(), False),
    (["norton"], {"norton", "nortonlifelock"}, set(), False),
    (["avast"], {"avast"}, set(), False),
    (["kaspersky"], {"kaspersky"}, set(), False),
    # Colis
    (["dhl"], {"dhl", "dpdhl"}, set(), False),
    (["fedex"], {"fedex"}, set(), False),
    (["ups"], {"ups"}, set(), True),
    (["dpd"], {"dpd"}, set(), False),
    (["colissimo"], {"colissimo", "laposte"}, set(), False),
    (["chronopost"], {"chronopost"}, set(), False),
    (["la poste"], {"laposte", "labanquepostale"}, set(), False),
    (["post luxembourg"], {"post"}, set(), False),
    (["deutsche post"], {"deutschepost", "dhl"}, set(), False),
    # Banques et paiement
    (["bnp paribas", "bnpparibas"], {"bnpparibas"}, {"bgl.lu"}, False),
    (["societe generale"], {"societegenerale"}, set(), False),
    (["credit agricole"], {"credit-agricole"}, set(), False),
    (["banque postale"], {"labanquepostale"}, set(), False),
    (["caisse d epargne", "caisse epargne"], {"caisse-epargne"}, set(), False),
    (["credit mutuel"], {"creditmutuel"}, set(), False),
    (["boursorama", "boursobank"], {"boursorama", "boursobank"}, set(), False),
    (["revolut"], {"revolut"}, set(), False),
    (["ing"], {"ing"}, set(), True),
    (["spuerkeess", "bcee"], {"bcee", "spuerkeess"}, set(), False),
    (["bgl"], {"bgl"}, set(), False),
    (["raiffeisen"], {"raiffeisen"}, set(), False),
    (["luxtrust"], {"luxtrust"}, set(), False),
    (["sparkasse"], {"sparkasse"}, set(), False),
    (["deutsche bank"], {"deutsche-bank", "db"}, set(), False),
    (["commerzbank"], {"commerzbank"}, set(), False),
    (["consorsbank"], {"consorsbank"}, set(), False),
    (["postbank"], {"postbank"}, set(), False),
    (["visa"], {"visa"}, set(), True),
    (["mastercard"], {"mastercard"}, set(), False),
    (["coinbase"], {"coinbase"}, set(), False),
    (["binance"], {"binance"}, set(), False),
    (["metamask"], {"metamask"}, set(), False),
    # Administrations (leurs vrais mails viennent de gouv.fr, public.lu, elster.de...)
    (["impots", "finances publiques"], set(), {"gouv.fr"}, False),
    (["ameli", "assurance maladie"], {"ameli", "assurance-maladie"}, set(), False),
    (["antai"], set(), {"gouv.fr"}, False),
    (["france travail", "pole emploi"], {"francetravail", "pole-emploi"}, set(), False),
    (["guichet lu"], {"guichet", "public"}, set(), False),
    (["elster", "finanzamt"], {"elster"}, set(), False),
    # Énergie et télécoms
    (["orange"], {"orange"}, set(), True),
    (["sfr"], {"sfr"}, set(), False),
    (["bouygues"], {"bouyguestelecom", "bouygues"}, set(), False),
    (["free"], {"free", "freetelecom"}, set(), True),
    (["edf"], {"edf"}, set(), False),
    (["engie"], {"engie"}, set(), False),
    (["telekom"], {"telekom", "t-online"}, set(), False),
]


def normalise_name(text: str) -> str:
    """« 𝗘𝗗𝗘𝗞𝗔 », « Ꮇi​crosoft », « Lerοy_Merlin » -> « edeka », « microsoft », « leroy merlin »."""
    text = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    # Enlève les accents et les caractères invisibles (catégories Mn et Cf d'Unicode).
    text = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) not in ("Mn", "Cf"))
    text = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return " ".join(text.split())


# Labels trop courants pour la vérification « domaine sosie » (publicis.com n'imite pas public.lu),
# ou marques qui ont des centaines de vrais domaines régionaux (sparkasse-koelnbonn.de).
LOOKALIKE_SKIP = {"public", "sparkasse", "credit-agricole", "raiffeisen"}
# Domaines qui contiennent un nom de marque mais appartiennent bien à la marque. onmicrosoft.com
# est à Microsoft, mais n'importe qui peut y créer une adresse : il ne prouve PAS que c'est
# Microsoft qui écrit (d'où son absence dans les vrais domaines de Microsoft plus haut).
LOOKALIKE_OWNED = {"onmicrosoft.com"}


def _is_legit(root_domain: str, labels: set, domains: set) -> bool:
    return root_domain in domains or root_domain.split(".")[0] in labels


def find_impersonated_brand(sender_name: str, root_domain: str) -> str | None:
    """Renvoie le mot-clé de la marque usurpée dans le nom affiché, ou None."""
    name = normalise_name(sender_name)
    if not name or not root_domain:
        return None
    words = set(name.split())
    for keywords, labels, domains, ambiguous in BRANDS:
        for kw in keywords:
            if not re.search(r"(?:^| )" + re.escape(kw) + r"(?: |$)", name):
                continue
            if ambiguous and not words <= set(kw.split()) | GENERIC_WORDS:
                continue   # « Orange » seul = la marque ; « Jus d'orange bio » = pas la marque
            if not _is_legit(root_domain, labels, domains):
                return kw
    return None


def find_lookalike_domain(root_domain: str) -> str | None:
    """« mcafee-renew.com », « paypal-securite.fr » : la marque est dans le domaine, mais ce
    n'est pas un de ses vrais domaines. Seulement pour les marques à nom long et non ambigu."""
    if root_domain in LOOKALIKE_OWNED:
        return None
    label = root_domain.split(".")[0]
    for keywords, labels, domains, ambiguous in BRANDS:
        if ambiguous:
            continue
        for brand_label in labels:
            if brand_label in LOOKALIKE_SKIP:
                continue
            if len(brand_label) >= 5 and brand_label in label and not _is_legit(root_domain, labels, domains):
                return brand_label
    return None
