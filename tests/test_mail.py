from sentinelle.modules.mail import analyze_eml

SAFE_EML = b"""From: ami@example.com
Subject: Salut
Content-Type: text/plain

Comment vas-tu ? On se voit ce week-end ?
"""

DANGEROUS_EML = b"""From: banque@faux-domaine-xn--exemple.com
Subject: Action urgente requise
Authentication-Results: spf=fail dkim=fail
Content-Type: multipart/mixed; boundary="X"

--X
Content-Type: text/plain

Cliquez ici immediatement, votre compte sera ferme.

--X
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="facture.exe"

FAKE
--X--
"""


def test_safe_mail_scores_low():
    v = analyze_eml(SAFE_EML)
    assert v.verdict == "safe"
    assert v.score < 20


def test_dangerous_mail_scores_high():
    v = analyze_eml(DANGEROUS_EML)
    assert v.verdict == "dangerous"
    assert v.score >= 50
    assert any("exe" in r for r in v.reasons)


# ---------- une règle = un test : si quelqu'un casse une règle, on le sait tout de suite ----------

def _mail(headers: str, body: str, content_type: str = "text/plain") -> bytes:
    return (f"From: \"Banque\" <noreply@banque.example>\n{headers}"
            f"Subject: Information\nContent-Type: {content_type}\n\n{body}\n").encode()


def test_reply_to_other_domain_is_flagged():
    v = analyze_eml(_mail("Reply-To: pirate@freemail.test\n", "Bonjour."))
    assert any("autre domaine" in r for r in v.reasons)


def test_reply_to_same_domain_is_fine():
    v = analyze_eml(_mail("Reply-To: support@banque.example\n", "Bonjour."))
    assert v.verdict == "safe"


def test_link_to_ip_address_is_flagged():
    v = analyze_eml(_mail("", "Payez ici : http://192.0.2.10/paiement"))
    assert any("adresse IP" in r for r in v.reasons)


def test_html_link_with_misleading_text_is_flagged():
    html = '<p><a href="http://pirate.test/login">https://www.banque.example</a></p>'
    v = analyze_eml(_mail("", html, "text/html"))
    assert v.verdict != "safe"
    assert any("mène en réalité" in r for r in v.reasons)


def test_shortened_link_is_flagged():
    v = analyze_eml(_mail("", "Voir : https://bit.ly/abc123"))
    assert any("raccourci" in r for r in v.reasons)


def test_html_attachment_is_flagged():
    raw = (b'From: a@b.example\nSubject: Facture\nContent-Type: multipart/mixed; boundary="S"\n\n'
           b'--S\nContent-Type: text/plain\n\nFacture jointe.\n'
           b'--S\nContent-Type: text/html\nContent-Disposition: attachment; filename="facture.html"\n\n<p>x</p>\n--S--\n')
    v = analyze_eml(raw)
    assert any("facture.html" in r for r in v.reasons)


def test_urgency_without_accents_is_detected():
    v = analyze_eml(_mail("", "Reglez immediatement."))
    assert any("agir vite" in r for r in v.reasons)


def test_sensitive_word_must_be_a_whole_word():
    # « rib » est un mot sensible, mais pas quand il est caché dans « attribut »
    v = analyze_eml(_mail("", "Voici un attribut du fichier."))
    assert v.verdict == "safe"


# ---------- en-têtes encodés (RFC 2047) ----------

URGENT_ENCODE = b"""From: a@b.example
Subject: =?UTF-8?B?VXJnZW50IDogdm90cmUgY29tcHRlIHNlcmEgZmVybcOp?=
Content-Type: text/plain

Bonjour.
"""


def test_encoded_subject_is_decoded():
    # L'objet est « Urgent : votre compte sera fermé », mais encodé en base64.
    v = analyze_eml(URGENT_ENCODE)
    assert any("agir vite" in r for r in v.reasons)


def test_encoded_name_cannot_hide_reply_to():
    # Decode, le nom affiche contient une fausse adresse <x@banque.example>.
    raw = (b'From: "Banque" <noreply@banque.example>\n'
           b'Reply-To: =?UTF-8?Q?Support_=3Cx=40banque.example=3E?= <pirate@freemail.test>\n'
           b'Subject: Info\n\nBonjour.\n')
    v = analyze_eml(raw)
    assert any("autre domaine" in r for r in v.reasons)


def test_broken_encoded_header_does_not_crash():
    v = analyze_eml(b"From: a@b.example\nSubject: =?inconnu?Q?abc?=\n\nBonjour.\n")
    assert v.verdict in ("safe", "suspect", "dangerous")


def test_raw_utf8_header_does_not_crash():
    # Vrai cas (échantillon Sublime « punycode_robinhood ») : un en-tête avec des accents NON
    # encodés faisait planter l'analyse (AttributeError: 'Header' object has no attribute 'lower').
    raw = ("From: a@b.example\nAuthentication-Results: mx.example; spf=fail (domaine robínhood.com)\n"
           "Subject: Info\n\nBonjour.\n").encode("utf-8")
    v = analyze_eml(raw)
    assert any("SPF/DKIM" in r for r in v.reasons)


def test_raw_utf8_subject_is_read():
    # Vrai cas (phishing_pot) : objet en UTF-8 brut, sans encodage =?...?=.
    # Avant : « Imm��diatement » -> le mot d'urgence n'était pas trouvé.
    raw = "From: a@b.example\nSubject: Agissez immédiatement\n\nBonjour.\n".encode("utf-8")
    v = analyze_eml(raw)
    assert any("agir vite" in r for r in v.reasons)
