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
