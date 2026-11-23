"""Tests des règles adaptées de Sublime Security (sentinelle/modules/mail/sublime_rules.py).

Pour chaque règle : un mail qui DOIT la déclencher. Et quelques mails normaux qui ne doivent
en déclencher AUCUNE (un détecteur qui crie au loup est inutile).
"""
import base64

import pytest

from sentinelle.modules.mail import analyze_eml
from sentinelle.modules.mail.parser import parse_eml
from sentinelle.modules.mail.sublime_rules import SUBLIME_RULES, run_sublime_rules


def _mail(headers: str = "", body: str = "Bonjour.", content_type: str = "text/plain",
          sender: str = '"Service" <contact@service.example>') -> bytes:
    return (f"From: {sender}\nTo: victime@ecole.example\nSubject: Information\n{headers}"
            f"Content-Type: {content_type}; charset=utf-8\n\n{body}\n").encode("utf-8")


def _with_attachment(filename: str, data: bytes, content_type: str = "application/octet-stream") -> bytes:
    b64 = base64.b64encode(data).decode()
    return (f'From: a@b.example\nTo: victime@ecole.example\nSubject: Document\n'
            f'Content-Type: multipart/mixed; boundary="S"\n\n'
            f'--S\nContent-Type: text/plain\n\nVoir la pièce jointe.\n'
            f'--S\nContent-Type: {content_type}\nContent-Transfer-Encoding: base64\n'
            f'Content-Disposition: attachment; filename="{filename}"\n\n{b64}\n--S--\n').encode("utf-8")


def _fired(raw: bytes) -> set[str]:
    """Noms des fichiers Sublime des règles déclenchées par ce mail."""
    return {rule.file for rule, _ in run_sublime_rules(parse_eml(raw))}


def _html(body: str) -> bytes:
    return _mail(body=body, content_type="text/html")


HEX_VICTIME = "victime@ecole.example".encode().hex()

# (fichier de la règle Sublime, mail qui doit la déclencher)
CAS_POSITIFS = [
    ("punycode_sender_domain.yml", _mail(sender="Banque <info@xn--bnque-6ua.example>")),
    ("link_contains_punycode_characters.yml", _mail(body="Voir https://xn--pypal-4ve.example/login")),
    ("attachment_filename_with_unicode_rtlo.yml", _with_attachment("facture‮fdp.exe", b"MZ\x90\x00")),
    ("attachment_filename_with_unicode_rtlo.yml",
     _with_attachment("x.exe", b"MZ").replace(b'filename="x.exe"', b"filename*=UTF-8''facture%E2%80%AEfdp.exe")),
    ("attachment_tar_with_rar_type.yml", _with_attachment("archive.tar", b"Rar!\x1a\x07\x01\x00data")),
    ("attachment_html_smuggling_atob.yml",
     _with_attachment("doc.html", b"<script>document.write(atob('PGgxPmhpPC9oMT4='));</script>", "text/html")),
    ("headers_reply_to_wildcard_sender.yml",
     _mail(headers="In-Reply-To: <123@x.example>\n", sender="x <a**b@spam.example>")),
    ("sender_freemail_replyto_different_freemail.yml",
     _mail(headers="Reply-To: escroc@outlook.com\n", sender="Paul <paul.martin@gmail.com>")),
    ("evasion_zero_width_char_stuffing.yml",
     _mail(sender="=?UTF-8?Q?" + "U=E2=80=8B" * 12 + "?= <a@b.example>", body="https://site.example")),
    ("evasion_unicode_tag_chars_not_attachment.yml", _mail(body="Bon" + "\U000E0041" * 12 + "jour")),
    ("link_display_text_excessive_right_to_left_marks.yml",
     _html('<a href="https://x.example">P‏a‏y‏p</a>')),
    ("body_unicode_slashes_in_url.yml", _mail(body="Connecte-toi : https://banque.example⁄login")),
    ("link_hidden_span_split_url.yml",
     _html('https:/<span style="display:none">ABC123XYZ</span>/pirate.example')),
    ("body_css_clip_path.yml", _html('<div style="clip-path: inset(100%)">' + "texte cache " * 20 + "</div>")),
    ("link_cve_2024-21413.yml", _html('<a href="file:///\\\\10.0.0.1\\partage\\test.rtf!something">Ouvrir</a>')),
    ("body_cve_2023_5631.yml", _html('<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCc+#x"/></svg>')),
    ("gophish_abuse_pixel_tracking.yml",
     _html('<img alt="" style="display: none" src="https://p.example/track?rid=abc123">')),
    ("link_rcpt_hex_encoded_fragment.yml", _mail(body=f"https://p.example/page#{HEX_VICTIME}")),
    ("hex_encoded_rcpt_subject.yml",
     _mail().replace(b"Subject: Information", f"Subject: Document {HEX_VICTIME}".encode())),
    ("sender_local_part_built_from_recipient.yml", _mail(sender="x <ecole_victime@autre.example>")),
    ("link_malfrom_subdomain_hyphen.yml", _mail(body="https://login-.pirate.example/")),
    ("malformed_url_prefix.yml", _mail(body="Clique ici : https:\\\\pirate.example\\login")),
    ("headers_malformed_mailer_string.yml", _mail(headers="X-Mailer: Microsoft Outlook, Build 99\n")),
    ("link_obfuscation_underscore_dot_substitution.yml",
     _html('<a href="https://pirate.example">https://banque_com/login</a>')),
    ("sender_suspicious_display_name_from_gmail_domain.yml",
     _mail(sender='"Urgent - please reply" <jean.dupont@gmail.com>')),
]


@pytest.mark.parametrize("rule_file,raw", CAS_POSITIFS, ids=[c[0] for c in CAS_POSITIFS])
def test_rule_fires(rule_file, raw):
    assert rule_file in _fired(raw)


def test_every_rule_has_a_positive_test():
    # Sauf la liste d'IOC (adresses d'escrocs réelles : on ne les connaît que par leur empreinte).
    tested = {c[0] for c in CAS_POSITIFS}
    for rule in SUBLIME_RULES:
        if not rule.file.startswith("observed_malicious"):
            assert rule.file in tested, f"pas de test pour {rule.file}"


def test_ioc_list_is_loaded_and_checked_by_hash():
    from sentinelle.modules.mail import sublime_rules
    assert len(sublime_rules._IOC["sender_emails"]) > 100
    # On ajoute temporairement l'empreinte d'une fausse adresse pour vérifier la comparaison.
    fake = "escroc@liste-noire.example"
    sublime_rules._IOC["sender_emails"].append(sublime_rules._sha256(fake))
    try:
        assert "observed_malicious_sender_emails.yml + observed_malicious_sender_root_domains.yml" in _fired(
            _mail(sender=f"x <{fake}>"))
    finally:
        sublime_rules._IOC["sender_emails"].pop()


# ---------- mails normaux : AUCUNE règle Sublime ne doit se déclencher ----------

CAS_NORMAUX = [
    _mail(body="Salut, on se voit samedi ? https://www.cinema.example/seances"),
    _mail(sender='"Paul" <paul.martin@gmail.com>', headers="Reply-To: paul.martin@gmail.com\n"),
    _mail(sender='"Maman" <maman@gmail.com>', body="Tu rentres a quelle heure ?"),
    _html('<p>Votre commande est <a href="https://shop.example/suivi">ici</a>.</p>'),
    _mail(headers="X-Mailer: Microsoft Outlook, Build 10.0.6626\n"),
    _mail(headers="In-Reply-To: <1@x.example>\n").replace(b"Subject: Information", b"Subject: RE: Information"),
    _with_attachment("photos.zip", b"PK\x03\x04data"),
    _with_attachment("cours.pdf", b"%PDF-1.7"),
]


@pytest.mark.parametrize("raw", CAS_NORMAUX)
def test_normal_mail_fires_nothing(raw):
    assert _fired(raw) == set()


def test_sublime_points_are_added_to_score():
    v = analyze_eml(_mail(sender="Banque <info@xn--bnque-6ua.example>"))
    assert v.score >= 40 and v.verdict != "safe"
    assert any("règle Sublime" in r for r in v.reasons)


def test_encoded_display_name_cannot_hide_sender_address():
    # Même piège que pour le Reply-To : le nom décodé contient une fausse adresse gmail.
    raw = _mail(sender="=?UTF-8?Q?Paul_=3Cpaul=40gmail.com=3E?= <escroc@pirate.example>")
    assert parse_eml(raw).sender_email == "escroc@pirate.example"
