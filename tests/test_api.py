import io

HEADERS = {"X-Sentinelle": "1"}
SAFE_EML = b"From: ami@example.com\nSubject: Salut\nContent-Type: text/plain\n\nCoucou\n"


def _upload(client, raw: bytes, filename: str, headers=HEADERS):
    return client.post("/api/mail", headers=headers,
                       data={"eml_file": (io.BytesIO(raw), filename)},
                       content_type="multipart/form-data")


def test_console_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "compagnon de sécurité".encode() in resp.data


def test_pages_under_construction_load(client):
    for url in ("/reseau/", "/alertes/", "/ia/"):
        resp = client.get(url)
        assert resp.status_code == 200
        assert "En cours de construction".encode() in resp.data


def test_post_without_custom_header_is_refused(client):
    # Protection CSRF : un site étranger ne peut pas ajouter cet en-tête
    assert _upload(client, SAFE_EML, "test.eml", headers={}).status_code == 403


def test_mail_upload_returns_verdict_and_counts(client):
    data = _upload(client, SAFE_EML, "test.eml").get_json()
    assert data["verdict"] == "safe"
    assert data["explanation"]
    assert data["counts"] == {"total": 1, "safe": 1, "suspect": 0, "dangerous": 0}


def test_mail_upload_rejects_other_extensions(client):
    assert _upload(client, b"x", "virus.exe").status_code == 400


def test_boot_checks_report_real_results(client):
    base = client.get("/api/demarrage/base").get_json()
    assert base["ok"] is True and "ok" in base["detail"]
    moteur = client.get("/api/demarrage/moteur-mail").get_json()
    assert "20 mails" in moteur["detail"]
