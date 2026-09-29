def test_dashboard_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Sentinelle".encode() in resp.data
