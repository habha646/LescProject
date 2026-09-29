from sentinelle.modules.network import fake


def test_fake_scan_returns_baseline_devices():
    fake.reset()
    devices = fake.scan()
    assert len(devices) == 4
    assert all(d.mac for d in devices)


def test_fake_scan_adds_unknown_device_on_second_call():
    fake.reset()
    fake.scan()
    second = fake.scan()
    assert len(second) == 5
    assert any(d.hostname == "" for d in second)


def test_scan_route_creates_alert_on_unknown_device(client):
    fake.reset()
    client.post("/reseau/scanner")  # 1er scan = référence, personne n'est "inconnu"
    resp = client.post("/reseau/scanner", follow_redirects=True)
    assert resp.status_code == 200
    assert "Inconnu".encode() in resp.data or "1 nouvel".encode() in resp.data
