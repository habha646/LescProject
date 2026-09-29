import pytest

from sentinelle.modules.network.guard import ensure_allowed


def test_allowed_subnet_passes():
    ensure_allowed("192.168.1.0/24", ["192.168.1.0/24"])


def test_disallowed_subnet_raises():
    with pytest.raises(PermissionError):
        ensure_allowed("10.0.0.0/24", ["192.168.1.0/24"])
