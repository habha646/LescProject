import os
import tempfile

import pytest

from sentinelle import create_app
from sentinelle.config import Config


@pytest.fixture
def app():
    fd, path = tempfile.mkstemp(suffix=".db")

    class TestConfig(Config):
        DATABASE = path
        TESTING = True

    app = create_app(TestConfig)
    yield app

    os.close(fd)
    os.unlink(path)


@pytest.fixture
def client(app):
    return app.test_client()
