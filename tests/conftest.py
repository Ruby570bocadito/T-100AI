import subprocess

import pytest

try:
    import requests
except ImportError:
    requests = None


@pytest.fixture
def mock_subprocess(monkeypatch):
    class DummyProcess:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def communicate(self):
            return (b"mock stdout", b"mock stderr")

        @property
        def returncode(self):
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: DummyProcess(*args, **kwargs))
    return DummyProcess


@pytest.fixture
def mock_network(monkeypatch):
    if requests is None:
        pytest.skip("requests not installed")

    class DummyResponse:
        def __init__(self, status=200, json_data=None, text=""):
            self.status_code = status
            self._json = json_data or {}
            self.text = text

        def json(self):
            return self._json

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            return DummyResponse()

    monkeypatch.setattr(requests, "Session", DummySession, raising=False)
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: DummyResponse())
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: DummyResponse())
    return DummySession
