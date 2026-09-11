"""Tests for REST API and engagement management."""

from t100ai.api.server import T100AIAPI, APIResponse


class TestAPIResponse:
    def test_success_response(self):
        resp = APIResponse(200, data={"key": "value"})
        assert resp.status == 200
        assert resp.error == ""
        json_str = resp.to_json()
        assert '"status": "ok"' in json_str
        assert '"key": "value"' in json_str

    def test_error_response(self):
        resp = APIResponse(404, error="Not found")
        json_str = resp.to_json()
        assert '"status": "error"' in json_str
        assert '"error": "Not found"' in json_str

    def test_response_with_none_data(self):
        resp = APIResponse(200)
        json_str = resp.to_json()
        assert "data" not in json_str


class TestT100AIAPI:
    def test_creation(self):
        api = T100AIAPI(host="127.0.0.1", port=9999)
        assert api.host == "127.0.0.1"
        assert api.port == 9999
        assert api.is_running is False

    def test_base_url(self):
        api = T100AIAPI(host="127.0.0.1", port=8080)
        assert api.base_url == "http://127.0.0.1:8080"

    def test_register_handler(self):
        api = T100AIAPI()
        api.register_handler("GET", "/api/custom", lambda q: APIResponse(200, {"custom": True}))
        assert "GET:/api/custom" in api._handlers

    def test_start_stop(self):
        api = T100AIAPI(host="127.0.0.1", port=18080)
        api.start()
        assert api.is_running is True
        api.stop()
        assert api.is_running is False

    def test_default_status_endpoint(self):
        api = T100AIAPI(host="127.0.0.1", port=18081)
        api.start()
        import json
        import urllib.request
        try:
            with urllib.request.urlopen(f"{api.base_url}/api/status", timeout=5) as resp:
                data = json.loads(resp.read())
                assert data["status"] == "ok"
        finally:
            api.stop()

    def test_default_404_endpoint(self):
        api = T100AIAPI(host="127.0.0.1", port=18082)
        api.start()
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(f"{api.base_url}/api/nonexistent", timeout=5):
                pass
        except urllib.error.HTTPError as e:
            assert e.code == 404
        finally:
            api.stop()

    def test_custom_handler(self):
        api = T100AIAPI(host="127.0.0.1", port=18083)
        api.register_handler("GET", "/api/health", lambda q: APIResponse(200, {"healthy": True}))
        api.start()
        import json
        import urllib.request
        try:
            with urllib.request.urlopen(f"{api.base_url}/api/health", timeout=5) as resp:
                data = json.loads(resp.read())
                assert data["data"]["healthy"] is True
        finally:
            api.stop()
