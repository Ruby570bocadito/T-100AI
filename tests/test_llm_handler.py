"""Tests for LLM Handler with offline fallback."""

from t100ai.llm.handler import LLMHandler


class TestLLMHandlerCreation:
    def test_creation(self):
        handler = LLMHandler()
        assert handler._client is None
        assert handler._cache == {}
        assert handler._available is None

    def test_not_available_by_default(self):
        handler = LLMHandler()
        # May or may not be available depending on Ollama setup
        result = handler.is_available()
        assert isinstance(result, bool)


class TestFallbackResponses:
    def test_greeting_hola(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("hola")
        assert "T-100AI" in resp

    def test_greeting_hello(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("hello")
        assert "T-100AI" in resp

    def test_capabilities(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("que puedes hacer")
        assert "v2.0" in resp
        assert "capacidades" in resp.lower() or "Capacidades" in resp

    def test_nmap_scan(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("como escaneo puertos con nmap")
        assert "nmap" in resp.lower()

    def test_sqli(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("como exploto sqli")
        assert "sqlmap" in resp.lower() or "SQL" in resp

    def test_xss(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("como hago xss")
        assert "XSS" in resp or "xss" in resp.lower()

    def test_directory_fuzz(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("directory fuzz con gobuster")
        assert "gobuster" in resp.lower() or "ffuf" in resp.lower()

    def test_active_directory(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("kerberos domain controller attack")
        assert "BloodHound" in resp or "Kerberoast" in resp or "LDAP" in resp

    def test_privilege_escalation(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("privilege escalation linux")
        assert "LinPEAS" in resp or "linpeas" in resp

    def test_report(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("generar reporte")
        assert "informe" in resp.lower() or "reporte" in resp.lower()

    def test_unknown_query(self):
        handler = LLMHandler()
        resp = handler.get_fallback_response("algo completamente aleatorio xyz123")
        assert "predefinida" in resp.lower() or "especifico" in resp.lower()


class TestCache:
    def test_cache_set_get(self):
        handler = LLMHandler()
        handler._set_cached("key1", "value1")
        assert handler._get_cached("key1") == "value1"

    def test_cache_clear(self):
        handler = LLMHandler()
        handler._set_cached("key1", "value1")
        handler.clear_cache()
        assert handler._get_cached("key1") is None

    def test_cache_ttl_expiry(self):
        handler = LLMHandler()
        handler._cache_ttl = 0
        handler._set_cached("key1", "value1")
        import time
        time.sleep(0.01)
        assert handler._get_cached("key1") is None

    def test_generate_response_uses_cache(self):
        handler = LLMHandler()
        resp1 = handler.generate_response("hola")
        resp2 = handler.generate_response("hola")
        assert resp1 == resp2
