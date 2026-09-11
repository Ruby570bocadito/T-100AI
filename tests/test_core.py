"""T-100AI Test Suite - Basic Tests"""

import pytest

from t100ai.core.config import T100AIConfig
from t100ai.core.session import Finding, Session
from t100ai.mcp.registry import ToolRegistry
from t100ai.mcp.tool import MCPTool, ToolParameter
from t100ai.skills.base import SkillResult


class TestSession:
    """Tests para Session"""

    def test_session_creation(self):
        """Test creación de sesión"""
        session = Session(name="test")
        assert session.id is not None
        assert session.name == "test"
        assert len(session.findings) == 0
        assert len(session.scope) == 0

    def test_add_finding(self):
        """Test añadir hallazgo"""
        session = Session()
        finding = Finding(
            title="Puerto 22 abierto",
            severity="HIGH",
            tool="nmap"
        )
        session.add_finding(finding)
        assert len(session.findings) == 1
        assert session.findings[0].title == "Puerto 22 abierto"

    def test_scope_management(self):
        """Test gestión de scope"""
        session = Session()
        session.add_to_scope("192.168.1.1", "ip")
        assert len(session.scope) == 1
        assert session.is_in_scope("192.168.1.1")
        assert not session.is_in_scope("10.0.0.1")

    def test_findings_count(self):
        """Test conteo de hallazgos"""
        session = Session()
        session.add_finding(Finding(severity="CRIT"))
        session.add_finding(Finding(severity="HIGH"))
        session.add_finding(Finding(severity="HIGH"))
        session.add_finding(Finding(severity="MED"))

        counts = session.findings_count
        assert counts["CRIT"] == 1
        assert counts["HIGH"] == 2
        assert counts["MED"] == 1


class TestT100AIConfig:
    """Tests para T100AIConfig"""

    def test_default_config(self):
        """Test configuración por defecto"""
        import os
        os.environ["OLLAMA_MODEL"] = "mistral:7b"
        config = T100AIConfig()
        assert config.ollama_host == "http://localhost:11434"
        assert config.ollama_model == "mistral:7b"
        assert config.llm_enabled is True
        assert config.permission_mode == "standard"
        del os.environ["OLLAMA_MODEL"]

    def test_permission_levels(self):
        """Test niveles de permisos"""
        config = T100AIConfig(permission_mode="paranoid")
        assert config.get_permission_level("active") == 0

        config = T100AIConfig(permission_mode="standard")
        assert config.get_permission_level("active") == 1


class TestMCPTool:
    """Tests para MCPTool"""

    def test_tool_creation(self):
        """Test creación de herramienta"""
        tool = MCPTool(
            name="test.tool",
            description="Tool de prueba",
            category="test",
            skill="recon",
            risk_level=1
        )
        assert tool.name == "test.tool"
        assert tool.risk_level == 1

    def test_tool_validation(self):
        """Test validación de parámetros"""
        tool = MCPTool(
            name="test.tool",
            description="Tool de prueba",
            category="test",
            skill="recon",
            parameters=[
                ToolParameter(name="target", type="string", required=True),
                ToolParameter(name="port", type="string", default="80"),
            ]
        )

        # Valid params
        valid, msg = tool.validate_params({"target": "192.168.1.1"})
        assert valid is True

        # Missing required
        valid, msg = tool.validate_params({})
        assert valid is False
        # Check for error message (works with any language)
        assert len(msg) > 0 and ("required" in msg.lower() or "requerido" in msg.lower() or "requerida" in msg.lower())


class TestToolRegistry:
    """Tests para ToolRegistry"""

    @pytest.mark.asyncio
    async def test_registry_discovery(self):
        """Test descubrimiento de herramientas"""
        registry = ToolRegistry()
        await registry.discover_tools()

        # Verificar herramientas registradas
        assert len(registry.tools) > 0
        assert "network.port_scan" in registry.tools
        assert "system.process_list" in registry.tools

    @pytest.mark.asyncio
    async def test_get_tool(self):
        """Test obtener herramienta"""
        registry = ToolRegistry()
        await registry.discover_tools()

        tool = registry.get_tool("network.port_scan")
        assert tool is not None
        assert tool.name == "network.port_scan"
        assert tool.risk_level == 1

    @pytest.mark.asyncio
    async def test_search_tools(self):
        """Test búsqueda de herramientas"""
        registry = ToolRegistry()
        await registry.discover_tools()

        results = registry.search("port")
        assert len(results) >= 1
        assert any("port" in t.name for t in results)


class TestSkillResult:
    """Tests para SkillResult"""

    def test_successful_result(self):
        """Test resultado exitoso"""
        result = SkillResult(
            success=True,
            output="Scan completed"
        )
        assert result.success is True
        assert result.output == "Scan completed"

    def test_failed_result(self):
        """Test resultado fallido"""
        result = SkillResult(
            success=False,
            error="Tool not found"
        )
        assert result.success is False
        assert result.error == "Tool not found"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_session():
    """Fixture de sesión de ejemplo"""
    return Session(name="test_session")


@pytest.fixture
def sample_config():
    """Fixture de configuración de ejemplo"""
    import os
    os.environ["OLLAMA_MODEL"] = "mistral:7b"
    os.environ["LLM_ENABLED"] = "false"
    os.environ["PERMISSION_MODE"] = "standard"
    cfg = T100AIConfig()
    del os.environ["OLLAMA_MODEL"]
    del os.environ["LLM_ENABLED"]
    del os.environ["PERMISSION_MODE"]
    return cfg
