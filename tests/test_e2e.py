"""End-to-end integration tests for T-100AI."""
import pytest

from t100ai.core.config import T100AIConfig
from t100ai.core.session import Finding, Session
from t100ai.llm.handler import LLMHandler
from t100ai.mcp.executor import ToolExecutor
from t100ai.mcp.registry import ToolRegistry
from t100ai.mcp.tool import MCPTool, ToolParameter
from t100ai.skills.base import SkillResult
from t100ai.wordlists.dictionaries import AttackDictionary
from t100ai.workflows.executor import WorkflowExecutor


class TestE2EFullReconFlow:
    """Simulate a full recon flow from session to findings."""

    def test_session_to_findings(self):
        session = Session(name="e2e_recon")
        session.set_config(T100AIConfig())

        # Simulate skill results being added as findings
        result = SkillResult(
            success=True,
            output="22/tcp open ssh\n80/tcp open http\n443/tcp open https",
            findings=[
                {"type": "open_port", "port": "22", "service": "ssh", "severity": "INFO"},
                {"type": "open_port", "port": "80", "service": "http", "severity": "INFO"},
                {"type": "open_port", "port": "443", "service": "https", "severity": "INFO"},
            ],
        )
        for f in result.findings:
            session.add_finding(Finding(
                title=f"Port {f['port']}/{f['service']} open",
                severity=f["severity"],
                tool="nmap",
                target="192.168.1.1",
            ))

        assert len(session.findings) == 3
        counts = session.findings_count
        assert counts["INFO"] == 3

    def test_session_report_generation(self):
        session = Session(name="e2e_report")
        session.add_finding(Finding(title="SSH open", severity="HIGH", tool="nmap"))
        session.add_finding(Finding(title="HTTP open", severity="MED", tool="nmap"))
        session.add_to_scope("192.168.1.1", "ip")

        report = session.generate_session_report()
        assert "SSH open" in report
        assert "192.168.1.1" in report


class TestE2EToolExecution:
    """Test tool execution flow from registry to executor."""

    def test_tool_registry_to_executor(self):
        registry = ToolRegistry()
        registry.register(MCPTool(
            name="test.echo",
            description="Echo test tool",
            category="test",
            skill="test",
            risk_level=0,
            parameters=[
                ToolParameter(name="message", type="string", required=True),
            ],
            command="echo",
        ))

        ToolExecutor(registry)  # debe instanciar sin error
        assert "test.echo" in registry.tools


class TestE2EWordlistIntegration:
    """Test wordlist integration with tools."""

    def test_wordlist_to_tool(self):
        wordlists = AttackDictionary()
        dirs = wordlists.get_directories()
        assert len(dirs) > 50
        assert "admin" in dirs
        assert ".env" in dirs

        subs = wordlists.get_subdomains()
        assert len(subs) > 100
        assert "www" in subs
        assert "api" in subs

        pwds = wordlists.get_passwords()
        assert len(pwds) > 100
        assert "password" in pwds

    def test_executor_integrated_wordlist(self):
        registry = ToolRegistry()
        registry.register(MCPTool(
            name="web.dir_fuzz",
            description="Directory fuzzing",
            category="web",
            skill="web",
            risk_level=1,
            parameters=[
                ToolParameter(name="url", type="string", required=True),
                ToolParameter(name="wordlist", type="string", default=""),
            ],
            command="gobuster",
        ))

        executor = ToolExecutor(registry)
        tool = registry.get_tool("web.dir_fuzz")
        wl_path = executor._get_integrated_wordlist(tool)
        assert wl_path != ""
        assert "dirs" in wl_path


class TestE2EWorkflowExecution:
    """Test end-to-end workflow execution."""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        executor = WorkflowExecutor()
        result = await executor.run_workflow("quick_scan", {"target": "10.0.0.1"})
        assert result["success"] is True
        assert result["name"] == "quick_scan"
        assert len(result["steps"]) == 3
        assert all(s["status"] == "completed" for s in result["steps"])

    @pytest.mark.asyncio
    async def test_workflow_cancellation(self):
        executor = WorkflowExecutor()
        executor.cancel()
        result = await executor.run_workflow("quick_scan", {"target": "10.0.0.1"})
        # Steps should be skipped after cancel
        assert result["success"] is True


class TestE2ELLMHandler:
    """Test LLM handler end-to-end with fallback."""

    def test_handler_fallback_chain(self):
        handler = LLMHandler()
        # Test fallback responses directly (bypass Ollama)
        responses = [
            handler.get_fallback_response("hola"),
            handler.get_fallback_response("como escaneo con nmap"),
            handler.get_fallback_response("que es sqli"),
        ]
        assert all(isinstance(r, str) and len(r) > 0 for r in responses)

    def test_handler_caching(self):
        handler = LLMHandler()
        # Test cache with fallback directly
        resp1 = handler.get_fallback_response("hola")
        resp2 = handler.get_fallback_response("hola")
        assert resp1 == resp2

        handler.clear_cache()
        resp3 = handler.get_fallback_response("hola")
        assert len(resp3) > 0


class TestE2ESessionBackupRestore:
    """Test session backup and restore flow."""

    def test_backup_and_restore(self, tmp_path):
        session = Session(name="e2e_backup")
        session.add_finding(Finding(title="Test finding", severity="HIGH"))
        session.add_to_scope("10.0.0.1", "ip")

        backup_path = session.export_full_backup(str(tmp_path))
        restored = Session.restore_from_backup(str(backup_path))

        assert restored.name == "e2e_backup"
        assert len(restored.findings) == 1
        assert len(restored.scope) == 1
