"""Comprehensive tests for ToolExecutor in specter.mcp.executor."""

import pytest

from t100ai.mcp.executor import ExecutionResult, ToolExecutor
from t100ai.mcp.registry import ToolRegistry
from t100ai.mcp.tool import MCPTool, ToolParameter
from t100ai.wordlists.dictionaries import AttackDictionary


@pytest.fixture
def sample_registry():
    """Create a registry with sample tools for testing."""
    registry = ToolRegistry()
    nmap_tool = MCPTool(
        name="nmap",
        description="Network scanner",
        category="recon",
        skill="recon",
        command="nmap",
        parameters=[
            ToolParameter(name="targets", type="string", required=True, description="Target hosts"),
            ToolParameter(name="ports", type="string", required=False, description="Port range"),
            ToolParameter(name="scan_type", type="string", required=False, description="Scan type"),
        ],
    )
    gobuster_tool = MCPTool(
        name="gobuster",
        description="Directory brute-forcer",
        category="web",
        skill="web",
        command="gobuster dir",
        parameters=[
            ToolParameter(name="url", type="string", required=True, description="Target URL"),
            ToolParameter(name="wordlist", type="string", required=False, description="Wordlist path"),
        ],
    )
    registry.register(nmap_tool)
    registry.register(gobuster_tool)
    return registry


@pytest.fixture
def executor(sample_registry):
    """Create a ToolExecutor with sample registry."""
    return ToolExecutor(registry=sample_registry, wordlists=AttackDictionary())


class TestToolExecutorCreation:
    """Test ToolExecutor initialization."""

    def test_create_with_defaults(self, sample_registry):
        executor = ToolExecutor(registry=sample_registry)
        assert executor.registry is sample_registry
        assert executor.timeout == 300
        assert executor._execution_history == []

    def test_create_with_custom_timeout(self, sample_registry):
        executor = ToolExecutor(registry=sample_registry, timeout=60)
        assert executor.timeout == 60

    def test_create_with_custom_wordlists(self, sample_registry):
        wordlists = AttackDictionary()
        executor = ToolExecutor(registry=sample_registry, wordlists=wordlists)
        assert executor.wordlists is wordlists


class TestToolExecutorExecute:
    """Test ToolExecutor.execute() method."""

    @pytest.mark.asyncio
    async def test_execute_missing_tool(self, executor):
        result = await executor.execute("nonexistent_tool", {})
        assert result.success is False
        assert "not found" in result.error.lower()
        assert result.tool_name == "nonexistent_tool"

    @pytest.mark.asyncio
    async def test_execute_invalid_params(self, executor):
        result = await executor.execute("nmap", {})
        assert result.success is False
        assert "invalid params" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_command_not_found(self, executor):
        result = await executor.execute("nmap", {"targets": "127.0.0.1"})
        assert result.tool_name == "nmap"
        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_execute_returns_result_object(self, executor):
        result = await executor.execute("nonexistent_tool", {})
        assert isinstance(result, ExecutionResult)
        assert result.success is False


class TestBuildCommand:
    """Test _build_command() parameter resolution."""

    def test_build_command_with_target(self, executor, sample_registry):
        tool = sample_registry.get_tool("nmap")
        cmd = executor._build_command(tool, {"targets": "192.168.1.1"}, "default")
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd

    def test_build_command_with_ports(self, executor, sample_registry):
        tool = sample_registry.get_tool("nmap")
        cmd = executor._build_command(tool, {"targets": "192.168.1.1", "ports": "80,443"}, "default")
        assert "-p" in cmd
        assert "80,443" in cmd

    def test_build_command_with_url(self, executor, sample_registry):
        tool = sample_registry.get_tool("gobuster")
        cmd = executor._build_command(tool, {"url": "http://example.com"}, "default")
        assert "-u" in cmd
        assert "http://example.com" in cmd

    def test_build_command_auto_wordlist(self, executor, sample_registry):
        tool = MCPTool(
            name="dir_fuzz",
            description="Directory fuzzer",
            category="web",
            skill="web",
            command="gobuster dir",
            parameters=[
                ToolParameter(name="url", type="string", required=True),
                ToolParameter(name="wordlist", type="string", required=False),
            ],
        )
        cmd = executor._build_command(tool, {"url": "http://example.com", "wordlist": ""}, "default")
        assert "-w" in cmd
        wordlist_idx = cmd.index("-w")
        assert cmd[wordlist_idx + 1].startswith("/tmp/t100ai_wl_dirs.txt")


class TestGetIntegratedWordlist:
    """Test _get_integrated_wordlist() returns correct wordlist types."""

    def test_wordlist_for_dir_tool(self, executor, sample_registry):
        tool = MCPTool(
            name="dir_fuzz",
            description="Directory fuzzer",
            category="web",
            skill="web",
            command="gobuster dir",
        )
        wl = executor._get_integrated_wordlist(tool)
        assert wl.startswith("/tmp/t100ai_wl_dirs.txt")

    def test_wordlist_for_nmap(self, executor, sample_registry):
        tool = sample_registry.get_tool("nmap")
        wl = executor._get_integrated_wordlist(tool)
        assert wl == ""


class TestSuggestNextTools:
    """Test _suggest_next_tools() returns appropriate suggestions."""

    def test_suggest_after_web_port(self, executor):
        findings = [{"type": "open_port", "port": "80", "service": "http"}]
        suggestions = executor._suggest_next_tools("nmap", findings)
        assert "web.dir_fuzz" in suggestions
        assert "web.sqlmap" in suggestions

    def test_suggest_after_smb_port(self, executor):
        findings = [{"type": "open_port", "port": "445", "service": "microsoft-ds"}]
        suggestions = executor._suggest_next_tools("nmap", findings)
        assert "exploit.run" in suggestions

    def test_suggest_after_sql_injection(self, executor):
        findings = [{"type": "sql_injection", "severity": "CRIT"}]
        suggestions = executor._suggest_next_tools("sqlmap", findings)
        assert "exploit.run" in suggestions

    def test_suggest_after_cve(self, executor):
        findings = [{"type": "cve_found", "severity": "HIGH"}]
        suggestions = executor._suggest_next_tools("nuclei", findings)
        assert "cve.lookup" in suggestions

    def test_suggest_no_findings(self, executor):
        suggestions = executor._suggest_next_tools("nmap", [])
        assert suggestions == []

    def test_suggest_deduplicates(self, executor):
        findings = [
            {"type": "open_port", "port": "80", "service": "http"},
            {"type": "open_port", "port": "443", "service": "https"},
        ]
        suggestions = executor._suggest_next_tools("nmap", findings)
        assert len(suggestions) == len(set(suggestions))


class TestExecutionHistory:
    """Test get_execution_history() returns history."""

    @pytest.mark.asyncio
    async def test_history_starts_empty(self, executor):
        history = executor.get_execution_history()
        assert history == []

    @pytest.mark.asyncio
    async def test_history_after_execution(self, executor):
        result = await executor.execute("nonexistent_tool", {})
        assert isinstance(result, ExecutionResult)
        history = executor.get_execution_history()
        assert len(history) == 0

    @pytest.mark.asyncio
    async def test_history_after_valid_execution(self, executor):
        await executor.execute("nmap", {"targets": "127.0.0.1"})
        history = executor.get_execution_history()
        assert len(history) == 1
        assert isinstance(history[0], ExecutionResult)

    @pytest.mark.asyncio
    async def test_history_returns_copy(self, executor):
        await executor.execute("nonexistent_tool", {})
        history1 = executor.get_execution_history()
        history2 = executor.get_execution_history()
        assert history1 is not history2


class TestGetSummary:
    """Test get_summary() returns correct stats."""

    @pytest.mark.asyncio
    async def test_summary_empty(self, executor):
        summary = executor.get_summary()
        assert summary["total_executions"] == 0
        assert summary["successful"] == 0
        assert summary["failed"] == 0
        assert summary["total_time"] == 0
        assert summary["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_summary_after_failed_execution(self, executor):
        result = await executor.execute("nmap", {"targets": "127.0.0.1"})
        summary = executor.get_summary()
        assert summary["total_executions"] == 1
        assert summary["successful"] == result.success
        assert summary["failed"] == 1 - result.success
        assert summary["total_time"] >= 0

    @pytest.mark.asyncio
    async def test_summary_has_severity_breakdown(self, executor):
        summary = executor.get_summary()
        assert "findings_by_severity" in summary
        assert "CRIT" in summary["findings_by_severity"]
        assert "HIGH" in summary["findings_by_severity"]
        assert "MED" in summary["findings_by_severity"]
        assert "LOW" in summary["findings_by_severity"]
        assert "INFO" in summary["findings_by_severity"]
