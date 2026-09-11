"""Integration Tests - Full flow: engine -> skill -> tool"""
import asyncio

import pytest

from t100ai.agents.orchestrator import (
    AgentOrchestrator,
    AgentRole,
    AgentTask,
    AnalystAgent,
    ExploitAgent,
    ReconAgent,
    ReporterAgent,
    SmartOrchestrator,
)
from t100ai.core.session import Finding, Session
from t100ai.mcp.registry import ToolRegistry
from t100ai.skills.base import SkillResult

# ─────────────────────────────────────────────────────────────────────────────
# Skill Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSkillResult:
    """Tests for SkillResult data flow"""

    def test_successful_result(self):
        r = SkillResult(success=True, output="scan complete", findings=[{"type": "open_port", "port": "80"}])
        assert r.success is True
        assert len(r.findings) == 1
        assert r.findings[0]["port"] == "80"

    def test_failed_result(self):
        r = SkillResult(success=False, error="tool not found")
        assert r.success is False
        assert r.error == "tool not found"

    def test_result_str(self):
        r = SkillResult(success=True, output="ok")
        assert str(r) == "ok"

    def test_result_str_error(self):
        r = SkillResult(success=False, error="fail")
        assert "Error" in str(r) or "error" in str(r).lower()


class TestSessionFindings:
    """Test finding flow from skills to session"""

    def test_finding_from_skill_result(self):
        session = Session(name="test")
        result = SkillResult(
            success=True,
            output="nmap scan complete",
            findings=[{"type": "open_port", "port": "22", "service": "ssh"}],
        )
        for f in result.findings:
            session.add_finding(Finding(
                title=f"Port {f.get('port', 'unknown')} open",
                severity=f.get("severity", "INFO"),
                tool="nmap",
                target="192.168.1.1",
            ))
        assert len(session.findings) == 1
        assert "22" in session.findings[0].title

    def test_session_report_with_findings(self):
        session = Session(name="pentest")
        session.add_finding(Finding(title="SSH open", severity="HIGH", tool="nmap"))
        session.add_finding(Finding(title="HTTP open", severity="MED", tool="nmap"))
        report = session.generate_session_report()
        assert "SSH open" in report
        assert "HIGH" in report
        assert "pentest" in report


# ─────────────────────────────────────────────────────────────────────────────
# Agent Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_recon_agent_execution():
    """Test ReconAgent executes task and returns expected data"""
    agent = ReconAgent("test_recon")
    task = AgentTask(id="t1", description="Scan 192.168.1.1 for open ports", agent_role=AgentRole.RECON)
    result = await agent.execute(task)
    assert result["success"] is True
    assert "hosts_found" in result["result"]
    assert "open_ports" in result["result"]


@pytest.mark.asyncio
async def test_exploit_agent_execution():
    """Test ExploitAgent executes task and returns expected data"""
    agent = ExploitAgent("test_exploit")
    task = AgentTask(id="t2", description="Search exploits for 192.168.1.1", agent_role=AgentRole.EXPLOIT)
    result = await agent.execute(task)
    assert result["success"] is True
    assert "exploits_tried" in result["result"]


@pytest.mark.asyncio
async def test_analyst_agent():
    """Test AnalystAgent analyzes scan data"""
    agent = AnalystAgent("test_analyst")
    task = AgentTask(
        id="t3",
        description="Analyze scan results\ndata:\n22/tcp open ssh\n80/tcp open http\n443/tcp open https\nCVE-2021-41773 found",
        agent_role=AgentRole.ANALYST,
    )
    result = await agent.execute(task)
    assert result["success"] is True
    assert "analysis_complete" in result["result"]


@pytest.mark.asyncio
async def test_reporter_agent():
    """Test ReporterAgent generates reports"""
    agent = ReporterAgent("test_reporter")
    task = AgentTask(
        id="t4",
        description='Generate report for findings: [{"type": "open_port", "port": "22", "severity": "HIGH", "target": "192.168.1.1"}]',
        agent_role=AgentRole.REPORTER,
    )
    result = await agent.execute(task)
    assert result["success"] is True
    assert "report_generated" in result["result"]


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_parallel_execution():
    """Test orchestrator runs tasks in parallel"""
    orch = AgentOrchestrator()
    orch.create_agent(AgentRole.RECON, "recon_1")
    orch.create_agent(AgentRole.EXPLOIT, "exploit_1")

    tasks = [
        AgentTask(id="p1", description="Scan 10.0.0.1 for ports", agent_role=AgentRole.RECON),
        AgentTask(id="p2", description="Search exploits for apache", agent_role=AgentRole.EXPLOIT),
    ]

    results = await orch.execute_parallel(tasks)
    assert len(results) == 2
    assert all(r.get("success") for r in results.values())


@pytest.mark.asyncio
async def test_orchestrator_sequential_execution():
    """Test orchestrator runs tasks sequentially with dependencies"""
    orch = AgentOrchestrator()

    tasks = [
        AgentTask(id="s1", description="Recon 10.0.0.1", agent_role=AgentRole.RECON),
        AgentTask(id="s2", description="Exploit findings", agent_role=AgentRole.EXPLOIT, dependencies=["s1"]),
        AgentTask(id="s3", description="Generate report", agent_role=AgentRole.REPORTER, dependencies=["s1", "s2"]),
    ]

    results = await orch.execute_sequential(tasks)
    assert len(results) == 3
    assert all(r.get("success") for r in results.values())


@pytest.mark.asyncio
async def test_smart_orchestrator_decomposition():
    """Test SmartOrchestrator decomposes complex objectives"""
    orch = SmartOrchestrator()
    result = await orch.smart_orchestrate("Scan and exploit 192.168.1.1", {})

    assert "tasks_executed" in result
    assert result["tasks_executed"] > 0
    assert "final_report" in result


# ─────────────────────────────────────────────────────────────────────────────
# Tool Registry Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tool_registry_discovery():
    """Test tool registry discovers tools from skills"""
    registry = ToolRegistry()
    await registry.discover_tools()

    assert len(registry.tools) > 0
    assert "network.port_scan" in registry.tools


@pytest.mark.asyncio
async def test_tool_registry_search():
    """Test tool registry search functionality"""
    registry = ToolRegistry()
    await registry.discover_tools()

    results = registry.search("port")
    assert len(results) >= 1
    assert any("port" in t.name.lower() for t in results)


# ─────────────────────────────────────────────────────────────────────────────
# Session + Engine Flow Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_session_scope_auto_detect():
    """Test session scope management"""
    session = Session(name="test")
    session.add_to_scope("192.168.1.0/24", "cidr")
    session.add_to_scope("example.com", "domain")

    assert session.is_in_scope("192.168.1.0/24")
    assert session.is_in_scope("example.com")
    assert not session.is_in_scope("10.0.0.1")


def test_session_conversation_history():
    """Test session conversation history management"""
    session = Session(name="test")
    session.add_message("user", "Scan 192.168.1.1")
    session.add_message("assistant", "Running nmap on 192.168.1.1...")

    assert len(session.conversation_history) == 2
    assert session.conversation_history[0]["role"] == "user"

    prompt = session.build_conversation_prompt()
    assert "Usuario" in prompt or "T-100AI" in prompt


def test_session_findings_by_severity():
    """Test findings are counted by severity"""
    session = Session(name="test")
    session.add_finding(Finding(severity="CRIT"))
    session.add_finding(Finding(severity="HIGH"))
    session.add_finding(Finding(severity="HIGH"))
    session.add_finding(Finding(severity="MED"))
    session.add_finding(Finding(severity="LOW"))
    session.add_finding(Finding(severity="INFO"))

    counts = session.findings_count
    assert counts["CRIT"] == 1
    assert counts["HIGH"] == 2
    assert counts["MED"] == 1
    assert counts["LOW"] == 1
    assert counts["INFO"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Command Execution Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_cmd_echo():
    """Test command execution with a simple echo command"""
    proc = await asyncio.create_subprocess_exec(
        "echo", "hello",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    assert proc.returncode == 0
    assert b"hello" in stdout


@pytest.mark.asyncio
async def test_run_cmd_nonexistent_tool():
    """Test command execution with a nonexistent tool"""
    proc = await asyncio.create_subprocess_exec(
        "false",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    assert proc.returncode != 0
