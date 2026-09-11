"""Tests for Workflow Executor."""
import pytest

from t100ai.workflows.definitions import BUILTIN_WORKFLOWS
from t100ai.workflows.executor import StepStatus, WorkflowExecutor, WorkflowResult, WorkflowStep


class TestWorkflowExecutorCreation:
    def test_creation(self):
        we = WorkflowExecutor()
        assert we._workflows == {}
        assert we._current_result is None
        assert we._cancelled is False


class TestRunWorkflow:
    @pytest.mark.asyncio
    async def test_run_nonexistent_workflow(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("nonexistent", {})
        assert result["success"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_run_full_pentest(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("full_pentest", {"target": "192.168.1.1"})
        assert result["success"] is True
        assert result["name"] == "full_pentest"
        assert len(result["steps"]) == 5
        assert all(s["status"] == "completed" for s in result["steps"])

    @pytest.mark.asyncio
    async def test_run_web_audit(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("web_audit", {"target": "http://example.com"})
        assert result["success"] is True
        assert len(result["steps"]) == 4

    @pytest.mark.asyncio
    async def test_run_quick_scan(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("quick_scan", {"target": "10.0.0.0/24"})
        assert result["success"] is True
        assert len(result["steps"]) == 3

    @pytest.mark.asyncio
    async def test_run_ad_attack(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("ad_attack", {"domain": "corp.local"})
        assert result["success"] is True
        assert len(result["steps"]) == 4

    @pytest.mark.asyncio
    async def test_run_ir_response(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("ir_response", {"incident_id": "INC-001"})
        assert result["success"] is True
        assert len(result["steps"]) == 4

    @pytest.mark.asyncio
    async def test_run_workflow_has_total_time(self):
        we = WorkflowExecutor()
        result = await we.run_workflow("quick_scan", {"target": "10.0.0.1"})
        assert "total_time" in result
        assert isinstance(result["total_time"], float)
        assert result["total_time"] >= 0


class TestListWorkflows:
    def test_list_workflows(self):
        we = WorkflowExecutor()
        workflows = we.list_workflows()
        assert isinstance(workflows, list)
        assert len(workflows) >= 5
        names = [w["name"] for w in workflows]
        assert "full_pentest" in names
        assert "web_audit" in names
        assert "quick_scan" in names
        assert "ad_attack" in names
        assert "ir_response" in names

    def test_workflow_has_description(self):
        we = WorkflowExecutor()
        workflows = we.list_workflows()
        for wf in workflows:
            assert "description" in wf
            assert "steps" in wf


class TestGetStatus:
    def test_status_idle(self):
        we = WorkflowExecutor()
        status = we.get_status()
        assert status["status"] == "idle"

    @pytest.mark.asyncio
    async def test_status_after_run(self):
        we = WorkflowExecutor()
        await we.run_workflow("quick_scan", {"target": "10.0.0.1"})
        status = we.get_status()
        assert status["status"] in ("completed", "running")
        assert "workflow" in status


class TestCancel:
    def test_cancel(self):
        we = WorkflowExecutor()
        we.cancel()
        assert we._cancelled is True


class TestBuiltinWorkflows:
    def test_builtin_count(self):
        assert len(BUILTIN_WORKFLOWS) >= 5

    def test_builtin_has_description(self):
        for name, wf in BUILTIN_WORKFLOWS.items():
            assert "description" in wf
            assert "steps" in wf
            assert isinstance(wf["steps"], list)
            assert len(wf["steps"]) > 0

    def test_builtin_has_stop_on_failure(self):
        for name, wf in BUILTIN_WORKFLOWS.items():
            assert "stop_on_failure" in wf
            assert isinstance(wf["stop_on_failure"], bool)

    def test_workflow_step_dataclass(self):
        step = WorkflowStep(name="test", action="scan", params={"target": "10.0.0.1"})
        assert step.status == StepStatus.PENDING
        assert step.result is None
        assert step.error is None

    def test_workflow_result_dataclass(self):
        result = WorkflowResult(name="test", success=True)
        assert result.success is True
        assert result.total_time == 0.0
        assert result.steps == []

    def test_step_status_enum(self):
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.COMPLETED.value == "completed"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"
