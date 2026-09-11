"""Tests for Command Router."""
from unittest.mock import AsyncMock, MagicMock

import pytest


def _make_engine():
    """Create a mock engine with all expected methods."""
    engine = MagicMock()
    engine.console = MagicMock()
    engine.console.clear = MagicMock()
    engine.console.print = MagicMock()
    engine.session = MagicMock()
    engine.session.scope = []

    # Async methods
    engine._list_models = AsyncMock()
    engine._switch_model = AsyncMock()
    engine._set_role = AsyncMock()
    engine._generate_report = AsyncMock()
    engine._handle_agent_command = AsyncMock()
    engine._route_deploy = AsyncMock()
    engine._route_workflow = AsyncMock()
    engine._route_plugin = AsyncMock()
    engine._handle_deploy_task = AsyncMock()
    engine._handle_workflow_run = AsyncMock()
    engine._handle_plugin_install = AsyncMock()
    engine._show_plugin_info = AsyncMock()
    engine._handle_plugin_search = AsyncMock()

    # Sync methods
    engine._show_help = MagicMock()
    engine._handle_save_command = MagicMock()
    engine._handle_scope_command = MagicMock()
    engine._show_scope = MagicMock()
    engine._list_roles = MagicMock()
    engine._show_role = MagicMock()
    engine._show_skills = MagicMock()
    engine._show_tools = MagicMock()
    engine._show_findings = MagicMock()
    engine._add_finding = MagicMock()
    engine._show_session_report = MagicMock()
    engine._show_session_info = MagicMock()
    engine._show_log = MagicMock()
    engine._show_history = MagicMock()
    engine._show_wordlists = MagicMock()
    engine._handle_read_command = MagicMock()
    engine._show_model_info = MagicMock()
    engine._show_deploy_status = MagicMock()
    engine._show_deploy_list = MagicMock()
    engine._show_workflow_list = MagicMock()
    engine._show_workflow_status = MagicMock()
    engine._show_plugin_list = MagicMock()
    engine._show_performance_stats = MagicMock()

    return engine


class TestCommandRouterCreation:
    def test_creation(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        assert router._engine is engine


class TestBasicCommands:
    @pytest.mark.asyncio
    async def test_help_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/help")
        engine._show_help.assert_called_once()

    @pytest.mark.asyncio
    async def test_clear_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/clear")
        engine.console.clear.assert_called_once()

    @pytest.mark.asyncio
    async def test_exit_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/exit")
        engine.console.print.assert_called()

    @pytest.mark.asyncio
    async def test_quit_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/quit")
        engine.console.print.assert_called()

    @pytest.mark.asyncio
    async def test_salir_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/salir")
        engine.console.print.assert_called()


class TestScopeCommands:
    @pytest.mark.asyncio
    async def test_scope_set(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/scope set 192.168.1.1")
        engine._handle_scope_command.assert_called_once_with("192.168.1.1")

    @pytest.mark.asyncio
    async def test_scope_show(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/scope show")
        engine._show_scope.assert_called_once()

    @pytest.mark.asyncio
    async def test_scope_clear(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        engine.session.scope = [MagicMock()]
        router = CommandRouter(engine)
        await router.route("/scope clear")
        assert len(engine.session.scope) == 0


class TestSkillsToolsCommands:
    @pytest.mark.asyncio
    async def test_skill_list(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/skill list")
        engine._show_skills.assert_called_once()

    @pytest.mark.asyncio
    async def test_tool_list(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/tool list")
        engine._show_tools.assert_called_once()


class TestFindingsCommands:
    @pytest.mark.asyncio
    async def test_findings_show(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/findings show")
        engine._show_findings.assert_called_once()

    @pytest.mark.asyncio
    async def test_findings_add(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/findings add SQL Injection found")
        engine._add_finding.assert_called_once_with("SQL Injection found")


class TestUnknownCommand:
    @pytest.mark.asyncio
    async def test_unknown_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/foobar")
        engine.console.print.assert_called()
        calls = [str(c) for c in engine.console.print.call_args_list]
        assert any("desconocido" in c for c in calls)


class TestPerfCommand:
    @pytest.mark.asyncio
    async def test_perf_command(self):
        from t100ai.core.command_router import CommandRouter
        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/perf")
        engine._show_performance_stats.assert_called_once()
