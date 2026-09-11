"""Tests for the professional CLI round (v0.3.0).

Cubre:
- Router: usos sin argumento, /model switch con nombre real, salida por /exit,
  sugerencias difflib de comandos desconocidos.
- Ayuda unificada (core.help_text) vs tabla del router (anti-drift).
- Autocompletado readline (_completion_candidates).
- Doctor (diagnóstico de entorno) en modo sin red.
- Rutas de datos rebrandizadas (~/.t100ai) y migración del historial legacy.
- Subcomandos typer: --version y session.
"""

import io
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

runner = CliRunner()


def _patched_console():
    """Consola de t100ai.cli.main redirigida a un buffer inspeccionable."""
    buf = io.StringIO()
    return buf, Console(file=buf, force_terminal=False, width=200)


def _make_engine():
    """Mock engine con los métodos que toca el router."""
    engine = MagicMock()
    engine.console = MagicMock()
    engine.session = MagicMock()
    engine.session.scope = []
    engine._list_models = AsyncMock()
    engine._switch_model = AsyncMock()
    engine._set_role = AsyncMock()
    return engine


class TestRouterGuardedUsage:
    @pytest.mark.asyncio
    async def test_scope_set_without_arg_shows_usage(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/scope set")
        engine._handle_scope_command.assert_not_called()
        printed = [str(c) for c in engine.console.print.call_args_list]
        assert any("Uso" in c for c in printed)

    @pytest.mark.asyncio
    async def test_model_switch_forwards_real_name(self):
        """/model switch llama3 debe cambiar a 'llama3', no a 'switch'."""
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/model switch llama3")
        engine._switch_model.assert_called_once_with("llama3")

    @pytest.mark.asyncio
    async def test_model_switch_without_arg_shows_usage(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/model switch")
        engine._switch_model.assert_not_called()
        printed = [str(c) for c in engine.console.print.call_args_list]
        assert any("Uso" in c for c in printed)

    @pytest.mark.asyncio
    async def test_skill_use_without_arg_shows_usage(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/skill use")
        engine.session.current_skill = "recon"  # no debe llegar a asignarse vía _use_skill
        printed = [str(c) for c in engine.console.print.call_args_list]
        assert any("Uso" in c for c in printed)

    @pytest.mark.asyncio
    async def test_exit_sets_exit_requested(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/exit")
        assert engine._exit_requested is True

    @pytest.mark.asyncio
    async def test_unknown_command_suggests_close_match(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/scop")
        printed = [str(c) for c in engine.console.print.call_args_list]
        assert any("desconocido" in c for c in printed)
        assert any("scope" in c for c in printed)

    @pytest.mark.asyncio
    async def test_unknown_command_without_match_falls_back_to_help(self):
        from t100ai.core.command_router import CommandRouter

        engine = _make_engine()
        router = CommandRouter(engine)
        await router.route("/zzzzzzzz")
        printed = [str(c) for c in engine.console.print.call_args_list]
        assert any("desconocido" in c for c in printed)
        assert any("/help" in c for c in printed)


class TestHelpAntiDrift:
    def test_help_first_token_known_by_router(self):
        """Cada comando /x anunciado por la ayuda existe en KNOWN_COMMANDS."""
        from t100ai.core.command_router import KNOWN_COMMANDS
        from t100ai.core.help_text import markdown_help

        text = markdown_help()
        for line in text.splitlines():
            if not line.strip().startswith("| `/"):
                continue
            first = line.split("`")[1]  # p.ej. "/scope set [ip/cidr/domain]"
            token = first.split()[0].lstrip("/").lower()
            assert token in KNOWN_COMMANDS, f"la ayuda anuncia /{token} pero el router no lo conoce"

    def test_help_does_not_advertise_ghost_commands(self):
        from t100ai.core.help_text import markdown_help

        text = markdown_help()
        # Comandos fantasma históricos
        assert "| `/export` |" not in text
        assert "forensic-analyst" not in text

    def test_help_mentions_tab_and_exit_aliases(self):
        from t100ai.core.help_text import markdown_help

        text = markdown_help()
        assert "TAB" in text
        assert "salir" in text

    def test_router_knows_every_subaction_group(self):
        from t100ai.core.command_router import KNOWN_COMMANDS

        for group in ("scope", "role", "mode", "skill", "model", "findings",
                      "report", "log", "context", "wordlist", "agent",
                      "deploy", "workflow", "plugin"):
            assert group in KNOWN_COMMANDS


class TestCompletionCandidates:
    def test_complete_slash_command(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("/sc", "/sc")
        assert "/scope" in cands

    def test_complete_empty_slash_shows_all(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("/", "/")
        assert "/help" in cands and "/scope" in cands and "/wordlist" in cands

    def test_complete_subactions_after_space(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("/scope ", "/scope ")
        assert cands == ["set", "show", "clear"]

    def test_complete_partial_subaction(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("/scope s", "/scope s")
        assert set(cands) == {"set", "show"}

    def test_complete_model_subactions(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("/model ", "/model ")
        assert set(cands) == {"info", "switch", "list"}

    def test_natural_word_multi_token_returns_empty(self):
        from t100ai.cli.main import _completion_candidates

        assert _completion_candidates("escanea los puertos de ", "de ") == []

    def test_natural_word_single_token_from_discovered(self):
        from t100ai.cli.main import _completion_candidates

        cands = _completion_candidates("re", "re")
        assert isinstance(cands, list)  # según FS: skills/tools/workflows


class TestDoctor:
    def test_run_checks_structure_offline(self):
        from t100ai.cli.doctor import run_checks

        results = run_checks(skip_network=True)
        assert len(results) >= 8
        for r in results:
            assert set(r) == {"check", "status", "detail"}
            assert r["status"] in ("ok", "warn", "fail", "skip")

    def test_run_checks_python_ok(self):
        from t100ai.cli.doctor import run_checks

        results = run_checks(skip_network=True)
        py = next(r for r in results if r["check"] == "python")
        assert py["status"] == "ok"

    def test_run_checks_includes_sandbox(self):
        from t100ai.cli.doctor import run_checks

        results = run_checks(skip_network=True)
        names = [r["check"] for r in results]
        assert "sandbox" in names and "wordlists" in names and "datos" in names

    def test_doctor_command_json(self):
        from t100ai.cli.main import app

        buf, con = _patched_console()
        with patch("t100ai.cli.doctor.run_checks", return_value=[
            {"check": "python", "status": "ok", "detail": "3.12"}]), \
             patch("t100ai.cli.main.console", con):
            result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0
        assert "python" in buf.getvalue()


class TestDataRebrand:
    def test_history_default_path_is_t100ai(self):
        from t100ai.utils.history import CommandHistory

        history = CommandHistory()
        expected = __import__("pathlib").Path("~/.t100ai/history.json").expanduser()
        assert history.history_file == expected

    def test_history_migrates_legacy_file(self, tmp_path):
        import t100ai.utils.history as hist_module

        legacy = tmp_path / "legacy.json"
        legacy.write_text(json.dumps([
            {"timestamp": "2025-01-01T00:00:00", "command": "/scope show",
             "session_id": None, "success": True}
        ]), encoding="utf-8")

        target = tmp_path / "new.json"
        with patch.object(hist_module, "DEFAULT_HISTORY_FILE", str(target)), \
             patch.object(hist_module, "LEGACY_HISTORY_FILE", str(legacy)):
            history = hist_module.CommandHistory(str(target))
        assert history.get_recent(5) == ["/scope show"]

    def test_storage_default_dir_is_t100ai(self):
        from t100ai.core.storage import SessionStorage

        storage = SessionStorage()
        assert ".t100ai" in str(storage.base_dir)
        assert ".specter" not in str(storage.base_dir)


class TestSessionSubcommand:
    def test_session_list_empty(self):
        import t100ai.cli.session_commands as sc

        sm = MagicMock()
        sm.list_sessions.return_value = []
        with patch.object(sc, "SessionManager", return_value=sm):
            sc.handle_session_command(["list"])

    def test_session_load_not_found_is_soft(self):
        import t100ai.cli.session_commands as sc

        sm = MagicMock()
        sm.load_session.side_effect = FileNotFoundError("missing")
        with patch.object(sc, "SessionManager", return_value=sm):
            sc.handle_session_command(["load", "nope"])  # no debe lanzar

    def test_session_save_uses_tz_aware_timestamp(self):
        import t100ai.cli.session_commands as sc

        sm = MagicMock()
        sm.save_session.return_value = "sid123"
        with patch.object(sc, "SessionManager", return_value=sm):
            sc.handle_session_command(["save", "demo"])
        sess = sm.save_session.call_args[0][0]
        assert sess.created_at.tzinfo is not None

    def test_session_cli_command_wired(self):
        import t100ai.cli.session_commands as sc
        from t100ai.cli.main import app

        sm = MagicMock()
        sm.list_sessions.return_value = []
        with patch.object(sc, "SessionManager", return_value=sm):
            result = runner.invoke(app, ["session", "list"])
        assert result.exit_code == 0


class TestVersionFlag:
    def test_version_flag(self):
        from t100ai import __version__
        from t100ai.cli.main import app

        buf, con = _patched_console()
        with patch("t100ai.cli.main.console", con):
            result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in buf.getvalue() + result.output

    def test_version_subcommand_still_works(self):
        from t100ai import __version__
        from t100ai.cli.main import app

        buf, con = _patched_console()
        with patch("t100ai.cli.main.console", con):
            result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in buf.getvalue() + result.output
