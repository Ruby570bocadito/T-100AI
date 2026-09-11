"""Tests for CLI main module."""
from unittest.mock import MagicMock, patch


class TestCLIImports:
    def test_app_exists(self):
        from t100ai.cli.main import app
        assert app is not None

    def test_main_entry_exists(self):
        from t100ai.cli.main import main_entry
        assert callable(main_entry)

    def test_version_command(self):
        from t100ai.cli.main import version
        # Should not raise
        with patch("t100ai.cli.main.console"):
            version()

    def test_info_command(self):
        from t100ai.cli.main import info
        with patch("t100ai.cli.main.console"):
            with patch("t100ai.cli.main.Table"):
                info()


class TestCLIColors:
    def test_ansi_colors_reset(self):
        from t100ai.cli.main import ANSIColors
        assert ANSIColors.RESET == "\033[0m"

    def test_ansi_colors_bold(self):
        from t100ai.cli.main import ANSIColors
        assert ANSIColors.BOLD == "\033[1m"

    def test_ansi_colors_rgb(self):
        from t100ai.cli.main import ANSIColors
        rgb = ANSIColors.rgb(255, 0, 0)
        assert "38;2;255;0;0" in rgb

    def test_ansi_colors_bg_rgb(self):
        from t100ai.cli.main import ANSIColors
        rgb = ANSIColors.bg_rgb(0, 255, 0)
        assert "48;2;0;255;0" in rgb

    def test_ansi_colors_cursor_hide(self):
        from t100ai.cli.main import ANSIColors
        assert "?25l" in ANSIColors.cursor_hide()

    def test_ansi_colors_cursor_show(self):
        from t100ai.cli.main import ANSIColors
        assert "?25h" in ANSIColors.cursor_show()

    def test_ansi_colors_clear_screen(self):
        from t100ai.cli.main import ANSIColors
        assert "2J" in ANSIColors.clear_screen()

    def test_ansi_colors_clear_line(self):
        from t100ai.cli.main import ANSIColors
        assert "2K" in ANSIColors.clear_line()


class TestKeyboardShortcuts:
    def test_ctrl_c(self):
        from t100ai.cli.main import KeyboardShortcuts
        assert KeyboardShortcuts.CTRL_C == "\x03"

    def test_ctrl_l(self):
        from t100ai.cli.main import KeyboardShortcuts
        assert KeyboardShortcuts.CTRL_L == "\x0c"

    def test_ctrl_d(self):
        from t100ai.cli.main import KeyboardShortcuts
        assert KeyboardShortcuts.CTRL_D == "\x04"

    def test_handle_ctrl_l(self):
        from t100ai.cli.main import KeyboardShortcuts
        mock_console = MagicMock()
        result = KeyboardShortcuts.handle_input("\x0c", mock_console)
        assert result is True
        mock_console.clear.assert_called_once()

    def test_handle_ctrl_d(self):
        from t100ai.cli.main import KeyboardShortcuts
        mock_console = MagicMock()
        result = KeyboardShortcuts.handle_input("\x04", mock_console)
        assert result is True

    def test_handle_other(self):
        from t100ai.cli.main import KeyboardShortcuts
        mock_console = MagicMock()
        result = KeyboardShortcuts.handle_input("a", mock_console)
        assert result is False


class TestSystemCommandList:
    def test_returns_list(self):
        from t100ai.cli.main import _system_command_list
        cmds = _system_command_list()
        assert isinstance(cmds, list)
        assert "help" in cmds
        assert "exit" in cmds
        assert "quit" in cmds


class TestDiscoverNames:
    def test_returns_dict(self):
        from t100ai.cli.main import _discover_names
        names = _discover_names()
        assert isinstance(names, dict)
        assert "tools" in names
        assert "skills" in names
        assert "workflows" in names


class TestMarkdownHelp:
    def test_help_contains_sections(self):
        from t100ai.cli.main import markdown_help
        help_text = markdown_help()
        assert "T-100AI" in help_text
        assert "scope" in help_text.lower() or "SCOPE" in help_text
        assert "skill" in help_text.lower() or "SKILL" in help_text
