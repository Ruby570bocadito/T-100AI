"""T-100AI CLI - Main Entry Point

Terminal interactivo honesto: cada comando documentado en ``markdown_help()``
está cableado en t100ai.core.command_router.CommandRouter. Si un comando no
está en la tabla del router, no existe y la ayuda no lo anuncia.

La ayuda vive en t100ai.core.help_text (fuente única compartida con el engine)
y KNOWN_COMMANDS en command_router alimenta sugerencias y TAB-completion.
"""

import asyncio
import atexit
import sys
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from t100ai import __version__
from t100ai.core import Session, T100AIEngine
from t100ai.utils.history import CommandHistory

if TYPE_CHECKING:
    from t100ai.core.config import T100AIConfig

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Sin ``force_terminal``: rich detecta TTY solo. En una tubería el output es
# texto limpio (scriptable); en un pty mantiene el color. FORCE_COLOR fuerza.
console = Console(file=sys.stdout)

# Persistent command history
command_history = CommandHistory()

app = typer.Typer(
    name="t100ai",
    help="T-100AI - AI-Powered Offensive Security Terminal",
    add_completion=False,
    invoke_without_command=True,
)

VERSION = __version__


# ─────────────────────────────────────────────────────────────────────────────
# TAB completion (readline) — comandos slash, subacciones y nombres descubiertos
# ─────────────────────────────────────────────────────────────────────────────
from t100ai.core.command_router import KNOWN_COMMANDS  # noqa: E402

_SUBACTIONS = {
    "scope": ["set", "show", "clear"],
    "role": ["set", "show", "list"],
    "mode": ["paranoid", "standard", "expert"],
    "skill": ["list", "use", "info"],
    "model": ["info", "switch", "list"],
    "findings": ["show", "add", "score"],
    "report": ["generate", "preview", "session", "export"],
    "log": ["show", "export"],
    "context": ["show", "clear"],
    "wordlist": ["dir", "subdomain", "user", "pass", "sql", "xss", "lfi", "cve", "all"],
    "agent": ["list", "spawn", "status"],
    "deploy": ["task", "status", "list"],
    "workflow": ["list", "run", "status"],
    "plugin": ["list", "install", "info", "search"],
}


def _completion_candidates(line: str, text: str) -> List[str]:
    """Candidatos de autocompletado para la línea actual."""
    stripped = line.lstrip()
    if not stripped.startswith("/"):
        # Entrada natural: nombres de tools/skills/workflows descubiertos
        if len(stripped.split()) > 1:
            return []
        names = _discover_names()
        pool = names["tools"] + names["skills"] + names["workflows"]
        low = text.lower()
        return [n for n in pool if n.startswith(low)]

    inner = stripped[1:]
    if not inner or inner.endswith(" "):
        word = inner.strip().lower()
        if not word:
            return [f"/{c}" for c in KNOWN_COMMANDS]
        if " " in word:
            first = word.split()[0]
            return list(_SUBACTIONS.get(first, []))
        if word in KNOWN_COMMANDS:
            return list(_SUBACTIONS.get(word, []))
        return [f"/{c}" for c in KNOWN_COMMANDS if c.startswith(word)]

    parts = inner.split()
    if len(parts) == 1:
        prefix = parts[0].lower()
        return [f"/{c}" for c in KNOWN_COMMANDS if c.startswith(prefix)]
    subs = _SUBACTIONS.get(parts[0].lower(), [])
    last = parts[-1].lower()
    return [s for s in subs if s.startswith(last)]


def _readline_completer(text: str, state: int):
    try:
        line = readline.get_line_buffer()  # noqa: F821 — solo se registra con readline
    except NameError:
        return None
    matches = [m + " " for m in _completion_candidates(line, text)]
    try:
        return matches[state]
    except IndexError:
        return None


def _setup_readline() -> None:
    """Activa TAB-completion y flecha-arriba persistentes (POSIX)."""
    try:
        import readline  # noqa: F401 — módulo global para el completer
    except ImportError:
        return  # Windows sin pyreadline: REPL funcional sin autocompletado

    hist_file = Path("~/.t100ai/readline_history").expanduser()
    try:
        hist_file.parent.mkdir(parents=True, exist_ok=True)
        if hist_file.exists():
            readline.read_history_file(str(hist_file))
        readline.set_history_length(1000)
    except OSError:
        pass

    # Precarga el historial persistente de sesiones anteriores
    for cmd in command_history.get_recent(200):
        try:
            readline.add_history(cmd)
        except Exception:
            break

    readline.set_completer(_readline_completer)
    readline.set_completer_delims(" \t\n;,")
    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("set completion-display-width 0")

    def _save() -> None:
        try:
            readline.write_history_file(str(hist_file))
        except OSError:
            pass

    atexit.register(_save)


def _confirm_ethical_use() -> None:
    """Gate de uso ético. Obligatorio antes de cualquier operación."""
    try:
        confirmed = Confirm.ask(
            "[yellow]!! CONFIRMACION DE USO ETICO !!\n"
            "Este software esta disenado exclusivamente para uso profesional etico autorizado.\n"
            "Solo debe usarse en sistemas donde tengas autorizacion explicita.\n\n"
            "Confirmas que tienes autorizacion para operar en estos sistemas?",
            default=False,
        )
    except EOFError:
        confirmed = False
    if not confirmed:
        console.print("[red]Operacion cancelada. T-100AI requiere autorizacion explicita.[/]")
        raise typer.Exit(code=1)


def _apply_config_and_confirm(
    config_path: Optional[str], debug: bool, model: Optional[str], no_llm: bool
) -> "T100AIConfig":
    """Load config, apply CLI overrides, and confirm ethical use."""
    from t100ai.core.config import T100AIConfig  # noqa: E402

    cfg = T100AIConfig.load(config_path=config_path)
    if debug:
        cfg.log_level = "DEBUG"
    if model:
        cfg.ollama_model = model
    if no_llm:
        cfg.llm_enabled = False
        console.print("[yellow]Modo sin LLM activado[/]")

    sys.stdout.flush()
    _confirm_ethical_use()
    return cfg


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[#00FF88]T-100AI v{VERSION}[/]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def cli_callback(
    ctx: typer.Context,
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: mistral:7b)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Omite el banner (para scripts)"),
    version_flag: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Muestra la versión y sale",
    ),
) -> None:
    """T-100AI - AI-Powered Offensive Security Terminal.

    Sin subcomando arranca el terminal interactivo.
    """
    if ctx.invoked_subcommand is None:
        cfg = _apply_config_and_confirm(config, debug, model, no_llm)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_t100ai(cfg, scope, no_banner=no_banner))


@app.command("main")
def main_entry(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: mistral:7b)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Omite el banner (para scripts)"),
    version_flag: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Muestra la versión y sale",
    ),
) -> None:
    """Inicia el terminal interactivo de T-100AI.

    Ejemplos:
      python -m t100ai.cli.main
      python -m t100ai.cli.main -s 192.168.1.1
      python -m t100ai.cli.main -m llama3.2 -s example.com
      python -m t100ai.cli.main --no-llm
    """
    cfg = _apply_config_and_confirm(config, debug, model, no_llm)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_t100ai(cfg, scope, no_banner=no_banner))


@app.command("session")
def session_command(
    args: Optional[List[str]] = typer.Argument(
        None, help="save [nombre] | load <id> | list | export <id> <formato>"
    ),
) -> None:
    """Gestiona sesiones guardadas (save/load/list/export)."""
    from t100ai.cli.session_commands import handle_session_command

    handle_session_command(list(args or []))


@app.command("doctor")
def doctor(
    json_out: bool = typer.Option(False, "--json", help="Salida en JSON"),
) -> None:
    """Diagnóstico del entorno: Python, dependencias, config, sandbox y Ollama."""
    from t100ai.cli.doctor import run_checks

    results = run_checks()
    if json_out:
        import json

        console.print_json(json.dumps(results))
    else:
        icons = {
            "ok": "[#00FF88]●[/]",
            "warn": "[#FFD60A]●[/]",
            "fail": "[#FF3366]●[/]",
            "skip": "[#8B949E]●[/]",
        }
        table = Table(title="◈ T-100AI doctor — diagnóstico del entorno", border_style="#00D4FF")
        table.add_column("", width=2)
        table.add_column("Comprobación", style="#00D4FF")
        table.add_column("Estado", width=8)
        table.add_column("Detalle", style="#8B949E")
        for r in results:
            table.add_row(icons.get(r["status"], "?"), r["check"], r["status"], r["detail"])
        console.print(table)
    if any(r["status"] == "fail" for r in results):
        raise typer.Exit(code=1)


def _system_command_list() -> list[str]:
    """Return a list of system commands (non-slash built-ins)."""
    return [
        "help", "version", "info", "doctor", "session", "workflow", "skill", "tool",
        "finding", "report", "mode", "scope", "role", "model", "context", "wordlist",
        "clear", "history", "perf", "exit", "quit", "salir",
    ]


def _discover_names() -> dict:
    """Discover tool/skill/workflow names from the filesystem when available."""
    names: dict[str, list] = {"tools": [], "skills": [], "workflows": []}
    t100ai_root = Path(__file__).resolve().parent.parent
    for key, sub in (("tools", "tools"), ("skills", "skills"), ("workflows", "workflows")):
        p = t100ai_root / sub
        if p.exists():
            for child in sorted(p.iterdir()):
                if child.is_dir():
                    names[key].append(child.name)
                elif child.is_file() and child.suffix == ".py":
                    names[key].append(child.stem)
    return names


def _show_help() -> None:
    """Display comprehensive help with all commands."""
    console.print(Markdown(markdown_help()))


def markdown_help() -> str:
    """Ayuda honesta: delega en la fuente única (core.help_text)."""
    from t100ai.core.help_text import markdown_help as _markdown_help

    return _markdown_help(VERSION)


# ─────────────────────────────────────────────────────────────────────────────
# Paleta de Colores T-100AI
# ─────────────────────────────────────────────────────────────────────────────
class T100AI_COLORS:
    """Paleta de colores del tema T-100AI"""
    BG_PRIMARY = "#080C14"
    GREEN_PRIMARY = "#00FF88"
    CYAN_PRIMARY = "#00D4FF"
    RED_CRITICAL = "#FF3366"
    ORANGE_HIGH = "#FF6B35"
    YELLOW_MEDIUM = "#FFD60A"
    GRAY_MUTED = "#8B949E"

    SEVERITY_COLORS = {
        "CRIT": RED_CRITICAL,
        "HIGH": ORANGE_HIGH,
        "MED": YELLOW_MEDIUM,
        "LOW": GREEN_PRIMARY,
        "INFO": GRAY_MUTED,
    }

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        return cls.SEVERITY_COLORS.get(severity.upper(), cls.GRAY_MUTED)


class ANSIColors:
    """Códigos ANSI para terminal"""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_BLACK = "\033[90m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_CYAN = "\033[96m"

    @classmethod
    def rgb(cls, r: int, g: int, b: int) -> str:
        return f"\033[38;2;{r};{g};{b}m"

    @classmethod
    def bg_rgb(cls, r: int, g: int, b: int) -> str:
        return f"\033[48;2;{r};{g};{b}m"

    @classmethod
    def cursor_hide(cls) -> str:
        return "\033[?25l"

    @classmethod
    def cursor_show(cls) -> str:
        return "\033[?25h"

    @classmethod
    def clear_screen(cls) -> str:
        return "\033[2J\033[H"

    @classmethod
    def clear_line(cls) -> str:
        return "\033[2K"


class KeyboardShortcuts:
    """Keyboard shortcuts support"""

    CTRL_C = "\x03"
    CTRL_L = "\x0c"
    CTRL_D = "\x04"

    @staticmethod
    def handle_input(char: str, console) -> bool:
        """Procesa atajos de teclado. Retorna True si se manejó."""
        if char == KeyboardShortcuts.CTRL_L:
            console.clear()
            return True
        elif char == KeyboardShortcuts.CTRL_D:
            console.print("[yellow]Usa 'exit' para salir[/]")
            return True
        return False


def get_enhanced_prompt(session, config) -> str:
    """Genera prompt mejorado con colores ANSI"""
    role_tag = f"|{session.role.name}|" if session.role else ""
    model_tag = config.ollama_model

    cyan = ANSIColors.CYAN
    green = ANSIColors.GREEN
    gray = ANSIColors.BRIGHT_BLACK
    reset = ANSIColors.RESET

    return (
        f"\n{green}⟩{reset} "
        f"{gray}[{reset}"
        f"{cyan}{model_tag}{reset}"
        f"{green}{role_tag}{reset}"
        f"{gray}@t100ai]{reset} "
        f"{green}▶{reset} "
    )


# ─────────────────────────────────────────────────────────────────────────────
# Banner — Ghost-ship ASCII art
# ─────────────────────────────────────────────────────────────────────────────

T100AI_LOGO = r"""         ^
       _-^-_
    _-',^. `-_.
 ._-' ,'   `.   `-_
!`-_._________`-':::
!   /\        /\::::
;  /  \      /..\ :::
! /    \    /....\::
!/      \  /......\:
;--.___. \/_.__.--;;
 '-_    `:!;;;;;;;'
     `-_, :!;;;''
         `-!'"""

SUBTITLE = "[#8B949E]Security | Pentesting | Exploitation | Control | Terminal[/]"
TAGLINE = "[#00D4FF italic]Unseen. Unconstrained. Unstoppable.[/]"


def show_banner() -> None:
    """Muestra el banner de T-100AI"""
    console.print(f"[bold #00FF88]{T100AI_LOGO}[/bold #00FF88]")
    console.print()
    console.print(SUBTITLE)
    console.print(TAGLINE)
    console.print(f"[#8B949E]v{VERSION} · uso exclusivo en sistemas con autorización explícita[/]")
    console.print()
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# REPL
# ─────────────────────────────────────────────────────────────────────────────
async def run_t100ai(cfg, initial_scope: Optional[str] = None, no_banner: bool = False) -> None:
    """Ejecuta la sesión principal de T-100AI"""
    if not no_banner:
        show_banner()

    session = Session()
    session.set_config(cfg)

    if initial_scope:
        session.add_to_scope(initial_scope)

    engine = T100AIEngine(session=session, config=cfg)

    print("Inicializando motor T-100AI...")
    await engine.initialize()
    print("OK: Motor inicializado")

    if initial_scope:
        print(f"Scope: {initial_scope}")

    console.print(Panel.fit(
        "[#00FF88]T-100AI iniciado correctamente[/]\n"
        f"Modelo: [#00D4FF]{cfg.ollama_model}[/]\n"
        f"Scope: [#FFD60A]{', '.join(s.target for s in session.scope) if session.scope else 'None'}[/]\n"
        f"Modo: [#00FF88]{'CLI Interactivo' if cfg.llm_enabled else 'Herramientas'}[/]\n"
        f"Permisos: [#FFD60A]{cfg.permission_mode}[/]",
        border_style="#00FF88"
    ))

    console.print("\n[#8B949E]Escribe 'help' para ver comandos · TAB autocompleta · 'exit' para salir.[/]\n")
    sys.stdout.flush()

    # Diagnóstico de errores accionable + readline (TAB/historial) una sola vez
    try:
        from t100ai.utils.errors import ErrorHandler

        ErrorHandler.register_defaults()
    except Exception:
        pass
    _setup_readline()

    # Loop principal
    consecutive_cancel = 0
    while True:
        try:
            if engine.interactive_mode:
                prompt = "\033[1;33m⟩ \033[0m"
            else:
                prompt = get_enhanced_prompt(session, session.config)
            sys.stdout.write(prompt)
            sys.stdout.flush()

            try:
                user_input = input()
            except EOFError:
                console.print("\n[yellow]Entrada cerrada.[/]")
                break

            consecutive_cancel = 0

            if not user_input or not user_input.strip():
                continue

            if user_input.lower() in ("exit", "quit", "salir"):
                break

            command_history.add(user_input, session_id=session.id)

            if user_input.strip() in ("/help", "help"):
                _show_help()
                continue

            if user_input.strip() == "/clear":
                console.clear()
                continue

            was_interactive = engine.interactive_mode
            engine.interactive_mode = False

            if was_interactive:
                await engine.process_interactive_input(user_input)
            else:
                await engine.process_input(user_input)

            if getattr(engine, "_exit_requested", False):
                break

        except KeyboardInterrupt:
            consecutive_cancel += 1
            if consecutive_cancel >= 2:
                console.print("\n[bold #FF3366]Saliendo de T-100AI...[/]")
                break
            engine._cancel_requested = True
            console.print("\n[yellow]Cancelando... (Ctrl+C de nuevo para salir)[/]")
        except EOFError:
            console.print("\n[yellow]Entrada cerrada. Saliendo...[/]")
            break
        except Exception as e:
            from t100ai.utils.errors import format_error

            console.print(format_error(e))


@app.command()
def version() -> None:
    """Muestra la versión de T-100AI"""
    console.print(f"[#00FF88]T-100AI v{VERSION}[/]")
    console.print("[#8B949E]AI-Powered Offensive Security Terminal[/]")


@app.command()
def info() -> None:
    """Muestra informacion del sistema"""
    table = Table(title="Informacion del Sistema T-100AI")
    table.add_column("Componente", style="#00D4FF")
    table.add_column("Estado", style="#00FF88")
    table.add_column("Detalles", style="#8B949E")

    table.add_row("Version", "[OK]", VERSION)
    table.add_row("Python", "[OK]", f"{sys.version.split()[0]}")
    table.add_row("LLM", "[--]", "No conectado (se conecta al iniciar sesion)")
    table.add_row("Herramientas", "[--]", "Se descubren al iniciar sesion")

    console.print(table)


if __name__ == "__main__":
    app()
