"""T-100AI CLI - Main Entry Point

Terminal interactivo honesto: cada comando documentado en `markdown_help()`
está cableado en t100ai.core.command_router.CommandRouter. Si un comando no
está en la tabla del router, no existe y la ayuda no lo anuncia.
"""

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from t100ai.core import Session, T100AIEngine
from t100ai.utils.history import CommandHistory

prompt_toolkit_available = importlib.util.find_spec("prompt_toolkit") is not None
if prompt_toolkit_available:
    from prompt_toolkit.completion import Completion
else:
    Completion = None

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

console = Console(force_terminal=True, file=sys.stdout)

# Persistent command history
command_history = CommandHistory()

app = typer.Typer(
    name="t100ai",
    help="T-100AI - AI-Powered Offensive Security Terminal",
    add_completion=False,
    invoke_without_command=True,
)

VERSION = "0.2.0"


class ContextAwareCompleter:
    """Autocompletado de comandos del sistema y nombres descubiertos."""

    def __init__(self, session: Optional["Session"] = None, engine: Optional["T100AIEngine"] = None):
        self.session = session
        self.engine = engine

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text:
            return

        parts = text.split()
        if len(parts) == 1:
            last = parts[0]
            pool = set(_system_command_list())
            if last.startswith("/"):
                for cmd in pool:
                    if cmd.startswith(last[1:]):
                        yield Completion(f"/{cmd}", start_position=-len(last))
            else:
                names = _discover_names()
                for suggestion in (
                    names.get("tools", []) + names.get("skills", []) + names.get("workflows", [])
                ):
                    if suggestion.startswith(last.lower()):
                        yield Completion(suggestion, start_position=-len(last))

    def update_context(self, session, engine) -> None:
        self.session = session
        self.engine = engine


# NOTE: prompt_toolkit requiere contexto async correcto; el REPL usa input()
# estándar que funciona de forma fiable en todas las plataformas.
from t100ai.core.config import T100AIConfig  # noqa: E402


def _confirm_ethical_use() -> None:
    """Gate de uso ético. Obligatorio antes de cualquier operación."""
    if not Confirm.ask(
        "[yellow]!! CONFIRMACION DE USO ETICO !!\n"
        "Este software esta disenado exclusivamente para uso profesional etico autorizado.\n"
        "Solo debe usarse en sistemas donde tengas autorizacion explicita.\n\n"
        "Confirmas que tienes autorizacion para operar en estos sistemas?",
        default=False,
    ):
        console.print("[red]Operacion cancelada. T-100AI requiere autorizacion expliita.[/]")
        raise typer.Exit(code=1)


def _apply_config_and_confirm(
    config_path: Optional[str], debug: bool, model: Optional[str], no_llm: bool
) -> T100AIConfig:
    """Load config, apply CLI overrides, and confirm ethical use."""
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


@app.callback(invoke_without_command=True)
def cli_callback(
    ctx: typer.Context,
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: mistral:7b)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
) -> None:
    """T-100AI - AI-Powered Offensive Security Terminal.

    Sin subcomando arranca el terminal interactivo.
    """
    if ctx.invoked_subcommand is None:
        show_banner()
        cfg = _apply_config_and_confirm(config, debug, model, no_llm)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_t100ai(cfg, scope))


@app.command("main")
def main_entry(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: mistral:7b)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
) -> None:
    """Inicia el terminal interactivo de T-100AI.

    Ejemplos:
      python -m t100ai.cli.main
      python -m t100ai.cli.main -s 192.168.1.1
      python -m t100ai.cli.main -m llama3.2 -s example.com
      python -m t100ai.cli.main --no-llm
    """
    show_banner()
    cfg = _apply_config_and_confirm(config, debug, model, no_llm)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_t100ai(cfg, scope))


def _system_command_list() -> list[str]:
    """Return a list of system commands (non-slash built-ins)."""
    return [
        "help", "version", "info", "workflow", "skill", "tool", "finding", "report", "mode", "clear", "history",
        "exit", "quit", "salir",
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
    """Ayuda honesta: exactamente los comandos que CommandRouter soporta."""
    return f"""
# ◈ T-100AI — Ayuda de Comandos

**T-100AI** · AI-Powered Offensive Security Terminal · v{VERSION}

---

## SESIÓN Y ALCANCE
| Comando | Descripción |
|---|---|
| `/session` | Información de la sesión actual |
| `/scope set [ip/cidr/domain]` | Definir el scope de la operación |
| `/scope show` | Mostrar scope actual |
| `/scope clear` | Limpiar scope |
| `/save [archivo]` | Guardar código/hallazgos de la sesión |

## ROLES Y MODOS
| Comando | Descripción |
|---|---|
| `/role set [nombre]` | Cambiar rol activo |
| `/role show` | Mostrar rol actual |
| `/role list` | Listar roles disponibles |
| `/mode paranoid` | Confirmación en TODAS las acciones |
| `/mode standard` | Modo estándar (por defecto) |
| `/mode expert` | Auto-ejecución sin confirmaciones |

Roles disponibles: `pentester` · `red-teamer` · `blue-teamer` · `ctf-player` · `forensic`

## SKILLS Y HERRAMIENTAS
| Comando | Descripción |
|---|---|
| `/skill list` | Listar skills disponibles |
| `/skill use [nombre]` | Activar skill específico |
| `/skill info [nombre]` | Info detallada de un skill |
| `/tools` | Listar herramientas MCP disponibles |

Skills: `recon` · `osint` · `web` · `exploit` · `postex` · `forense` · `ad` · `report`

## MODELO DE IA
| Comando | Descripción |
|---|---|
| `/model info` | Info del modelo activo |
| `/model switch [nombre]` | Cambiar modelo Ollama |
| `/model list` | Listar modelos instalados en Ollama |

## HALLAZGOS
| Comando | Descripción |
|---|---|
| `/findings show` | Ver todos los hallazgos registrados |
| `/findings add [sev] [título]` | Añadir hallazgo manual (ej: `HIGH MySQL expuesto`) |
| `/findings score [id] [cvss]` | Asignar score CVSS a un hallazgo |

## REPORTES Y LOGS
| Comando | Descripción |
|---|---|
| `/report generate` | Generar informe final (markdown) |
| `/report preview` | Vista previa del informe |
| `/report session` | Resumen de la sesión |
| `/report export [formato]` | Exportar informe |
| `/log show` | Ver log de acciones de sesión |
| `/log export` | Exportar log completo |

## CONTEXTO Y HISTORIAL
| Comando | Descripción |
|---|---|
| `/context show` | Ver historial conversacional en memoria |
| `/context clear` | Limpiar historial (mantiene hallazgos) |
| `/history [query]` | Historial de comandos del terminal |
| `/perf` | Estadísticas de rendimiento |

## AGENTES, WORKFLOWS Y PLUGINS
| Comando | Descripción |
|---|---|
| `/agent list` | Listar agentes disponibles |
| `/agent spawn [tarea]` | Desplegar tarea en un agente |
| `/agent status` | Estado del orquestador |
| `/workflow list` | Listar workflows disponibles |
| `/workflow run [nombre]` | Ejecutar workflow completo |
| `/workflow status` | Estado del workflow en curso |
| `/deploy task [desc]` | Desplegar tarea al orquestador |
| `/plugin list` | Listar plugins |
| `/plugin search [query]` | Buscar plugins |
| `/plugin install [nombre]` | Instalar plugin |

## UTILIDADES
| Comando | Descripción |
|---|---|
| `/wordlist dir|subdomain|user|pass|sql|xss|lfi|cve` | Wordlists integradas |
| `/read [archivo]` | Leer un archivo y mostrarlo |
| `help` / `/help` | Mostrar esta ayuda |
| `/clear` | Limpiar pantalla |
| `exit` / `quit` | Cerrar T-100AI |

---

## CONTROL DE SISTEMA (LLM)

El LLM puede ejecutar comandos reales usando la sintaxis:

```
<cmd>nmap -sV 192.168.1.1</cmd>
```

Se pedirá confirmación antes de ejecutar cada comando (excepto en modo `expert`).
El output se analiza automáticamente y el LLM propone los siguientes pasos.
El sandbox valida scope, rate-limit y bloquea comandos destructivos.

---

## ENTRADA NATURAL

Todo lo que no sea un comando `/cmd` se procesa como lenguaje natural:

```
escanea los puertos de 192.168.1.1
tengo este hash: $2y$10$abc...
explícame el ataque Kerberoasting
inicia un pentest completo contra 10.0.0.0/24
```
"""


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
    console.print()
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# REPL
# ─────────────────────────────────────────────────────────────────────────────
async def run_t100ai(cfg: T100AIConfig, initial_scope: Optional[str] = None) -> None:
    """Ejecuta la sesión principal de T-100AI"""
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

    console.print("\n[#8B949E]Escribe 'help' para ver comandos disponibles o 'exit' para salir.[/]\n")
    sys.stdout.flush()

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
            from t100ai.utils.errors import ErrorHandler, format_error
            ErrorHandler.register_defaults()
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
