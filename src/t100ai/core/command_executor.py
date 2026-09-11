"""Command Executor - Handles command execution logic extracted from T100AIEngine."""

from __future__ import annotations

import asyncio
import platform
import re
import subprocess
import uuid
from pathlib import Path
from typing import Optional

import structlog
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table

from t100ai.core.config import T100AIConfig
from t100ai.core.llm_handler import LLMHandler
from t100ai.core.sandbox import CommandSandbox
from t100ai.core.session import Finding, Session

logger = structlog.get_logger()


class CommandExecutor:
    """Handles command execution: shell commands, batches, LLM commands, file operations, and agents."""

    def __init__(
        self,
        session: Session,
        config: T100AIConfig,
        console: Console,
        sandbox: CommandSandbox,
        llm_handler: LLMHandler,
    ) -> None:
        self.session = session
        self.config = config
        self.console = console
        self.sandbox = sandbox
        self.llm_handler = llm_handler
        self.interactive_mode = False
        self._last_generated_code: Optional[dict] = None
        self._agent_orchestrator = None

    def set_agent_orchestrator(self, orchestrator) -> None:
        """Set the agent orchestrator for agent-related commands."""
        self._agent_orchestrator = orchestrator

    async def _run_shell_command(
        self, cmd: str, source: str = "llm"
    ) -> tuple[str, str, int]:
        """Ejecuta un comando de shell con sandbox completo."""
        scope_targets = [e.target for e in self.session.scope]
        self.sandbox.set_scope_targets(scope_targets)
        self.sandbox.set_permission_mode(self.config.permission_mode)

        from t100ai.core.guardrails import LLMCommandValidator

        guardrails = LLMCommandValidator(strict=False)
        gv = guardrails.validate(cmd)
        if gv.warnings:
            for w in gv.warnings:
                self.console.print(f"[yellow]Guardrail warning:[/] {w}")
        if not gv.is_valid and gv.errors:
            self.console.print(f"[red]Guardrail bloqueo:[/] {'; '.join(gv.errors)}")
            return "", f"Guardrail: {'; '.join(gv.errors)}", -1
        if gv.confidence < 0.7:
            self.console.print(f"[yellow]Confianza baja ({gv.confidence}): {cmd[:80]}[/]")

        allowed, reason = self.sandbox.validate(cmd, source)
        if not allowed:
            self.console.print(f"[red]Sandbox bloqueo:[/] {reason}")
            return "", f"Sandbox: {reason}", -1

        if self.sandbox.requires_confirmation(cmd):
            if not Confirm.ask(
                f"[bold #FF6B35]Confirmar ejecucion: {cmd[:80]}?[/]", default=False
            ):
                self.console.print("[#8B949E]Comando rechazado por el usuario[/]")
                return "", "User declined", -1

        stats = self.sandbox.get_stats()
        self.console.print(
            f"[dim]Sandbox: {stats['executed_commands']} ejecutados | "
            f"{stats['blocked_commands']} bloqueados | "
            f"{stats['remaining_commands']} restantes[/]"
        )

        try:
            if platform.system() == "Windows":
                shell_args = ["cmd.exe", "/c", cmd]
            else:
                shell_args = ["/bin/sh", "-c", cmd]

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    shell_args,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    errors="replace",
                ),
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout: el comando tardo mas de 5 minutos.", -1
        except Exception as exc:
            return "", f"Error al ejecutar comando: {exc}", -1

    async def _execute_batch(self, commands: list[str]) -> list[dict]:
        """Ejecuta múltiples comandos en paralelo.

        Args:
            commands: Lista de comandos a ejecutar

        Returns:
            Lista de diccionarios con {command, stdout, stderr, returncode, success}
        """
        if not commands:
            return []

        self.console.print(
            f"[#00D4FF]▶ Ejecutando {len(commands)} comandos en paralelo...[/]"
        )

        tasks = [self._run_shell_command(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        batch_results = []
        for cmd, result in zip(commands, results):
            if isinstance(result, Exception):
                batch_results.append(
                    {
                        "command": cmd,
                        "stdout": "",
                        "stderr": str(result),
                        "returncode": -1,
                        "success": False,
                    }
                )
            else:
                stdout, stderr, returncode = result
                batch_results.append(
                    {
                        "command": cmd,
                        "stdout": stdout,
                        "stderr": stderr,
                        "returncode": returncode,
                        "success": returncode == 0,
                    }
                )

        successful = sum(1 for r in batch_results if r["success"])
        self.console.print(
            f"[#00FF88]✓[/] {successful}/{len(commands)} comandos completados"
        )

        return batch_results

    async def _execute_batch_with_dependencies(
        self,
        commands: list[dict],
        max_concurrent: int = 5,
    ) -> list[dict]:
        """Ejecuta comandos con dependencias y límite de concurrencia.

        Args:
            commands: Lista de {command, depends_on: list[str]}
            max_concurrent: Número máximo de comandos simultáneos

        Returns:
            Lista de resultados
        """
        if not commands:
            return []

        results: dict = {}
        running: set = set()
        completed: set = set()

        async def run_command(cmd_item: dict) -> tuple[str, tuple]:
            cmd = cmd_item["command"]
            result = await self._run_shell_command(cmd)
            return cmd_item.get("id", cmd), result

        while len(completed) < len(commands):
            available = [
                c
                for c in commands
                if c.get("id", c["command"]) not in completed
                and all(d in completed for d in c.get("depends_on", []))
                and c.get("id", c["command"]) not in running
            ]

            if not available:
                if running:
                    done, _ = await asyncio.wait(
                        running, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in done:
                        cmd_id, result = await task
                        results[cmd_id] = result
                        completed.add(cmd_id)
                        running.discard(task)
                continue

            batch = available[:max_concurrent]
            tasks: set = set()
            for cmd_item in batch:
                task = asyncio.create_task(run_command(cmd_item))
                running.add(task)
                tasks.add(task)

            if tasks:
                done, _ = await asyncio.wait(
                    tasks, return_when=asyncio.ALL_COMPLETED
                )
                for task in done:
                    cmd_id, result = await task
                    results[cmd_id] = result
                    completed.add(cmd_id)
                    running.discard(task)

        return [
            {
                "command": c.get("id", c["command"]),
                "result": results.get(c.get("id", c["command"])),
            }
            for c in commands
        ]

    async def _execute_llm_commands(
        self, response: str, client, system_prompt: str
    ) -> None:
        """Detecta bloques <cmd>...</cmd> o <code>...</code> y ejecuta comandos.

        Características:
        - Detecta automáticamente si el usuario quiere leer archivos
        - Despliega agentes automáticamente para tareas complejas
        - Formatea outputs para comandos comunes (nmap, etc.)
        - Parsea resultados y sugiere hallazgos
        - Pide al usuario qué hacer después
        """
        user_input = (
            self.session.conversation_history[-1]["content"]
            if self.session.conversation_history
            else ""
        )

        permission_mode = getattr(self.config, "permission_mode", "standard")

        file_patterns = [
            r"^leer\s+([^\s]+)",
            r"^ver\s+([^\s]+)",
            r"^mostrar\s+([^\s]+)",
            r"^cat\s+([^\s]+)",
        ]

        is_file_request = False
        for pattern in file_patterns:
            match = re.match(pattern, user_input.strip(), re.IGNORECASE)
            if match:
                filepath = match.group(1).strip().strip("'\"")
                if permission_mode == "paranoid":
                    self.console.print(
                        "[yellow]⚠ Modo Paranoid: ¿Confirmas leer el archivo?[/]"
                    )
                    if not Confirm.ask("  Leer archivo?", default=False):
                        self.console.print("[#444444]Operación cancelada[/]")
                        return
                self._handle_read_command(filepath)
                is_file_request = True
                break

        if is_file_request:
            return

        agent_patterns = [
            r"^despliega\s+(?:el\s+)?agente",
            r"^crea\s+(?:un\s+)?agente",
            r"^inicia\s+(?:el\s+)?agente",
            r"^ejecuta\s+agente",
        ]

        is_agent_request = False
        for pattern in agent_patterns:
            if re.match(pattern, user_input.strip(), re.IGNORECASE):
                if permission_mode == "paranoid":
                    self.console.print(
                        "[yellow]⚠ Modo Paranoid: ¿Confirmas crear un agente?[/]"
                    )
                    if not Confirm.ask("  Desplegar agente?", default=False):
                        self.console.print("[#444444]Operación cancelada[/]")
                        return
                if self._agent_orchestrator:
                    await self._handle_agent_command("spawn", user_input)
                    is_agent_request = True
                    break

        if is_agent_request:
            return

        cmd_pattern = r"<(?:cmd|code|shell)>(.*?)</(?:cmd|code|shell)>"
        commands = re.findall(cmd_pattern, response, re.DOTALL | re.IGNORECASE)
        if not commands:
            return

        for raw_cmd in commands:
            cmd = raw_cmd.strip()
            if not cmd:
                continue

            invalid_patterns = [
                r"^(comando|command|cmd|example|e\.g\.|example:|sample)$",
                r"^<.*>$",
                r"^\[.*\]$",
                r"^[^a-zA-Z]*$",
            ]

            is_invalid = any(
                re.match(p, cmd, re.IGNORECASE) for p in invalid_patterns
            )
            if is_invalid or len(cmd) < 3:
                self.console.print(
                    f"[yellow]Ignorando comando inválido: '{cmd}'[/]"
                )
                continue

            self.console.print()
            self.console.print(
                Panel.fit(
                    "[#00FF88]▶ COMANDO[/]\n" + f"[#FFFFFF]{cmd}[/]",
                    title="[#00D4FF]T-100AI[/]",
                    border_style="#00D4FF",
                    style="#1a1a2e on #0d1117",
                )
            )

            permission_mode = getattr(self.config, "permission_mode", "standard")
            if permission_mode == "expert":
                confirmed = True
                self.console.print("[#666666]Modo expert: auto-ejecutando...[/]")
            elif permission_mode == "paranoid":
                self.console.print("[#FFD60A]⚠ Modo paranoid: confirmación requerida[/]")
                confirmed = Confirm.ask("[#FF6B35]¿Ejecutar?[/]", default=False)
            else:
                confirmed = Confirm.ask("[bold #FFD60A]¿Ejecutar?[/]", default=False)

            if not confirmed:
                self.console.print("[#8B949E]Comando omitido.[/]")
                continue

            self.console.print()
            self.console.print("[bold #00FF88]▶ Ejecutando...[/]")

            output, error, returncode = await self._run_shell_command(cmd)

            self._display_command_output(cmd, output, error, returncode)

            findings_data = self._parse_command_results(
                cmd, output, error, returncode
            )
            if findings_data:
                self._display_findings_summary(findings_data)

            self.console.print()
            action_type, user_input = self._ask_next_action()

            if action_type == "interactive":
                if user_input.lower() in [
                    "continuar",
                    "continue",
                    "siguiente",
                    "next",
                    "",
                ]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere CONTINUAR con más comandos. "
                        "Propón el siguiente paso lógico en esta fase de pentesting. "
                        "Usa <cmd> para solicitar ejecución."
                    )
                elif user_input.lower() in [
                    "analiza",
                    "analizar",
                    "analyze",
                    "análisis",
                    "explica",
                ]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere un ANÁLISIS DETALLADO. "
                        "Explica qué significa cada resultado, qué vulnerabilidades se encontraron, "
                        "y qué impacto tienen. Sugiere qué hacer después."
                    )
                elif user_input.lower() in [
                    "cambia",
                    "cambiar",
                    "cambio",
                    "otro",
                    "change",
                ]:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        "El usuario quiere CAMBIAR DE ENFOQUE o hacer algo diferente. "
                        "Pregúntale qué quiere hacer o sugiere alternativas."
                    )
                elif user_input.lower() in [
                    "estado",
                    "status",
                    "sesión",
                    "session",
                ]:
                    continue_prompt = None
                    self.interactive_mode = False
                    self._show_session_info()
                    return
                elif user_input.lower() in [
                    "parar",
                    "stop",
                    "fin",
                    "salir",
                ]:
                    continue_prompt = None
                    self.interactive_mode = False
                    self.console.print(
                        "[yellow]Operación detenida por el usuario[/]"
                    )
                    return
                else:
                    continue_prompt = (
                        f"Comando ejecutado: {cmd}\n"
                        f"Resultados:\n{output[:2000]}\n\n"
                        f"El usuario ha dicho: '{user_input}'\n"
                        "Responde a lo que el usuario pide y propón siguiente paso si es apropiado."
                    )
            else:
                continue_prompt = None

            if continue_prompt and output:
                self.console.print()
                from t100ai.llm.connection_manager import OllamaConnectionManager

                cm = OllamaConnectionManager.get_instance()

                analysis = await self.llm_handler.stream_response(
                    lambda: cm.generate_stream(continue_prompt, system_prompt),
                    "Analizando",
                )

                if analysis and analysis.strip():
                    self.console.print()
                    self.console.rule("[bold #00FF88]◆ Análisis[/]")
                    self.console.print(Markdown(analysis.strip()))
                    await self._execute_llm_commands(
                        analysis, cm, system_prompt
                    )

    def _display_command_output(
        self, cmd: str, output: str, error: str, returncode: int
    ) -> None:
        """Delega al ToolService para formateo de output."""
        if hasattr(self, "tool_service"):
            self.tool_service.display_command_output(
                cmd, output, error, returncode
            )
        else:
            if output:
                self.console.print(f"[dim]{output[:3000]}[/]")
            if error:
                self.console.print(f"[red]{error[:1000]}[/]")

    def _parse_command_results(
        self, cmd: str, output: str, error: str, returncode: int
    ) -> list[dict]:
        """Delega al ToolService para parseo de resultados."""
        if hasattr(self, "tool_service"):
            return self.tool_service.parse_command_results(
                cmd, output, error, returncode
            )
        return []

    def _display_findings_summary(self, findings: list[dict]) -> None:
        """Muestra resumen de hallazgos y permite añadirlos a la sesión."""
        if not findings:
            return
        if hasattr(self, "tool_service"):
            self.tool_service.display_findings_summary(findings)
        if Confirm.ask(
            "[bold #00D4FF]Anadir estos hallazgos a la sesion?[/]",
            default=False,
        ):
            for f in findings:
                self.session.add_finding(
                    Finding(
                        title=f["title"],
                        description=f["detail"],
                        severity=f["severity"],
                        tool="auto-detect",
                    )
                )
            self.console.print(f"[#00FF88]{len(findings)} hallazgos anadidos[/]")

    def _ask_next_action(self) -> tuple[str, str]:
        """Modo interactivo: muestra sugerencias y retorna acción

        Returns:
            tuple: (action, user_input)
            - action: 'interactive'
            - user_input: texto libre del usuario
        """
        suggestions = (
            "[dim]Escribe número o texto libremente:[/]\n\n"
            "[1] [#FF6B35]continuar[/] → siguiente paso lógico\n"
            "[2] [#00D4FF]analiza esto[/] → análisis detallado\n"
            "[3] [#FFD60A]cambia enfoque[/] → otro enfoque\n"
            "[4] [#8B949E]estado[/] → ver sesión actual\n"
            "[5] [#FF3366]parar[/] → finalizar aquí"
        )

        self.console.print()
        self.console.print(
            Panel(
                suggestions,
                title="◈ Modo Interactivo",
                border_style="#FF6B35",
                width=65,
            )
        )

        self.interactive_mode = True

        choice = Prompt.ask("\n[#FFD60A]¿Qué deseas hacer?[/]", default="1")

        choice_map = {
            "1": "continuar",
            "2": "analiza esto",
            "3": "cambia enfoque",
            "4": "estado",
            "5": "parar",
        }

        return ("interactive", choice_map.get(choice.strip(), choice.strip()))

    def _handle_read_command(self, filepath: str) -> None:
        """Lee un archivo y lo muestra"""
        if not filepath:
            self.console.print("[yellow]Uso: /read <ruta_archivo>[/]")
            return

        path = Path(filepath)
        if not path.exists():
            self.console.print(f"[red]Archivo no encontrado: {filepath}[/]")
            return

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lang = "python" if filepath.endswith(".py") else "text"
            syntax = Syntax(
                content, lang, theme="monokai", line_numbers=True
            )
            self.console.print(syntax)
        except Exception as e:
            self.console.print(f"[red]Error al leer archivo: {e}[/]")

    async def _handle_agent_command(self, action: str, arg: str) -> None:
        """Maneja comandos de agentes"""
        if action == "list":
            agents = (
                self._agent_orchestrator.list_agents()
                if self._agent_orchestrator
                else []
            )
            table = Table(title="Agentes Disponibles")
            table.add_column("Nombre", style="#00D4FF")
            table.add_column("Rol", style="#FFD60A")
            table.add_column("Estado", style="#00FF88")
            for agent in agents:
                table.add_row(
                    agent.get("name", ""),
                    agent.get("role", ""),
                    agent.get("status", ""),
                )
            self.console.print(table)
        elif action == "spawn" and arg:
            self.console.print(
                "[#444444]◈ Worker:[/] [#666666]specter-mini 1[/]"
            )
            self.console.print(
                f"[#444444]  Desplegando tarea:[/] [#00D4FF]{arg}[/]"
            )

            task_id = await self._agent_orchestrator.deploy_task(arg, {})

            self.console.print(
                f"[#444444]  Tarea ID:[/] [#00FF88]{task_id}[/]"
            )
            self.console.print(f"[#00FF88][OK][/] Tarea desplegada: {arg}")

            await self._show_agent_progress(task_id)
        elif action == "status":
            status = (
                self._agent_orchestrator.get_status()
                if self._agent_orchestrator
                else {}
            )
            self.console.print("[bold]◈ Estado del Orquestador[/bold]")
            self.console.print(
                f"  Agentes: {status.get('active_agents', 0)}"
            )
            self.console.print(f"  Tareas: {status.get('pending_tasks', 0)}")
        else:
            self.console.print(
                "[yellow]Uso: /agent list | spawn <tarea> | status[/]"
            )

    async def _show_agent_progress(self, task_id: str) -> None:
        """Muestra el progreso del agente en tiempo real"""
        status = (
            self._agent_orchestrator.get_task_status(task_id)
            if self._agent_orchestrator
            else {}
        )

        with Progress(
            SpinnerColumn(spinner_name="dots2", style="#00FF88"),
            TextColumn(
                f"[#666666]Ejecutando:[/] [#00D4FF]{status.get('description', task_id)}[/]"
            ),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("working", total=None)

            while status.get("status") not in ["done", "error", "cancelled"]:
                await asyncio.sleep(0.5)
                status = (
                    self._agent_orchestrator.get_task_status(task_id)
                    if self._agent_orchestrator
                    else {}
                )
                progress.update(
                    task,
                    description=f"[#666666]{status.get('status', 'working')}[/]",
                )

        if status.get("result"):
            self.console.print("[#00FF88]✓ Resultado:[/]")
            self.console.print(f"  [#8B949E]{status.get('result')}[/]")

    def _save_generated_code(
        self, code: str, lang: str, custom_name: str = ""
    ) -> str:
        """Guarda código generado en archivos ordenados

        Estructura de directorios:
        generated/
        ├── scripts/
        ├── exploits/
        ├── payloads/
        ├── analysis/
        └── reports/
        """
        category = self._categorize_code(code, lang)
        base_dir = Path(f"generated/{category}")
        base_dir.mkdir(parents=True, exist_ok=True)

        ext = self._get_extension(lang)
        if custom_name:
            filename = (
                custom_name if custom_name.endswith(ext) else custom_name + ext
            )
        else:
            filename = f"script_{uuid.uuid4().hex[:8]}{ext}"

        filepath = base_dir / filename
        filepath.write_text(code, encoding="utf-8")

        return str(filepath)

    def _categorize_code(self, code: str, lang: str) -> str:
        """Categoriza el código según su contenido"""
        code_lower = code.lower()

        if any(
            x in code_lower
            for x in ["exploit", "payload", "shellcode", "msfvenom", "metasploit"]
        ):
            return "exploits"
        elif any(x in code_lower for x in ["nmap", "scan", "recon", "enum"]):
            return "scans"
        elif any(
            x in code_lower
            for x in ["hash", "crack", "password", "credential"]
        ):
            return "passwords"
        elif any(
            x in code_lower
            for x in ["analyze", "forensic", "volatility", "memory"]
        ):
            return "analysis"
        elif any(
            x in code_lower for x in ["report", "document", "findings"]
        ):
            return "reports"
        elif lang in ["python", "bash", "powershell"] and len(code.split("\n")) > 10:
            return "scripts"
        else:
            return "misc"

    def _get_extension(self, lang: str) -> str:
        """Obtiene extensión según lenguaje"""
        extensions = {
            "python": ".py",
            "py": ".py",
            "javascript": ".js",
            "js": ".js",
            "bash": ".sh",
            "sh": ".sh",
            "powershell": ".ps1",
            "ps1": ".ps1",
            "c": ".c",
            "cpp": ".cpp",
            "java": ".java",
            "ruby": ".rb",
            "go": ".go",
            "rust": ".rs",
            "text": ".txt",
        }
        return extensions.get(lang.lower(), ".txt")

    def _handle_save_code(
        self, code: str, lang: str, name: str = ""
    ) -> str:
        """Maneja guardar código y retorna la ruta"""
        try:
            filepath = self._save_generated_code(code, lang, name)
            self.console.print(
                f"[#00FF88]✓[/] Guardado en: [dim]{filepath}[/]"
            )
            return filepath
        except Exception as e:
            self.console.print(f"[#FF3366]Error[/] al guardar: {e}")
            return ""

    def _handle_save_command(self, filename: str = "") -> None:
        """Maneja el comando /save"""
        if not self._last_generated_code:
            self.console.print("[yellow]No hay código para guardar.[/]")
            self.console.print("[dim]Genera código primero y luego usa /save[/]")
            return

        code = self._last_generated_code["code"]
        lang = self._last_generated_code["lang"]

        self._handle_save_code(code, lang, filename)

    def _show_history(self, query: str = "") -> None:
        """Muestra el historial de comandos"""
        from t100ai.utils.history import CommandHistory

        history = CommandHistory()

        if query:
            commands = history.search(query)
            if not commands:
                self.console.print(
                    f"[dim]No hay resultados para '{query}'[/]"
                )
                return

            table = Table(
                title=f"Resultados de búsqueda: '{query}'",
                border_style="#00D4FF",
            )
            table.add_column("#", style="#8B949E", width=4)
            table.add_column("Comando", style="#00FF88")

            for i, cmd in enumerate(commands, 1):
                table.add_row(str(i), cmd)
        else:
            commands = history.get_recent(20)
            if not commands:
                self.console.print("[dim]No hay historial[/]")
                return

            table = Table(
                title="Historial de Comandos (últimos 20)",
                border_style="#00D4FF",
            )
            table.add_column("#", style="#8B949E", width=4)
            table.add_column("Comando", style="#00FF88")
            table.add_column("Timestamp", style="#8B949E")

            history_data = history._history[-20:]
            for i, (entry, cmd) in enumerate(zip(history_data, commands), 1):
                ts = (
                    entry.get("timestamp", "")[:19].replace("T", " ")
                    if isinstance(entry, dict)
                    else ""
                )
                table.add_row(str(i), cmd, ts)

        self.console.print(table)

    def _show_session_info(self) -> None:
        """Muestra información de la sesión"""
        counts = self.session.findings_count
        self.console.print(
            Panel.fit(
                f"""[b]Información de Sesión[/b]

ID: [#00D4FF]{self.session.id}[/]
Nombre: [#00FF88]{self.session.name}[/]
Duración: [#00FF88]{self.session.duration}[/]
Rol: [#FFD60A]{self.session.role.value if self.session.role else "Ninguno"}[/]

[b]Hallazgos[/b]
[#FF3366]CRIT: {counts['CRIT']}[/]  [#FF6B35]HIGH: {counts['HIGH']}[/]
[#FFD60A]MED: {counts['MED']}[/]  [#00FF88]LOW: {counts['LOW']}[/]  [#8B949E]INFO: {counts['INFO']}[/]

[b]Scope[/b]
Objetivos: [#00D4FF]{len(self.session.scope)}[/]""",
                border_style="#00FF88",
            )
        )
