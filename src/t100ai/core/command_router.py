"""Command Router - Slash command parsing and dispatch

Every command advertised in /help is wired here to a real handler.
If a command is not in this table, it does not exist in the terminal.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from t100ai.core.engine import T100AIEngine


class CommandRouter:
    """
    Routes slash commands (/help, /scope, /tools, etc.) to engine handlers.

    Extracted from T100AIEngine._handle_slash_command to reduce coupling.
    """

    def __init__(self, engine: "T100AIEngine"):
        self._engine = engine

    async def route(self, command: str) -> None:
        """Parse and dispatch a slash command.

        Args:
            command: Full slash command string (e.g. "/scope set 192.168.1.1")
        """
        parts = command[1:].split(maxsplit=2)
        cmd = parts[0].lower() if parts else ""
        action = parts[1].lower() if len(parts) > 1 else ""
        arg = parts[2] if len(parts) > 2 else ""

        handlers = {
            "help": lambda: self._engine._show_help(),
            "save": lambda: self._engine._handle_save_command(arg),
            "clear": lambda: self._engine.console.clear(),
            "exit": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o escribe 'exit' sin barra para salir[/]"),
            "quit": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o escribe 'quit' sin barra para salir[/]"),
            "salir": lambda: self._engine.console.print("[yellow]Usa Ctrl+C o escribe 'salir' sin barra para salir[/]"),
        }

        if cmd in handlers:
            handlers[cmd]()
            return

        # Commands with sub-actions
        if cmd == "model":
            await self._route_model(action, arg)
        elif cmd == "scope":
            self._route_scope(action, arg)
        elif cmd == "role":
            await self._route_role(action, arg)
        elif cmd == "mode":
            self._engine._set_mode(action or arg)
        elif cmd in ("skills", "skill"):
            await self._route_skills(action, arg)
        elif cmd in ("tools", "tool"):
            self._engine._show_tools()
        elif cmd in ("findings", "finding"):
            self._route_findings(action, arg)
        elif cmd == "report":
            await self._route_report(action, arg)
        elif cmd == "session":
            self._engine._show_session_info()
        elif cmd == "log":
            self._route_log(action)
        elif cmd == "history":
            self._engine._show_history(arg)
        elif cmd == "context":
            self._route_context(action)
        elif cmd == "wordlist" or cmd == "dict":
            self._engine._show_wordlists(action, arg)
        elif cmd == "agent":
            await self._engine._handle_agent_command(action, arg)
        elif cmd == "read":
            self._engine._handle_read_command(arg)
        elif cmd == "deploy":
            await self._route_deploy(action, arg)
        elif cmd == "workflow":
            await self._route_workflow(action, arg)
        elif cmd == "plugin":
            await self._route_plugin(action, arg)
        elif cmd == "perf":
            self._engine._show_performance_stats()
        else:
            self._engine.console.print(f"[yellow]Comando desconocido: /{cmd}[/]")
            self._engine.console.print("[dim]Usa /help para ver comandos disponibles[/]")

    async def _route_model(self, action: str, arg: str) -> None:
        """Route /model sub-commands."""
        if action == "list":
            await self._engine._list_models()
        elif action == "switch" or (action and not action.startswith("-")):
            await self._engine._switch_model(action if action else arg)
        else:
            self._engine._show_model_info()

    def _route_scope(self, action: str, arg: str) -> None:
        """Route /scope sub-commands.

        Forma corta compatible: ``/scope <target>`` equivale a ``/scope set <target>``.
        """
        if action == "set" and arg:
            self._engine._handle_scope_command(arg)
        elif action in ("show", ""):
            self._engine._show_scope()
        elif action == "clear":
            self._engine.session.scope.clear()
            self._engine.console.print("[#00FF88][OK][/] Scope limpiado")
        elif action:
            self._engine._handle_scope_command(" ".join(filter(None, (action, arg))))
        else:
            self._engine.console.print("[yellow]Uso: /scope set <ip|cidr|domain> | show | clear[/]")

    async def _route_role(self, action: str, arg: str) -> None:
        """Route /role sub-commands."""
        if action == "list":
            self._engine._list_roles()
        elif action == "set" and arg:
            await self._engine._set_role(arg)
        elif action and action not in ("set", "show", "list"):
            await self._engine._set_role(action)
        else:
            self._engine._show_role()

    async def _route_skills(self, action: str, arg: str) -> None:
        """Route /skill sub-commands.

        Forma corta compatible: ``/skill recon`` equivale a ``/skill use recon``.
        """
        if action == "use" and arg:
            await self._use_skill(arg)
        elif action == "info" and arg:
            await self._skill_info(arg)
        elif action in ("list", ""):
            self._engine._show_skills()
        elif action and not arg:
            await self._use_skill(action)
        else:
            self._engine.console.print("[yellow]Uso: /skill list | use <nombre> | info <nombre>[/]")

    async def _use_skill(self, name: str) -> None:
        """Activa un skill sobre la sesión actual."""
        sm = self._engine.skill_manager
        available = set(sm.get_available_skills()) if sm else set()
        if available and name not in available:
            self._engine.console.print(
                f"[red]Skill no disponible: {name}[/] "
                f"[dim]Disponibles: {', '.join(sorted(available))}[/]"
            )
            return
        self._engine.session.current_skill = name
        self._engine.console.print(f"[#00FF88][OK][/] Skill activo: [bold]{name}[/]")

    async def _skill_info(self, name: str) -> None:
        """Muestra información detallada de un skill."""
        sm = self._engine.skill_manager
        skill = sm.get_skill(name) if sm else None
        if skill is None:
            self._engine.console.print(
                f"[yellow]Skill '{name}' no está cargado. "
                f"Usa /skill list para ver los cargados.[/]"
            )
            return
        self._engine.console.print(f"[bold #00D4FF]◈ {name}[/]")
        for attr in ("name", "description", "version", "author"):
            val = getattr(skill, attr, None)
            if val:
                self._engine.console.print(f"  [#8B949E]{attr}:[/] {val}")

    def _route_findings(self, action: str, arg: str) -> None:
        """Route /findings sub-commands."""
        if action == "add" and arg:
            self._engine._add_finding(arg)
        elif action == "score" and arg:
            self._engine._score_finding(arg)
        elif action in ("show", ""):
            self._engine._show_findings()
        else:
            self._engine.console.print(
                "[yellow]Uso: /findings show | add [sev] <título> | score <id> <cvss>[/]"
            )

    async def _route_report(self, action: str, arg: str) -> None:
        """Route /report sub-commands."""
        if action in ("session", "status"):
            self._engine._show_session_report()
        elif action == "preview":
            await self._engine._generate_report(preview=True)
        elif action == "export":
            await self._engine._export_report(arg or "md")
        elif action in ("generate", ""):
            await self._engine._generate_report()
        else:
            self._engine.console.print(
                "[yellow]Uso: /report generate | preview | session | export [formato][/]"
            )

    def _route_log(self, action: str) -> None:
        """Route /log sub-commands."""
        if action == "export":
            self._engine._export_log()
        else:
            self._engine._show_log()

    def _route_context(self, action: str) -> None:
        """Route /context sub-commands."""
        if action == "clear":
            history = self._engine.session.conversation_history
            n = len(history)
            history.clear()
            self._engine.console.print(
                f"[#00FF88][OK][/] Contexto limpiado ({n} mensajes). Los hallazgos se mantienen."
            )
        else:
            self._engine._show_context()

    async def _route_deploy(self, action: str, arg: str) -> None:
        """Route /deploy sub-commands."""
        if action == "task" and arg:
            await self._engine._handle_deploy_task(arg)
        elif action == "status":
            self._engine._show_deploy_status()
        elif action == "list":
            self._engine._show_deploy_list()
        else:
            self._engine.console.print("[yellow]Uso: /deploy task <description> | status | list[/]")

    async def _route_workflow(self, action: str, arg: str) -> None:
        """Route /workflow sub-commands."""
        if action == "run" and arg:
            await self._engine._handle_workflow_run(arg)
        elif action == "list":
            self._engine._show_workflow_list()
        elif action == "status":
            self._engine._show_workflow_status()
        else:
            self._engine.console.print("[yellow]Uso: /workflow run <name> | list | status[/]")

    async def _route_plugin(self, action: str, arg: str) -> None:
        """Route /plugin sub-commands."""
        if action == "list":
            self._engine._show_plugin_list()
        elif action == "install" and arg:
            await self._engine._handle_plugin_install(arg)
        elif action == "info" and arg:
            await self._engine._show_plugin_info(arg)
        elif action == "search" and arg:
            await self._engine._handle_plugin_search(arg)
        else:
            self._engine.console.print("[yellow]Uso: /plugin list | install <name> | info <name> | search <query>[/]")
