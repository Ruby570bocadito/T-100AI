"""LLM Handler - Streaming, response generation, and model management."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING, Callable, Optional

from rich.console import Console
from rich.markup import escape as markup_escape
from rich.panel import Panel

if TYPE_CHECKING:
    from t100ai.core.config import T100AIConfig
    from t100ai.core.session import Session

logger = __import__("structlog").get_logger()


class LLMHandler:
    """Handles all LLM interactions: streaming, model switching, prompt building."""

    def __init__(self, session: "Session", config: "T100AIConfig", console: Console):
        self.session = session
        self.config = config
        self.console = console
        self._cancel_requested = False
        self._last_generated_code: Optional[dict] = None

    async def stream_response(self, stream_func: Callable, label: str) -> str:
        """Genera respuesta con streaming en tiempo real."""
        from rich.live import Live

        result = {"chunks": [], "error": None, "done": False, "first_token": False}
        self._cancel_requested = False
        start_time = time.time()

        def collect_stream():
            try:
                for chunk in stream_func():
                    if self._cancel_requested:
                        break
                    result["chunks"].append(chunk)
                    if not result["first_token"]:
                        result["first_token"] = True
            except Exception as e:
                result["error"] = e
            finally:
                result["done"] = True

        thread = threading.Thread(target=collect_stream)
        thread.start()

        def make_panel() -> Panel:
            elapsed = int(time.time() - start_time)
            tokens_count = len(result["chunks"])
            response_so_far = "".join(result["chunks"])

            if not result["first_token"]:
                content = f"[yellow]Cargando modelo...[/] [dim]({elapsed}s)[/]"
            else:
                if response_so_far:
                    content = f"[green]Generando[/] [cyan]{tokens_count} tokens[/] [dim]({elapsed}s)[/]\n\n{response_so_far}"
                else:
                    content = f"[green]Generando[/] [cyan]{tokens_count} tokens[/] [dim]({elapsed}s)[/]"

            return Panel.fit(
                content,
                title=f"[bold]{label}[/]",
                border_style="#00D4FF",
                width=80,
            )

        try:
            with Live(make_panel(), console=self.console, refresh_per_second=10, transient=True) as live:
                while not result["done"]:
                    if result["error"]:
                        thread.join(timeout=0.1)
                        raise result["error"]
                    live.update(make_panel())
                    await asyncio.sleep(0.1)
        finally:
            thread.join(timeout=1)

        if result["error"]:
            raise result["error"]

        # Show completion indicator before returning
        elapsed = int(time.time() - start_time)
        tokens_count = len(result["chunks"])
        self.console.print(f"[dim]✓ Completado: {tokens_count} tokens en {elapsed}s[/]")
        self.console.print()

        return "".join(result["chunks"])

    async def generate_response(self, user_input: str, system_prompt: str, label: str = "Pensando") -> Optional[str]:
        """Full LLM query with connection management."""
        from t100ai.llm.connection_manager import OllamaConnectionError, OllamaConnectionManager

        cm = OllamaConnectionManager.get_instance()
        cm.update_config(self.config.ollama_host, self.config.ollama_model)

        try:
            cm.connect()
        except OllamaConnectionError as e:
            self.console.print(f"[yellow]LLM no disponible: {e}[/]")
            return None

        self.console.print()
        self.console.print(f"[#555555]Modelo:[/] [#00D4FF]{markup_escape(self.config.ollama_model)}[/]")

        response = await self.stream_response(
            lambda: cm.generate_stream(user_input, system_prompt),
            label,
        )

        if response and response.strip():
            if response.startswith("[cache]"):
                response = response[7 : response.find("[/cache]")]
                self.console.print("[#555555][Cache hit][/]")
            return response.strip()

        return None

    def cancel(self) -> None:
        self._cancel_requested = True

    @property
    def last_generated_code(self) -> Optional[dict]:
        return self._last_generated_code

    def save_generated_code(self, code: str, lang: str, filename: str = "") -> str:
        """Guarda codigo generado en disco."""
        import uuid
        from pathlib import Path

        category = self._categorize_code(code, lang)
        base_dir = Path("generated") / category
        base_dir.mkdir(parents=True, exist_ok=True)

        ext = self._get_extension(lang)
        if filename:
            fn = filename if filename.endswith(ext) else filename + ext
        else:
            fn = f"script_{uuid.uuid4().hex[:8]}{ext}"

        filepath = base_dir / fn
        filepath.write_text(code, encoding="utf-8")
        return str(filepath)

    def _categorize_code(self, code: str, lang: str) -> str:
        code_lower = code.lower()
        if any(x in code_lower for x in ["exploit", "payload", "shellcode", "msfvenom", "metasploit"]):
            return "exploits"
        if any(x in code_lower for x in ["nmap", "scan", "recon", "enum"]):
            return "scans"
        if any(x in code_lower for x in ["hash", "crack", "password", "credential"]):
            return "passwords"
        if any(x in code_lower for x in ["analyze", "forensic", "volatility", "memory"]):
            return "analysis"
        if any(x in code_lower for x in ["report", "document", "findings"]):
            return "reports"
        if lang in ("python", "bash", "powershell") and len(code.split("\n")) > 10:
            return "scripts"
        return "misc"

    def _get_extension(self, lang: str) -> str:
        return {
            "python": ".py", "py": ".py", "javascript": ".js", "js": ".js",
            "bash": ".sh", "sh": ".sh", "powershell": ".ps1", "ps1": ".ps1",
            "c": ".c", "cpp": ".cpp", "java": ".java", "ruby": ".rb",
            "go": ".go", "rust": ".rs", "text": ".txt",
        }.get(lang.lower(), ".txt")
