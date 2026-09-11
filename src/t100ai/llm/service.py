"""LLM Service - Streaming, connection management, and prompt building"""

import asyncio
import threading
import time
from typing import Callable

from rich.console import Console
from rich.live import Live
from rich.panel import Panel


class LLMService:
    """
    Handles LLM streaming and response generation.

    Extracted from T100AIEngine to isolate LLM concerns:
    - Streaming with real-time Rich panels
    - Cancellation support
    - Connection management via OllamaConnectionManager
    """

    def __init__(self, console: Console):
        self._console = console
        self._cancel_requested = False

    def cancel(self) -> None:
        """Signal cancellation of the current streaming operation."""
        self._cancel_requested = True

    def reset_cancel(self) -> None:
        """Reset cancellation flag for next operation."""
        self._cancel_requested = False

    async def stream_response(
        self,
        stream_func: Callable,
        label: str = "Generando",
    ) -> str:
        """
        Generate a streaming response with real-time Rich panel updates.

        Args:
            stream_func: Callable that yields text chunks (runs in thread)
            label: Label shown in the streaming panel title

        Returns:
            Complete response string
        """
        self._cancel_requested = False
        result = {"chunks": [], "error": None, "done": False, "first_token": False}
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
                    content = (
                        f"[green]Generando[/] [cyan]{tokens_count} tokens[/] "
                        f"[dim]({elapsed}s)[/]\n\n{response_so_far}"
                    )
                else:
                    content = (
                        f"[green]Generando[/] [cyan]{tokens_count} tokens[/] "
                        f"[dim]({elapsed}s)[/]"
                    )

            return Panel.fit(
                content,
                title=f"[bold]{label}[/]",
                border_style="#00D4FF",
                width=80,
            )

        try:
            with Live(
                make_panel(),
                console=self._console,
                refresh_per_second=10,
                transient=True,
            ) as live:
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

        return "".join(result["chunks"])
