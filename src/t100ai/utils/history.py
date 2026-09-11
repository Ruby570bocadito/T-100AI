"""Persistent command history manager"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_HISTORY_FILE = "~/.t100ai/history.json"
LEGACY_HISTORY_FILE = "~/.specter/history.json"  # pre-rebrand


class CommandHistory:
    """
    Persistent command history with:
    - File-based storage
    - Search capability
    - Deduplication
    - Session tagging
    - Legacy ~/.specter migration on first load
    """

    def __init__(self, history_file: str = DEFAULT_HISTORY_FILE, max_entries: int = 1000):
        self.history_file = Path(history_file).expanduser()
        self.max_entries = max_entries
        self._history: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.history_file.exists():
            try:
                with open(self.history_file, "r") as f:
                    self._history = json.load(f)
                return
            except Exception:
                self._history = []
        # Migración silenciosa desde la ruta antigua del pre-rebrand
        legacy = Path(LEGACY_HISTORY_FILE).expanduser()
        if self.history_file == Path(DEFAULT_HISTORY_FILE).expanduser() and legacy.exists():
            try:
                with open(legacy, "r") as f:
                    self._history = json.load(f)
            except Exception:
                self._history = []

    def _save(self) -> None:
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.history_file, "w") as f:
            json.dump(self._history[-self.max_entries:], f, indent=2)

    def add(self, command: str, session_id: Optional[str] = None, success: bool = True) -> None:
        if not command.strip():
            return

        if self._history and self._history[-1].get("command") == command:
            return

        self._history.append({
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "session_id": session_id,
            "success": success,
        })

        if len(self._history) > self.max_entries:
            self._history = self._history[-self.max_entries:]

        self._save()

    def search(self, query: str, limit: int = 20) -> list[str]:
        query_lower = query.lower()
        results = [
            entry["command"] for entry in reversed(self._history)
            if query_lower in entry["command"].lower()
        ]
        return results[:limit]

    def get_recent(self, limit: int = 50) -> list[str]:
        return [entry["command"] for entry in self._history[-limit:]]

    def clear(self) -> None:
        self._history = []
        self._save()

    def export(self, filepath: str) -> None:
        with open(filepath, "w") as f:
            json.dump(self._history, f, indent=2)

    @property
    def all_commands(self) -> list[str]:
        return [entry["command"] for entry in self._history]
