from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Set

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table


class PermissionLevel(Enum):
    OBSERVATION = 0  # view/read-only, no action
    ACTIVE = 1       # allow simple confirmations
    INTRUSIVE = 2    # require explicit confirmation with impact description

_MAX_DENIED_HISTORY = 1000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PermissionManager:
    """Robust permission manager with Rich UI, tool trust lists and history.

    Features:
    - confirm_interactive(tool_name, risk_level, description, role=None) -> bool
    - is_trusted_tool(tool_name, role=None) -> bool
    - add_to_whitelist(tool_name, role=None)
    - add_to_blacklist(tool_name, role=None)
    - confirmation_required property
    - warn/deny history for non-allowed attempts
    """

    def __init__(self, current_level: PermissionLevel = PermissionLevel.OBSERVATION,
                 log_path: Optional[str] = None) -> None:
        self.current_level = current_level
        if log_path:
            self.log_path = log_path
        else:
            base = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
            self.log_path = os.path.abspath(os.path.join(base, "permissions.log"))
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        self.denied_history: list[Dict[str, Any]] = []

        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.role_whitelist: Dict[str, Set[str]] = {}
        self.role_blacklist: Dict[str, Set[str]] = {}

        self.console = Console()

    def _log(self, text: str) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _log_event(self, event: Dict[str, Any]) -> None:
        self._log(json.dumps(event, ensure_ascii=False))

    @property
    def confirmation_required(self) -> bool:
        return self.current_level != PermissionLevel.OBSERVATION

    def is_trusted_tool(self, tool_name: str, role: Optional[str] = None) -> bool:
        if tool_name in self.whitelist:
            return True
        if role:
            whitelist = self.role_whitelist.get(role, set())
            if tool_name in whitelist:
                return True
            blacklist = self.role_blacklist.get(role, set())
            if tool_name in blacklist:
                return False
        return False

    def add_to_whitelist(self, tool_name: str, role: Optional[str] = None) -> None:
        if role:
            self.role_whitelist.setdefault(role, set()).add(tool_name)
        else:
            self.whitelist.add(tool_name)

    def add_to_blacklist(self, tool_name: str, role: Optional[str] = None) -> None:
        if role:
            self.role_blacklist.setdefault(role, set()).add(tool_name)
        else:
            self.blacklist.add(tool_name)

    def confirm_interactive(self, tool_name: str, risk_level: int, description: str, role: Optional[str] = None) -> bool:
        if tool_name in self.whitelist:
            self._log_event({"timestamp": _now_iso(),
                             "action": "confirm_interactive",
                             "tool": tool_name,
                             "granted": True,
                             "role": role})
            return True
        if role and tool_name in self.role_whitelist.get(role, set()):
            self._log_event({"timestamp": _now_iso(),
                             "action": "confirm_interactive",
                             "tool": tool_name,
                             "granted": True,
                             "role": role})
            return True
        if role and tool_name in self.role_blacklist.get(role, set()):
            self._append_denied(tool_name, role, "explicit blacklist")
            self._log_event({"timestamp": _now_iso(),
                             "action": "confirm_interactive_denied",
                             "tool": tool_name,
                             "role": role})
            return False
        if tool_name in self.blacklist:
            self._append_denied(tool_name, role, "global blacklist")
            self._log_event({"timestamp": _now_iso(),
                             "action": "confirm_interactive_denied",
                             "tool": tool_name})
            return False

        interactive = hasattr(sys, "stdin") and sys.stdin is not None and sys.stdin.isatty()
        if not interactive:
            self._log_event({"timestamp": _now_iso(),
                             "action": "confirm_interactive_non_interactive",
                             "tool": tool_name,
                             "role": role})
            return False

        panel_title = "Permission Confirmation"
        table = Table.grid(padding=1)
        table.add_row("Tool:", tool_name)
        table.add_row("Role:", str(role) if role else "N/A")
        table.add_row("Risk:", str(risk_level))
        table.add_row("Description:", description)
        panel = Panel(table, title=panel_title, border_style="#00FF88", box=box.ROUNDED)
        self.console.print(panel)

        try:
            granted = bool(Confirm.ask(f"Proceed with '{tool_name}'?" , default=False))
        except Exception:
            granted = False
        self._log_event({"timestamp": _now_iso(),
                         "action": "confirm_interactive",
                         "tool": tool_name,
                         "granted": granted,
                         "role": role})
        if not granted:
            self._append_denied(tool_name, role, description)
        return granted

    def _append_denied(self, tool_name: str, role: Optional[str], reason: str) -> None:
        self.denied_history.append({"timestamp": _now_iso(),
                                    "tool": tool_name, "role": role, "reason": reason})
        if len(self.denied_history) > _MAX_DENIED_HISTORY:
            self.denied_history = self.denied_history[-_MAX_DENIED_HISTORY:]

    def log_permission_event(self, action: str, granted: bool, reason: str) -> None:
        self._log_event({"timestamp": _now_iso(),
                         "action": action,
                         "granted": granted,
                         "reason": reason,
                         "level": self.current_level.name})
