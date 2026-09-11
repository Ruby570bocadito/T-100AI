from __future__ import annotations

import json
import os
from typing import List, Optional

from t100ai.core.models import SessionData
from t100ai.core.storage import SessionStorage


class SessionManager:
    """Persistent session manager storing sessions as JSON files on disk."""

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.storage = SessionStorage(base_dir=base_dir)

    def _load_raw(self, session_id: str) -> dict:
        path = self.storage.session_path(session_id)
        if not self.storage.exists(path):
            raise FileNotFoundError(f"Session '{session_id}' not found at {path}")
        return self.storage.load(path)

    def save_session(self, session: SessionData) -> str:
        path = self.storage.session_path(session.session_id)
        self.storage.save(session.dict(), path)
        return session.session_id

    def load_session(self, session_id: str) -> SessionData:
        raw = self._load_raw(session_id)
        # Pydantic will coerce datetime from ISO8601 string if necessary
        from t100ai.core.models import SessionData
        return SessionData.parse_obj(raw)

    def list_sessions(self) -> List[SessionData]:
        sessions: List[SessionData] = []
        for f in sorted(self.storage.base_dir.glob("*.json")):
            if f.is_file():
                try:
                    raw = self.storage.load(str(f))
                    sessions.append(SessionData.parse_obj(raw))
                except Exception:
                    # Ignore unreadable entries
                    continue
        return sessions

    def delete_session(self, session_id: str) -> bool:
        path = self.storage.session_path(session_id)
        if self.storage.exists(path):
            os.remove(path)
            return True
        return False

    def export_session(self, session_id: str, fmt: str = "json") -> str:
        raw = self._load_raw(session_id)
        if fmt.lower() == "json":
            return json.dumps(raw, indent=2, ensure_ascii=False)
        if fmt.lower() in ("yaml", "yml"):
            try:
                import yaml  # type: ignore

                return yaml.safe_dump(raw, sort_keys=False)
            except Exception:
                raise ValueError("YAML export requires PyYAML to be installed")
        raise ValueError(f"Unsupported export format: {fmt}")
