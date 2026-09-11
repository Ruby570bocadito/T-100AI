from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from t100ai.core.models import SessionData
from t100ai.core.session import Session
from t100ai.core.session_manager import SessionManager


def save_session(session: Optional[Session] = None) -> str:
    """Save the current session state instead of creating an empty one."""
    sm = SessionManager()
    if session is not None:
        sess = SessionData(
            session_id=session.id,
            name=session.name,
            created_at=session.created_at,
            findings=[],
            scopes=[],
        )
    else:
        sess = SessionData(
            session_id=uuid.uuid4().hex,
            name="engine_saved_session",
            created_at=datetime.now(timezone.utc),
            findings=[],
            scopes=[],
        )
    sid = sm.save_session(sess)
    return sid


def load_session(session_id: str) -> Optional[SessionData]:
    sm = SessionManager()
    try:
        return sm.load_session(session_id)
    except FileNotFoundError:
        return None


def list_saved_sessions() -> None:
    sm = SessionManager()
    for s in sm.list_sessions():
        print(f"{s.session_id}  {s.name}  created at {s.created_at}")
