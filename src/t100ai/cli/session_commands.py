from __future__ import annotations

import sys
import uuid
from datetime import datetime
from typing import List

from t100ai.core.models import SessionData
from t100ai.core.session_manager import SessionManager


def _generate_session_id() -> str:
    return uuid.uuid4().hex


def handle_session_command(argv: List[str]) -> None:
    sm = SessionManager()
    if not argv:
        print("Session commands: save <name>, load <id>, list, export <id> <format>")
        return
    sub = argv[0]
    if sub == "save":
        name = argv[1] if len(argv) > 1 else "unnamed_session"
        sess = SessionData(
            session_id=_generate_session_id(),
            name=name,
            created_at=datetime.utcnow(),
            findings=[],
            scopes=[],
        )
        sid = sm.save_session(sess)
        print(f"Saved session {sid} with name '{name}'")
        return
    if sub == "load":
        if len(argv) < 2:
            print("Usage: session load <session_id>")
            return
        sid = argv[1]
        sess = sm.load_session(sid)
        print(f"Loaded session {sess.session_id}: {sess.name} (created {sess.created_at})")
        return
    if sub == "list":
        sessions = sm.list_sessions()
        for s in sessions:
            print(f"{s.session_id} - {s.name} (created {s.created_at})")
        return
    if sub == "export":
        if len(argv) < 3:
            print("Usage: session export <session_id> <format>")
            return
        sid = argv[1]
        fmt = argv[2]
        content = sm.export_session(sid, fmt)
        print(content)
        return
    print("Unknown session command. Use: save|load|list|export")


if __name__ == "__main__":
    handle_session_command(sys.argv[1:])
