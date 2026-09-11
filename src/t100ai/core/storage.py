import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class JSONStorage:
    def save(self, data: Any, path: str) -> None:
        dirpath = os.path.dirname(path)
        os.makedirs(dirpath, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=self._default_json)

    def load(self, path: str) -> Any:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def _default_json(self, obj: Any) -> Any:
        try:
            return obj.isoformat()
        except Exception:
            return str(obj)


class SessionStorage(JSONStorage):
    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = Path(base_dir or os.path.expanduser("~/.specter/sessions"))
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def session_path(self, session_id: str) -> str:
        return str(self.base_dir / f"{session_id}.json")


# ── Persistencia SQLite para Findings ──────────────────────────────────

@dataclass
class PersistentFinding:
    """Finding persistente con SQLite."""
    id: str
    title: str
    severity: str
    description: str = ""
    tool: str = ""
    target: str = ""
    cvss: float = 0.0
    mitre_technique: str = ""
    remediation: str = ""
    created_at: str = ""
    updated_at: str = ""
    session_id: str = ""
    tags: list[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:8]
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if self.tags is None:
            self.tags = []


_FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO',
    description TEXT DEFAULT '',
    tool TEXT DEFAULT '',
    target TEXT DEFAULT '',
    cvss REAL DEFAULT 0.0,
    mitre_technique TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tags TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
"""


class FindingStore:
    """Almacen persistente de findings con SQLite."""

    def __init__(self, db_path: str = "sessions/findings.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_FINDINGS_SCHEMA)
        self._conn.commit()

    def add(self, finding: PersistentFinding) -> str:
        self._conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, title, severity, description, tool, target, cvss,
                mitre_technique, remediation, created_at, updated_at, session_id, tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (finding.id, finding.title, finding.severity,
             finding.description, finding.tool, finding.target, finding.cvss,
             finding.mitre_technique, finding.remediation,
             finding.created_at, finding.updated_at, finding.session_id,
             json.dumps(finding.tags))
        )
        self._conn.commit()
        return finding.id

    def get(self, finding_id: str) -> Optional[PersistentFinding]:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    def get_all(self, session_id: Optional[str] = None) -> list[PersistentFinding]:
        if session_id:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_by_severity(self, severity: str) -> list[PersistentFinding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC",
            (severity,)
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def update_severity(self, finding_id: str, severity: str) -> bool:
        now = datetime.utcnow().isoformat()
        cursor = self._conn.execute(
            "UPDATE findings SET severity = ?, updated_at = ? WHERE id = ?",
            (severity, now, finding_id)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def update_cvss(self, finding_id: str, cvss: float) -> bool:
        now = datetime.utcnow().isoformat()
        cursor = self._conn.execute(
            "UPDATE findings SET cvss = ?, updated_at = ? WHERE id = ?",
            (cvss, now, finding_id)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def delete(self, finding_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def count(self, session_id: Optional[str] = None) -> dict[str, int]:
        if session_id:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id = ? GROUP BY severity",
                (session_id,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ).fetchall()
        counts = {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
        for row in rows:
            counts[row["severity"]] = row["cnt"]
        return counts

    def total(self, session_id: Optional[str] = None) -> int:
        if session_id:
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM findings WHERE session_id = ?",
                (session_id,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM findings").fetchone()
        return row["cnt"]

    def export_json(self, session_id: Optional[str] = None) -> str:
        findings = self.get_all(session_id)
        return json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False)

    def export_markdown(self, session_id: Optional[str] = None) -> str:
        findings = self.get_all(session_id)
        counts = self.count(session_id)
        lines = [
            "# T-100AI - Hallazgos", "",
            f"**Total:** {self.total(session_id)} hallazgos", "",
            "| Severidad | Cantidad |", "|-----------|----------|",
            f"| CRIT | {counts['CRIT']} |", f"| HIGH | {counts['HIGH']} |",
            f"| MED | {counts['MED']} |", f"| LOW | {counts['LOW']} |",
            f"| INFO | {counts['INFO']} |", "", "---", "",
        ]
        for i, f in enumerate(findings, 1):
            lines += [
                f"## {i}. [{f.severity}] {f.title}", "",
                f"- **ID:** `{f.id}`", f"- **Herramienta:** {f.tool}",
                f"- **Target:** {f.target}", f"- **CVSS:** {f.cvss}",
                f"- **MITRE:** {f.mitre_technique}", f"- **Creado:** {f.created_at}", "",
                "### Descripcion", "", f.description or "*Sin descripcion*", "",
            ]
            if f.remediation:
                lines += ["### Remediacion", "", f.remediation, ""]
            lines += ["---", ""]
        return "\n".join(lines)

    def _row_to_finding(self, row: sqlite3.Row) -> PersistentFinding:
        return PersistentFinding(
            id=row["id"], title=row["title"], severity=row["severity"],
            description=row["description"], tool=row["tool"], target=row["target"],
            cvss=row["cvss"], mitre_technique=row["mitre_technique"],
            remediation=row["remediation"], created_at=row["created_at"],
            updated_at=row["updated_at"], session_id=row["session_id"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
        )

    def close(self) -> None:
        self._conn.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
