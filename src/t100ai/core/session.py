"""T-100AI Session Management"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from t100ai.core.permissions import PermissionLevel

if TYPE_CHECKING:
    from t100ai.core.config import T100AIConfig


MAX_HISTORY = 20


class Role(Enum):
    """Roles del operador T-100AI"""
    PENTESTER = "pentester"
    RED_TEAMER = "red-teamer"
    BLUE_TEAMER = "blue-teamer"
    CTF_PLAYER = "ctf-player"
    FORENSIC_ANALYST = "forensic-analyst"
    DEFAULT = "default"


@dataclass
class Finding:
    """Representa un hallazgo de seguridad"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: str = "INFO"  # CRIT, HIGH, MED, LOW, INFO
    cvss: Optional[float] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"


@dataclass
class ScopeEntry:
    """Entrada en el scope de la operación"""
    target: str
    type: str = "ip"  # ip, domain, cidr, url
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""


@dataclass
class Session:
    """Sesión de trabajo de T-100AI"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = "default"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    role: Optional[Role] = None
    scope: list[ScopeEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    current_skill: Optional[str] = None
    log: list[dict[str, Any]] = field(default_factory=list)
    permission_level: PermissionLevel = field(default_factory=lambda: PermissionLevel.OBSERVATION)

    conversation_history: list[dict[str, str]] = field(default_factory=list)

    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.config: Optional[Any] = None

    def set_config(self, config: "T100AIConfig") -> None:
        """Establece la configuración"""
        self.config = config

    def add_finding(self, finding: Finding) -> None:
        """Añade un hallazgo a la sesión"""
        self.findings.append(finding)
        self._log_action("finding_added", {"finding_id": finding.id})

    def add_to_scope(self, target: str, target_type: str = "ip", notes: str = "") -> None:
        """Añade un objetivo al scope"""
        entry = ScopeEntry(target=target, type=target_type, notes=notes)
        self.scope.append(entry)
        self._log_action("scope_added", {"target": target, "type": target_type})

    def is_in_scope(self, target: str) -> bool:
        """Verifica si un objetivo está en el scope"""
        return any(entry.target == target for entry in self.scope)

    def set_role(self, role: Role) -> None:
        """Establece el rol del operador"""
        self.role = role
        self._log_action("role_changed", {"role": role.value})

    # ── Memoria conversacional ────────────────────────────────────────────────

    def add_message(self, role: str, content: str) -> None:
        self.conversation_history.append({"role": role, "content": content})
        if len(self.conversation_history) > MAX_HISTORY:
            self.conversation_history = self.conversation_history[-MAX_HISTORY:]

    def build_conversation_prompt(self) -> str:
        if not self.conversation_history:
            return ""
        lines = ["\n\n## Historial de conversación reciente"]
        for msg in self.conversation_history[-MAX_HISTORY:]:
            prefix = "Usuario" if msg["role"] == "user" else "T-100AI"
            lines.append(f"  [{prefix}]: {msg['content'][:500]}")
        return "\n".join(lines)

    # ── Scope para el LLM ────────────────────────────────────────────────────

    def get_scope_summary(self) -> str:
        """Devuelve el scope formateado para incluir en el system prompt."""
        if not self.scope:
            return ""
        targets = ", ".join(e.target for e in self.scope)
        return (
            f"\n\n## Scope de la operación\n"
            f"Objetivos autorizados: {targets}\n"
            f"IMPORTANTE: Solo propones acciones contra estos objetivos. "
            f"Rechazas cualquier acción fuera de este scope."
        )

    # ── Persistencia de hallazgos ────────────────────────────────────────────

    def save_findings(self, sessions_dir: str = "sessions") -> Path:
        """Guarda los hallazgos en disco como JSON."""
        path = Path(sessions_dir) / self.id
        path.mkdir(parents=True, exist_ok=True)
        findings_file = path / "findings.json"
        data = [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "cvss": f.cvss,
                "tool": f.tool,
                "target": f.target,
                "timestamp": f.timestamp.isoformat(),
                "evidence": f.evidence,
            }
            for f in self.findings
        ]
        findings_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return findings_file

    def load_findings(self, sessions_dir: str = "sessions") -> int:
        """Carga hallazgos desde disco. Retorna el número cargado."""
        path = Path(sessions_dir) / self.id / "findings.json"
        if not path.exists():
            return 0
        data = json.loads(path.read_text())
        loaded = 0
        existing_ids = {f.id for f in self.findings}
        for item in data:
            if item["id"] not in existing_ids:
                self.findings.append(Finding(
                    id=item["id"],
                    title=item["title"],
                    description=item.get("description", ""),
                    severity=item.get("severity", "INFO"),
                    cvss=item.get("cvss"),
                    tool=item.get("tool"),
                    target=item.get("target"),
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    evidence=item.get("evidence", []),
                ))
                loaded += 1
        return loaded

    def _log_action(self, action: str, data: dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "data": data,
            "session_id": self.id,
        }
        self.log.append(entry)

    @property
    def duration(self) -> str:
        delta = datetime.now(timezone.utc) - self.created_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @property
    def findings_count(self) -> dict[str, int]:
        """Cuenta de hallazgos por severidad"""
        counts = {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def generate_session_report(self) -> str:
        """Genera un reporte de texto de la sesión usando datos reales"""
        lines = [
            "# SP ECTER - Session Report",
            "",
            f"**Session ID:** `{self.id}`",
            f"**Name:** {self.name}",
            f"**Created:** {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {self.duration}",
            f"**Role:** {self.role.value if self.role else 'None'}",
            "",
            "---",
            "",
            "## Scope",
            "",
        ]

        if self.scope:
            for entry in self.scope:
                lines.append(f"- **{entry.type.upper()}**: `{entry.target}`")
        else:
            lines.append("_No scope defined_")

        lines.extend([
            "",
            "---",
            "",
            "## Findings Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| CRIT | {self.findings_count['CRIT']} |",
            f"| HIGH | {self.findings_count['HIGH']} |",
            f"| MED | {self.findings_count['MED']} |",
            f"| LOW | {self.findings_count['LOW']} |",
            f"| INFO | {self.findings_count['INFO']} |",
            "",
            f"**Total Findings:** {len(self.findings)}",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        if self.findings:
            for i, f in enumerate(self.findings, 1):
                lines.extend([
                    f"### {i}. [{f.severity}] {f.title}",
                    "",
                    f"- **ID:** `{f.id}`",
                    f"- **Tool:** {f.tool or 'N/A'}",
                    f"- **Target:** {f.target or 'N/A'}",
                    f"- **CVSS:** {f.cvss if f.cvss else 'N/A'}",
                    f"- **Timestamp:** {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                ])
                if f.description:
                    lines.extend([f"**Description:** {f.description}", ""])
                if f.evidence:
                    lines.append("**Evidence:**")
                    for ev in f.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")
        else:
            lines.append("_No findings in this session_")

        lines.extend([
            "---",
            "",
            "*Report generated by T-100AI AI-Powered Security Terminal*",
        ])

        return "\n".join(lines)

    def export_full_backup(self, sessions_dir: str = "sessions") -> Path:
        """Exporta sesion completa (scope, findings, config, conversation) a JSON."""
        path = Path(sessions_dir) / self.id
        path.mkdir(parents=True, exist_ok=True)
        backup_file = path / "session_backup.json"
        data = {
            "version": "1.0",
            "session": {
                "id": self.id,
                "name": self.name,
                "created_at": self.created_at.isoformat(),
                "role": self.role.value if self.role else None,
                "permission_level": self.permission_level.value if hasattr(self.permission_level, "value") else str(self.permission_level),
            },
            "scope": [
                {"target": e.target, "type": e.type, "notes": e.notes, "added_at": e.added_at.isoformat()}
                for e in self.scope
            ],
            "findings": [
                {
                    "id": f.id, "title": f.title, "description": f.description,
                    "severity": f.severity, "cvss": f.cvss, "tool": f.tool,
                    "target": f.target, "timestamp": f.timestamp.isoformat(),
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "conversation": self.conversation_history[-50:],
            "log": self.log[-100:],
            "config": {
                "llm_enabled": getattr(self, "config", None) is not None and getattr(getattr(self, "config", None), "llm_enabled", False),
                "ollama_model": getattr(getattr(self, "config", None), "ollama_model", "llama3"),
                "ollama_host": getattr(getattr(self, "config", None), "ollama_host", "http://localhost:11434"),
                "permission_mode": getattr(getattr(self, "config", None), "permission_mode", "standard"),
            } if hasattr(self, "config") else {},
        }
        backup_file.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return backup_file

    @classmethod
    def restore_from_backup(cls, backup_path: str) -> "Session":
        """Restaura una sesion desde un archivo de backup JSON."""
        path = Path(backup_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup no encontrado: {backup_path}")
        data = json.loads(path.read_text())
        session_data = data.get("session", {})
        session = cls(
            id=session_data.get("id", str(uuid.uuid4())[:8]),
            name=session_data.get("name", "restored"),
            created_at=datetime.fromisoformat(session_data.get("created_at", datetime.now().isoformat())),
        )
        role_val = session_data.get("role")
        if role_val:
            try:
                session.role = Role(role_val)
            except ValueError:
                pass
        for entry in data.get("scope", []):
            session.scope.append(ScopeEntry(
                target=entry["target"],
                type=entry.get("type", "ip"),
                notes=entry.get("notes", ""),
                added_at=datetime.fromisoformat(entry.get("added_at", datetime.now().isoformat())),
            ))
        for item in data.get("findings", []):
            session.findings.append(Finding(
                id=item["id"], title=item["title"],
                description=item.get("description", ""),
                severity=item.get("severity", "INFO"),
                cvss=item.get("cvss"), tool=item.get("tool"),
                target=item.get("target"),
                timestamp=datetime.fromisoformat(item.get("timestamp", datetime.now().isoformat())),
                evidence=item.get("evidence", []),
            ))
        session.conversation_history = data.get("conversation", [])
        session.log = data.get("log", [])
        return session


def list_backups(sessions_dir: str = "sessions") -> list[dict]:
    """Lista todos los backups de sesiones disponibles."""
    backups = []
    base = Path(sessions_dir)
    if not base.exists():
        return backups
    for session_dir in base.iterdir():
        if session_dir.is_dir():
            backup_file = session_dir / "session_backup.json"
            if backup_file.exists():
                data = json.loads(backup_file.read_text())
                session_data = data.get("session", {})
                findings = data.get("findings", [])
                backups.append({
                    "id": session_data.get("id", session_dir.name),
                    "name": session_data.get("name", "unknown"),
                    "created_at": session_data.get("created_at", "unknown"),
                    "findings_count": len(findings),
                    "scope_count": len(data.get("scope", [])),
                    "backup_path": str(backup_file),
                })
    return sorted(backups, key=lambda x: x.get("created_at", ""), reverse=True)


# (Permissions integration is handled via Session.permission_level in the dataclass)
