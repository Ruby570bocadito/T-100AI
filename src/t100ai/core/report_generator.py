"""T-100AI Report Generator - Extracted report/export logic from T100AIEngine"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from t100ai.core.config import T100AIConfig
from t100ai.core.session import Session


class ReportGenerator:
    """Handles report generation, export, and session log operations.

    Extracted from T100AIEngine to separate concerns.
    """

    def __init__(self, session: Session, config: T100AIConfig, console: Console) -> None:
        self.session = session
        self.config = config
        self.console = console

    async def generate_report(self, preview: bool = False) -> str:
        """Genera un informe Markdown de la sesión actual.

        Args:
            preview: If True, render to console only and return the markdown string.
                     If False, also write to disk.

        Returns:
            The generated Markdown content as a string.
        """
        session = self.session
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        counts = session.findings_count
        scope_targets = ", ".join(e.target for e in session.scope) or "Sin scope definido"
        role = session.role.value if session.role else "Ninguno"

        lines = [
            "# T-100AI — Informe de Sesión",
            "",
            f"**Fecha:** {now}  ",
            f"**Sesión ID:** `{session.id}`  ",
            f"**Nombre:** {session.name}  ",
            f"**Duración:** {session.duration}  ",
            f"**Rol:** {role}  ",
            "",
            "---",
            "",
            "## Scope de la Operación",
            "",
            f"{scope_targets}",
            "",
            "---",
            "",
            "## Resumen Ejecutivo",
            "",
            "| Severidad | Hallazgos |",
            "|---|---|",
            f"| 🚨 CRÍTICA | {counts['CRIT']} |",
            f"| 🔴 ALTA | {counts['HIGH']} |",
            f"| 🟡 MEDIA | {counts['MED']} |",
            f"| 🟢 BAJA | {counts['LOW']} |",
            f"| ℹ️ INFO | {counts['INFO']} |",
            f"| **TOTAL** | **{len(session.findings)}** |",
            "",
            "---",
            "",
            "## Hallazgos Detallados",
            "",
        ]

        if not session.findings:
            lines.append("*No hay hallazgos registrados en esta sesión.*")
        else:
            for i, finding in enumerate(session.findings, 1):
                lines += [
                    f"### {i}. [{finding.severity}] {finding.title}",
                    "",
                    f"- **ID:** `{finding.id}`",
                    f"- **Severidad:** {finding.severity}",
                    f"- **CVSS:** {finding.cvss if finding.cvss is not None else 'N/A'}",
                    f"- **Herramienta:** {finding.tool or 'manual'}",
                    f"- **Objetivo:** {finding.target or scope_targets}",
                    f"- **Timestamp:** {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                ]
                if finding.description:
                    lines += ["**Descripción:**", "", finding.description, ""]
                if finding.evidence:
                    lines += ["**Evidencia:**", ""]
                    for ev in finding.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")

        lines += [
            "---",
            "",
            "## Log de Acciones",
            "",
            "| Timestamp | Acción | Datos |",
            "|---|---|---|",
        ]
        for entry in session.log[-20:]:
            ts = entry['timestamp'][:19].replace('T', ' ')
            action = entry['action']
            data = str(entry.get('data', ''))[:60]
            lines.append(f"| {ts} | {action} | {data} |")

        lines += [
            "",
            "---",
            "",
            "*Generado automáticamente por T-100AI v2.0*",
        ]

        report_md = "\n".join(lines)

        if preview:
            self.console.print(Markdown(report_md))
            return report_md

        report_dir = Path("sessions") / session.id
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"report_{now.replace(':', '-').replace(' ', '_')}.md"
        report_path.write_text(report_md, encoding="utf-8")

        self.console.print()
        self.console.print(Panel.fit(
            f"[bold #00FF88]◎ Informe generado[/]\n\n"
            f"Ruta: [bold #00D4FF]{report_path}[/]\n"
            f"Hallazgos: [bold]{len(session.findings)}[/] — "
            f"[#FF3366]CRIT: {counts['CRIT']}[/]  "
            f"[#FF6B35]HIGH: {counts['HIGH']}[/]  "
            f"[#FFD60A]MED: {counts['MED']}[/]  "
            f"[#00FF88]LOW: {counts['LOW']}[/]",
            border_style="#00FF88"
        ))

        return report_md

    async def export_report(self, fmt: str) -> Optional[str]:
        """Exporta report en el formato pedido.

        Args:
            fmt: Target format. Currently only 'md' is fully implemented.
                 'pdf' and 'docx' are placeholders for future implementation.

        Returns:
            Path to the exported file, or None on failure/unsupported format.
        """
        fmt_lower = fmt.lower().strip()

        if fmt_lower in ("md", "markdown"):
            return await self.generate_report(preview=False)

        if fmt_lower in ("pdf",):
            self.console.print("[yellow]Export PDF: placeholder — aún no implementado.[/]")
            return None

        if fmt_lower in ("docx",):
            self.console.print("[yellow]Export DOCX: placeholder — aún no implementado.[/]")
            return None

        self.console.print(f"[yellow]Formato no soportado: '{fmt}'. Use md, pdf o docx.[/]")
        return None

    def export_log(self) -> None:
        """Exporta el log de sesión como JSON en el directorio de la sesión."""
        log_dir = Path("sessions") / self.session.id
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "session_log.json"
        log_path.write_text(
            json.dumps(self.session.log, indent=2, ensure_ascii=False)
        )
        self.console.print(f"[#00FF88][OK][/] Log exportado: [#00D4FF]{log_path}[/]")

    def show_session_info(self) -> None:
        """Muestra información de la sesión."""
        counts = self.session.findings_count
        self.console.print(Panel.fit(
            f"""[b]Información de Sesión[/b]

ID: [#00D4FF]{self.session.id}[/]
Nombre: [#00FF88]{self.session.name}[/]
Duración: [#00FF88]{self.session.duration}[/]
Rol: [#FFD60A]{self.session.role.value if self.session.role else "Ninguno"}[/]

[b]Hallazgos[/b]
[#FF3366]CRIT: {counts['CRIT']}[/]  [#FF6B35]HIGH: {counts['HIGH']}[/]
[#FFD60A]MED: {counts['MED']}[/]  [#00FF88]LOW: {counts['LOW']}[/]  [#8B949E]INFO: {counts['INFO']}[/]

[b]Scope[/b]
Objetivos: [#00D4FF]{len(self.session.scope)}[/]""",
            border_style="#00FF88"
        ))

    def show_findings(self) -> None:
        """Muestra los hallazgos de la sesión en una tabla."""
        if not self.session.findings:
            self.console.print("[dim]No hay hallazgos en esta sesión.[/]")
            return
        table = Table(title=f"Hallazgos ({len(self.session.findings)})")
        table.add_column("ID", style="#8B949E")
        table.add_column("Severidad", style="#FFD60A")
        table.add_column("Título", style="#00FF88")
        table.add_column("Tool", style="#00D4FF")
        for finding in self.session.findings:
            table.add_row(
                finding.id,
                finding.severity,
                finding.title[:50],
                finding.tool or "N/A",
            )
        self.console.print(table)

    def show_session_report(self) -> None:
        """Muestra un reporte rápido de la sesión usando datos reales."""
        report = self.session.generate_session_report()
        self.console.print(Markdown(report))
