"""MITRE ATT&CK Navigator Exporter for T-100AI."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .mitre import MitreFinding, MitreMapper

SEVERITY_COLORS: dict[str, str] = {
    "CRIT": "#ff0000",
    "HIGH": "#ff8c00",
    "MED": "#ffff00",
    "LOW": "#00ff00",
    "INFO": "#0000ff",
}

SEVERITY_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class MitreNavigatorExporter:
    """Exports T-100AI findings as ATT&CK Navigator JSON layers."""

    def __init__(self, mapper: Optional[MitreMapper] = None):
        self.mapper = mapper or MitreMapper()

    @staticmethod
    def _severity_color(severity: str) -> str:
        return SEVERITY_COLORS.get(severity.upper(), "#808080")

    @staticmethod
    def _severity_score(severity: str) -> int:
        return {"CRIT": 95, "HIGH": 75, "MED": 50, "LOW": 25, "INFO": 10}.get(
            severity.upper(), 50
        )

    @staticmethod
    def _cvss_score(cvss: Optional[float]) -> int:
        if cvss is None:
            return 50
        return max(0, min(100, int(cvss * 10)))

    def _finding_to_technique_entry(self, finding: MitreFinding) -> dict[str, Any]:
        tech = finding.technique
        cvss = finding.__dict__.get("cvss")
        score = self._cvss_score(cvss) if cvss is not None else self._severity_score(finding.severity)
        color = self._severity_color(finding.severity)

        comment_parts = []
        if finding.evidence:
            comment_parts.append(finding.evidence)
        if finding.target:
            comment_parts.append(f"Target: {finding.target}")
        if finding.tool_used:
            comment_parts.append(f"Tool: {finding.tool_used}")
        comment_parts.append(f"Confidence: {finding.confidence}")

        return {
            "techniqueID": tech.technique_id,
            "tactic": tech.tactic.value,
            "score": score,
            "color": color,
            "comment": " | ".join(comment_parts),
            "enabled": True,
            "metadata": [
                {"name": "severity", "value": finding.severity.upper()},
                {"name": "technique_name", "value": tech.technique_name},
                {"name": "confidence", "value": finding.confidence},
            ],
        }

    def export_layer(
        self, findings: list, session_name: str = ""
    ) -> dict[str, Any]:
        mitre_findings: list[MitreFinding] = []
        for f in findings:
            if isinstance(f, MitreFinding):
                mitre_findings.append(f)
            elif isinstance(f, dict):
                mitre_findings.extend(self.mapper.map_finding(f))

        seen: dict[str, dict[str, Any]] = {}
        for mf in mitre_findings:
            tid = mf.technique.technique_id
            if tid in seen:
                existing = seen[tid]
                if SEVERITY_ORDER.get(mf.severity.upper(), 99) < SEVERITY_ORDER.get(
                    existing["metadata"][0]["value"], 99
                ):
                    entry = self._finding_to_technique_entry(mf)
                    existing["comment"] += f"\n---\n{entry['comment']}"
                    existing["metadata"].append(
                        {"name": "severity", "value": mf.severity.upper()}
                    )
            else:
                seen[tid] = self._finding_to_technique_entry(mf)

        techniques = list(seen.values())

        name = f"T-100AI - {session_name}" if session_name else "T-100AI Findings"
        description = (
            f"T-100AI session: {session_name}" if session_name else "T-100AI session findings"
        )

        return {
            "name": name,
            "versions": {"attack": "15", "navigator": "4.9", "layer": "4.4"},
            "domain": "enterprise-attack",
            "description": description,
            "techniques": techniques,
            "gradient": {
                "colors": ["#00ff00", "#ffff00", "#ff8c00", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
                "expandedSubtechniques": "annotated",
            },
            "hideDisabled": False,
        }

    def save_layer(
        self, findings: list, output_path: str, session_name: str = ""
    ) -> str:
        layer = self.export_layer(findings, session_name)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(layer, fh, indent=2)
        return str(path)

    def generate_coverage_matrix(self, findings: list) -> dict[str, Any]:
        mitre_findings: list[MitreFinding] = []
        for f in findings:
            if isinstance(f, MitreFinding):
                mitre_findings.append(f)
            elif isinstance(f, dict):
                mitre_findings.extend(self.mapper.map_finding(f))

        matrix: dict[str, list[dict[str, Any]]] = {}
        for mf in mitre_findings:
            tactic = mf.technique.tactic.value
            if tactic not in matrix:
                matrix[tactic] = []
            entry = {
                "technique_id": mf.technique.technique_id,
                "technique_name": mf.technique.technique_name,
                "severity": mf.severity.upper(),
                "evidence": mf.evidence,
            }
            if not any(
                e["technique_id"] == entry["technique_id"] for e in matrix[tactic]
            ):
                matrix[tactic].append(entry)

        ordered: dict[str, list[dict[str, Any]]] = {}
        for tactic in TACTIC_ORDER:
            if tactic in matrix:
                ordered[tactic] = matrix[tactic]
        for tactic, techs in matrix.items():
            if tactic not in ordered:
                ordered[tactic] = techs

        return ordered

    def _technique_summary_table(self, findings: list) -> str:
        mitre_findings: list[MitreFinding] = []
        for f in findings:
            if isinstance(f, MitreFinding):
                mitre_findings.append(f)
            elif isinstance(f, dict):
                mitre_findings.extend(self.mapper.map_finding(f))

        tech_map: dict[str, list[MitreFinding]] = {}
        for mf in mitre_findings:
            tid = mf.technique.technique_id
            tech_map.setdefault(tid, []).append(mf)

        lines = [
            "## Technique Summary",
            "",
            "| Technique ID | Technique Name | Tactic | Severity | Count |",
            "|---|---|---|---|---|",
        ]
        for tid, mfs in sorted(
            tech_map.items(),
            key=lambda x: min(
                SEVERITY_ORDER.get(m.severity.upper(), 99) for m in x[1]
            ),
        ):
            tech = mfs[0].technique
            worst_sev = min(
                mfs, key=lambda m: SEVERITY_ORDER.get(m.severity.upper(), 99)
            ).severity.upper()
            lines.append(
                f"| {tid} | {tech.technique_name} | {tech.tactic.value.replace('-', ' ').title()} | {worst_sev} | {len(mfs)} |"
            )
        lines.append("")
        return "\n".join(lines)

    def _coverage_statistics(self, findings: list) -> str:
        mitre_findings: list[MitreFinding] = []
        for f in findings:
            if isinstance(f, MitreFinding):
                mitre_findings.append(f)
            elif isinstance(f, dict):
                mitre_findings.extend(self.mapper.map_finding(f))

        total_techniques = len(self.mapper._db)
        covered = {mf.technique.technique_id for mf in mitre_findings}
        covered_count = len(covered)
        coverage_pct = (covered_count / total_techniques * 100) if total_techniques else 0

        tactics_hit: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for mf in mitre_findings:
            tactic = mf.technique.tactic.value
            tactics_hit[tactic] = tactics_hit.get(tactic, 0) + 1
            sev = mf.severity.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = [
            "## Coverage Statistics",
            "",
            f"- **Total techniques in DB**: {total_techniques}",
            f"- **Techniques covered**: {covered_count}",
            f"- **Coverage**: {coverage_pct:.1f}%",
            f"- **Total findings**: {len(mitre_findings)}",
            "",
            "### Findings by Severity",
            "",
        ]
        for sev in ("CRIT", "HIGH", "MED", "LOW", "INFO"):
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- **{sev}**: {count}")
        lines.extend(["", "### Findings by Tactic", ""])
        for tactic in TACTIC_ORDER:
            if tactic in tactics_hit:
                lines.append(f"- **{tactic.replace('-', ' ').title()}**: {tactics_hit[tactic]}")
        lines.append("")
        return "\n".join(lines)

    def _recommendations(self, findings: list) -> str:
        mitre_findings: list[MitreFinding] = []
        for f in findings:
            if isinstance(f, MitreFinding):
                mitre_findings.append(f)
            elif isinstance(f, dict):
                mitre_findings.extend(self.mapper.map_finding(f))

        tech_map: dict[str, MitreFinding] = {}
        for mf in mitre_findings:
            tid = mf.technique.technique_id
            if tid not in tech_map or SEVERITY_ORDER.get(
                mf.severity.upper(), 99
            ) < SEVERITY_ORDER.get(tech_map[tid].severity.upper(), 99):
                tech_map[tid] = mf

        lines = ["## Recommendations", ""]
        for tid in sorted(
            tech_map,
            key=lambda t: SEVERITY_ORDER.get(tech_map[t].severity.upper(), 99),
        ):
            mf = tech_map[tid]
            tech = mf.technique
            lines.append(f"### {tid} - {tech.technique_name}")
            lines.append("")
            if tech.mitigation:
                lines.append(f"**Mitigation**: {tech.mitigation}")
            if tech.detection:
                lines.append(f"**Detection**: {tech.detection}")
            lines.append(f"**Severity**: {mf.severity.upper()}")
            lines.append(f"**Confidence**: {mf.confidence}")
            lines.append("")
        return "\n".join(lines)

    def export_full_report(
        self, findings: list, session, output_path: str
    ) -> str:
        session_name = ""
        if isinstance(session, dict):
            session_name = session.get("name", session.get("session_name", ""))
        elif hasattr(session, "name"):
            session_name = session.name
        elif hasattr(session, "session_name"):
            session_name = session.session_name

        layer = self.export_layer(findings, session_name)
        matrix = self.generate_coverage_matrix(findings)

        report_name = f"T-100AI - {session_name}" if session_name else "T-100AI Findings"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"# {report_name} - MITRE ATT&CK Report",
            "",
            f"**Generated**: {timestamp}",
            f"**Session**: {session_name}",
            "",
            "---",
            "",
            "## Navigator Layer",
            "",
            "The following ATT&CK Navigator layer can be imported at",
            "https://mitre-attack.github.io/attack-navigator/",
            "",
            "```json",
            json.dumps(layer, indent=2),
            "```",
            "",
            "---",
            "",
            "## Coverage Matrix",
            "",
        ]

        for tactic, techs in matrix.items():
            lines.append(f"### {tactic.replace('-', ' ').title()}")
            lines.append("")
            for t in techs:
                lines.append(f"- **{t['technique_id']}** {t['technique_name']} ({t['severity']})")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(self._technique_summary_table(findings))
        lines.append(self._coverage_statistics(findings))
        lines.append(self._recommendations(findings))

        report = "\n".join(lines)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
        return str(path)
