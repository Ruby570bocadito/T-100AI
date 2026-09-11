"""Compliance Frameworks - Map findings to compliance standards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ComplianceMapping:
    """Maps a finding to compliance framework controls."""
    finding_id: str
    framework: str
    control_id: str
    control_name: str
    status: str = "non_compliant"


FRAMEWORK_CONTROLS: dict[str, dict[str, list[dict[str, str]]]] = {
    "ISO27001": {
        "A.5": [{"id": "A.5.1", "name": "Information security policies"}],
        "A.6": [{"id": "A.6.1", "name": "Internal organization"}],
        "A.8": [{"id": "A.8.1", "name": "User endpoint devices"}],
        "A.9": [{"id": "A.9.1", "name": "Access control"}, {"id": "A.9.2", "name": "User access management"}],
        "A.10": [{"id": "A.10.1", "name": "Cryptographic controls"}],
        "A.12": [{"id": "A.12.1", "name": "Operational procedures"}, {"id": "A.12.6", "name": "Technical vulnerability management"}],
        "A.14": [{"id": "A.14.1", "name": "Security requirements of information systems"}],
        "A.16": [{"id": "A.16.1", "name": "Incident management"}],
    },
    "NIST_CSF": {
        "ID": [{"id": "ID.AM", "name": "Asset Management"}, {"id": "ID.RA", "name": "Risk Assessment"}],
        "PR": [{"id": "PR.AC", "name": "Access Control"}, {"id": "PR.DS", "name": "Data Security"}, {"id": "PR.IP", "name": "Information Protection"}],
        "DE": [{"id": "DE.CM", "name": "Security Continuous Monitoring"}, {"id": "DE.DP", "name": "Detection Processes"}],
        "RS": [{"id": "RS.RP", "name": "Response Planning"}, {"id": "RS.CO", "name": "Communications"}],
        "RC": [{"id": "RC.RP", "name": "Recovery Planning"}],
    },
    "PCI_DSS": {
        "Req1": [{"id": "1.1", "name": "Firewall configuration standards"}],
        "Req2": [{"id": "2.1", "name": "Default passwords and security parameters"}],
        "Req4": [{"id": "4.1", "name": "Encrypt transmission of cardholder data"}],
        "Req5": [{"id": "5.1", "name": "Anti-virus software"}],
        "Req6": [{"id": "6.1", "name": "Secure systems and applications"}],
        "Req8": [{"id": "8.1", "name": "Identify and authenticate access"}],
        "Req10": [{"id": "10.1", "name": "Audit trails"}],
        "Req11": [{"id": "11.1", "name": "Regular security testing"}],
    },
}


class ComplianceMapper:
    """Maps security findings to compliance framework controls."""

    def __init__(self) -> None:
        self._mappings: list[ComplianceMapping] = []

    def map_finding(self, finding_id: str, category: str, description: str) -> list[ComplianceMapping]:
        """Map a finding to relevant compliance controls."""
        mappings = []
        text = f"{category} {description}".lower()

        if any(kw in text for kw in ["access", "auth", "password", "credential"]):
            mappings.extend([
                ComplianceMapping(finding_id, "ISO27001", "A.9.1", "Access control"),
                ComplianceMapping(finding_id, "NIST_CSF", "PR.AC", "Access Control"),
                ComplianceMapping(finding_id, "PCI_DSS", "Req8", "Identify and authenticate access"),
            ])

        if any(kw in text for kw in ["vuln", "patch", "update", "cve"]):
            mappings.extend([
                ComplianceMapping(finding_id, "ISO27001", "A.12.6", "Technical vulnerability management"),
                ComplianceMapping(finding_id, "NIST_CSF", "ID.RA", "Risk Assessment"),
                ComplianceMapping(finding_id, "PCI_DSS", "Req11", "Regular security testing"),
            ])

        if any(kw in text for kw in ["encrypt", "tls", "ssl", "cipher"]):
            mappings.extend([
                ComplianceMapping(finding_id, "ISO27001", "A.10.1", "Cryptographic controls"),
                ComplianceMapping(finding_id, "NIST_CSF", "PR.DS", "Data Security"),
                ComplianceMapping(finding_id, "PCI_DSS", "Req4", "Encrypt transmission of cardholder data"),
            ])

        if any(kw in text for kw in ["log", "audit", "monitor"]):
            mappings.extend([
                ComplianceMapping(finding_id, "ISO27001", "A.12.1", "Operational procedures"),
                ComplianceMapping(finding_id, "NIST_CSF", "DE.CM", "Security Continuous Monitoring"),
                ComplianceMapping(finding_id, "PCI_DSS", "Req10", "Audit trails"),
            ])

        if any(kw in text for kw in ["firewall", "network", "segment"]):
            mappings.extend([
                ComplianceMapping(finding_id, "ISO27001", "A.8.1", "User endpoint devices"),
                ComplianceMapping(finding_id, "NIST_CSF", "PR.IP", "Information Protection"),
                ComplianceMapping(finding_id, "PCI_DSS", "Req1", "Firewall configuration standards"),
            ])

        if not mappings:
            mappings.append(ComplianceMapping(finding_id, "NIST_CSF", "ID.RA", "Risk Assessment"))

        self._mappings.extend(mappings)
        return mappings

    def get_compliance_report(self) -> dict[str, Any]:
        """Generate a compliance status report."""
        report: dict[str, Any] = {}
        for m in self._mappings:
            if m.framework not in report:
                report[m.framework] = {"controls": {}, "total_findings": 0}
            if m.control_id not in report[m.framework]["controls"]:
                report[m.framework]["controls"][m.control_id] = {
                    "name": m.control_name,
                    "findings": [],
                    "status": m.status,
                }
            report[m.framework]["controls"][m.control_id]["findings"].append(m.finding_id)
            report[m.framework]["total_findings"] += 1

        return report
