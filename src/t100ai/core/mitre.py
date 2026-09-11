"""MITRE ATT&CK Mapping Module for T-100AI."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TacticCategory(Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: TacticCategory
    description: str
    sub_techniques: list[str] = field(default_factory=list)
    detection: str = ""
    mitigation: str = ""


@dataclass
class MitreFinding:
    technique: MitreTechnique
    evidence: str = ""
    severity: str = "INFO"
    target: str = ""
    tool_used: str = ""
    confidence: str = "medium"


TECHNIQUE_DB: dict[str, MitreTechnique] = {
    "T1046": MitreTechnique("T1046", "Network Service Discovery", TacticCategory.DISCOVERY, "Scanning for open ports and services"),
    "T1595": MitreTechnique("T1595", "Active Scanning", TacticCategory.RECONNAISSANCE, "Scanning IP spaces to identify hosts"),
    "T1590": MitreTechnique("T1590", "Gather Victim Network Information", TacticCategory.RECONNAISSANCE, "Collecting network info about victim"),
    "T1596.001": MitreTechnique("T1596.001", "DNS/Passive DNS", TacticCategory.RECONNAISSANCE, "Searching DNS or passive DNS data"),
    "T1596.002": MitreTechnique("T1596.002", "WHOIS", TacticCategory.RECONNAISSANCE, "Searching WHOIS data"),
    "T1596.003": MitreTechnique("T1596.003", "Digital Certificates", TacticCategory.RECONNAISSANCE, "Searching digital certificate data"),
    "T1596.005": MitreTechnique("T1596.005", "Scan Databases", TacticCategory.RECONNAISSANCE, "Scanning databases for info"),
    "T1589.002": MitreTechnique("T1589.002", "Email Addresses", TacticCategory.RECONNAISSANCE, "Gathering email addresses"),
    "T1593.002": MitreTechnique("T1593.002", "Search Engines", TacticCategory.RECONNAISSANCE, "Searching search engines"),
    "T1593.003": MitreTechnique("T1593.003", "Code Repositories", TacticCategory.RECONNAISSANCE, "Searching code repositories"),
    "T1594": MitreTechnique("T1594", "Search Victim-Owned Websites", TacticCategory.RECONNAISSANCE, "Searching victim-owned websites"),
    "T1082": MitreTechnique("T1082", "System Information Discovery", TacticCategory.DISCOVERY, "Collecting system information"),
    "T1083": MitreTechnique("T1083", "File and Directory Discovery", TacticCategory.DISCOVERY, "Enumerating files and directories"),
    "T1087.002": MitreTechnique("T1087.002", "Domain Account Discovery", TacticCategory.DISCOVERY, "Enumerating domain accounts via LDAP"),
    "T1602": MitreTechnique("T1602", "Data from Configuration Repository", TacticCategory.COLLECTION, "Collecting data from SNMP/WMI"),
    "T1615": MitreTechnique("T1615", "Group Policy Discovery", TacticCategory.DISCOVERY, "Enumerating group policy settings"),
    "T1654": MitreTechnique("T1654", "Log Enumeration", TacticCategory.DISCOVERY, "Enumerating logs on systems"),
    "T1190": MitreTechnique("T1190", "Exploit Public-Facing Application", TacticCategory.INITIAL_ACCESS, "Exploiting public-facing app vulns"),
    "T1558.003": MitreTechnique("T1558.003", "Kerberoasting", TacticCategory.CREDENTIAL_ACCESS, "Requesting and cracking service tickets"),
    "T1558.004": MitreTechnique("T1558.004", "AS-REP Roasting", TacticCategory.CREDENTIAL_ACCESS, "Requesting AS-REP for pre-auth disabled accounts"),
    "T1003": MitreTechnique("T1003", "OS Credential Dumping", TacticCategory.CREDENTIAL_ACCESS, "Dumping credentials from the OS"),
    "T1003.001": MitreTechnique("T1003.001", "LSASS Memory", TacticCategory.CREDENTIAL_ACCESS, "Dumping credentials from LSASS memory"),
    "T1003.006": MitreTechnique("T1003.006", "DCSync", TacticCategory.CREDENTIAL_ACCESS, "Using DCSync to replicate DC credentials"),
    "T1005": MitreTechnique("T1005", "Data from Local System", TacticCategory.COLLECTION, "Collecting data from local system"),
    "T1021": MitreTechnique("T1021", "Remote Services", TacticCategory.LATERAL_MOVEMENT, "Using remote services for lateral movement"),
    "T1021.002": MitreTechnique("T1021.002", "SMB/Windows Admin Shares", TacticCategory.LATERAL_MOVEMENT, "Lateral movement via SMB/PsExec"),
    "T1021.003": MitreTechnique("T1021.003", "WMI", TacticCategory.LATERAL_MOVEMENT, "Lateral movement via WMI"),
    "T1548": MitreTechnique("T1548", "Abuse Elevation Control Mechanism", TacticCategory.PRIVILEGE_ESCALATION, "Exploiting misconfigured elevation"),
    "T1053": MitreTechnique("T1053", "Scheduled Task/Job", TacticCategory.PERSISTENCE, "Using scheduled tasks for persistence"),
    "T1547": MitreTechnique("T1547", "Boot or Logon Autostart Execution", TacticCategory.PERSISTENCE, "Autostart via registry or startup"),
    "T1090": MitreTechnique("T1090", "Proxy", TacticCategory.COMMAND_AND_CONTROL, "Using proxies for C2 communication"),
    "T1553.004": MitreTechnique("T1553.004", "Install Root Certificate", TacticCategory.DEFENSE_EVASION, "Installing root certificates"),
    "T1557.001": MitreTechnique("T1557.001", "LLMNR/NBT-NS Poisoning", TacticCategory.CREDENTIAL_ACCESS, "Poisoning LLMNR/NBT-NS for creds"),
    "T1557": MitreTechnique("T1557", "Adversary-in-the-Middle", TacticCategory.CREDENTIAL_ACCESS, "MITM attacks to intercept communications"),
}

SKILL_TECHNIQUE_MAP: dict[str, list[str]] = {
    "port_scan": ["T1046"], "ping_sweep": ["T1595"], "dns_enum": ["T1590", "T1596.001"],
    "service_scan": ["T1046", "T1082"], "os_fingerprint": ["T1082"],
    "vuln_scan": ["T1595", "T1190"], "ssl_analyze": ["T1595"], "snmp_enum": ["T1602"],
    "dir_fuzz": ["T1083", "T1595"], "sqlmap_test": ["T1190"],
    "nuclei_scan": ["T1595", "T1190"], "waf_detect": ["T1595"],
    "header_analyze": ["T1595"], "xss_test": ["T1190"], "cors_scan": ["T1595"], "graphql_map": ["T1595"],
    "whois_lookup": ["T1596.002"], "subdomain_enum": ["T1596.001"],
    "email_harvest": ["T1589.002"], "shodan_query": ["T1596.005"],
    "metadata_extract": ["T1589.002"], "github_search": ["T1593.003"],
    "crtsh_query": ["T1596.003"], "google_dorks": ["T1593.002"],
    "wayback_query": ["T1594"], "hunter_lookup": ["T1589.002"],
    "bloodhound_collect": ["T1087.002", "T1590"], "kerberoast": ["T1558.003"],
    "asrep_roast": ["T1558.004"], "ldap_enum": ["T1087.002", "T1615"],
    "certipy_check": ["T1553.004"], "ntlm_relay": ["T1557.001"],
    "dcsync": ["T1003.006"], "pass_the_hash": ["T1021.002", "T1021.003"],
    "priv_esc": ["T1548"], "priv_esc_linux": ["T1548"], "priv_esc_windows": ["T1548"],
    "credential_dump": ["T1003", "T1003.001"],
    "lateral_movement": ["T1021", "T1021.002", "T1021.003"],
    "persistence": ["T1053", "T1547"], "pivot_setup": ["T1090"],
    "memory_acquire": ["T1003.001"], "memory_analyze": ["T1003.001"],
    "disk_acquire": ["T1005"], "log_analysis": ["T1654"],
    "ioc_extract": ["T1005"], "yara_scan": ["T1005"], "timeline_create": ["T1005"],
}

KEYWORD_MAP: dict[str, list[str]] = {
    "T1046": ["open_port", "port_scan", "service"], "T1595": ["scan", "discovery", "enum"],
    "T1558.003": ["kerberoast"], "T1558.004": ["asrep"],
    "T1003.006": ["dcsync", "secretsdump"], "T1021.002": ["psexec", "lateral"],
    "T1021.003": ["wmiexec", "lateral"], "T1548": ["priv_esc", "privilege"],
    "T1003": ["credential", "dump", "lsass"], "T1053": ["persistence", "scheduled", "cron"],
    "T1547": ["persistence", "autostart", "registry"],
    "T1087.002": ["ldap", "domain_account"], "T1590": ["dns", "network"],
    "T1190": ["exploit", "vuln", "injection"], "T1090": ["pivot", "proxy", "tunnel"],
    "T1003.001": ["memory", "lsass", "mimikatz"], "T1005": ["data", "collect", "extract"],
    "T1654": ["log", "event"], "T1553.004": ["certipy", "certificate", "adcs"],
    "T1557.001": ["ntlm", "relay", "llmnr"],
}


class MitreMapper:
    """Maps T-100AI actions and findings to MITRE ATT&CK techniques."""

    def __init__(self):
        self._db = TECHNIQUE_DB
        self._skill_map = SKILL_TECHNIQUE_MAP

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        return self._db.get(technique_id)

    def map_action(self, skill: str, action: str) -> list[MitreTechnique]:
        """Map a skill+action to MITRE ATT&CK techniques."""
        tech_ids = self._skill_map.get(action, [])
        return [self._db[tid] for tid in tech_ids if tid in self._db]

    def map_finding(self, finding: dict) -> list[MitreFinding]:
        """Map a finding dict to MITRE ATT&CK findings."""
        findings = []
        ftype = finding.get("type", "").lower()
        for tech_id, tech in self._db.items():
            if any(kw in ftype for kw in KEYWORD_MAP.get(tech_id, [])):
                findings.append(MitreFinding(
                    technique=tech, evidence=str(finding),
                    severity=finding.get("severity", "INFO"),
                    target=finding.get("target", ""), confidence="medium",
                ))
        return findings

    def map_skill_findings(self, skill: str, results: list[dict]) -> list[MitreFinding]:
        """Map all findings from a skill execution to MITRE ATT&CK."""
        all_findings = []
        for finding in results:
            all_findings.extend(self.map_finding(finding))
        return all_findings

    def get_tactic_summary(self, findings: list[MitreFinding]) -> dict[str, list[str]]:
        """Group findings by MITRE ATT&CK tactic."""
        summary: dict[str, list[str]] = {}
        for f in findings:
            tactic = f.technique.tactic.value
            if tactic not in summary:
                summary[tactic] = []
            summary[tactic].append(f"{f.technique.technique_id}: {f.technique.technique_name}")
        return summary

    def get_attack_chain(self, findings: list[MitreFinding]) -> list[str]:
        """Generate an ordered attack chain from findings."""
        tactic_order = [t.value for t in TacticCategory]
        summary = self.get_tactic_summary(findings)
        chain = []
        for tactic in tactic_order:
            if tactic in summary:
                chain.append(f"[{tactic.upper()}]")
                chain.extend(f"  - {t}" for t in summary[tactic])
        return chain

    def export_markdown(self, findings: list[MitreFinding]) -> str:
        """Export MITRE ATT&CK mapping as Markdown."""
        lines = ["# MITRE ATT&CK Mapping Report", ""]
        chain = self.get_attack_chain(findings)
        if chain:
            lines.extend(["## Attack Chain", ""] + chain + [""])
        summary = self.get_tactic_summary(findings)
        lines.append("## Tactic Summary")
        lines.append("")
        for tactic, techs in summary.items():
            lines.append(f"### {tactic.replace('-', ' ').title()}")
            lines.append("")
            for t in techs:
                lines.append(f"- {t}")
            lines.append("")
        return "\n".join(lines)
