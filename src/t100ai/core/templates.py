"""Session Templates for T-100AI.

Pre-configured session templates for common assessment types.
Each template defines: role, scope, skills to load, workflows to run,
and permission mode.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SessionTemplate:
    """A pre-configured session template."""
    name: str
    description: str
    role: str  # pentester, red-teamer, blue-teamer, ctf-player
    scope_type: str  # ip, domain, cidr, url
    default_scope: str = ""
    skills: list[str] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    permission_mode: str = "standard"  # paranoid, standard, expert
    llm_model: str = ""
    initial_commands: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ── Template Registry ────────────────────────────────────────────────────────

TEMPLATES: dict[str, SessionTemplate] = {
    "web_app_pentest": SessionTemplate(
        name="Web Application Pentest",
        description="Full web application penetration testing workflow",
        role="pentester",
        scope_type="url",
        skills=["web", "osint", "recon", "report"],
        workflows=["web_audit", "quick_web_scan"],
        permission_mode="standard",
        initial_commands=[
            "skill web header_analyze {target}",
            "skill web waf_detect {target}",
            "skill web dir_fuzz {target}",
            "skill web nuclei_scan {target}",
            "skill web sqlmap_test {target}",
        ],
        tags=["web", "owasp", "pentest"],
    ),
    "infra_pentest": SessionTemplate(
        name="Infrastructure Pentest",
        description="Network infrastructure penetration testing",
        role="pentester",
        scope_type="cidr",
        skills=["recon", "osint", "report"],
        workflows=["full_recon", "quick_scan"],
        permission_mode="standard",
        initial_commands=[
            "skill recon ping_sweep {target}",
            "skill recon port_scan {target}",
            "skill recon service_scan {target}",
            "skill recon os_fingerprint {target}",
        ],
        tags=["network", "infra", "pentest"],
    ),
    "ad_assessment": SessionTemplate(
        name="Active Directory Assessment",
        description="Active Directory security assessment and attack chain",
        role="red-teamer",
        scope_type="domain",
        skills=["ad", "recon", "osint", "postex", "report"],
        workflows=["ad_assessment", "ad_attack_chain"],
        permission_mode="expert",
        initial_commands=[
            "skill osint subdomain_enum {target}",
            "skill ad bloodhound_collect {target}",
            "skill ad ldap_enum {target}",
            "skill ad kerberoast {target}",
            "skill ad asrep_roast {target}",
        ],
        tags=["ad", "red-team", "kerberos"],
    ),
    "red_team_full": SessionTemplate(
        name="Full Red Team Engagement",
        description="Complete red team engagement from recon to reporting",
        role="red-teamer",
        scope_type="domain",
        skills=["osint", "recon", "ad", "web", "postex", "forense", "report"],
        workflows=["full_recon", "web_audit", "ad_assessment", "post_exploitation"],
        permission_mode="expert",
        initial_commands=[
            "skill osint full_osint {target}",
            "skill recon full_recon {target}",
            "skill ad bloodhound_collect {target}",
        ],
        tags=["red-team", "full-engagement"],
    ),
    "blue_team_hunt": SessionTemplate(
        name="Blue Team Threat Hunt",
        description="Defensive threat hunting and incident response",
        role="blue-teamer",
        scope_type="ip",
        skills=["forense", "recon", "report"],
        workflows=["incident_response", "memory_forensics"],
        permission_mode="paranoid",
        initial_commands=[
            "skill forense log_analysis {target}",
            "skill forense ioc_extract {target}",
            "skill forense yara_scan {target}",
        ],
        tags=["blue-team", "threat-hunt", "ir"],
    ),
    "ctf_quick": SessionTemplate(
        name="CTF Quick Scan",
        description="Quick reconnaissance for CTF challenges",
        role="ctf-player",
        scope_type="ip",
        skills=["recon", "web", "osint"],
        workflows=["quick_scan", "web_footprint"],
        permission_mode="expert",
        initial_commands=[
            "skill recon port_scan {target}",
            "skill recon service_scan {target}",
            "skill web dir_fuzz {target}",
        ],
        tags=["ctf", "quick"],
    ),
    "compliance_audit": SessionTemplate(
        name="Compliance Audit",
        description="Non-intrusive compliance-focused assessment",
        role="pentester",
        scope_type="domain",
        skills=["osint", "recon", "web", "report"],
        workflows=["quick_web_scan", "rapid_osint"],
        permission_mode="paranoid",
        initial_commands=[
            "skill osint whois_lookup {target}",
            "skill osint crtsh_query {target}",
            "skill recon port_scan {target}",
            "skill web header_analyze {target}",
        ],
        tags=["compliance", "non-intrusive"],
    ),
    "incident_response": SessionTemplate(
        name="Incident Response",
        description="Forensic incident response workflow",
        role="forensic-analyst",
        scope_type="ip",
        skills=["forense", "osint", "report"],
        workflows=["incident_response", "memory_forensics"],
        permission_mode="paranoid",
        initial_commands=[
            "skill forense memory_acquire {target}",
            "skill forense disk_acquire {target}",
            "skill forense log_analysis {target}",
            "skill forense ioc_extract {target}",
            "skill forense timeline_create {target}",
        ],
        tags=["ir", "forensics", "incident"],
    ),
}


def list_templates() -> list[dict[str, Any]]:
    """List all available session templates."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "role": t.role,
            "skills": t.skills,
            "tags": t.tags,
        }
        for t in TEMPLATES.values()
    ]


def get_template(name: str) -> Optional[SessionTemplate]:
    """Get a template by name or alias."""
    # Direct match
    if name in TEMPLATES:
        return TEMPLATES[name]
    # Search by name (case-insensitive)
    name_lower = name.lower()
    for key, t in TEMPLATES.items():
        if name_lower in key.lower() or name_lower in t.name.lower():
            return t
    return None


def template_to_config(template: SessionTemplate) -> dict[str, Any]:
    """Convert a template to engine configuration dict."""
    return {
        "role": template.role,
        "scope_type": template.scope_type,
        "default_scope": template.default_scope,
        "skills": template.skills,
        "workflows": template.workflows,
        "permission_mode": template.permission_mode,
        "llm_model": template.llm_model,
        "initial_commands": template.initial_commands,
    }
