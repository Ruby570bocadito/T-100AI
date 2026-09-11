"""Tests for AD skill."""
import asyncio

from t100ai.skills.ad import AdSkill
from t100ai.skills.base import RiskLevel


def test_ad_skill_creation():
    skill = AdSkill()
    assert skill.name == "ad"
    assert skill.category == "ad"
    assert skill.risk_level == RiskLevel.INTRUSIVE


def test_ad_skill_available_actions():
    skill = AdSkill()
    actions = skill.get_available_actions()
    assert isinstance(actions, list)
    assert len(actions) >= 10
    assert "bloodhound_collect" in actions
    assert "kerberoast" in actions
    assert "asrep_roast" in actions
    assert "ldap_enum" in actions
    assert "certipy_check" in actions
    assert "dcsync" in actions


def test_ad_skill_validate_params():
    skill = AdSkill()
    assert asyncio.run(skill.validate_params("bloodhound_collect", {
        "domain": "corp.local", "user": "admin", "password": "pass"
    })) is True
    assert asyncio.run(skill.validate_params("certipy_check", {
        "domain": "corp.local", "target": "dc.corp.local"
    })) is True


def test_ad_skill_validate_params_missing():
    skill = AdSkill()
    assert asyncio.run(skill.validate_params("bloodhound_collect", {"domain": "corp.local"})) is False


def test_ad_skill_unknown_action():
    skill = AdSkill()
    result = asyncio.run(skill.execute("unknown_action", {}))
    assert result.success is False
    assert "desconocida" in result.error


def test_ad_skill_parse_ad_output_kerberoast():
    skill = AdSkill()
    output = """
$krb5tgs$23$*user$CORP.LOCAL$corp.local/user*$abcdef1234567890
Some other output
$krb5tgs$23$*admin$CORP.LOCAL$corp.local/admin*$1234567890abcdef
"""
    findings = skill._parse_ad_output(output, "kerberoast", {"domain": "corp.local"})
    assert len(findings) == 2
    assert all(f["type"] == "crackable_hash" for f in findings)
    assert all(f["severity"] == "HIGH" for f in findings)


def test_ad_skill_parse_ad_output_bloodhound():
    skill = AdSkill()
    output = "INFO: Done in 00:00:05\nCollected 500 nodes"
    findings = skill._parse_ad_output(output, "bloodhound", {"domain": "corp.local"})
    assert len(findings) == 1
    assert findings[0]["type"] == "bloodhound_complete"


def test_ad_skill_parse_ad_output_certipy():
    skill = AdSkill()
    output = """
[*] Certificate template: User
[*] Vulnerable: ESC1 - Misconfigured Certificate Template
[*] VULNERABLE: ESC8 - AD CS Relay Attack
"""
    findings = skill._parse_ad_output(output, "certipy", {"domain": "corp.local"})
    assert any(f["severity"] == "CRIT" for f in findings)
    assert any("ESC" in f.get("value", "") for f in findings)


def test_ad_skill_parse_ad_output_dcsync():
    skill = AdSkill()
    output = """
[*] Getting TGT for user
[*] DRSUAPI connection established
krbtgt:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
Administrator:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
"""
    findings = skill._parse_ad_output(output, "dcsync", {"domain": "corp.local"})
    assert any(f["type"] == "ntds_hash" for f in findings)
    assert any(f["severity"] == "CRIT" for f in findings)


def test_ad_skill_tools_list():
    skill = AdSkill()
    assert isinstance(skill.tools, list)
    assert len(skill.tools) >= 5
    assert "ad.bloodhound_collect" in skill.tools
    assert "ad.kerberoast" in skill.tools
