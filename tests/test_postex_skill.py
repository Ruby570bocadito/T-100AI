"""Tests for PostEx skill."""

from t100ai.skills.base import RiskLevel
from t100ai.skills.postex import PostExSkill


def test_postex_skill_creation():
    skill = PostExSkill()
    assert skill.name == "postex"
    assert skill.category == "postex"
    assert skill.risk_level == RiskLevel.INTRUSIVE


def test_postex_skill_available_actions():
    skill = PostExSkill()
    actions = skill.get_available_actions()
    assert isinstance(actions, list)
    assert len(actions) >= 10
    assert "priv_esc" in actions
    assert "credential_dump" in actions
    assert "lateral_movement" in actions
    assert "persistence" in actions
    assert "pivoting" in actions


def test_postex_skill_validate_params():
    skill = PostExSkill()
    import asyncio
    assert asyncio.run(skill.validate_params("lateral_movement", {"target": "10.0.0.1"})) is True
    assert asyncio.run(skill.validate_params("pivoting", {"target": "10.0.0.1"})) is True
    assert asyncio.run(skill.validate_params("priv_esc", {"os": "linux"})) is True


def test_postex_skill_validate_params_missing():
    skill = PostExSkill()
    import asyncio
    assert asyncio.run(skill.validate_params("lateral_movement", {})) is False


def test_postex_skill_unknown_action():
    skill = PostExSkill()
    import asyncio
    result = asyncio.run(skill.execute("unknown_action", {}))
    assert result.success is False
    assert "desconocida" in result.error


def test_postex_skill_parse_postex_linpeas():
    skill = PostExSkill()
    output = """
[+] Sudo version
Sudo version 1.9.5p2
[+] Writable files
/etc/passwd
[+] Private keys found
/home/user/.ssh/id_rsa
"""
    findings = skill._parse_postex_output(output, "linpeas", {})
    assert any(f["severity"] in ("CRIT", "HIGH") for f in findings)


def test_postex_skill_parse_postex_lateral_success():
    skill = PostExSkill()
    output = r"""
whoami
nt authority\system
hostname
DC01
"""
    findings = skill._parse_postex_output(output, "lateral_ssh", {"target": "10.0.0.1"})
    assert any(f["type"] == "lateral_success" for f in findings)
    assert any(f["severity"] == "CRIT" for f in findings)


def test_postex_skill_parse_postex_lateral_denied():
    skill = PostExSkill()
    output = "Access Denied: Invalid credentials"
    findings = skill._parse_postex_output(output, "lateral_smb", {"target": "10.0.0.1"})
    assert any(f["type"] == "lateral_denied" for f in findings)


def test_postex_skill_parse_postex_mimikatz():
    skill = PostExSkill()
    output = """
  Username : Administrator
  Domain   : CORP
  NTLM     : 5f4dcc3b5aa765d61d8327deb882cf99
  Password : password123
"""
    findings = skill._parse_postex_output(output, "mimikatz", {})
    assert any(f["type"] == "credential" for f in findings)
    assert any(f["severity"] == "CRIT" for f in findings)


def test_postex_skill_parse_postex_pivot():
    skill = PostExSkill()
    output = "SSH tunnel established"
    findings = skill._parse_postex_output(output, "pivot_ssh", {"target": "10.0.0.1"})
    assert any(f["type"] == "pivot_established" for f in findings)


def test_postex_skill_tools_list():
    skill = PostExSkill()
    assert isinstance(skill.tools, list)
    assert len(skill.tools) >= 5
    assert "postex.priv_esc" in skill.tools
    assert "postex.credential_dump" in skill.tools
