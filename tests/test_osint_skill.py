"""Tests for OSINT skill."""

from t100ai.skills.base import RiskLevel
from t100ai.skills.osint import OSINT_RATE_LIMIT, OsintSkill


def test_osint_skill_creation():
    skill = OsintSkill()
    assert skill.name == "osint"
    assert skill.category == "osint"
    assert skill.risk_level == RiskLevel.PASSIVE


def test_osint_skill_available_actions():
    skill = OsintSkill()
    actions = skill.get_available_actions()
    assert isinstance(actions, list)
    assert len(actions) >= 8
    assert "whois_lookup" in actions
    assert "subdomain_enum" in actions
    assert "email_harvest" in actions
    assert "shodan_query" in actions
    assert "crtsh_query" in actions
    assert "google_dorks" in actions
    assert "wayback_query" in actions
    assert "hunter_lookup" in actions


def test_osint_skill_validate_params():
    skill = OsintSkill()
    import asyncio
    assert asyncio.run(skill.validate_params("whois_lookup", {"domain": "example.com"})) is True
    assert asyncio.run(skill.validate_params("shodan_query", {"query": "apache"})) is True
    assert asyncio.run(skill.validate_params("metadata_extract", {"path": "/tmp/test.pdf"})) is True


def test_osint_skill_validate_params_missing():
    skill = OsintSkill()
    import asyncio
    assert asyncio.run(skill.validate_params("whois_lookup", {})) is False
    assert asyncio.run(skill.validate_params("shodan_query", {})) is False


def test_osint_skill_rate_limit_constant():
    assert OSINT_RATE_LIMIT > 0
    assert isinstance(OSINT_RATE_LIMIT, float)


def test_osint_skill_tools_list():
    skill = OsintSkill()
    assert isinstance(skill.tools, list)
    assert len(skill.tools) >= 8
    assert "osint.whois" in skill.tools
    assert "osint.subdomain_enum" in skill.tools
    assert "osint.shodan" in skill.tools


def test_osint_skill_workflows():
    skill = OsintSkill()
    assert isinstance(skill.workflows, list)
    assert "full_osint" in skill.workflows
    assert "rapid_osint" in skill.workflows
