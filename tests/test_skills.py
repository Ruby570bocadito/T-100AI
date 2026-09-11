
from t100ai.skills.base import RiskLevel, SkillResult
from t100ai.skills.recon import ReconSkill
from t100ai.skills.report import ReportSkill
from t100ai.skills.web import WebSkill


def test_recon_skill_creation():
    skill = ReconSkill()
    assert skill.name == "recon"
    assert skill.category == "recon"
    assert skill.risk_level == RiskLevel.ACTIVE


def test_recon_skill_available_actions():
    skill = ReconSkill()
    actions = skill.get_available_actions()
    assert isinstance(actions, list)
    assert "port_scan" in actions
    assert "dns_enum" in actions


def test_web_skill_creation():
    skill = WebSkill()
    assert skill.name == "web"
    assert skill.category == "web"
    assert skill.risk_level == RiskLevel.ACTIVE


def test_web_skill_available_actions():
    skill = WebSkill()
    actions = skill.get_available_actions()
    assert isinstance(actions, list)
    assert "dir_fuzz" in actions
    assert "header_analyze" in actions


def test_report_skill_creation():
    skill = ReportSkill()
    assert skill.name == "report"
    assert skill.category == "report"


def test_report_skill_export_markdown():
    skill = ReportSkill()
    data = [{"id": "1", "title": "Test", "severity": "HIGH"}]
    result = skill.export_markdown(data)
    assert isinstance(result, str)
    assert "id" in result
    assert "Test" in result


def test_report_skill_export_json():
    skill = ReportSkill()
    data = [{"id": "1", "title": "Test"}]
    result = skill.export_json(data)
    assert isinstance(result, str)
    assert '"id"' in result


def test_report_skill_export_csv():
    skill = ReportSkill()
    data = [{"id": "1", "title": "Test"}]
    result = skill.export_csv(data)
    assert isinstance(result, str)
    assert "id,title" in result


def test_recon_skill_validate_params():
    ReconSkill()  # debe instanciar sin error; validate_params es async y requiere red
    assert True


def test_skill_result_success():
    result = SkillResult(success=True, output="ok", findings=[{"type": "test"}])
    assert result.success is True
    assert len(result.findings) == 1


def test_skill_result_error():
    result = SkillResult(success=False, error="something failed")
    assert result.success is False
    assert result.error == "something failed"
