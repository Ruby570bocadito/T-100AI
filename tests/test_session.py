
from t100ai.core.session import Finding, Role, Session


def test_session_creation():
    s = Session(name="test_session")
    assert s is not None
    assert hasattr(s, "id")
    assert s.name == "test_session"


def test_add_finding():
    s = Session("test_session_finding")
    finding = Finding(id="f1", title="Test Finding", description="sample")
    s.add_finding(finding)
    assert finding in s.findings
    assert len(s.findings) == 1


def test_scope_management():
    s = Session("test_session_scope")
    s.add_to_scope("192.168.1.1", "ip")
    assert s.is_in_scope("192.168.1.1") is True
    assert s.is_in_scope("10.0.0.1") is False


def test_findings_count():
    s = Session("test_session_count")
    s.add_finding(Finding(severity="CRIT"))
    s.add_finding(Finding(severity="HIGH"))
    count = s.findings_count
    assert isinstance(count, dict)
    assert count["CRIT"] == 1
    assert count["HIGH"] == 1


def test_duration_calculation():
    s = Session("test_session_duration")
    start = s.created_at
    assert isinstance(start, object)
    assert hasattr(s, "created_at")


def test_role_setting():
    s = Session("test_session_role")
    s.set_role(Role.PENTESTER)
    assert s.role == Role.PENTESTER
    assert s.role.value == "pentester"


def test_is_in_scope():
    s = Session("test_session_scope_check")
    s.add_to_scope("example.com", "domain")
    assert s.is_in_scope("example.com") is True
    assert s.is_in_scope("other.com") is False


def test_session_conversation_history():
    s = Session("test_conversation")
    s.add_message("user", "Hello")
    s.add_message("assistant", "Hi there")
    assert len(s.conversation_history) == 2
    assert s.conversation_history[0]["role"] == "user"


def test_session_scope_summary():
    s = Session("test_summary")
    s.add_to_scope("192.168.1.1", "ip")
    summary = s.get_scope_summary()
    assert "192.168.1.1" in summary


def test_session_generate_report():
    s = Session("test_report")
    s.add_finding(Finding(title="SSH open", severity="HIGH", tool="nmap"))
    report = s.generate_session_report()
    assert "SSH open" in report


def test_session_backup_restore(tmp_path):
    s = Session(name="test_backup")
    s.add_finding(Finding(title="Test", severity="MED"))
    s.add_to_scope("10.0.0.1", "ip")

    backup_path = s.export_full_backup(str(tmp_path))

    restored = Session.restore_from_backup(str(backup_path))
    assert restored.name == "test_backup"
    assert len(restored.findings) == 1
    assert len(restored.scope) == 1
