"""Tests for T-100AI core engine components."""

from t100ai.core.audit import AuditLogger
from t100ai.core.config import T100AIConfig
from t100ai.core.guardrails import LLMCommandValidator
from t100ai.core.mitre import TECHNIQUE_DB, MitreMapper
from t100ai.core.permissions import PermissionLevel, PermissionManager
from t100ai.core.sandbox import CommandSandbox
from t100ai.core.session import MAX_HISTORY, Finding, Session
from t100ai.wordlists.dictionaries import AttackDictionary


class TestConfig:
    def test_model_from_env(self):
        import os
        os.environ["OLLAMA_MODEL"] = "mistral:7b"
        cfg = T100AIConfig()
        assert cfg.ollama_model == "mistral:7b"
        del os.environ["OLLAMA_MODEL"]

    def test_default_model_is_real(self):
        cfg = T100AIConfig()
        assert cfg.ollama_model == "mistral:7b"

    def test_default_host(self):
        cfg = T100AIConfig()
        assert cfg.ollama_host == "http://localhost:11434"

    def test_default_permission_mode(self):
        cfg = T100AIConfig()
        assert cfg.permission_mode == "standard"


class TestSession:
    def test_max_history_constant(self):
        assert MAX_HISTORY == 20

    def test_add_message_truncates(self):
        session = Session()
        for i in range(30):
            session.add_message("user", f"msg {i}")
        assert len(session.conversation_history) == MAX_HISTORY

    def test_build_conversation_prompt_empty(self):
        session = Session()
        assert session.build_conversation_prompt() == ""

    def test_build_conversation_prompt_uses_max_history(self):
        session = Session()
        for i in range(MAX_HISTORY):
            session.add_message("user", f"msg {i}")
        prompt = session.build_conversation_prompt()
        assert "msg 0" in prompt
        assert f"msg {MAX_HISTORY - 1}" in prompt

    def test_add_finding(self):
        session = Session()
        f = Finding(title="Test", severity="HIGH", tool="nmap")
        session.add_finding(f)
        assert len(session.findings) == 1
        assert session.findings[0].severity == "HIGH"

    def test_scope_operations(self):
        session = Session()
        session.add_to_scope("192.168.1.1", "ip")
        assert session.is_in_scope("192.168.1.1")
        assert not session.is_in_scope("10.0.0.1")

    def test_findings_count(self):
        session = Session()
        session.add_finding(Finding(title="c", severity="CRIT"))
        session.add_finding(Finding(title="h", severity="HIGH"))
        session.add_finding(Finding(title="i", severity="INFO"))
        counts = session.findings_count
        assert counts["CRIT"] == 1
        assert counts["HIGH"] == 1
        assert counts["INFO"] == 1


class TestSandbox:
    def test_normal_command_allowed(self):
        sandbox = CommandSandbox()
        allowed, reason = sandbox.validate("nmap -sV 192.168.1.1")
        assert allowed is True

    def test_rm_rf_root_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("rm -rf /")
        assert allowed is False

    def test_rm_recursive_f_root_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("rm -r -f /")
        assert allowed is False

    def test_rm_f_recursive_root_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("rm -f -r /")
        assert allowed is False

    def test_reboot_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("reboot")
        assert allowed is False

    def test_systemctl_poweroff_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("systemctl poweroff")
        assert allowed is False

    def test_sbin_reboot_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("/sbin/reboot")
        assert allowed is False

    def test_halt_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("halt")
        assert allowed is False

    def test_poweroff_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("poweroff")
        assert allowed is False

    def test_kill_sigkill_1_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("kill -SIGKILL 1")
        assert allowed is False

    def test_dd_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate("dd of=/dev/sda if=/dev/zero")
        assert allowed is False

    def test_fork_bomb_blocked(self):
        sandbox = CommandSandbox()
        allowed, _ = sandbox.validate(":(){:|:&};:")
        assert allowed is False

    def test_scope_validation(self):
        sandbox = CommandSandbox(scope_targets=["192.168.1.0/24"])
        allowed, _ = sandbox.validate("nmap 192.168.1.10")
        assert allowed is True
        allowed, _ = sandbox.validate("nmap 10.0.0.1")
        assert allowed is False

    def test_command_limit(self):
        sandbox = CommandSandbox(max_commands=2)
        sandbox._executed_count = 2
        allowed, _ = sandbox.validate("echo 3")
        assert allowed is False

    def test_stats(self):
        sandbox = CommandSandbox()
        stats = sandbox.get_stats()
        assert "executed_commands" in stats
        assert "blocked_commands" in stats
        assert "remaining_commands" in stats


class TestGuardrails:
    def test_valid_nmap_command(self):
        v = LLMCommandValidator()
        result = v.validate("nmap -sV -p 80,443 192.168.1.1")
        assert result.is_valid is True

    def test_nmap_without_target(self):
        v = LLMCommandValidator()
        result = v.validate("nmap -sV")
        assert result.is_valid is False

    def test_gobuster_without_subcommand(self):
        v = LLMCommandValidator()
        result = v.validate("gobuster -u http://example.com")
        assert result.is_valid is False

    def test_sqlmap_without_url(self):
        v = LLMCommandValidator()
        result = v.validate("sqlmap --dbs")
        assert result.is_valid is False

    def test_empty_command(self):
        v = LLMCommandValidator()
        result = v.validate("")
        assert result.is_valid is False

    def test_cve_year_validation(self):
        v = LLMCommandValidator()
        result = v.validate("searchsploit CVE-1999-0001")
        assert result.is_valid is False

    def test_invalid_ip(self):
        v = LLMCommandValidator()
        result = v.validate("nmap 999.999.999.999")
        assert result.is_valid is False


class TestPermissions:
    def test_observation_mode_no_confirmation(self):
        pm = PermissionManager(current_level=PermissionLevel.OBSERVATION)
        assert pm.confirmation_required is False

    def test_active_mode_requires_confirmation(self):
        pm = PermissionManager(current_level=PermissionLevel.ACTIVE)
        assert pm.confirmation_required is True

    def test_intrusive_mode_requires_confirmation(self):
        pm = PermissionManager(current_level=PermissionLevel.INTRUSIVE)
        assert pm.confirmation_required is True

    def test_whitelist_trusted(self):
        pm = PermissionManager()
        pm.add_to_whitelist("nmap")
        assert pm.is_trusted_tool("nmap") is True
        assert pm.is_trusted_tool("unknown") is False

    def test_blacklist_denied(self):
        pm = PermissionManager()
        pm.add_to_blacklist("malicious_tool")
        assert pm.is_trusted_tool("malicious_tool") is False

    def test_denied_history_bounded(self):
        pm = PermissionManager()
        pm._append_denied("tool1", None, "test")
        pm._append_denied("tool2", None, "test")
        assert len(pm.denied_history) == 2


class TestMitreMapper:
    def test_get_technique(self):
        mapper = MitreMapper()
        tech = mapper.get_technique("T1046")
        assert tech is not None
        assert tech.technique_name == "Network Service Discovery"

    def test_map_action(self):
        mapper = MitreMapper()
        techniques = mapper.map_action("recon", "port_scan")
        assert len(techniques) > 0
        assert techniques[0].technique_id == "T1046"

    def test_db_not_empty(self):
        assert len(TECHNIQUE_DB) > 30

    def test_export_markdown(self):
        mapper = MitreMapper()
        md = mapper.export_markdown([])
        assert "# MITRE ATT&CK Mapping Report" in md


class TestAuditLogger:
    def test_log_and_verify(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path), secret="test-secret")
        logger.log_action("sess1", "scan", "nmap", {"target": "10.0.0.1"}, "done")
        assert logger.verify_integrity() is True

    def test_verify_empty(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        result = logger.verify_integrity()
        assert result is None

    def test_export_json(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        logger.log_action("s1", "test", "tool", {}, "ok")
        data = logger.export_audit_log("json")
        assert "test" in data


class TestAttackDictionary:
    def test_get_directories(self):
        d = AttackDictionary()
        items = d.get_directories()
        assert "admin" in items
        assert len(items) > 0

    def test_get_subdomains(self):
        d = AttackDictionary()
        items = d.get_subdomains()
        assert "www" in items

    def test_get_usernames(self):
        d = AttackDictionary()
        items = d.get_usernames()
        assert "admin" in items
        assert len(items) > 0

    def test_get_passwords(self):
        d = AttackDictionary()
        items = d.get_passwords()
        assert "admin" in items
        assert len(items) > 0

    def test_get_sql_payloads(self):
        d = AttackDictionary()
        items = d.get_sql_payloads()
        assert len(items) > 0
        assert "' OR '1'='1" in items

    def test_get_xss_payloads(self):
        d = AttackDictionary()
        items = d.get_xss_payloads()
        assert len(items) > 0

    def test_get_lfi_payloads(self):
        d = AttackDictionary()
        items = d.get_lfi_payloads()
        assert "../../../etc/passwd" in items

    def test_get_cve_patterns(self):
        d = AttackDictionary()
        items = d.get_cve_patterns()
        assert len(items) > 0
        assert "CVE-2024-" in items

    def test_get_all(self):
        d = AttackDictionary()
        items = d.get_all()
        assert len(items) > 0

    def test_password_mutations_use_current_year(self):
        from datetime import datetime
        d = AttackDictionary()
        mutations = d.generate_password_mutations("test")
        current_year = str(datetime.now().year)
        assert f"test{current_year}" in mutations
