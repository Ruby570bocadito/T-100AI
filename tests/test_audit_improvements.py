"""Tests for the audit-improvements branch changes (security fixes)."""

import os
import warnings

import pytest

from t100ai.analysis.chain_of_custody import ChainOfCustody
from t100ai.core.audit import AuditLogger
from t100ai.core.config import T100AIConfig
from t100ai.core.sandbox import CommandSandbox


@pytest.fixture
def sandbox():
    return CommandSandbox(timeout=5, rate_limit=0)


class TestSandboxHardening:
    """Previously-bypassable destructive commands must now be blocked."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "rm -rf /",
            "rm -rf /*",
            "rm -rf /home/../..",
            "rm -rf /tmp/../../",
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/zero of=/dev/nvme0n1",
            "dd if=/dev/urandom of=/dev/vda",
            "sgdisk --zap-all /dev/sda",
            "wipefs -a /dev/sda",
            "blkdiscard /dev/nvme0n1",
            "mkfs.ext4 /dev/sda1",
        ],
    )
    def test_destructive_blocked(self, sandbox, cmd):
        allowed, _ = sandbox.validate(cmd)
        assert not allowed, f"expected blocked: {cmd}"

    def test_normal_rm_allowed(self, sandbox):
        allowed, _ = sandbox.validate("rm /tmp/test.txt")
        assert allowed


class TestSecretHandling:
    def test_chain_of_custody_no_hardcoded_secret(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            coc = ChainOfCustody(engagement_id="t")
        assert len(coc._secret) == 64  # 32 bytes hex
        assert coc._secret != "change-me-in-production"
        # Solo cuenta el RuntimeWarning esperado; el intérprete puede emitir
        # ResourceWarnings ajenos (finalizadores de otros tests) en el mismo bloque.
        runtime = [x for x in w if issubclass(x.category, RuntimeWarning)]
        assert len(runtime) == 1
        assert "T100AI_AUDIT_SECRET" in str(runtime[0].message)

    def test_chain_of_custody_explicit_secret(self):
        coc = ChainOfCustody(secret="my-secret")
        assert coc._secret == "my-secret"

    def test_audit_logger_no_hardcoded_secret(self, tmp_path):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            al = AuditLogger(log_dir=str(tmp_path))
        assert len(al._hmac_secret) == 64
        assert al._hmac_secret != "default-secret-change-me"
        runtime = [x for x in w if issubclass(x.category, RuntimeWarning)]
        assert len(runtime) == 1
        assert "T100AI_AUDIT_SECRET" in str(runtime[0].message)


class TestConfigAliases:
    def test_default_model_is_real(self):
        assert T100AIConfig().ollama_model == "mistral:7b"

    def test_t100ai_prefix_host_alias(self):
        os.environ["T100AI_OLLAMA_HOST"] = "http://alias:11434"
        try:
            assert T100AIConfig().ollama_host == "http://alias:11434"
        finally:
            del os.environ["T100AI_OLLAMA_HOST"]

    def test_t100ai_data_dir_alias(self):
        os.environ["T100AI_DATA_DIR"] = "/app"
        try:
            assert str(T100AIConfig().session_dir) == "/app"
        finally:
            del os.environ["T100AI_DATA_DIR"]
