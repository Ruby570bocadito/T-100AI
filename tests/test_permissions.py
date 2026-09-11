
from t100ai.core.permissions import PermissionLevel, PermissionManager


def test_permission_levels():
    levels = [PermissionLevel.OBSERVATION, PermissionLevel.ACTIVE, PermissionLevel.INTRUSIVE]
    assert len(levels) == 3
    assert PermissionLevel.OBSERVATION.value == 0
    assert PermissionLevel.ACTIVE.value == 1
    assert PermissionLevel.INTRUSIVE.value == 2


def test_permission_manager_creation():
    pm = PermissionManager(current_level=PermissionLevel.OBSERVATION)
    assert pm.current_level == PermissionLevel.OBSERVATION
    assert pm.confirmation_required is False


def test_whitelist_blacklist():
    pm = PermissionManager(current_level=PermissionLevel.ACTIVE)
    assert isinstance(pm.whitelist, set)
    assert isinstance(pm.blacklist, set)

    pm.add_to_whitelist("nmap")
    assert "nmap" in pm.whitelist

    pm.add_to_blacklist("rm -rf")
    assert "rm -rf" in pm.blacklist


def test_trusted_tool():
    pm = PermissionManager(current_level=PermissionLevel.ACTIVE)
    pm.add_to_whitelist("nmap")
    assert pm.is_trusted_tool("nmap") is True
    assert pm.is_trusted_tool("unknown") is False


def test_role_based_whitelist():
    pm = PermissionManager(current_level=PermissionLevel.ACTIVE)
    pm.add_to_whitelist("nmap", role="pentester")
    assert pm.is_trusted_tool("nmap", role="pentester") is True
    assert pm.is_trusted_tool("nmap") is False


def test_role_based_blacklist():
    pm = PermissionManager(current_level=PermissionLevel.ACTIVE)
    pm.add_to_blacklist("dangerous_tool", role="red-teamer")
    assert pm.is_trusted_tool("dangerous_tool", role="red-teamer") is False


def test_confirmation_required_property():
    pm_obs = PermissionManager(current_level=PermissionLevel.OBSERVATION)
    assert pm_obs.confirmation_required is False

    pm_act = PermissionManager(current_level=PermissionLevel.ACTIVE)
    assert pm_act.confirmation_required is True

    pm_intr = PermissionManager(current_level=PermissionLevel.INTRUSIVE)
    assert pm_intr.confirmation_required is True
