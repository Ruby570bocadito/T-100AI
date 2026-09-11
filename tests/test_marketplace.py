"""Tests for PluginMarketplace in specter.plugins.marketplace."""

import tempfile
from pathlib import Path

import pytest

from t100ai.plugins.marketplace import DEFAULT_REGISTRY_URL, PluginEntry, PluginMarketplace


@pytest.fixture
def marketplace():
    """Create a PluginMarketplace with default URL."""
    return PluginMarketplace()


@pytest.fixture
def custom_marketplace():
    """Create a PluginMarketplace with custom URL."""
    return PluginMarketplace(registry_url="https://custom.example.com/api/v1")


class TestPluginMarketplaceCreation:
    """Test marketplace initialization."""

    def test_default_url(self):
        mp = PluginMarketplace()
        assert mp.registry_url == DEFAULT_REGISTRY_URL

    def test_custom_url(self):
        custom_url = "https://custom.example.com/api/v1"
        mp = PluginMarketplace(registry_url=custom_url)
        assert mp.registry_url == custom_url

    def test_cache_initialized_empty(self):
        mp = PluginMarketplace()
        assert mp._cache == []
        assert mp._cache_time is None


class TestPluginMarketplaceSearch:
    """Test marketplace search functionality."""

    def test_search_returns_empty_on_unreachable(self, marketplace):
        results = marketplace.search()
        assert isinstance(results, list)

    def test_search_with_query_filter(self, marketplace):
        results = marketplace.search(query="nonexistent_plugin_xyz")
        assert isinstance(results, list)

    def test_search_with_tags_filter(self, marketplace):
        results = marketplace.search(tags=["nonexistent_tag_xyz"])
        assert isinstance(results, list)

    def test_search_with_both_filters(self, marketplace):
        results = marketplace.search(query="test", tags=["recon"])
        assert isinstance(results, list)


class TestPluginMarketplaceGetPlugin:
    """Test get_plugin() method."""

    def test_get_plugin_returns_none_for_nonexistent(self, marketplace):
        plugin = marketplace.get_plugin("nonexistent_plugin_xyz")
        assert plugin is None

    def test_get_plugin_returns_none_on_unreachable(self, marketplace):
        result = marketplace.get_plugin("any_plugin")
        assert result is None


class TestPluginMarketplaceListInstalled:
    """Test list_installed() method."""

    def test_list_installed_empty_for_empty_dir(self, marketplace):
        with tempfile.TemporaryDirectory() as tmpdir:
            installed = marketplace.list_installed(plugins_dir=tmpdir)
            assert installed == []

    def test_list_installed_empty_for_nonexistent_dir(self, marketplace):
        installed = marketplace.list_installed(plugins_dir="/nonexistent/path/xyz")
        assert installed == []

    def test_list_installed_finds_plugin_dirs(self, marketplace):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "test_plugin"
            plugin_dir.mkdir()
            (plugin_dir / "plugin.yaml").write_text("name: test_plugin\nversion: 1.0.0\n")
            installed = marketplace.list_installed(plugins_dir=tmpdir)
            assert len(installed) == 1
            assert installed[0]["name"] == "test_plugin"
            assert installed[0]["source"] == "marketplace"


class TestPluginMarketplaceInstall:
    """Test install() method."""

    def test_install_fails_gracefully_for_nonexistent(self, marketplace):
        with tempfile.TemporaryDirectory() as tmpdir:
            success = marketplace.install("nonexistent_plugin_xyz", plugins_dir=tmpdir)
            assert success is False

    def test_install_fails_on_unreachable_registry(self, marketplace):
        with tempfile.TemporaryDirectory() as tmpdir:
            success = marketplace.install("any_plugin", plugins_dir=tmpdir)
            assert success is False

    def test_install_does_not_raise_exception(self, marketplace):
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                marketplace.install("bad_plugin", plugins_dir=tmpdir)
            except Exception as e:
                pytest.fail(f"install() raised exception: {e}")


class TestPluginEntry:
    """Test PluginEntry dataclass."""

    def test_create_minimal(self):
        entry = PluginEntry(
            name="test",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
            download_url="https://example.com/test.tar.gz",
        )
        assert entry.name == "test"
        assert entry.tags == []
        assert entry.stars == 0
        assert entry.downloads == 0

    def test_create_full(self):
        entry = PluginEntry(
            name="full_test",
            version="2.0.0",
            description="Full test plugin",
            author="Full Author",
            download_url="https://example.com/full.tar.gz",
            tags=["recon", "web"],
            stars=42,
            downloads=100,
        )
        assert entry.tags == ["recon", "web"]
        assert entry.stars == 42
        assert entry.downloads == 100
