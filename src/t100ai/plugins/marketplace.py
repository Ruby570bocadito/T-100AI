"""Plugin Marketplace - Download, search and install plugins from remote registry."""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("t100ai.marketplace")

DEFAULT_REGISTRY_URL = "https://plugins.t100ai.example.com/api/v1"


@dataclass
class PluginEntry:
    """Metadata de un plugin en el marketplace."""
    name: str
    version: str
    description: str
    author: str
    download_url: str
    tags: list[str] = field(default_factory=list)
    stars: int = 0
    downloads: int = 0
    created_at: str = ""
    updated_at: str = ""


class PluginMarketplace:
    """Cliente del marketplace de plugins de T-100AI."""

    def __init__(self, registry_url: str = DEFAULT_REGISTRY_URL):
        self.registry_url = registry_url
        self._cache: list[PluginEntry] = []
        self._cache_time: Optional[float] = None
        self._cache_ttl = 300  # 5 minutos

    def search(self, query: str = "", tags: list[str] | None = None) -> list[PluginEntry]:
        """Busca plugins en el marketplace."""
        plugins = self._fetch_index()
        results = plugins

        if query:
            query_lower = query.lower()
            results = [
                p for p in results
                if query_lower in p.name.lower()
                or query_lower in p.description.lower()
                or any(query_lower in t.lower() for t in p.tags)
            ]

        if tags:
            results = [
                p for p in results
                if any(t in p.tags for t in tags)
            ]

        return sorted(results, key=lambda p: p.stars, reverse=True)

    def get_plugin(self, name: str) -> Optional[PluginEntry]:
        """Obtiene metadata de un plugin específico."""
        plugins = self._fetch_index()
        for p in plugins:
            if p.name == name:
                return p
        return None

    def install(self, name: str, plugins_dir: str = "plugins") -> bool:
        """Descarga e instala un plugin del marketplace."""
        plugin = self.get_plugin(name)
        if plugin is None:
            logger.error(f"Plugin '{name}' not found in marketplace")
            return False

        dest = Path(plugins_dir) / name
        dest.mkdir(parents=True, exist_ok=True)

        try:
            with urllib.request.urlopen(plugin.download_url, timeout=60) as resp:
                data = resp.read()

            # Save downloaded plugin
            plugin_file = dest / f"{name}.py"
            plugin_file.write_bytes(data)

            # Create manifest (YAML a mano: evita dependencia obligatoria de pyyaml)
            manifest_yaml = (
                f"name: {plugin.name}\n"
                f"version: {plugin.version}\n"
                f"description: {plugin.description}\n"
                f"author: {plugin.author}\n"
                f"min_t100ai_version: '1.0.0'\n"
                f"entry_point: {name}.run\n"
                f"permissions:\n  - shell\n  - filesystem\n"
                f"source: marketplace\n"
                f"installed_at: '{datetime.now(timezone.utc).isoformat()}'\n"
            )
            (dest / "plugin.yaml").write_text(manifest_yaml)

            logger.info(f"Plugin '{name}' installed from marketplace to {dest}")
            return True
        except Exception as e:
            logger.error(f"Failed to install plugin '{name}': {e}")
            return False

    def list_installed(self, plugins_dir: str = "plugins") -> list[dict[str, Any]]:
        """Lista plugins instalados desde el marketplace."""
        installed = []
        base = Path(plugins_dir)
        if not base.exists():
            return installed

        for entry in base.iterdir():
            if entry.is_dir():
                manifest = entry / "plugin.yaml"
                if manifest.exists():
                    installed.append({
                        "name": entry.name,
                        "path": str(entry),
                        "source": "marketplace",
                    })

        return installed

    def _fetch_index(self) -> list[PluginEntry]:
        """Descarga el índice del marketplace."""
        now = __import__("time").time()
        if self._cache and self._cache_time and (now - self._cache_time) < self._cache_ttl:
            return self._cache

        try:
            url = f"{self.registry_url}/plugins"
            req = urllib.request.Request(url, headers={"User-Agent": "T-100AI/2.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            plugins = []
            for item in data.get("plugins", []):
                plugins.append(PluginEntry(
                    name=item["name"],
                    version=item["version"],
                    description=item.get("description", ""),
                    author=item.get("author", ""),
                    download_url=item["download_url"],
                    tags=item.get("tags", []),
                    stars=item.get("stars", 0),
                    downloads=item.get("downloads", 0),
                ))

            self._cache = plugins
            self._cache_time = now
            return plugins
        except Exception as e:
            logger.warning(f"Failed to fetch marketplace index: {e}")
            # Return cached data even if stale
            return self._cache
