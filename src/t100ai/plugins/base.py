"""Plugin base classes for T-100AI"""

import importlib.util
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PluginMetadata:
    """Metadatos de un plugin"""
    name: str
    version: str
    description: str
    author: str = ""
    dependencies: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)


class BasePlugin(ABC):
    """Clase base para plugins de T-100AI"""

    metadata: PluginMetadata

    def __init__(self):
        self._enabled = False
        self._loaded = False

    @abstractmethod
    def initialize(self) -> bool:
        """Inicializa el plugin. Retorna True si exitoso."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Limpia el plugin antes de cerrar"""
        pass

    def enable(self) -> None:
        """Activa el plugin"""
        self._enabled = True

    def disable(self) -> None:
        """Desactiva el plugin"""
        self._enabled = False

    def is_enabled(self) -> bool:
        """Retorna si el plugin está activo"""
        return self._enabled

    def is_loaded(self) -> bool:
        """Retorna si el plugin está cargado"""
        return self._loaded

    def get_metadata(self) -> PluginMetadata:
        """Retorna metadatos del plugin"""
        return self.metadata


class PluginLoader:
    """Cargador de plugins para T-100AI"""

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugins: dict[str, BasePlugin] = {}
        self._discovery_cache: Optional[dict[str, PluginMetadata]] = None

    def discover_plugins(self) -> dict[str, PluginMetadata]:
        """Descubre plugins disponibles"""
        if self._discovery_cache:
            return self._discovery_cache

        discovered = {}

        if not self.plugin_dir.exists():
            return discovered

        for item in self.plugin_dir.iterdir():
            if item.is_dir() and (item / "plugin.yaml").exists():
                metadata = self._load_metadata(item)
                if metadata:
                    discovered[metadata.name] = metadata

        self._discovery_cache = discovered
        return discovered

    def _load_metadata(self, plugin_path: Path) -> Optional[PluginMetadata]:
        """Carga metadatos desde plugin.yaml"""
        import yaml

        yaml_file = plugin_path / "plugin.yaml"
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                return PluginMetadata(
                    name=data.get('name', plugin_path.name),
                    version=data.get('version', '1.0.0'),
                    description=data.get('description', ''),
                    author=data.get('author', ''),
                    dependencies=data.get('dependencies', []),
                    skills=data.get('skills', []),
                    tools=data.get('tools', [])
                )
        except Exception:
            return None

    def load_plugin(self, name: str) -> Optional[BasePlugin]:
        """Carga un plugin por nombre"""
        if name in self.plugins:
            return self.plugins[name]

        discovered = self.discover_plugins()
        if name not in discovered:
            return None

        plugin_path = self.plugin_dir / name

        init_file = plugin_path / "__init__.py"
        if not init_file.exists():
            init_file = plugin_path / "plugin.py"

        if not init_file.exists():
            return None

        spec = importlib.util.spec_from_file_location(f"t100ai.plugins.{name}", init_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"t100ai.plugins.{name}"] = module
            spec.loader.exec_module(module)

            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                    plugin = obj()
                    if plugin.initialize():
                        plugin._loaded = True
                        self.plugins[name] = plugin
                        return plugin

        return None

    def unload_plugin(self, name: str) -> bool:
        """Descarga un plugin"""
        if name in self.plugins:
            plugin = self.plugins[name]
            plugin.shutdown()
            plugin.disable()
            del self.plugins[name]
            return True
        return False

    def list_plugins(self) -> list[dict]:
        """Lista todos los plugins"""
        return [
            {
                "name": name,
                "metadata": p.get_metadata(),
                "enabled": p.is_enabled(),
                "loaded": p.is_loaded()
            }
            for name, p in self.plugins.items()
        ]

    def enable_plugin(self, name: str) -> bool:
        """Activa un plugin"""
        if name in self.plugins:
            self.plugins[name].enable()
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """Desactiva un plugin"""
        if name in self.plugins:
            self.plugins[name].disable()
            return True
        return False


def load_plugins_from_directory(plugin_dir: str) -> dict[str, BasePlugin]:
    """Función utilitaria para cargar plugins desde un directorio"""
    loader = PluginLoader(plugin_dir)
    discovered = loader.discover_plugins()

    plugins = {}
    for name in discovered:
        plugin = loader.load_plugin(name)
        if plugin:
            plugins[name] = plugin

    return plugins
