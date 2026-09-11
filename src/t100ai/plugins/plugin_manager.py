"""Plugin Manager - Advanced plugin system with sandboxing, validation, and hot-reload."""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except ImportError:
    raise ImportError("pydantic is required. Install with: pip install pydantic")

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from t100ai.core.audit import AuditLogger
from t100ai.core.sandbox import CommandSandbox, SandboxResult

logger = logging.getLogger("t100ai.plugins")


# ── Plugin Manifest Schema ──────────────────────────────────────────────

VALID_PERMISSIONS = {"filesystem", "network", "shell", "subprocess", "memory"}


class PluginManifest(BaseModel):
    """Validated schema for plugin.yaml files."""

    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    version: str = Field(..., min_length=1, max_length=32, pattern=r"^\d+\.\d+\.\d+.*$")
    description: str = Field(..., min_length=1, max_length=500)
    author: str = Field(..., min_length=1, max_length=128)
    min_specter_version: str = Field(default="1.0.0")
    dependencies: list[str] = Field(default_factory=list)
    entry_point: str = Field(..., pattern=r"^[a-zA-Z0-9_.]+\.[a-zA-Z_][a-zA-Z0-9_]*$")
    permissions: list[str] = Field(default_factory=list)

    @field_validator("permissions", mode="before", each_item=True)
    @classmethod
    def validate_permission(cls, v: str) -> str:
        if v not in VALID_PERMISSIONS:
            raise ValueError(f"Invalid permission '{v}'. Must be one of: {VALID_PERMISSIONS}")
        return v

    @field_validator("dependencies", mode="before", each_item=True)
    @classmethod
    def validate_dependency(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Dependency name cannot be empty")
        return v.strip()

    model_config = {"extra": "forbid"}


# ── Plugin State ────────────────────────────────────────────────────────

class PluginState(str, Enum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    UNINSTALLED = "uninstalled"


@dataclass
class PluginInfo:
    """Runtime information about a loaded plugin."""

    manifest: PluginManifest
    path: Path
    state: PluginState = PluginState.DISCOVERED
    loaded_at: Optional[datetime] = None
    module: Optional[Any] = None
    instance: Optional[Any] = None
    error: Optional[str] = None
    file_hashes: dict[str, str] = field(default_factory=dict)


# ── Plugin Sandbox ──────────────────────────────────────────────────────

class PluginSandbox:
    """Isolated execution environment for plugin commands.

    Restricts filesystem access to the plugin's own directory,
    routes all shell commands through CommandSandbox,
    and logs every action to the audit trail.
    """

    def __init__(
        self,
        plugin_name: str,
        plugin_dir: Path,
        permissions: set[str],
        command_sandbox: Optional[CommandSandbox] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.plugin_name = plugin_name
        self.plugin_dir = plugin_dir.resolve()
        self.permissions = permissions
        self.command_sandbox = command_sandbox or CommandSandbox()
        self.audit_logger = audit_logger or AuditLogger()

    def _log_action(self, action: str, details: dict[str, Any]) -> None:
        self.audit_logger.log_action(
            session_id=f"plugin:{self.plugin_name}",
            action=action,
            tool="plugin_sandbox",
            params=details,
            result=None,
        )

    def _check_permission(self, permission: str) -> bool:
        if permission not in self.permissions:
            self._log_action("permission_denied", {
                "plugin": self.plugin_name,
                "requested_permission": permission,
            })
            return False
        return True

    def execute_command(self, command: str) -> SandboxResult:
        """Execute a shell command through the CommandSandbox."""
        if not self._check_permission("shell"):
            return SandboxResult(
                allowed=False,
                error=f"Plugin '{self.plugin_name}' lacks 'shell' permission",
                command=command,
                source="plugin",
            )

        self._log_action("execute_command", {
            "plugin": self.plugin_name,
            "command": command,
        })

        return self.command_sandbox.execute(command, source="plugin")

    def read_file(self, file_path: str) -> Optional[str]:
        """Read a file, restricted to the plugin's directory."""
        if not self._check_permission("filesystem"):
            return None

        resolved = (self.plugin_dir / file_path).resolve()
        if not str(resolved).startswith(str(self.plugin_dir)):
            self._log_action("filesystem_violation", {
                "plugin": self.plugin_name,
                "attempted_path": file_path,
                "resolved_path": str(resolved),
            })
            return None

        self._log_action("read_file", {
            "plugin": self.plugin_name,
            "path": str(resolved),
        })

        try:
            return resolved.read_text(encoding="utf-8")
        except Exception as e:
            self._log_action("read_file_error", {
                "plugin": self.plugin_name,
                "path": str(resolved),
                "error": str(e),
            })
            return None

    def write_file(self, file_path: str, content: str) -> bool:
        """Write a file, restricted to the plugin's directory."""
        if not self._check_permission("filesystem"):
            return False

        resolved = (self.plugin_dir / file_path).resolve()
        if not str(resolved).startswith(str(self.plugin_dir)):
            self._log_action("filesystem_violation", {
                "plugin": self.plugin_name,
                "attempted_path": file_path,
                "resolved_path": str(resolved),
            })
            return False

        self._log_action("write_file", {
            "plugin": self.plugin_name,
            "path": str(resolved),
        })

        try:
            resolved.write_text(content, encoding="utf-8")
            return True
        except Exception as e:
            self._log_action("write_file_error", {
                "plugin": self.plugin_name,
                "path": str(resolved),
                "error": str(e),
            })
            return False

    def make_network_request(self, url: str, **kwargs: Any) -> Optional[Any]:
        """Make a network request (requires 'network' permission)."""
        if not self._check_permission("network"):
            return None

        self._log_action("network_request", {
            "plugin": self.plugin_name,
            "url": url,
            "kwargs": {k: v for k, v in kwargs.items() if k != "headers"},
        })

        try:
            import urllib.error
            import urllib.request

            req = urllib.request.Request(url, **kwargs)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            self._log_action("network_error", {
                "plugin": self.plugin_name,
                "url": url,
                "error": str(e),
            })
            return None

    def run_subprocess(
        self,
        args: list[str],
        timeout: int = 60,
        cwd: Optional[str] = None,
    ) -> SandboxResult:
        """Run a subprocess with restrictions."""
        if not self._check_permission("subprocess"):
            return SandboxResult(
                allowed=False,
                error=f"Plugin '{self.plugin_name}' lacks 'subprocess' permission",
                command=" ".join(args),
                source="plugin",
            )

        effective_cwd = Path(cwd).resolve() if cwd else self.plugin_dir
        if not str(effective_cwd).startswith(str(self.plugin_dir)):
            return SandboxResult(
                allowed=False,
                error="Subprocess cwd must be within plugin directory",
                command=" ".join(args),
                source="plugin",
            )

        self._log_action("run_subprocess", {
            "plugin": self.plugin_name,
            "args": args,
            "cwd": str(effective_cwd),
        })

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(effective_cwd),
            )
            return SandboxResult(
                allowed=True,
                output=result.stdout,
                error=result.stderr,
                command=" ".join(args),
                source="plugin",
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                allowed=False,
                timed_out=True,
                error=f"Subprocess timeout ({timeout}s)",
                command=" ".join(args),
                source="plugin",
            )
        except Exception as e:
            return SandboxResult(
                allowed=False,
                error=str(e),
                command=" ".join(args),
                source="plugin",
            )


# ── Plugin Runner (Subprocess Isolation) ────────────────────────────────

PLUGIN_RUNNER_SCRIPT = '''
import sys
import json
import importlib
from pathlib import Path

def run_entry_point(plugin_dir, entry_point, args):
    sys.path.insert(0, str(plugin_dir))
    module_path, func_name = entry_point.rsplit(".", 1)
    mod = importlib.import_module(module_path)
    func = getattr(mod, func_name)
    result = func(**args) if isinstance(args, dict) else func(*args)
    print(json.dumps({"success": True, "result": str(result)}))
    return 0

if __name__ == "__main__":
    config = json.loads(sys.argv[1])
    try:
        sys.exit(run_entry_point(
            Path(config["plugin_dir"]),
            config["entry_point"],
            config.get("args", {}),
        ))
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}))
        sys.exit(1)
'''


class PluginRunner:
    """Runs plugin code in an isolated subprocess."""

    def __init__(self, plugin_info: PluginInfo, sandbox: PluginSandbox):
        self.plugin_info = plugin_info
        self.sandbox = sandbox

    def run(self, args: Optional[dict[str, Any]] = None, timeout: int = 120) -> dict[str, Any]:
        """Execute the plugin's entry point in a subprocess."""
        manifest = self.plugin_info.manifest
        config = {
            "plugin_dir": str(self.plugin_info.path),
            "entry_point": manifest.entry_point,
            "args": args or {},
        }

        try:
            result = subprocess.run(
                [sys.executable, "-c", PLUGIN_RUNNER_SCRIPT, json.dumps(config)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.plugin_info.path),
            )

            if result.returncode == 0 and result.stdout:
                try:
                    return json.loads(result.stdout.strip())
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON output from plugin"}

            error_output = result.stderr.strip() or "Plugin subprocess failed"
            self.sandbox._log_action("subprocess_error", {
                "plugin": manifest.name,
                "stderr": error_output,
            })
            return {"success": False, "error": error_output}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Plugin timeout ({timeout}s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ── File Watcher for Hot-Reload ─────────────────────────────────────────

class _PluginFileChangeHandler(FileSystemEventHandler):
    """Watchdog handler that triggers reload on file changes."""

    def __init__(self, on_change: Callable[[str], None], watched_extensions: set[str] | None = None):
        super().__init__()
        self.on_change = on_change
        self.watched_extensions = watched_extensions or {".py", ".yaml", ".yml", ".json", ".toml"}
        self._cooldown: dict[str, float] = {}
        self._cooldown_seconds = 2.0

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = str(event.src_path)
        if not any(path.endswith(ext) for ext in self.watched_extensions):
            return
        now = time.time()
        last = self._cooldown.get(path, 0)
        if now - last < self._cooldown_seconds:
            return
        self._cooldown[path] = now
        logger.info(f"File change detected: {path}")
        self.on_change(path)

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = str(event.src_path)
        if any(path.endswith(ext) for ext in self.watched_extensions):
            logger.info(f"New file detected: {path}")
            self.on_change(path)


class PluginFileWatcher:
    """Watches plugin directories for file changes and triggers hot-reload."""

    def __init__(
        self,
        plugins_dir: str,
        on_plugin_change: Callable[[str], None],
    ):
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("watchdog is required for file watching. Install with: pip install watchdog")

        self.plugins_dir = Path(plugins_dir)
        self.on_plugin_change = on_plugin_change
        self.observer: Optional[Observer] = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return

        self.observer = Observer()
        handler = _PluginFileChangeHandler(self.on_plugin_change)

        if self.plugins_dir.exists():
            for subdir in self.plugins_dir.iterdir():
                if subdir.is_dir():
                    self.observer.schedule(handler, str(subdir), recursive=True)

        self.observer.start()
        self._running = True
        logger.info(f"Plugin file watcher started on {self.plugins_dir}")

    def stop(self) -> None:
        if self.observer and self._running:
            self.observer.stop()
            self.observer.join()
            self._running = False
            logger.info("Plugin file watcher stopped")

    def rescan(self) -> None:
        """Rescan plugin directories and update watched paths."""
        if not self.observer or not self._running:
            return
        self.observer.unschedule_all()
        handler = _PluginFileChangeHandler(self.on_plugin_change)
        if self.plugins_dir.exists():
            for subdir in self.plugins_dir.iterdir():
                if subdir.is_dir():
                    self.observer.schedule(handler, str(subdir), recursive=True)


# ── Plugin Manager ──────────────────────────────────────────────────────

class PluginManager:
    """Central plugin lifecycle manager.

    Handles discovery, validation, loading, unloading, hot-reload,
    installation, and uninstallation of plugins.
    """

    def __init__(
        self,
        plugins_dir: str = "plugins",
        command_sandbox: Optional[CommandSandbox] = None,
        audit_logger: Optional[AuditLogger] = None,
        specter_version: str = "1.0.0",
    ):
        self.plugins_dir = Path(plugins_dir).resolve()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.command_sandbox = command_sandbox or CommandSandbox()
        self.audit_logger = audit_logger or AuditLogger()
        self.specter_version = specter_version

        self._plugins: dict[str, PluginInfo] = {}
        self._sandboxes: dict[str, PluginSandbox] = {}
        self._runners: dict[str, PluginRunner] = {}
        self._file_watcher: Optional[PluginFileWatcher] = None

    # ── Discovery ───────────────────────────────────────────────────────

    def discover_plugins(self, plugins_dir: Optional[str] = None) -> dict[str, PluginManifest]:
        """Scan directory for plugin.yaml files and return discovered manifests."""
        target = Path(plugins_dir).resolve() if plugins_dir else self.plugins_dir
        discovered: dict[str, PluginManifest] = {}

        if not target.exists():
            logger.warning(f"Plugins directory does not exist: {target}")
            return discovered

        for item in sorted(target.iterdir()):
            if not item.is_dir():
                continue
            yaml_path = item / "plugin.yaml"
            if not yaml_path.exists():
                continue
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    logger.warning(f"Invalid plugin.yaml in {item}: not a mapping")
                    continue
                manifest = PluginManifest(**data)
                discovered[manifest.name] = manifest

                if manifest.name not in self._plugins:
                    self._plugins[manifest.name] = PluginInfo(
                        manifest=manifest,
                        path=item,
                        state=PluginState.DISCOVERED,
                    )
                else:
                    self._plugins[manifest.name].manifest = manifest
                    self._plugins[manifest.name].path = item
                    self._plugins[manifest.name].state = PluginState.DISCOVERED

            except ValidationError as e:
                logger.error(f"Schema validation failed for {item / 'plugin.yaml'}: {e}")
            except Exception as e:
                logger.error(f"Failed to parse plugin.yaml in {item}: {e}")

        logger.info(f"Discovered {len(discovered)} plugin(s) in {target}")
        return discovered

    # ── Validation ──────────────────────────────────────────────────────

    def validate_plugin(self, path: Path) -> bool:
        """Validate plugin schema and check dependencies are installed."""
        yaml_path = path / "plugin.yaml"
        if not yaml_path.exists():
            logger.error(f"No plugin.yaml found at {path}")
            return False

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            manifest = PluginManifest(**data)
        except ValidationError as e:
            logger.error(f"Schema validation failed for {path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to parse plugin.yaml at {path}: {e}")
            return False

        if manifest.min_specter_version:
            if not self._version_gte(self.specter_version, manifest.min_specter_version):
                logger.error(
                    f"Plugin '{manifest.name}' requires T-100AI >= {manifest.min_specter_version}, "
                    f"current is {self.specter_version}"
                )
                return False

        missing_deps = self._check_dependencies(manifest.dependencies)
        if missing_deps:
            logger.error(
                f"Plugin '{manifest.name}' has missing dependencies: {missing_deps}"
            )
            return False

        entry_module, entry_func = manifest.entry_point.rsplit(".", 1)
        module_file = path / f"{entry_module.replace('.', os.sep)}.py"
        init_file = path / entry_module / "__init__.py"
        if not module_file.exists() and not init_file.exists():
            logger.error(
                f"Plugin '{manifest.name}' entry point module not found: {entry_module}"
            )
            return False

        name = manifest.name
        if name in self._plugins:
            self._plugins[name].manifest = manifest
            self._plugins[name].state = PluginState.VALIDATED
            self._plugins[name].error = None
        else:
            self._plugins[name] = PluginInfo(
                manifest=manifest,
                path=path,
                state=PluginState.VALIDATED,
            )

        logger.info(f"Plugin '{manifest.name}' validated successfully")
        return True

    def _check_dependencies(self, dependencies: list[str]) -> list[str]:
        """Check which pip packages are missing."""
        if not dependencies:
            return []

        missing = []
        for dep in dependencies:
            pkg_name = dep.split("==")[0].split(">=")[0].split("<=")[0].strip()
            if not self._is_package_installed(pkg_name):
                missing.append(dep)
        return missing

    def _is_package_installed(self, package_name: str) -> bool:
        """Check if a pip package is installed."""
        try:
            import importlib.metadata
            importlib.metadata.version(package_name)
            return True
        except Exception:
            pass
        try:
            import importlib
            importlib.import_module(package_name)
            return True
        except Exception:
            return False

    def _version_gte(self, current: str, required: str) -> bool:
        """Check if current version >= required version."""
        def _parse(v: str) -> tuple[int, ...]:
            parts = v.split("-")[0].split("+")[0]
            return tuple(int(x) for x in parts.split(".") if x.isdigit())

        try:
            return _parse(current) >= _parse(required)
        except Exception:
            return True

    # ── Loading ─────────────────────────────────────────────────────────

    def load_plugin(self, path: Path) -> bool:
        """Load and initialize a plugin from its directory."""
        if not self.validate_plugin(path):
            return False

        name = self._plugins.get(path.name)
        if name is None:
            yaml_path = path / "plugin.yaml"
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                name = data.get("name", path.name)
            except Exception:
                name = path.name

        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            logger.error(f"No plugin info for {name}")
            return False

        try:
            module = self._import_plugin_module(plugin_info)
            if module is None:
                plugin_info.state = PluginState.ERROR
                plugin_info.error = "Failed to import plugin module"
                return False

            plugin_info.module = module
            plugin_info.state = PluginState.LOADED
            plugin_info.loaded_at = datetime.now(timezone.utc)

            sandbox = PluginSandbox(
                plugin_name=name,
                plugin_dir=plugin_info.path,
                permissions=set(plugin_info.manifest.permissions),
                command_sandbox=self.command_sandbox,
                audit_logger=self.audit_logger,
            )
            self._sandboxes[name] = sandbox

            runner = PluginRunner(plugin_info, sandbox)
            self._runners[name] = runner

            plugin_info.file_hashes = self._compute_file_hashes(plugin_info.path)

            self._log_plugin_event("load", name, {"path": str(plugin_info.path)})
            logger.info(f"Plugin '{name}' loaded successfully")
            return True

        except Exception as e:
            plugin_info.state = PluginState.ERROR
            plugin_info.error = str(e)
            logger.error(f"Failed to load plugin '{name}': {e}")
            return False

    def _import_plugin_module(self, plugin_info: PluginInfo) -> Optional[Any]:
        """Dynamically import a plugin's entry point module."""
        manifest = plugin_info.manifest
        module_path, func_name = manifest.entry_point.rsplit(".", 1)

        sys.path.insert(0, str(plugin_info.path))

        try:
            spec = importlib.util.find_spec(module_path)
            if spec is None:
                dotted = module_path.replace(".", os.sep)
                py_file = plugin_info.path / f"{dotted}.py"
                pkg_dir = plugin_info.path / module_path.replace(".", os.sep) / "__init__.py"
                if py_file.exists():
                    spec = importlib.util.spec_from_file_location(module_path, py_file)
                elif pkg_dir.exists():
                    spec = importlib.util.spec_from_file_location(
                        module_path, pkg_dir
                    )
                else:
                    logger.error(f"Cannot find module '{module_path}' for plugin '{manifest.name}'")
                    return None

            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_path] = module
            spec.loader.exec_module(module)

            if not hasattr(module, func_name):
                logger.error(
                    f"Entry point function '{func_name}' not found in module '{module_path}'"
                )
                return None

            return module

        except Exception as e:
            logger.error(f"Error importing module '{module_path}': {e}")
            return None

    # ── Unloading ───────────────────────────────────────────────────────

    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin by name."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            logger.warning(f"Plugin '{name}' not found")
            return False

        try:
            if plugin_info.instance and hasattr(plugin_info.instance, "shutdown"):
                plugin_info.instance.shutdown()

            module_name = plugin_info.manifest.entry_point.rsplit(".", 1)[0]
            if module_name in sys.modules:
                del sys.modules[module_name]

            plugin_info.module = None
            plugin_info.instance = None
            plugin_info.state = PluginState.DISCOVERED
            plugin_info.loaded_at = None

            self._sandboxes.pop(name, None)
            self._runners.pop(name, None)

            self._log_plugin_event("unload", name, {})
            logger.info(f"Plugin '{name}' unloaded")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin '{name}': {e}")
            return False

    # ── Reloading (Hot-Reload) ──────────────────────────────────────────

    def reload_plugin(self, name: str) -> bool:
        """Hot-reload a plugin by detecting file changes."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            logger.warning(f"Plugin '{name}' not found for reload")
            return False

        current_hashes = self._compute_file_hashes(plugin_info.path)
        if current_hashes == plugin_info.file_hashes:
            logger.info(f"Plugin '{name}' has no file changes, skipping reload")
            return True

        was_enabled = plugin_info.state == PluginState.ENABLED

        if plugin_info.state in (PluginState.LOADED, PluginState.ENABLED):
            self.unload_plugin(name)

        success = self.load_plugin(plugin_info.path)
        if success and was_enabled:
            self.enable_plugin(name)

        self._log_plugin_event("reload", name, {
            "file_changes": len(set(current_hashes.keys()) ^ set(plugin_info.file_hashes.keys())),
        })
        return success

    def _compute_file_hashes(self, directory: Path) -> dict[str, str]:
        """Compute SHA-256 hashes for all Python files in a directory."""
        import hashlib
        hashes: dict[str, str] = {}
        for py_file in directory.rglob("*.py"):
            try:
                content = py_file.read_bytes()
                hashes[str(py_file)] = hashlib.sha256(content).hexdigest()
            except Exception:
                pass
        yaml_file = directory / "plugin.yaml"
        if yaml_file.exists():
            try:
                content = yaml_file.read_bytes()
                hashes[str(yaml_file)] = hashlib.sha256(content).hexdigest()
            except Exception:
                pass
        return hashes

    # ── Enable / Disable ────────────────────────────────────────────────

    def enable_plugin(self, name: str) -> bool:
        """Enable a loaded plugin."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            return False
        if plugin_info.state == PluginState.ERROR:
            logger.error(f"Cannot enable plugin '{name}' in error state: {plugin_info.error}")
            return False

        if plugin_info.state not in (PluginState.LOADED, PluginState.DISABLED):
            if not self.load_plugin(plugin_info.path):
                return False

        plugin_info.state = PluginState.ENABLED
        self._log_plugin_event("enable", name, {})
        logger.info(f"Plugin '{name}' enabled")
        return True

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin without unloading it."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            return False
        if plugin_info.state != PluginState.ENABLED:
            return False

        plugin_info.state = PluginState.DISABLED
        self._log_plugin_event("disable", name, {})
        logger.info(f"Plugin '{name}' disabled")
        return True

    # ── Listing ─────────────────────────────────────────────────────────

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all known plugins with their status."""
        result = []
        for name, info in self._plugins.items():
            entry: dict[str, Any] = {
                "name": name,
                "version": info.manifest.version,
                "description": info.manifest.description,
                "author": info.manifest.author,
                "state": info.state.value,
                "permissions": info.manifest.permissions,
                "dependencies": info.manifest.dependencies,
                "entry_point": info.manifest.entry_point,
                "path": str(info.path),
                "loaded_at": info.loaded_at.isoformat() if info.loaded_at else None,
                "error": info.error,
            }
            result.append(entry)
        return result

    # ── Installation ────────────────────────────────────────────────────

    def install_plugin(self, archive_path: str) -> bool:
        """Extract and install a plugin from a .zip or .tar.gz archive."""
        archive = Path(archive_path)
        if not archive.exists():
            logger.error(f"Archive not found: {archive_path}")
            return False

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            try:
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive, "r") as zf:
                        zf.extractall(tmp)
                elif archive.suffix in (".gz", ".tgz") or str(archive).endswith(".tar.gz"):
                    with tarfile.open(archive, "r:gz") as tf:
                        tf.extractall(tmp)
                else:
                    logger.error(f"Unsupported archive format: {archive.suffix}")
                    return False
            except Exception as e:
                logger.error(f"Failed to extract archive: {e}")
                return False

            plugin_dir = self._find_plugin_directory(tmp)
            if plugin_dir is None:
                logger.error("No plugin.yaml found in archive")
                return False

            try:
                manifest_data = yaml.safe_load((plugin_dir / "plugin.yaml").read_text())
                manifest = PluginManifest(**manifest_data)
            except Exception as e:
                logger.error(f"Invalid plugin.yaml in archive: {e}")
                return False

            dest = self.plugins_dir / manifest.name
            if dest.exists():
                logger.warning(f"Plugin '{manifest.name}' already exists, replacing")
                shutil.rmtree(dest)

            shutil.copytree(plugin_dir, dest)

            self._plugins[manifest.name] = PluginInfo(
                manifest=manifest,
                path=dest,
                state=PluginState.DISCOVERED,
            )

            self._log_plugin_event("install", manifest.name, {
                "archive": str(archive),
                "destination": str(dest),
            })
            logger.info(f"Plugin '{manifest.name}' installed to {dest}")
            return True

    def _find_plugin_directory(self, root: Path) -> Optional[Path]:
        """Find the directory containing plugin.yaml in extracted archive."""
        yaml_files = list(root.rglob("plugin.yaml"))
        if not yaml_files:
            return None
        return yaml_files[0].parent

    # ── Uninstallation ──────────────────────────────────────────────────

    def uninstall_plugin(self, name: str) -> bool:
        """Uninstall a plugin by name."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            logger.warning(f"Plugin '{name}' not found for uninstall")
            return False

        if plugin_info.state in (PluginState.LOADED, PluginState.ENABLED, PluginState.DISABLED):
            self.unload_plugin(name)

        plugin_path = plugin_info.path
        try:
            if plugin_path.exists():
                shutil.rmtree(plugin_path)
        except Exception as e:
            logger.error(f"Failed to remove plugin directory: {e}")
            return False

        plugin_info.state = PluginState.UNINSTALLED
        self._plugins.pop(name, None)
        self._sandboxes.pop(name, None)
        self._runners.pop(name, None)

        self._log_plugin_event("uninstall", name, {"path": str(plugin_path)})
        logger.info(f"Plugin '{name}' uninstalled")
        return True

    # ── File Watcher (Hot-Reload) ───────────────────────────────────────

    def watch_for_changes(self) -> None:
        """Start file watcher for automatic hot-reload."""
        if not WATCHDOG_AVAILABLE:
            logger.error("watchdog not installed. Run: pip install watchdog")
            return

        if self._file_watcher and self._file_watcher._running:
            logger.warning("File watcher is already running")
            return

        def on_change(file_path: str) -> None:
            plugin_name = self._find_plugin_for_file(Path(file_path))
            if plugin_name:
                logger.info(f"Reloading plugin '{plugin_name}' due to file change")
                self.reload_plugin(plugin_name)

        self._file_watcher = PluginFileWatcher(
            plugins_dir=str(self.plugins_dir),
            on_plugin_change=on_change,
        )
        self._file_watcher.start()

    def stop_watcher(self) -> None:
        """Stop the file watcher."""
        if self._file_watcher:
            self._file_watcher.stop()
            self._file_watcher = None

    def _find_plugin_for_file(self, file_path: Path) -> Optional[str]:
        """Find which plugin a file belongs to."""
        resolved = file_path.resolve()
        for name, info in self._plugins.items():
            if str(resolved).startswith(str(info.path.resolve())):
                return name
        return None

    # ── Execute Plugin (via Sandbox) ────────────────────────────────────

    def execute_plugin(
        self,
        name: str,
        args: Optional[dict[str, Any]] = None,
        use_subprocess: bool = True,
    ) -> dict[str, Any]:
        """Execute a plugin's entry point, optionally in a subprocess sandbox."""
        plugin_info = self._plugins.get(name)
        if plugin_info is None:
            return {"success": False, "error": f"Plugin '{name}' not found"}

        if plugin_info.state != PluginState.ENABLED:
            if not self.enable_plugin(name):
                return {"success": False, "error": f"Plugin '{name}' could not be enabled"}

        if use_subprocess:
            runner = self._runners.get(name)
            if runner is None:
                return {"success": False, "error": f"No runner for plugin '{name}'"}
            return runner.run(args)

        sandbox = self._sandboxes.get(name)
        if sandbox is None:
            return {"success": False, "error": f"No sandbox for plugin '{name}'"}

        try:
            module = plugin_info.module
            if module is None:
                return {"success": False, "error": "Plugin module not loaded"}

            _, func_name = plugin_info.manifest.entry_point.rsplit(".", 1)
            func = getattr(module, func_name)

            if args:
                result = func(**args)
            else:
                result = func()

            return {"success": True, "result": str(result)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Audit Logging Helper ────────────────────────────────────────────

    def _log_plugin_event(self, event: str, name: str, details: dict[str, Any]) -> None:
        self.audit_logger.log_action(
            session_id=f"plugin:{name}",
            action=f"plugin_{event}",
            tool="plugin_manager",
            params={"plugin": name, **details},
            result=None,
        )

    # ── Cleanup ─────────────────────────────────────────────────────────

    def shutdown_all(self) -> None:
        """Unload all plugins and stop the file watcher."""
        self.stop_watcher()
        for name in list(self._plugins.keys()):
            if self._plugins[name].state in (
                PluginState.LOADED,
                PluginState.ENABLED,
                PluginState.DISABLED,
            ):
                self.unload_plugin(name)
        logger.info("All plugins shut down")
