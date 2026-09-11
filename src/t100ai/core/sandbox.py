"""Command Sandbox - Allow-all con blacklist de destructivos.

Diseñado para CTF y pentesting profesional.
Solo bloquea comandos que destruyen sistemas o causan daño irreversible.
Todo lo demás está permitido.
"""

import json
import os
import re
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class SandboxResult:
    """Resultado de ejecutar un comando con sandbox."""
    allowed: bool
    output: str = ""
    error: str = ""
    timed_out: bool = False
    dry_run: bool = False
    command: str = ""
    requires_confirmation: bool = False
    source: str = "unknown"  # "llm" o "manual"


class CommandSandbox:
    """
    Sandbox allow-all con blacklist de destructivos.

    Filosofía: "Permitir todo excepto lo que destruye sistemas."
    Diseñado para CTF y pentesting profesional donde necesitas
    reverse shells, privilege escalation, y cualquier herramienta.

    Restricciones activas:
    1. Blacklist de patrones destructivos (rm -rf, dd, mkfs, fork bombs)
    2. Rate limiting (evita loops infinitos del LLM)
    3. Scope validation (targets deben estar en scope autorizado)
    4. Límite de comandos por sesión
    5. Logging separado LLM vs manual
    6. Dry-run mode
    """

    # === Blacklist: Solo destructivos ===
    BLOCKED_PATTERNS: list[str] = [
        # Destructivos de disco/sistema (any flag order)
        r'\brm\s+(-rf|--recursive.*-f|-f.*--recursive|--no-preserve-root)\s+/$',
        r'\brm\s+(-r\s+-f|-f\s+-r)\s+/$',
        r'\brm\s+(-rf|--no-preserve-root)\s+/$',
        r'\bdd\s+if=/dev/(zero|urandom|random)\s+of=/dev/(sd|hd|vd|xvd|nvme|mmcblk)',
        r'\bdd\s+of=/dev/(sd|hd|vd|xvd|nvme|mmcblk)',
        r'\bmkfs\.\w+\s+/dev/(sd|hd|vd|xvd|nvme|mmcblk)',
        r'>\s*/dev/(sd|hd|vd|xvd|nvme|mmcblk)\w*',
        r'\b(sgdisk\s+--?zap-all|wipefs\s+-a\s+/dev/|blkdiscard\s+/dev/)',
        # Fork bombs
        r':\(\)\{:\|:&\};:',
        r'\b:\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;',
        # Apagado/reinicio del sistema (all variants)
        r'\bshutdown\s+(-h|-r|-P)\b',
        r'\bshutdown\b.*\b(now|halt|poweroff|reboot)\b',
        r'\binit\s+0\b',
        r'\breboot\b',
        r'(/sbin/|/usr/sbin/)?halt\b',
        r'(/sbin/|/usr/sbin/)?poweroff\b',
        r'\bsystemctl\s+(poweroff|reboot|halt)\b',
        # Matar procesos críticos del sistema (all signal variants)
        r'\bkill\s+(-9|--signal\s*SIGKILL|-SIGKILL)\s+1\b',
        r'\bpkill\s+(-9|--signal\s*SIGKILL|-SIGKILL)\s+-f\s+systemd',
        r'\bpkill\s+(-9|--signal\s*SIGKILL|-SIGKILL)\s+-f\s+init',
        r'\bkillall\s+(-9)?\s*(systemd|init|kthreadd)\b',
    ]

    # === Rate limiting por defecto ===
    DEFAULT_MAX_COMMANDS_PER_SESSION = 500
    DEFAULT_RATE_LIMIT_SECONDS = 2

    def __init__(
        self,
        timeout: int = 300,
        dry_run: bool = False,
        max_output_size: int = 1024 * 1024,  # 1MB
        permission_mode: str = "standard",  # paranoid | standard | expert
        max_commands: int = DEFAULT_MAX_COMMANDS_PER_SESSION,
        rate_limit: float = DEFAULT_RATE_LIMIT_SECONDS,
        scope_targets: Optional[list[str]] = None,
        log_dir: str = "sessions",
    ):
        self.timeout = timeout
        self.dry_run = dry_run
        self.max_output_size = max_output_size
        self.permission_mode = permission_mode
        self.max_commands = max_commands
        self.rate_limit = rate_limit
        self.scope_targets = scope_targets or []
        self._blocked_count = 0
        self._executed_count = 0
        self._last_command_time = 0.0
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)

    # ── Configuración dinámica ─────────────────────────────────────────

    def set_scope_targets(self, targets: list[str]) -> None:
        self.scope_targets = targets

    def set_permission_mode(self, mode: str) -> None:
        if mode in ("paranoid", "standard", "expert"):
            self.permission_mode = mode

    # ── Rate Limiting ──────────────────────────────────────────────────

    def _check_rate_limit(self) -> tuple[bool, str]:
        if self.rate_limit <= 0:
            return True, "OK"
        elapsed = time.time() - self._last_command_time
        if elapsed < self.rate_limit:
            remaining = self.rate_limit - elapsed
            return False, f"Rate limit: espera {remaining:.1f}s antes del siguiente comando"
        return True, "OK"

    # ── Scope Validation ───────────────────────────────────────────────

    def _extract_targets(self, command: str) -> list[str]:
        """Extrae IPs, dominios y URLs de un comando."""
        targets = []
        # IPs
        targets.extend(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            command
        ))
        # CIDR
        targets.extend(re.findall(
            r'\b(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})/(?:[0-9]|[1-2][0-9]|3[0-2])\b',
            command
        ))
        # URLs → extraer dominio
        for url in re.findall(r'https?://([^\s<>"{}|\\^`\[\]]+)', command):
            domain = url.split('/')[0].split(':')[0]
            if domain not in targets:
                targets.append(domain)
        # Dominios
        for d in re.findall(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|app|co|us|uk|eu|de|fr|es|it|ru|cn|jp|br|in|au|nl|pl|se|no|dk|fi|at|be|ch|ie|info|biz|xyz|top|site|live|cloud|tech|ai|app|me|tv|cc|pro|online|store)\b',
            command
        ):
            if d not in targets and not any(d in t for t in targets):
                targets.append(d)
        return targets

    def _check_scope(self, command: str) -> tuple[bool, str]:
        """Verifica que los targets del comando estén en scope autorizado."""
        if not self.scope_targets:
            return True, "OK"  # Sin scope = sin restricción

        cmd_targets = self._extract_targets(command)
        if not cmd_targets:
            return True, "OK"  # Comando sin targets (whoami, id, etc.)

        for target in cmd_targets:
            in_scope = False
            for scope_target in self.scope_targets:
                if target == scope_target:
                    in_scope = True
                    break
                if target.endswith(f".{scope_target}"):
                    in_scope = True
                    break
                if "/" in scope_target:
                    import ipaddress
                    try:
                        if ipaddress.ip_address(target) in ipaddress.ip_network(scope_target, strict=False):
                            in_scope = True
                            break
                    except ValueError:
                        pass
            if not in_scope:
                return False, (
                    f"Target '{target}' fuera de scope. "
                    f"Autorizados: {', '.join(self.scope_targets)}"
                )
        return True, "OK"

    # ── Límite de comandos ─────────────────────────────────────────────

    def _check_command_limit(self) -> tuple[bool, str]:
        if self._executed_count >= self.max_commands:
            return False, f"Límite alcanzado ({self.max_commands}). Usa /session para stats."
        return True, "OK"

    # ── Validación principal ──────────────────────────────────────────

    def validate(self, command: str, source: str = "llm") -> tuple[bool, str]:
        """
        Valida comando. Solo bloquea destructivos.

        Flujo:
        1. Límite de comandos
        2. Rate limiting
        3. Scope validation
        4. Blacklist de destructivos
        """
        command = command.strip()
        if not command:
            return False, "Comando vacío"

        ok, reason = self._check_command_limit()
        if not ok:
            return False, reason

        ok, reason = self._check_rate_limit()
        if not ok:
            return False, reason

        ok, reason = self._check_scope(command)
        if not ok:
            return False, reason

        # Blacklist de destructivos
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Comando destructivo bloqueado: {pattern}"

        # Semantic check: rm with -r and -f targeting /
        if self._is_rm_rf_root(command):
            return False, "Comando destructivo bloqueado: rm -rf /"

        return True, "OK"

    def _is_rm_rf_root(self, command: str) -> bool:
        """Semantic check for rm -rf targeting the filesystem root.

        Catches any flag ordering plus globs (``/*``) and path traversal
        that normalizes back to ``/`` (e.g. ``/home/../..``).
        """
        import shlex
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        if not parts or parts[0] != "rm":
            return False
        has_r = False
        has_f = False
        targets: list[str] = []
        for part in parts[1:]:
            if part.startswith("-"):
                flags = part.lstrip("-")
                if "r" in flags or "R" in flags:
                    has_r = True
                if "f" in flags:
                    has_f = True
            else:
                targets.append(part)
        if not (has_r and has_f):
            return False
        for target in targets:
            if target in ("/", "/*", "/.", "/.."):
                return True
            # Normalize paths that resolve back to root (e.g. /home/../..)
            if target.startswith("/") and os.path.normpath(target) == "/":
                return True
        return False

    def requires_confirmation(self, command: str) -> bool:
        """Determina si requiere confirmación del usuario."""
        # Paranoid: siempre
        if self.permission_mode == "paranoid":
            return True
        # Standard/expert: nunca (confiamos en el usuario)
        return False

    def execute(self, command: str, source: str = "llm") -> SandboxResult:
        """Ejecuta comando con todas las protecciones."""
        allowed, reason = self.validate(command, source)
        if not allowed:
            self._blocked_count += 1
            self._log_command(command, source, "blocked", reason)
            return SandboxResult(
                allowed=False, error=reason, command=command, source=source
            )

        if self.dry_run:
            self._log_command(command, source, "dry_run", "")
            return SandboxResult(
                allowed=True, dry_run=True, command=command,
                output=f"[DRY RUN] Se ejecutaría: {command}", source=source,
            )

        result = self._run_with_protections(command)

        if result.allowed:
            self._executed_count += 1
            self._last_command_time = time.time()
            self._log_command(command, source, "executed", "")
        else:
            self._blocked_count += 1
            self._log_command(command, source, "failed", result.error)

        result.source = source
        return result

    def _run_with_protections(self, command: str) -> SandboxResult:
        """Ejecuta con timeout y process group kill.

        Usa shlex.split para evitar shell injection cuando sea posible.
        Falls back to /bin/sh -c para comandos con pipes/redirections.
        En POSIX el proceso corre en su propio session/process-group
        (start_new_session) para poder matar todo el árbol en timeout.
        """
        try:
            if os.name == 'posix':
                has_shell_meta = bool(re.search(r'[|&;<>$`()]', command))
                if has_shell_meta:
                    args = ["/bin/sh", "-c", command]
                else:
                    try:
                        args = shlex.split(command)
                    except ValueError:
                        args = ["/bin/sh", "-c", command]
                    if not args:
                        args = ["/bin/sh", "-c", command]
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    start_new_session=True,
                )
                try:
                    stdout, stderr = proc.communicate(timeout=self.timeout)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    self._kill_process_tree(proc)
                    stdout, stderr = proc.communicate()
                    timed_out = True
            else:
                proc = subprocess.Popen(
                    command, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, errors="replace",
                )
                try:
                    stdout, stderr = proc.communicate(timeout=self.timeout)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    timed_out = True

            if timed_out:
                return SandboxResult(
                    allowed=False, timed_out=True,
                    output=(stdout or "")[:self.max_output_size],
                    error=f"Timeout ({self.timeout}s) — proceso terminado",
                    command=command,
                )

            output = (stdout or "")[:self.max_output_size]
            error = (stderr or "")[:self.max_output_size]
            if stdout and len(stdout) > self.max_output_size:
                output += f"\n[... output truncated at {self.max_output_size} bytes ...]"
            if stderr and len(stderr) > self.max_output_size:
                error += f"\n[... output truncated at {self.max_output_size} bytes ...]"
            return SandboxResult(
                allowed=True,
                output=output,
                error=error,
                command=command,
            )
        except Exception as e:
            return SandboxResult(allowed=False, error=str(e), command=command)

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen) -> None:
        """Mata el process group completo (POSIX) o el proceso (Windows)."""
        try:
            if os.name == 'posix':
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    # ── Logging ────────────────────────────────────────────────────────

    def _log_command(self, command: str, source: str, status: str, detail: str) -> None:
        log_file = self._log_dir / f"commands_{source}.jsonl"
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "source": source,
            "status": status,
            "detail": detail,
            "session_executed": self._executed_count,
            "session_blocked": self._blocked_count,
            "permission_mode": self.permission_mode,
        }
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    # ── Estadísticas ──────────────────────────────────────────────────

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    @property
    def executed_count(self) -> int:
        return self._executed_count

    @property
    def remaining_commands(self) -> int:
        return max(0, self.max_commands - self._executed_count)

    @property
    def seconds_since_last_command(self) -> float:
        if self._last_command_time == 0:
            return float('inf')
        return time.time() - self._last_command_time

    def get_stats(self) -> dict:
        return {
            "executed_commands": self._executed_count,
            "blocked_commands": self._blocked_count,
            "remaining_commands": self.remaining_commands,
            "max_commands": self.max_commands,
            "timeout": self.timeout,
            "dry_run": self.dry_run,
            "permission_mode": self.permission_mode,
            "rate_limit_seconds": self.rate_limit,
            "scope_targets": self.scope_targets,
            "blocked_patterns_count": len(self.BLOCKED_PATTERNS),
            "seconds_since_last_command": round(self.seconds_since_last_command, 1),
        }
