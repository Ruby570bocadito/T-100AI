"""Recon Skill - Reconocimiento y Enumeración"""

import asyncio
import shutil
import time
from typing import Any

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()


class ReconSkill(BaseSkill):
    """
    Skill de Reconocimiento

    Proporciona herramientas para:
    - Escaneo de puertos
    - Descubrimiento de hosts
    - Enumeración de servicios
    - Fingerprinting
    """

    name = "recon"
    description = "Reconocimiento y enumeración de objetivos"
    category = "recon"
    risk_level = RiskLevel.ACTIVE

    def __init__(self):
        super().__init__()
        self.tools = [
            "network.port_scan",
            "network.ping_sweep",
            "network.dns_enum",
            "network.service_enum",
            "recon.vuln_scan",
            "recon.ssl_analyze",
            "recon.snmp_enum",
        ]
        self.workflows = ["full_recon", "quick_scan", "web_footprint"]

    def get_available_actions(self) -> list[str]:
        return [
            "port_scan",
            "ping_sweep",
            "dns_enum",
            "service_scan",
            "os_fingerprint",
            "vuln_scan",
            "ssl_analyze",
            "snmp_enum",
        ]

    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        if action == "port_scan":
            return "target" in params
        if action == "ping_sweep":
            return "target" in params
        if action == "dns_enum":
            return "domain" in params
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        start_time = time.time()

        match action:
            case "port_scan":
                return await self._port_scan(params, start_time)
            case "ping_sweep":
                return await self._ping_sweep(params, start_time)
            case "dns_enum":
                return await self._dns_enum(params, start_time)
            case "service_scan":
                return await self._service_scan(params, start_time)
            case "os_fingerprint":
                return await self._os_fingerprint(params, start_time)
            case "vuln_scan":
                return await self._vuln_scan(params, start_time)
            case "ssl_analyze":
                return await self._ssl_analyze(params, start_time)
            case "snmp_enum":
                return await self._snmp_enum(params, start_time)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")

    async def _run_cmd(
        self, cmd: list[str], timeout: int = 300
    ) -> tuple[str, str, int]:
        """Ejecuta un comando de forma async sin bloquear el event loop."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
                proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            return "", f"Timeout after {timeout}s", -1
        except FileNotFoundError:
            return "", f"{cmd[0]} not found", -2

    async def _port_scan(self, params: dict, start: float) -> SkillResult:
        """Ejecuta escaneo de puertos con nmap"""
        target = params["target"]
        ports = params.get("ports", "1-1000")
        scan_type = params.get("scan_type", "-sS")
        timing = params.get("timing", "-T3")
        outfile = f"/tmp/specter_nmap_{target.replace('.', '_')}"

        cmd = ["nmap", scan_type, timing, "-p", ports, "-oA", outfile, target]
        logger.info("Running nmap", target=target, ports=ports)

        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 300))
        output = stdout + stderr

        if rc == -2:
            return SkillResult(
                success=False,
                error="nmap no está instalado. Instálalo con: sudo apt install nmap",
                execution_time=time.time() - start,
            )
        if rc == -1:
            return SkillResult(
                success=False,
                error=f"Timeout en escaneo de {target}",
                execution_time=time.time() - start,
            )

        findings = self._parse_nmap_output(output, target)
        return SkillResult(
            success=rc == 0,
            output=output,
            findings=findings,
            artifacts={
                f"{outfile}.xml": "Resultado XML de nmap",
                f"{outfile}.nmap": "Resultado normal de nmap",
            },
            execution_time=time.time() - start,
        )

    async def _ping_sweep(self, params: dict, start: float) -> SkillResult:
        """Ejecuta ping sweep para descubrir hosts"""
        target = params["target"]
        cmd = ["nmap", "-sn", "-oG", "-", target]
        logger.info("Running ping sweep", target=target)

        stdout, stderr, rc = await self._run_cmd(cmd, 60)
        output = stdout + stderr

        hosts = [line for line in output.split("\n") if "Up" in line or "Status: Up" in line]
        return SkillResult(
            success=rc == 0,
            output=f"Hosts descubiertos: {len(hosts)}\n" + "\n".join(hosts[:20]),
            findings=[{"type": "host_discovered", "count": len(hosts)}],
            execution_time=time.time() - start,
        )

    async def _dns_enum(self, params: dict, start: float) -> SkillResult:
        """Enumeración DNS"""
        domain = params["domain"]

        stdout, stderr, rc = await self._run_cmd(["dig", "+short", domain, "ANY"], 30)
        if rc == 0 and stdout:
            return SkillResult(success=True, output=stdout, execution_time=time.time() - start)

        # Fallback a nslookup
        stdout2, stderr2, rc2 = await self._run_cmd(["nslookup", domain], 30)
        if rc2 == -2:
            return SkillResult(success=False, error="Ni dig ni nslookup instalados", execution_time=time.time() - start)
        return SkillResult(success=rc2 == 0, output=stdout2 or "Sin resultados", execution_time=time.time() - start)

    async def _service_scan(self, params: dict, start: float) -> SkillResult:
        """Escaneo de servicios con detección de versiones"""
        target = params["target"]
        ports = params.get("ports", "top-100")
        cmd = ["nmap", "-sV", "-T4", "-p", ports, target]
        logger.info("Running service scan", target=target)

        stdout, stderr, rc = await self._run_cmd(cmd, 300)
        output = stdout + stderr
        findings = self._parse_nmap_output(output, target)
        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _os_fingerprint(self, params: dict, start: float) -> SkillResult:
        """Fingerprinting de sistema operativo"""
        target = params["target"]
        stdout, stderr, rc = await self._run_cmd(["nmap", "-O", "-T4", target], 120)
        return SkillResult(success=rc == 0, output=stdout + stderr, execution_time=time.time() - start)

    async def _vuln_scan(self, params: dict, start: float) -> SkillResult:
        """Escaneo de vulnerabilidades con nmap --script vuln"""
        target = params["target"]
        ports = params.get("ports", "1-1000")
        outfile = f"/tmp/specter_nmap_vuln_{target.replace('.', '_')}"
        cmd = ["nmap", "-sV", "--script", "vuln", "-p", ports, "-T4", "-oA", outfile, target]

        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 600))
        output = stdout + stderr

        if rc == -2:
            return SkillResult(success=False, error="nmap no está instalado", execution_time=time.time() - start)
        if rc == -1:
            return SkillResult(success=False, error=f"Timeout en vuln scan de {target}", execution_time=time.time() - start)

        findings = self._parse_nmap_output(output, target)
        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _ssl_analyze(self, params: dict, start: float) -> SkillResult:
        """Análisis de SSL con sslscan o testssl.sh"""
        target = params["target"]
        ssl_target = target if ":" in target else f"{target}:443"

        if shutil.which("sslscan"):
            cmd = ["sslscan", ssl_target]
        elif shutil.which("testssl.sh"):
            cmd = ["bash", "./testssl.sh", ssl_target]
        else:
            return SkillResult(success=False, error="ni sslscan ni testssl.sh están instalados", execution_time=time.time() - start)

        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 300))
        output = stdout + stderr

        findings = []
        if "RC4" in output or "weak" in output or "VULNERABLE" in output:
            findings.append({"type": "ssl_issue", "description": "Potential SSL weakness", "severity": "HIGH"})

        return SkillResult(
            success=rc == 0,
            output=output,
            findings=findings or [{"type": "ssl_analysis", "description": "No obvious issues"}],
            execution_time=time.time() - start,
        )

    async def _snmp_enum(self, params: dict, start: float) -> SkillResult:
        """Enumeración SNMP simple con snmpwalk"""
        target = params["target"]
        community = params.get("community", "public")
        cmd = ["snmpwalk", "-v2c", "-c", community, target]

        stdout, stderr, rc = await self._run_cmd(cmd, 60)
        if rc == -2:
            return SkillResult(success=False, error="snmpwalk no está instalado", execution_time=time.time() - start)

        findings = []
        for line in stdout.splitlines():
            if line.strip():
                findings.append({"type": "snmp", "oid": line.split(" ", 1)[0], "value": line.strip()})

        return SkillResult(
            success=rc == 0,
            output=stdout,
            findings=findings if findings else [{"type": "snmp", "value": "No SNMP data"}],
            execution_time=time.time() - start,
        )

    def _parse_nmap_output(self, output: str, target: str) -> list[dict]:
        """Parsea output de nmap y extrae hallazgos"""
        findings = []
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    if state == "open":
                        findings.append({
                            "type": "open_port",
                            "target": target,
                            "port": port,
                            "service": service,
                            "severity": "INFO",
                        })

            if "OS details:" in line or "OS:" in line:
                findings.append({"type": "os_detected", "target": target, "os": line.strip(), "severity": "INFO"})

            if "CVE-" in line:
                findings.append({"type": "potential_vulnerability", "target": target, "cve": line.strip(), "severity": "HIGH"})

        return findings
