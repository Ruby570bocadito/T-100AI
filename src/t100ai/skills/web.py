"""Web Skill - Auditoría de Aplicaciones Web"""

import asyncio
import shutil
import time
from typing import Any

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()


class WebSkill(BaseSkill):
    """
    Skill de Auditoría Web

    Proporciona herramientas para:
    - Fuzzing de directorios (gobuster, ffuf)
    - Test de inyección SQL (sqlmap)
    - Escaneo de vulnerabilidades (Nuclei)
    - Detección de WAF (wafw00f)
    - Análisis de cabeceras HTTP
    """

    name = "web"
    description = "Auditoría de aplicaciones web - OWASP Top 10"
    category = "web"
    risk_level = RiskLevel.ACTIVE

    def __init__(self):
        super().__init__()
        self.tools = [
            "web.dir_fuzz",
            "web.sqlmap",
            "web.nuclei",
            "web.waf_detect",
            "web.header_analyze",
            "web.screenshot",
            "web.xss_test",
            "web.cors_scan",
            "web.graphql_map",
        ]
        self.workflows = ["web_audit", "quick_web_scan"]

    def get_available_actions(self) -> list[str]:
        return [
            "dir_fuzz",
            "sqlmap_test",
            "nuclei_scan",
            "waf_detect",
            "header_analyze",
            "screenshot",
            "xss_test",
            "cors_scan",
            "graphql_map",
        ]

    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        if action in ("dir_fuzz", "sqlmap_test", "nuclei_scan", "waf_detect", "header_analyze", "screenshot"):
            return "target" in params
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        start_time = time.time()

        match action:
            case "dir_fuzz":
                return await self._dir_fuzz(params, start_time)
            case "sqlmap_test":
                return await self._sqlmap_test(params, start_time)
            case "nuclei_scan":
                return await self._nuclei_scan(params, start_time)
            case "waf_detect":
                return await self._waf_detect(params, start_time)
            case "header_analyze":
                return await self._header_analyze(params, start_time)
            case "screenshot":
                return await self._screenshot(params, start_time)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")

    async def _run_cmd(self, cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
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

    async def _dir_fuzz(self, params: dict, start: float) -> SkillResult:
        """Fuzzing de directorios web"""
        target = params["target"]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

        tool = "gobuster" if shutil.which("gobuster") else "ffuf" if shutil.which("ffuf") else None
        if not tool:
            return SkillResult(success=False, error="No se encontró gobuster ni ffuf", execution_time=time.time() - start)

        if tool == "gobuster":
            cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-o", "/tmp/specter_gobuster.txt"]
        else:
            cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", "/tmp/specter_ffuf.json"]

        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 300))
        output = stdout + stderr

        if rc == -2:
            return SkillResult(success=False, error=f"{tool} no está instalado", execution_time=time.time() - start)
        if rc == -1:
            return SkillResult(success=False, error="Timeout en fuzzing", execution_time=time.time() - start)

        findings = []
        if rc == 0:
            count = len([ln for ln in output.splitlines() if ln.strip()])
            findings.append({"type": "dir_fuzz", "paths_found": count, "target": target})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _sqlmap_test(self, params: dict, start: float) -> SkillResult:
        """Test de inyección SQL con sqlmap"""
        target = params["target"]

        if not shutil.which("sqlmap"):
            return SkillResult(success=False, error="sqlmap no está instalado", execution_time=time.time() - start)

        cmd = ["sqlmap", "-u", target, "--batch", "--risk=1", "--level=1"]
        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 300))
        output = stdout + stderr

        if rc == -1:
            return SkillResult(success=False, error="Timeout en sqlmap", execution_time=time.time() - start)

        findings = []
        if "vulnerable" in output.lower():
            findings.append({"type": "sqli", "target": target, "severity": "HIGH"})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _nuclei_scan(self, params: dict, start: float) -> SkillResult:
        """Escaneo con Nuclei"""
        target = params["target"]

        if not shutil.which("nuclei"):
            return SkillResult(success=False, error="nuclei no está instalado", execution_time=time.time() - start)

        template = params.get("template", "")
        cmd = ["nuclei", "-u", target] + (["-t", template] if template else [])
        stdout, stderr, rc = await self._run_cmd(cmd, params.get("timeout", 300))
        output = stdout + stderr

        if rc == -1:
            return SkillResult(success=False, error="Timeout en nuclei", execution_time=time.time() - start)

        findings = []
        if "CVE-" in output:
            findings.append({"type": "cve_found", "target": target, "severity": "MED"})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _waf_detect(self, params: dict, start: float) -> SkillResult:
        """Detección de WAF"""
        target = params["target"]

        if not shutil.which("wafw00f"):
            return SkillResult(success=False, error="wafw00f no está instalado", execution_time=time.time() - start)

        stdout, stderr, rc = await self._run_cmd(["wafw00f", target], 60)
        output = stdout + stderr

        findings = []
        if "No WAF detected" not in output:
            findings.append({"type": "waf_detected", "target": target})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _header_analyze(self, params: dict, start: float) -> SkillResult:
        """Análisis de cabeceras HTTP"""
        target = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        stdout, stderr, rc = await self._run_cmd(["curl", "-I", "-s", target], 30)
        output = stdout + stderr

        findings = []
        has_hsts = False
        for line in output.splitlines():
            lower_line = line.lower()
            if lower_line.startswith("server:"):
                findings.append({"type": "server_header", "value": line.split(":", 1)[1].strip()})
            if "x-powered-by" in lower_line:
                findings.append({"type": "x_powered_by", "value": line.split(":", 1)[1].strip()})
            if "strict-transport-security" in lower_line:
                has_hsts = True

        if not has_hsts:
            findings.append({"type": "missing_hsts", "severity": "LOW"})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _screenshot(self, params: dict, start: float) -> SkillResult:
        """Captura de pantalla web"""
        target = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        tool = "eyewitness" if shutil.which("eyewitness") else "webscreenshot" if shutil.which("webscreenshot") else None
        if not tool:
            return SkillResult(success=False, error="No se encontró eyewitness ni webscreenshot", execution_time=time.time() - start)

        outdir = f"/tmp/specter_screens_{target.replace('://', '_').replace('/', '_')}"

        if tool == "eyewitness":
            cmd = ["eyewitness", "-d", outdir, "-f", target]
        else:
            cmd = ["webscreenshot", "-u", target, "-o", outdir + ".png"]

        stdout, stderr, rc = await self._run_cmd(cmd, 300)
        return SkillResult(
            success=rc == 0,
            output=stdout + stderr,
            artifacts={outdir: "Capturas de pantalla"},
            execution_time=time.time() - start,
        )
