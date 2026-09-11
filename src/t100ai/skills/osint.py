"""OSINT Skill - Inteligencia de Fuentes Abiertas"""

import asyncio
import json
import re
import shutil
import time
from typing import Any

import structlog

from t100ai.skills.base import BaseSkill, RiskLevel, SkillResult

logger = structlog.get_logger()

OSINT_RATE_LIMIT = 2.0  # seconds between external API calls


class OsintSkill(BaseSkill):
    """
    Skill OSINT - Open Source Intelligence

    Proporciona herramientas para:
    - Consulta WHOIS
    - Enumeración de subdominios
    - Recolección de emails
    - Búsqueda en Shodan
    - Extracción de metadatos
    - Búsqueda en GitHub
    - Consulta Certificate Transparency
    """

    name = "osint"
    description = "Inteligencia de fuentes abiertas"
    category = "osint"
    risk_level = RiskLevel.PASSIVE

    def __init__(self):
        super().__init__()
        self.tools = [
            "osint.whois",
            "osint.subdomain_enum",
            "osint.email_harvest",
            "osint.shodan",
            "osint.metadata",
            "osint.github",
            "osint.crtsh",
            "osint.google_dorks",
            "osint.wayback_query",
            "osint.hunter_lookup",
        ]
        self.workflows = ["full_osint", "rapid_osint"]

    def get_available_actions(self) -> list[str]:
        """Return list of available OSINT actions."""
        return [
            "whois_lookup",
            "subdomain_enum",
            "email_harvest",
            "shodan_query",
            "metadata_extract",
            "github_search",
            "crtsh_query",
            "google_dorks",
            "wayback_query",
            "hunter_lookup",
        ]

    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        if action in ("whois_lookup", "subdomain_enum", "email_harvest", "crtsh_query"):
            return "domain" in params
        if action in ("shodan_query", "github_search"):
            return "query" in params
        if action == "metadata_extract":
            return "path" in params or "target" in params
        return True

    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        start = time.time()

        match action:
            case "whois_lookup":
                return await self._whois_lookup(params, start)
            case "subdomain_enum":
                return await self._subdomain_enum(params, start)
            case "email_harvest":
                return await self._email_harvest(params, start)
            case "shodan_query":
                return await self._shodan_query(params, start)
            case "metadata_extract":
                return await self._metadata_extract(params, start)
            case "github_search":
                return await self._github_search(params, start)
            case "crtsh_query":
                return await self._crtsh_query(params, start)
            case "google_dorks":
                return await self._google_dorks(params, start)
            case "wayback_query":
                return await self._wayback_query(params, start)
            case "hunter_lookup":
                return await self._hunter_lookup(params, start)
            case _:
                return SkillResult(success=False, error=f"Acción desconocida: {action}")

    async def _run_cmd(self, cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
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

    async def _http_get(self, url: str, headers: dict | None = None, timeout: int = 30) -> str:
        """Realiza una petición HTTP GET de forma async con rate limiting."""
        await asyncio.sleep(OSINT_RATE_LIMIT)
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, headers=headers or {"User-Agent": "T-100AI-OSINT"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            return f"Error: {e}"

    async def _whois_lookup(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        stdout, stderr, rc = await self._run_cmd(["whois", domain], 60)

        if rc == -2:
            return SkillResult(success=False, error="whois no instalado", execution_time=time.time() - start)

        findings = []
        for line in stdout.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                key, val = key.strip(), val.strip()
                if key in ("Registrar", "Name Server", "Registrant", "Creation Date", "Expiry Date"):
                    findings.append({"type": "whois", "field": key, "value": val})

        return SkillResult(
            success=rc == 0,
            output=stdout,
            findings=findings,
            execution_time=time.time() - start,
        )

    async def _subdomain_enum(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        findings = []
        output_parts = []

        if shutil.which("amass"):
            stdout, _, rc = await self._run_cmd(["amass", "enum", "-d", domain, "-silent"], 120)
            if rc == 0:
                for line in stdout.splitlines():
                    if line.strip():
                        findings.append({"type": "subdomain", "source": "amass", "value": line.strip()})
                output_parts.append(stdout)

        if shutil.which("subfinder"):
            stdout, _, rc = await self._run_cmd(["subfinder", "-d", domain, "-silent"], 60)
            if rc == 0:
                for line in stdout.splitlines():
                    if line.strip():
                        findings.append({"type": "subdomain", "source": "subfinder", "value": line.strip()})
                output_parts.append(stdout)

        if not findings:
            stdout, _, rc = await self._run_cmd(["dig", "+short", "ANY", domain], 30)
            if rc == 0:
                for line in stdout.splitlines():
                    line = line.strip()
                    if line and domain in line:
                        findings.append({"type": "subdomain", "source": "dig", "value": line})
                output_parts.append(stdout)

        seen = set()
        unique = []
        for f in findings:
            if f["value"] not in seen:
                seen.add(f["value"])
                unique.append(f)

        return SkillResult(
            success=True,
            output="\n".join(output_parts),
            findings=unique if unique else [{"type": "subdomain", "value": "No se encontraron subdominios"}],
            execution_time=time.time() - start,
        )

    async def _email_harvest(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        emails = set()
        output = ""

        if shutil.which("theHarvester"):
            stdout, _, rc = await self._run_cmd(
                ["theHarvester", "-d", domain, "-b", "all", "-f", "/tmp/specter_emails"], 120
            )
            if rc == 0:
                output += stdout
                for line in stdout.splitlines():
                    for email in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line):
                        emails.add(email)

        findings = [{"type": "email", "value": e} for e in sorted(emails)]
        if not findings:
            findings = [{"type": "email", "value": "No se encontraron emails"}]

        return SkillResult(success=True, output=output, findings=findings, execution_time=time.time() - start)

    async def _shodan_query(self, params: dict, start: float) -> SkillResult:
        query = params.get("query")
        limit = params.get("limit", 20)

        if not shutil.which("shodan"):
            return SkillResult(success=False, error="Shodan CLI no instalado", execution_time=time.time() - start)

        stdout, stderr, rc = await self._run_cmd(
            ["shodan", "search", "--limit", str(limit), query], 60
        )
        output = stdout + stderr

        findings = []
        for line in output.splitlines():
            ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            for ip in ip_match:
                findings.append({"type": "shodan_result", "ip": ip, "query": query})

        return SkillResult(
            success=rc == 0,
            output=output,
            findings=findings if findings else [{"type": "shodan_result", "value": "Sin resultados"}],
            execution_time=time.time() - start,
        )

    async def _metadata_extract(self, params: dict, start: float) -> SkillResult:
        path = params.get("path") or params.get("target")

        if not shutil.which("exiftool"):
            return SkillResult(success=False, error="exiftool no instalado", execution_time=time.time() - start)

        stdout, stderr, rc = await self._run_cmd(["exiftool", path], 30)
        output = stdout + stderr

        findings = []
        for line in output.splitlines():
            m = re.match(r"([^:]+):\s*(.+)", line)
            if m:
                findings.append({"type": "metadata", "tag": m.group(1).strip(), "value": m.group(2).strip()})

        return SkillResult(success=rc == 0, output=output, findings=findings, execution_time=time.time() - start)

    async def _github_search(self, params: dict, start: float) -> SkillResult:
        query = params.get("query")
        if not query:
            return SkillResult(success=False, error="query requerido", execution_time=time.time() - start)

        import urllib.parse
        url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&per_page=5"
        data_str = await self._http_get(url)

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return SkillResult(success=False, error=f"Invalid JSON from GitHub: {data_str[:200]}", execution_time=time.time() - start)

        findings = []
        for item in data.get("items", []):
            findings.append({
                "type": "github_repo",
                "name": item.get("full_name"),
                "url": item.get("html_url"),
                "stars": item.get("stargazers_count"),
            })

        output = "\n".join([f"{f['name']} - {f['url']}" for f in findings])
        return SkillResult(
            success=True,
            output=output,
            findings=findings,
            execution_time=time.time() - start,
        )

    async def _crtsh_query(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain")
        stdout, _, rc = await self._run_cmd(
            ["curl", "-s", f"https://crt.sh/?q={domain}&output=json"], 60
        )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = []

        domains = set()
        for item in data:
            name_value = item.get("name_value", "")
            for v in str(name_value).split("\n"):
                v = v.strip()
                if v:
                    domains.add(v)

        findings = [{"type": "certificate_domain", "domain": d} for d in sorted(domains)]
        return SkillResult(
            success=True,
            output=stdout,
            findings=findings if findings else [{"type": "certificate_domain", "value": "No se encontraron certificados"}],
            execution_time=time.time() - start,
        )

    async def _google_dorks(self, params: dict, start: float) -> SkillResult:
        query = params.get("query") or params.get("domain")
        if not query:
            return SkillResult(success=False, error="Se requiere 'query' o 'domain' para google_dorks", execution_time=time.time() - start)

        import urllib.parse
        url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        html = await self._http_get(url, headers={"User-Agent": "Mozilla/5.0 (Specter)"})

        urls = set(re.findall(r"/url\?q=(https?:\/\/[^&]+)(&|$)", html))
        findings = [{"type": "google_dork_result", "url": urllib.parse.unquote(u[0])} for u in urls if u]
        output = f"Found {len(findings)} results" if findings else "Sin resultados"

        return SkillResult(
            success=True,
            output=output,
            findings=findings or [{"type": "google_dork_result", "value": "No results"}],
            execution_time=time.time() - start,
        )

    async def _wayback_query(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        if not domain:
            return SkillResult(success=False, error="Se requiere 'domain' o 'target' para Wayback query", execution_time=time.time() - start)

        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=5&collapse=original"
        data_str = await self._http_get(url)

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return SkillResult(success=False, error="Invalid JSON from Wayback", execution_time=time.time() - start)

        findings = []
        for row in data[1:]:
            timestamp, original = row[0], row[2] if len(row) > 2 else ""
            findings.append({"type": "wayback_snapshot", "timestamp": timestamp, "original": original})

        output = f"Wayback snapshots: {len(findings)} results"
        return SkillResult(
            success=True,
            output=output,
            findings=findings or [{"type": "wayback_snapshot", "value": "No snapshots"}],
            execution_time=time.time() - start,
        )

    async def _hunter_lookup(self, params: dict, start: float) -> SkillResult:
        domain = params.get("domain") or params.get("target")
        if not domain:
            return SkillResult(success=False, error="Se requiere 'domain' para hunter_lookup", execution_time=time.time() - start)

        import os
        api_key = os.environ.get("HUNTER_API_KEY")
        if not api_key:
            return SkillResult(success=False, error="Hunter API key no configurada (HUNTER_API_KEY)", execution_time=time.time() - start)

        import urllib.parse
        url = f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(domain)}&api_key={urllib.parse.quote(api_key)}"
        data_str = await self._http_get(url)

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return SkillResult(success=False, error="Invalid JSON from Hunter", execution_time=time.time() - start)

        emails = data.get("data", {}).get("emails", [])
        findings = [{"type": "hunter_email", "email": e.get("value"), "confidence": e.get("confidence")} for e in emails]
        output = f"Emails found: {len(findings)}" if findings else "No emails found"

        return SkillResult(
            success=True,
            output=output,
            findings=findings or [{"type": "hunter_email", "value": "No emails"}],
            execution_time=time.time() - start,
        )
