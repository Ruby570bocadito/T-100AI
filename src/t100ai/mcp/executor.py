"""MCP Tool Execution Engine - Executes tools with parameter resolution, chaining, and wordlist integration."""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog

from t100ai.mcp.registry import ToolRegistry
from t100ai.mcp.tool import MCPTool
from t100ai.wordlists.dictionaries import AttackDictionary

logger = structlog.get_logger()


@dataclass
class ExecutionResult:
    """Resultado de ejecución de una herramienta."""
    tool_name: str
    success: bool
    output: str = ""
    error: str = ""
    execution_time: float = 0.0
    findings: list[dict] = field(default_factory=list)
    next_tools: list[str] = field(default_factory=list)


class ToolExecutor:
    """Motor de ejecución de herramientas MCP.

    Resuelve parámetros, inyecta wordlists integradas, construye comandos,
    ejecuta de forma async, parsea output y sugiere herramientas siguientes.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        wordlists: Optional[AttackDictionary] = None,
        timeout: int = 300,
    ):
        self.registry = registry
        self.wordlists = wordlists or AttackDictionary()
        self.timeout = timeout
        self._execution_history: list[ExecutionResult] = []

    async def execute(
        self,
        tool_name: str,
        params: dict[str, Any],
        mode: str = "default",
    ) -> ExecutionResult:
        """Ejecuta una herramienta MCP con los parámetros dados."""
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            return ExecutionResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' not found in registry",
            )

        valid, msg = tool.validate_params(params)
        if not valid:
            return ExecutionResult(
                tool_name=tool_name,
                success=False,
                error=f"Invalid params: {msg}",
            )

        start = time.time()

        if tool.command:
            cmd = self._build_command(tool, params, mode)
            result = await self._run_command(cmd)
            output = result.get("stdout", "") + result.get("stderr", "")
            rc = result.get("returncode", -1)
            success = rc == 0
        else:
            output = f"[{tool_name}] No command defined — use skill directly"
            success = False

        exec_time = time.time() - start
        findings = self._extract_findings(tool_name, output)
        next_tools = self._suggest_next_tools(tool_name, findings)

        exec_result = ExecutionResult(
            tool_name=tool_name,
            success=success,
            output=output,
            error=result.get("stderr", "") if not success else "",
            execution_time=exec_time,
            findings=findings,
            next_tools=next_tools,
        )
        self._execution_history.append(exec_result)
        return exec_result

    def _build_command(
        self, tool: MCPTool, params: dict[str, Any], mode: str
    ) -> list[str]:
        """Construye el comando con parámetros y wordlists integradas."""
        base_cmd = tool.command.split()

        # Inyectar wordlists integradas según el tipo de herramienta
        if "wordlist" in params and not params["wordlist"]:
            params["wordlist"] = self._get_integrated_wordlist(tool)

        # Construir argumentos basados en parámetros
        for param in tool.parameters:
            if param.name in params:
                val = str(params[param.name])
                if param.name == "targets" or param.name == "target":
                    base_cmd.append(val)
                elif param.name == "port_range" or param.name == "ports":
                    base_cmd.extend(["-p", val])
                elif param.name == "scan_type":
                    base_cmd.append(f"-{val}")
                elif param.name == "timing":
                    base_cmd.append(val)
                elif param.name == "url":
                    base_cmd.extend(["-u", val])
                elif param.name == "wordlist":
                    base_cmd.extend(["-w", val])
                elif param.name == "domain":
                    base_cmd.extend(["-d", val])
                elif param.name == "query":
                    base_cmd.append(val)
                elif param.name == "level":
                    base_cmd.extend(["--level", val])
                elif param.name == "record_type":
                    base_cmd.extend(["-t", val])

        return [c for c in base_cmd if c]

    def _get_integrated_wordlist(self, tool: MCPTool) -> str:
        """Devuelve una wordlist integrada según el tipo de herramienta."""
        name = tool.name.lower()
        if "dir" in name or "fuzz" in name:
            return self._save_temp_wordlist(self.wordlists.get_directories(), "dirs")
        if "subdomain" in name:
            return self._save_temp_wordlist(self.wordlists.get_subdomains(), "subdomains")
        if "sql" in name:
            return self._save_temp_wordlist(self.wordlists.get_sql_payloads(), "sql")
        if "xss" in name:
            return self._save_temp_wordlist(self.wordlists.get_xss_payloads(), "xss")
        if "user" in name or "enum" in name:
            return self._save_temp_wordlist(self.wordlists.get_usernames(), "users")
        if "pass" in name or "crack" in name:
            return self._save_temp_wordlist(self.wordlists.get_passwords(), "passwords")
        return ""

    def _save_temp_wordlist(self, items: list[str], name: str) -> str:
        """Guarda una wordlist en /tmp y devuelve la ruta."""
        path = f"/tmp/t100ai_wl_{name}.txt"
        try:
            with open(path, "w") as f:
                f.write("\n".join(items))
            return path
        except Exception:
            return ""

    async def _run_command(self, cmd: list[str]) -> dict[str, Any]:
        """Ejecuta un comando de forma async."""
        if not cmd or not shutil.which(cmd[0]):
            return {
                "stdout": "",
                "stderr": f"Command '{cmd[0] if cmd else 'unknown'}' not found",
                "returncode": -1,
            }

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            return {
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "returncode": proc.returncode or 0,
            }
        except asyncio.TimeoutError:
            return {
                "stdout": "",
                "stderr": f"Timeout after {self.timeout}s",
                "returncode": -1,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
            }

    def _extract_findings(self, tool_name: str, output: str) -> list[dict]:
        """Extrae hallazgos del output de una herramienta."""
        findings = []

        if "nmap" in tool_name:
            for line in output.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        findings.append({
                            "type": "open_port",
                            "port": parts[0].split("/")[0],
                            "service": parts[2],
                            "severity": "INFO",
                        })

        if "gobuster" in tool_name or "ffuf" in tool_name:
            count = sum(1 for line in output.splitlines() if line.strip() and "Status: 200" in line)
            if count > 0:
                findings.append({"type": "web_paths", "count": count, "severity": "INFO"})

        if "sqlmap" in tool_name and "vulnerable" in output.lower():
            findings.append({"type": "sql_injection", "severity": "CRIT"})

        if "nuclei" in tool_name and "CVE-" in output:
            findings.append({"type": "cve_found", "severity": "HIGH"})

        return findings

    def _suggest_next_tools(self, tool_name: str, findings: list[dict]) -> list[str]:
        """Sugiere herramientas siguientes basadas en hallazgos."""
        suggestions = []

        for f in findings:
            if f.get("type") == "open_port":
                port = f.get("port", "")
                if port in ("80", "443", "8080", "8443"):
                    suggestions.extend(["web.dir_fuzz", "web.sqlmap"])
                elif port == "445":
                    suggestions.extend(["exploit.run"])
                elif port in ("389", "636"):
                    suggestions.extend(["ad.ldap_enum"])

            if f.get("type") == "sql_injection":
                suggestions.extend(["exploit.run"])

            if f.get("type") == "cve_found":
                suggestions.extend(["cve.lookup"])

        return list(set(suggestions))

    def get_execution_history(self) -> list[ExecutionResult]:
        """Devuelve el historial de ejecución."""
        return list(self._execution_history)

    def get_summary(self) -> dict[str, Any]:
        """Devuelve un resumen de todas las ejecuciones."""
        total = len(self._execution_history)
        success = sum(1 for e in self._execution_history if e.success)
        total_time = sum(e.execution_time for e in self._execution_history)
        all_findings = []
        for e in self._execution_history:
            all_findings.extend(e.findings)

        return {
            "total_executions": total,
            "successful": success,
            "failed": total - success,
            "total_time": round(total_time, 2),
            "total_findings": len(all_findings),
            "findings_by_severity": {
                "CRIT": sum(1 for f in all_findings if f.get("severity") == "CRIT"),
                "HIGH": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
                "MED": sum(1 for f in all_findings if f.get("severity") == "MED"),
                "LOW": sum(1 for f in all_findings if f.get("severity") == "LOW"),
                "INFO": sum(1 for f in all_findings if f.get("severity") == "INFO"),
            },
        }
