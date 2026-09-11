"""MCP Tool Registry Avanzado con Templates, Chaining, Auto-discovery y Parsers"""

import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import structlog

from t100ai.mcp.tool import MCPTool, ToolParameter

logger = structlog.get_logger()


@dataclass
class ToolTemplate:
    """Plantilla para crear herramientas rápidamente"""
    name: str
    description: str
    category: str
    command_template: str
    default_params: dict = field(default_factory=dict)
    output_parser: str = "default"
    risk_level: int = 0


@dataclass
class ToolChain:
    """Encadenamiento de herramientas"""
    name: str
    steps: list[dict] = field(default_factory=list)
    description: str = ""


class OutputParser:
    """Parser de outputs para diferentes herramientas"""

    @staticmethod
    def nmap(output: str) -> dict:
        """Parser específico para nmap"""
        result = {
            "hosts": [],
            "ports": [],
            "services": [],
            "vulnerabilities": []
        }

        for line in output.split("\n"):
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    result["ports"].append({
                        "port": port,
                        "state": state,
                        "service": service
                    })
                    if "open" in state.lower():
                        result["services"].append({
                            "port": port,
                            "service": service,
                            "version": " ".join(parts[3:]) if len(parts) > 3 else ""
                        })
            elif "Nmap scan report for" in line:
                match = re.search(r"for (.+?) \(", line)
                if match:
                    result["hosts"].append(match.group(1))

        return result

    @staticmethod
    def gobuster(output: str) -> dict:
        """Parser para gobuster/dirb"""
        result = {
            "directories": [],
            "files": [],
            "status_codes": {}
        }

        for line in output.split("\n"):
            if "Status:" in line or "(Status:" in line:
                match = re.search(r"(https?://[^\s]+)", line)
                if match:
                    url = match.group(1)
                    code_match = re.search(r"\((\d+)\)", line)
                    code = code_match.group(1) if code_match else "?"

                    if url.endswith("/"):
                        result["directories"].append({"url": url, "code": code})
                    else:
                        result["files"].append({"url": url, "code": code})

                    result["status_codes"][code] = result["status_codes"].get(code, 0) + 1

        return result

    @staticmethod
    def nikto(output: str) -> dict:
        """Parser para Nikto"""
        result = {
            "findings": [],
            "vulnerabilities": []
        }

        for line in output.split("\n"):
            if "+ " in line and any(x in line for x in ["OSVDB", "CVE", "WARNING"]):
                finding = line[2:].strip()
                result["findings"].append(finding)
                if "WARNING" in line:
                    result["vulnerabilities"].append(finding)

        return result

    @staticmethod
    def hydra(output: str) -> dict:
        """Parser para Hydra"""
        result = {
            "credentials": [],
            "success": False
        }

        for line in output.split("\n"):
            if "[80][http-post-form]" in line or "login:" in line.lower():
                if "password" in line.lower():
                    match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line, re.IGNORECASE)
                    if match:
                        result["credentials"].append({
                            "login": match.group(1),
                            "password": match.group(2)
                        })
                        result["success"] = True

        return result

    @staticmethod
    def default(output: str) -> dict:
        """Parser por defecto"""
        return {
            "raw": output[:1000],
            "lines": len(output.split("\n")),
            "length": len(output)
        }

    @staticmethod
    def nuclei(output: str) -> dict:
        """Parser para Nuclei"""
        result = {
            "findings": [],
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for line in output.split("\n"):
            if "[CRITICAL]" in line or "[CRIT]" in line:
                result["critical"] += 1
                result["findings"].append(("CRITICAL", line.strip()))
            elif "[HIGH]" in line:
                result["high"] += 1
                result["findings"].append(("HIGH", line.strip()))
            elif "[MEDIUM]" in line:
                result["medium"] += 1
                result["findings"].append(("MEDIUM", line.strip()))
            elif "[LOW]" in line:
                result["low"] += 1
                result["findings"].append(("LOW", line.strip()))

        return result

    @staticmethod
    def ffuf(output: str) -> dict:
        """Parser para FFUF"""
        result = {
            "urls": [],
            "status_codes": {}
        }

        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                status = parts[0]
                result["status_codes"][status] = result["status_codes"].get(status, 0) + 1
                if status.startswith("2"):
                    result["urls"].append(line.strip())

        return result

    @staticmethod
    def crackmapexec(output: str) -> dict:
        """Parser para CrackMapExec"""
        result = {
            "hosts": [],
            "shares": [],
            "credentials": [],
            "vulnerabilities": []
        }

        for line in output.split("\n"):
            if not line.strip():
                continue
            if "STATUS_SUCCESS" in line:
                result["hosts"].append(line.strip())
            elif "Enumerating shares" in line or "$" in line:
                result["shares"].append(line.strip())
            elif "Password" in line or "NTLM" in line:
                result["credentials"].append(line.strip())

        return result

    @staticmethod
    def bloodhound(output: str) -> dict:
        """Parser para BloodHound"""
        result = {
            "users": [],
            "groups": [],
            "computers": [],
            "paths": []
        }

        for line in output.split("\n"):
            if "User:" in line:
                result["users"].append(line.strip())
            elif "Group:" in line:
                result["groups"].append(line.strip())
            elif "Computer:" in line:
                result["computers"].append(line.strip())
            elif "Path:" in line or "->" in line:
                result["paths"].append(line.strip())

        return result

    @staticmethod
    def sslscan(output: str) -> dict:
        """Parser para SSLscan"""
        result = {
            "certificates": [],
            "ciphers": [],
            "vulnerabilities": []
        }

        in_ciphers = False
        for line in output.split("\n"):
            if "Certificate:" in line or "Subject:" in line:
                result["certificates"].append(line.strip())
                in_ciphers = False
            elif "Accepted" in line or "Supported" in line:
                in_ciphers = True
                result["ciphers"].append(line.strip())
            elif "VULNERABLE" in line or "WARNING" in line:
                result["vulnerabilities"].append(line.strip())
            elif in_ciphers and line.strip().startswith(" "):
                result["ciphers"].append(line.strip())

        return result

    @staticmethod
    def testssl(output: str) -> dict:
        """Parser para testssl.sh"""
        result = {
            "findings": [],
            "cve_list": [],
            "grades": []
        }

        for line in output.split("\n"):
            if "VULNERABLE" in line:
                result["findings"].append(line.strip())
                cve_match = re.findall(r"CVE-\d+-\d+", line)
                result["cve_list"].extend(cve_match)
            elif "Rating:" in line or "Grade" in line:
                result["grades"].append(line.strip())

        return result

    @staticmethod
    def dnsrecon(output: str) -> dict:
        """Parser para dnsrecon"""
        result = {
            "records": [],
            "hosts": []
        }

        for line in output.split("\n"):
            if any(rtype in line for rtype in ["A:", "AAAA:", "MX:", "NS:", "TXT:", "CNAME:", "SOA:"]):
                result["records"].append(line.strip())
            elif "Host:" in line:
                result["hosts"].append(line.strip())

        return result

    @staticmethod
    def hashcat(output: str) -> dict:
        """Parser para Hashcat"""
        result = {
            "cracked": [],
            "hashes_left": 0
        }

        for line in output.split("\n"):
            if "Cracked" in line or "Time.Started" in line:
                continue
            if ":" in line and len(line) < 100:
                result["cracked"].append(line.strip())
            elif "Remaining" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    result["hashes_left"] = int(match.group(1))

        return result

    @staticmethod
    def volatility(output: str) -> dict:
        """Parser para Volatility"""
        result = {
            "processes": [],
            "connections": [],
            "dlls": []
        }

        in_processes = False
        in_connections = False
        for line in output.split("\n"):
            if "Process" in line or "Name" in line:
                in_processes = True
                in_connections = False
            elif "Connection" in line or "Local" in line:
                in_connections = True
                in_processes = False
            elif line.strip():
                if in_processes:
                    result["processes"].append(line.strip())
                elif in_connections:
                    result["connections"].append(line.strip())
                elif "dll" in line.lower():
                    result["dlls"].append(line.strip())

        return result


class AdvancedToolRegistry:
    """Registry avanzado de herramientas MCP"""

    TEMPLATES: dict[str, ToolTemplate] = {}

    def __init__(self, cache_ttl: int = 3600):
        self.tools: dict[str, MCPTool] = {}
        self._cache: dict[str, tuple[MCPTool, float]] = {}
        self._cache_ttl = cache_ttl
        self._discovery_cache: Optional[tuple[list[MCPTool], float]] = None
        self._chains: dict[str, ToolChain] = {}
        self._categories: dict[str, list[str]] = {}
        self._parsers: dict[str, Callable] = {
            "nmap": OutputParser.nmap,
            "gobuster": OutputParser.gobuster,
            "dirb": OutputParser.gobuster,
            "nikto": OutputParser.nikto,
            "hydra": OutputParser.hydra,
            "nuclei": OutputParser.nuclei,
            "ffuf": OutputParser.ffuf,
            "crackmapexec": OutputParser.crackmapexec,
            "bloodhound": OutputParser.bloodhound,
            "sslscan": OutputParser.sslscan,
            "testssl": OutputParser.testssl,
            "dnsrecon": OutputParser.dnsrecon,
            "hashcat": OutputParser.hashcat,
            "volatility": OutputParser.volatility,
            "default": OutputParser.default,
        }
        self._init_templates()

    def _init_templates(self):
        """Inicializa plantillas predefinidas"""
        self.TEMPLATES = {
            "nmap_basic": ToolTemplate(
                name="nmap_basic",
                description="Escaneo básico de puertos",
                category="network/recon",
                command_template="nmap -sV {target}",
                default_params={"target": ""},
                risk_level=0
            ),
            "nmap_full": ToolTemplate(
                name="nmap_full",
                description="Escaneo completo con OS detection",
                category="network/recon",
                command_template="nmap -A -p- {target}",
                risk_level=1
            ),
            "gobuster_dir": ToolTemplate(
                name="gobuster_dir",
                description="Fuzzing de directorios web",
                category="web/fuzz",
                command_template="gobuster dir -u {url} -w {wordlist}",
                default_params={"url": "", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
                risk_level=1
            ),
            "gobuster_subdomain": ToolTemplate(
                name="gobuster_subdomain",
                description="Fuzzing de subdominios",
                category="web/recon",
                command_template="gobuster dns -d {domain} -w {wordlist}",
                risk_level=0
            ),
            "nikto_scan": ToolTemplate(
                name="nikto_scan",
                description="Escaneo de vulnerabilidades web",
                category="web/vuln",
                command_template="nikto -h {target}",
                risk_level=1
            ),
            "sqlmap_basic": ToolTemplate(
                name="sqlmap_basic",
                description="Test básico de SQL injection",
                category="web/vuln",
                command_template="sqlmap -u {url} --batch",
                risk_level=2
            ),
            "hydra_ssh": ToolTemplate(
                name="hydra_ssh",
                description="Brute force SSH",
                category="password",
                command_template="hydra -l {user} -P {wordlist} ssh://{target}",
                risk_level=2
            ),
            "theHarvester": ToolTemplate(
                name="theHarvester",
                description="Recolección de emails y subdominios",
                category="osint",
                command_template="theHarvester -d {domain} -b all",
                risk_level=0
            ),
            "shodan_query": ToolTemplate(
                name="shodan_query",
                description="Búsqueda en Shodan (API key requerida)",
                category="osint",
                command_template="shodan search {query}",
                risk_level=0
            ),
            "whois_lookup": ToolTemplate(
                name="whois_lookup",
                description="Información WHOIS de dominio",
                category="osint",
                command_template="whois {domain}",
                risk_level=0
            ),
        }

        for name, template in self.TEMPLATES.items():
            self._categories.setdefault(template.category, []).append(name)

    def create_tool_from_template(self, template_name: str, custom_params: Optional[dict] = None) -> Optional[MCPTool]:
        """Crea una herramienta desde una plantilla"""
        if template_name not in self.TEMPLATES:
            return None

        template = self.TEMPLATES[template_name]
        params = {**template.default_params, **(custom_params or {})}

        command = template.command_template
        for key, value in params.items():
            command = command.replace(f"{{{key}}}", str(value))

        tool = MCPTool(
            name=f"template.{template_name}",
            description=template.description,
            category=template.category,
            skill="custom",
            risk_level=template.risk_level,
            command=command,
        )

        for param_name, param_value in params.items():
            tool.parameters.append(ToolParameter(
                name=param_name,
                type="string",
                default=str(param_value),
                description=f"Parámetro {param_name}"
            ))

        return tool

    async def discover_tools(self) -> None:
        """Descubre y registra todas las herramientas"""
        logger.info("Discovering MCP tools...")
        self._init_templates()
        self._register_builtin_tools()
        self._discover_system_tools()
        self._discover_from_config()
        logger.info("Tools discovered", count=len(self.tools))

    def _register_builtin_tools(self) -> None:
        """Registra herramientas built-in desde plantillas"""
        tool_templates = [
            ToolTemplate(
                name="nmap_scan",
                description="Escaneo de puertos y servicios con nmap",
                category="recon",
                command_template="nmap {{args}}",
                default_params={"-sV": True, "-p-": True},
                output_parser="nmap",
                risk_level=0
            ),
            ToolTemplate(
                name="gobuster_dir",
                description="Enumeración de directorios web",
                category="web",
                command_template="gobuster dir -u {{url}} -w {{wordlist}}",
                default_params={"-t": 10},
                output_parser="gobuster",
                risk_level=0
            ),
            ToolTemplate(
                name="nikto_scan",
                description="Escaneo de vulnerabilidades web",
                category="web",
                command_template="nikto -h {{host}}",
                default_params={},
                output_parser="nikto",
                risk_level=1
            ),
            ToolTemplate(
                name="hydra_brute",
                description="Fuerza bruta de autenticación",
                category="auth",
                command_template="hydra {{target}} {{service}} {{user}} {{pass}}",
                default_params={"-V": True},
                output_parser="hydra",
                risk_level=2
            ),
            ToolTemplate(
                name="sqlmap_inject",
                description="Detección de SQL Injection",
                category="injection",
                command_template="sqlmap -u {{url}}",
                default_params={"--batch": True, "--level": 2},
                output_parser="sqlmap",
                risk_level=2
            ),
            ToolTemplate(
                name="sublist3r_enum",
                description="Enumeración de subdominios",
                category="recon",
                command_template="sublist3r -d {{domain}}",
                default_params={"-o": "results.txt"},
                output_parser="sublist3r",
                risk_level=0
            ),
            ToolTemplate(
                name="zap_scan",
                description="Escaneo OWASP ZAP",
                category="web",
                command_template="zap-baseline.py -t {{target}}",
                default_params={"-r": "report.html"},
                output_parser="zap",
                risk_level=1
            ),
            ToolTemplate(
                name="metasploit_check",
                description="Verificar vulnerabilidades con Metasploit",
                category="exploit",
                command_template="msfconsole -q -x 'check {{target}}'",
                default_params={},
                output_parser="metasploit",
                risk_level=2
            ),
            ToolTemplate(
                name="curl_request",
                description="Solicitudes HTTP personalizadas",
                category="web",
                command_template="curl -v {{url}}",
                default_params={},
                output_parser="curl",
                risk_level=0
            ),
            ToolTemplate(
                name="wpscan_enum",
                description="Escaneo de WordPress",
                category="web",
                command_template="wpscan --url {{url}} --enumerate",
                default_params={"--wp-content-dir": "wp-content"},
                output_parser="wpscan",
                risk_level=0
            ),
            # === ACTIVE DIRECTORY ===
            ToolTemplate(name="bloodhound_ingest", description="Recolección de datos AD con BloodHound", category="ad", command_template="python3 /opt/BloodHound-python/bloodhound-python -d {{domain}} -u {{user}} -p {{pass}} -c All", default_params={}, output_parser="bloodhound", risk_level=1),
            ToolTemplate(name="crackmapexec", description="Enumeración y explotación de AD", category="ad", command_template="cme smb {{target}} -u {{user}} -p {{pass}}", default_params={"--samr": True}, output_parser="crackmapexec", risk_level=2),
            ToolTemplate(name="impacket_secretsdump", description="Extracción de credenciales desde AD", category="ad", command_template="secretsdump.py {{user}}:{{pass}}@{{target}}", default_params={}, output_parser="impacket", risk_level=2),
            ToolTemplate(name="kerbrute_userenum", description="Enumeración de usuarios Kerberos", category="ad", command_template="kerbrute userenum -d {{domain}} {{userlist}}", default_params={}, output_parser="kerbrute", risk_level=1),
            ToolTemplate(name="ldapsearch", description="Consulta LDAP/AD", category="ad", command_template="ldapsearch -H ldap://{{target}} -D '{{user}}' -w {{pass}} -b '{{base}}'", default_params={}, output_parser="ldapsearch", risk_level=1),
            # === DNS ===
            ToolTemplate(name="dnsenum_full", description="Enumeración completa de DNS", category="dns", command_template="dnsenum {{domain}}", default_params={"-f": True}, output_parser="dnsenum", risk_level=0),
            ToolTemplate(name="dnsrecon_enum", description="Enumeración de registros DNS", category="dns", command_template="dnsrecon -d {{domain}} -a", default_params={}, output_parser="dnsrecon", risk_level=0),
            ToolTemplate(name="fierce_scan", description="Descubrimiento de subdominios", category="dns", command_template="fierce --domain {{domain}}", default_params={}, output_parser="fierce", risk_level=0),
            ToolTemplate(name="amass_enum", description="Enumeración de subdominios con Amass", category="dns", command_template="amass enum -d {{domain}}", default_params={"-passive": True}, output_parser="amass", risk_level=0),
            # === WIFI ===
            ToolTemplate(name="aircrack_wpa", description="Auditoría WPA/WPA2", category="wifi", command_template="aircrack-ng -w {{wordlist}} {{capture}}", default_params={}, output_parser="aircrack", risk_level=1),
            ToolTemplate(name="wifite_auto", description="Auditoría WiFi automática", category="wifi", command_template="wifite --dict {{wordlist}}", default_params={}, output_parser="wifite", risk_level=1),
            ToolTemplate(name="reaver_wps", description="Ataque WPS", category="wifi", command_template="reaver -i {{interface}} -b {{bssid}} -vv", default_params={}, output_parser="reaver", risk_level=1),
            # === SSL/TLS ===
            ToolTemplate(name="testssl_scan", description="Análisis SSL/TLS completo", category="ssl", command_template="testssl --jsonfile {{output}} {{target}}", default_params={}, output_parser="testssl", risk_level=0),
            ToolTemplate(name="sslscan_ssl", description="Escaneo de certificados SSL", category="ssl", command_template="sslscan {{target}}", default_params={}, output_parser="sslscan", risk_level=0),
            ToolTemplate(name="sslyze_scan", description="Análisis SSL/TLS avanzado", category="ssl", command_template="sslyze {{target}}", default_params={"--json_out": "{{output}}"}, output_parser="sslyze", risk_level=0),
            # === EMAIL/OSINT ===
            ToolTemplate(name="theharvester", description="Recolección de emails y OSINT", category="osint", command_template="theHarvester -d {{domain}} -b all", default_params={}, output_parser="theharvester", risk_level=0),
            ToolTemplate(name="hunterio_lookup", description="Búsqueda de emails via Hunter.io", category="osint", command_template="hunterio {{domain}}", default_params={}, output_parser="hunter", risk_level=0),
            ToolTemplate(name="emailrep_verify", description="Verificación de emails", category="osint", command_template="emailrep {{email}}", default_params={}, output_parser="emailrep", risk_level=0),
            # === FORENSE ===
            ToolTemplate(name="volatility_mem", description="Análisis de memoria con Volatility", category="forense", command_template="volatility -f {{memdump}} {{profile}}", default_params={}, output_parser="volatility", risk_level=0),
            ToolTemplate(name="autopsy_analysis", description="Análisis de disco con Autopsy", category="forense", command_template="autopsy -d {{case}} {{image}}", default_params={}, output_parser="autopsy", risk_level=0),
            ToolTemplate(name="binwalk_extract", description="Análisis de binarios embebidos", category="forense", command_template="binwalk -e {{file}}", default_params={}, output_parser="binwalk", risk_level=0),
            ToolTemplate(name="strings_analysis", description="Extracción de strings", category="forense", command_template="strings {{file}} | grep {{pattern}}", default_params={}, output_parser="strings", risk_level=0),
            # === PASSWORD ===
            ToolTemplate(name="hashcat_crack", description="Cracking de hashes", category="password", command_template="hashcat -m {{mode}} {{hashfile}} {{wordlist}}", default_params={"-O": True}, output_parser="hashcat", risk_level=2),
            ToolTemplate(name="john_cracker", description="Cracking con John the Ripper", category="password", command_template="john --wordlist={{wordlist}} {{hashfile}}", default_params={}, output_parser="john", risk_level=2),
            ToolTemplate(name="cewl_generate", description="Generador de wordlist desde web", category="password", command_template="cewl {{url}} -w {{output}}", default_params={"-d": 2}, output_parser="cewl", risk_level=0),
            # === WEB ===
            ToolTemplate(name="nuclei_scan", description="Escaneo de vulnerabilidades", category="web", command_template="nuclei -u {{url}} -severity critical,high,medium", default_params={"-silent": True}, output_parser="nuclei", risk_level=1),
            ToolTemplate(name="ffuf_fuzz", description="Fuzzing web", category="web", command_template="ffuf -u {{url}}/FUZZ -w {{wordlist}}", default_params={"-t": 50}, output_parser="ffuf", risk_level=0),
            ToolTemplate(name="dirb_scan", description="Enumeración de directorios", category="web", command_template="dirb {{url}} {{wordlist}}", default_params={}, output_parser="dirb", risk_level=0),
            ToolTemplate(name="wpscan_wp", description="Escaneo WordPress", category="web", command_template="wpscan --url {{url}} --enumerate vp,vt", default_params={}, output_parser="wpscan", risk_level=0),
            # === NETWORK ===
            ToolTemplate(name="rustscan_fast", description="Escaneo rápido de puertos", category="network", command_template="rustscan -a {{target}} -b 4500", default_params={"-t": 1500}, output_parser="rustscan", risk_level=0),
            ToolTemplate(name="masscan_scan", description="Escaneo masivo de puertos", category="network", command_template="masscan {{target}} -p{{ports}} --rate=1000", default_params={}, output_parser="masscan", risk_level=0),
            ToolTemplate(name="netdiscover_scan", description="Descubrimiento de hosts", category="network", command_template="netdiscover -i {{interface}} -r {{range}}", default_params={}, output_parser="netdiscover", risk_level=0),
            ToolTemplate(name="arpwatch_monitor", description="Monitor de cambios ARP", category="network", command_template="arpwatch -i {{interface}}", default_params={}, output_parser="arpwatch", risk_level=0),
            # === EXPLOIT ===
            ToolTemplate(name="searchsploit", description="Búsqueda de exploits", category="exploit", command_template="searchsploit {{search}}", default_params={}, output_parser="searchsploit", risk_level=0),
            ToolTemplate(name="msf_console", description="Metasploit Framework", category="exploit", command_template="msfconsole -q -x '{{command}}'", default_params={}, output_parser="msf", risk_level=2),
            ToolTemplate(name="exploitdb", description="Base de datos de exploits", category="exploit", command_template="searchsploit -c {{keyword}}", default_params={}, output_parser="exploitdb", risk_level=0),
            # === RECON ===
            ToolTemplate(name="whois_lookup", description="Información WHOIS", category="recon", command_template="whois {{domain}}", default_params={}, output_parser="whois", risk_level=0),
            ToolTemplate(name="whatweb", description="Identificación de tecnologías", category="recon", command_template="whatweb {{url}}", default_params={}, output_parser="whatweb", risk_level=0),
            ToolTemplate(name="wappalyzer", description="Detección de tecnologías", category="recon", command_template="wappalyzer {{url}}", default_params={}, output_parser="wappalyzer", risk_level=0),
            # === PRIVILEGE ESCALATION ===
            ToolTemplate(name="linpeas_script", description="Enumeración Linux", category="postex", command_template="curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", default_params={}, output_parser="linpeas", risk_level=1),
            ToolTemplate(name="winpeas_script", description="Enumeración Windows", category="postex", command_template="winpeas.exe", default_params={}, output_parser="winpeas", risk_level=1),
            # === CVE ===
            ToolTemplate(name="cve_search", description="Búsqueda de CVEs", category="cve", command_template="cve_search {{keyword}}", default_params={}, output_parser="cve", risk_level=0),
            ToolTemplate(name="snyk_vuln", description="Análisis de vulnerabilidades", category="cve", command_template="snyk test --json", default_params={}, output_parser="snyk", risk_level=0),
        ]

        for template in tool_templates:
            self.TEMPLATES[template.name] = template

            tool = MCPTool(
                name=template.name,
                description=template.description,
                category=template.category,
                skill=template.category,
                risk_level=template.risk_level,
                command=template.command_template,
                execution_modes=["fast", "stealth", "loud"],
                output_parser=template.output_parser,
            )

            self._add_chaining_rules(tool)
            self.tools[tool.name] = tool

        logger.info("Registered builtin tools", count=len(tool_templates))

    def _add_chaining_rules(self, tool: MCPTool) -> None:
        """Añade reglas de encadenamiento basadas en la categoría"""
        chain_map = {
            "recon": {"output_to": ["network", "web", "ad", "osint"]},
            "network": {"output_to": ["exploit", "password", "postex"]},
            "web": {"output_to": ["exploit", "injection"]},
            "dns": {"output_to": ["recon", "web"]},
            "ad": {"output_to": ["exploit", "postex"]},
            "osint": {"output_to": ["recon", "password"]},
            "password": {"output_to": ["ad", "exploit"]},
            "exploit": {"output_to": ["postex", "forense"]},
            "postex": {"output_to": ["ad", "exploit"]},
        }

        category = tool.category.split("/")[0]
        if category in chain_map:
            tool.output_to = chain_map[category].get("output_to", [])
            tool.input_from = chain_map[category].get("input_from", [])

    def _discover_from_config(self) -> None:
        """Descubre herramientas desde configuración"""
        config_paths = [
            Path("t100ai/tools.toml"),
            Path("~/.specter/tools.toml").expanduser(),
            Path("t100ai/config/tools.toml"),
        ]

        for config_path in config_paths:
            if config_path.exists():
                try:
                    import toml
                    data = toml.loads(config_path.read_text())
                    for tool_data in data.get("tools", []):
                        tool = MCPTool(**tool_data)
                        self.register(tool)
                except Exception as e:
                    logger.warning("Failed to load tools from config", path=str(config_path), error=str(e))

    def _discover_system_tools(self) -> None:
        """Auto-descubre herramientas del sistema"""
        tools_map = {
            "nmap": "network/recon",
            "masscan": "network/recon",
            "rustscan": "network/recon",
            "gobuster": "web/fuzz",
            "ffuf": "web/fuzz",
            "dirb": "web/fuzz",
            "nikto": "web/vuln",
            "sqlmap": "web/vuln",
            "hydra": "password",
            "john": "password",
            "hashcat": "password",
            "searchsploit": "exploit",
            "msfconsole": "exploit",
            "theHarvester": "osint",
            "shodan": "osint",
            "amass": "osint",
            "sublist3r": "osint",
            "whois": "osint",
            "dig": "network/dns",
            "nslookup": "network/dns",
            "wpscan": "web/wordpress",
            "nuclei": "web/vuln",
            "testssl": "web/ssl",
            "sslscan": "web/ssl",
        }

        discovered = []
        for tool_name, category in tools_map.items():
            if shutil.which(tool_name):
                discovered.append((tool_name, category))
                logger.debug("System tool discovered", tool=tool_name, category=category)

        logger.info("System tools discovered", count=len(discovered))

    def register_chain(self, chain: ToolChain) -> None:
        """Registra un encadenamiento de herramientas"""
        self._chains[chain.name] = chain
        logger.info("Tool chain registered", name=chain.name, steps=len(chain.steps))

    def execute_chain(self, chain_name: str, initial_params: dict) -> list[dict]:
        """Ejecuta un chain de herramientas"""
        if chain_name not in self._chains:
            return [{"error": f"Chain '{chain_name}' not found"}]

        chain = self._chains[chain_name]
        results = []
        context = {**initial_params}

        for step in chain.steps:
            tool_name = step.get("tool", "")
            params = step.get("params", {})

            for key, value in params.items():
                if isinstance(value, str) and value.startswith("$"):
                    ref = value[1:]
                    params[key] = context.get(ref, value)

            tool = self.get_tool(tool_name)
            if tool and tool.command:
                result = {"tool": tool_name, "command": tool.command, "success": True}
                results.append(result)
                context[tool_name] = result

        return results

    def parse_output(self, tool_name: str, output: str) -> dict:
        """Parsea el output de una herramienta"""
        parser_name = "default"
        for name, parser in self._parsers.items():
            if name in tool_name.lower():
                parser_name = name
                break

        return self._parsers[parser_name](output)

    def get_categories(self) -> dict[str, list[str]]:
        """Retorna las categorías organizadas jerárquicamente"""
        return self._categories

    def list_by_category(self, category_path: str) -> list[MCPTool]:
        """Lista herramientas por categoría (ej: 'web', 'web/vuln')"""
        results = []
        for tool in self.tools.values():
            if tool.category.startswith(category_path):
                results.append(tool)
        return results

    def register(self, tool: MCPTool) -> None:
        """Registra una herramienta"""
        self.tools[tool.name] = tool
        self._update_categories(tool)
        logger.debug("Tool registered", name=tool.name)

    def _update_categories(self, tool: MCPTool) -> None:
        """Actualiza el índice de categorías"""
        if tool.category not in self._categories:
            self._categories[tool.category] = []
        if tool.name not in self._categories[tool.category]:
            self._categories[tool.category].append(tool.name)

    def get_tool(self, name: str) -> Optional[MCPTool]:
        """Obtiene una herramienta por nombre"""
        return self.tools.get(name)

    def list_tools(self, category: Optional[str] = None) -> list[MCPTool]:
        """Lista herramientas"""
        if category:
            return self.list_by_category(category)
        return list(self.tools.values())

    def list_templates(self) -> list[ToolTemplate]:
        """Lista plantillas disponibles"""
        return list(self.TEMPLATES.values())

    def list_chains(self) -> list[dict]:
        """Lista chains disponibles"""
        return [
            {"name": name, "description": chain.description, "steps": len(chain.steps)}
            for name, chain in self._chains.items()
        ]

    def search(self, query: str) -> list[MCPTool]:
        """Busca herramientas"""
        query = query.lower()
        return [
            t for t in self.tools.values()
            if query in t.name.lower() or query in t.description.lower()
        ]

    def _get_cached_tool(self, name: str) -> Optional[MCPTool]:
        """Obtiene herramienta del caché"""
        if name in self._cache:
            tool, timestamp = self._cache[name]
            if time.time() - timestamp < self._cache_ttl:
                return tool
            del self._cache[name]
        return None

    def _set_cached_tool(self, name: str, tool: MCPTool) -> None:
        """Guarda herramienta en caché"""
        self._cache[name] = (tool, time.time())

    def get_tool_cached(self, name: str) -> Optional[MCPTool]:
        """Obtiene herramienta con caché"""
        cached_tool = self._get_cached_tool(name)
        if cached_tool is not None:
            logger.debug("Tool cache hit", tool=name)
            return cached_tool

        tool = self.tools.get(name)
        if tool is not None:
            self._set_cached_tool(name, tool)
        return tool

    def invalidate_cache(self, tool_name: Optional[str] = None) -> None:
        """Invalida el caché"""
        if tool_name:
            self._cache.pop(tool_name, None)
        else:
            self._cache.clear()

    def get_cache_stats(self) -> dict:
        """Estadísticas del caché"""
        return {
            "cached_tools": len(self._cache),
            "total_tools": len(self.tools),
            "cache_ttl": self._cache_ttl,
            "categories": len(self._categories),
            "templates": len(self.TEMPLATES),
            "chains": len(self._chains)
        }


# ToolRegistry alias for backwards compatibility
ToolRegistry = AdvancedToolRegistry  # noqa: F811
