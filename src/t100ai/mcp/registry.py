"""MCP Tool Registry with caching"""

import shutil
import time
from typing import Optional

import structlog

from t100ai.mcp.tool import MCPTool, ToolParameter

logger = structlog.get_logger()


def cached(ttl: int = 3600):
    """Decorator para cache con TTL"""
    def decorator(func):
        cache = {}
        def wrapper(self, *args, **kwargs):
            key = args[0] if args else kwargs.get('name', '')
            current_time = time.time()
            if key in cache:
                cached_value, timestamp = cache[key]
                if current_time - timestamp < ttl:
                    return cached_value
            result = func(self, *args, **kwargs)
            cache[key] = (result, current_time)
            return result
        return wrapper
    return decorator


class ToolRegistry:
    """Registry central de herramientas MCP con caché"""

    def __init__(self, cache_ttl: int = 3600):
        self.tools: dict[str, MCPTool] = {}
        self._cache: dict[str, tuple[MCPTool, float]] = {}
        self._cache_ttl = cache_ttl
        self._discovery_cache: Optional[tuple[list[MCPTool], float]] = None

    async def discover_tools(self) -> None:
        """Descubre y registra todas las herramientas disponibles"""
        logger.info("Discovering MCP tools...")

        # Registrar herramientas built-in
        self._register_builtin_tools()

        # Descubrir herramientas del sistema
        self._discover_system_tools()

        logger.info("Tools discovered", count=len(self.tools))

    def _register_builtin_tools(self) -> None:
        """Registra herramientas built-in de T-100AI"""

        # Herramientas de red - Observación
        self.register(MCPTool(
            name="network.port_scan",
            description="Escaneo de puertos TCP/UDP contra uno o varios hosts",
            category="network",
            skill="recon",
            risk_level=1,
            parameters=[
                ToolParameter(name="targets", type="string", required=True,
                             description="IPs o rangos CIDR objetivo"),
                ToolParameter(name="port_range", type="string", default="1-1024",
                             description="Rango de puertos (ej: 80,443 o 1-65535)"),
                ToolParameter(name="scan_type", type="enum", default="SYN",
                             enum_values=["SYN", "TCP", "UDP", "version"],
                             description="Tipo de escaneo"),
                ToolParameter(name="timing", type="enum", default="T3",
                             enum_values=["T0", "T1", "T2", "T3", "T4", "T5"],
                             description="Timing del escaneo"),
            ],
            command="nmap",
            examples=["network.port_scan(targets='192.168.1.1', port_range='1-1000')"]
        ))

        self.register(MCPTool(
            name="network.ping_sweep",
            description="Descubrimiento de hosts activos mediante ping",
            category="network",
            skill="recon",
            risk_level=0,
            parameters=[
                ToolParameter(name="target", type="string", required=True,
                             description="Rango de red en formato CIDR"),
            ],
            command="nmap -sn",
        ))

        self.register(MCPTool(
            name="network.dns_enum",
            description="Enumeración de registros DNS",
            category="network",
            skill="recon",
            risk_level=0,
            parameters=[
                ToolParameter(name="domain", type="string", required=True,
                             description="Dominio a enumerar"),
                ToolParameter(name="record_type", type="enum", default="ANY",
                             enum_values=["A", "AAAA", "MX", "NS", "TXT", "ANY"],
                             description="Tipo de registro DNS"),
            ],
            command="dig",
        ))

        # Herramientas de sistema
        self.register(MCPTool(
            name="system.process_list",
            description="Lista procesos activos del sistema",
            category="system",
            skill="recon",
            risk_level=0,
            parameters=[
                ToolParameter(name="filter", type="string", default="",
                             description="Filtrar por nombre de proceso"),
            ],
            command="ps",
        ))

        self.register(MCPTool(
            name="system.network_conns",
            description="Lista conexiones de red activas",
            category="system",
            skill="recon",
            risk_level=0,
            command="netstat",
        ))

        # Hash tools
        self.register(MCPTool(
            name="hash.identify",
            description="Identifica el tipo de hash",
            category="crypto",
            skill="recon",
            risk_level=0,
            parameters=[
                ToolParameter(name="hash", type="string", required=True,
                             description="Hash a identificar"),
            ],
        ))

        # CVE tools
        self.register(MCPTool(
            name="cve.lookup",
            description="Busca información sobre un CVE específico",
            category="intelligence",
            skill="recon",
            risk_level=0,
            parameters=[
                ToolParameter(name="cve_id", type="string", required=True,
                             description="ID del CVE (ej: CVE-2021-44228)"),
            ],
        ))

        # Vulnerabilidad tools
        self.register(MCPTool(
            name="vuln.scan",
            description="Escaneo de vulnerabilidades",
            category="vuln",
            skill="recon",
            risk_level=1,
            parameters=[
                ToolParameter(name="target", type="string", required=True,
                             description="Objetivo a escanear"),
                ToolParameter(name="scan_type", type="enum", default="basic",
                             enum_values=["basic", "full", "vuln"],
                             description="Tipo de escaneo"),
            ],
            command="nmap --script vuln",
        ))

        # Password tools
        self.register(MCPTool(
            name="password.hash_crack",
            description="Crackeo de hashes de contraseñas",
            category="password",
            skill="recon",
            risk_level=1,
            parameters=[
                ToolParameter(name="hash", type="string", required=True,
                             description="Hash a crackear"),
                ToolParameter(name="wordlist", type="string", default="/usr/share/wordlists/rockyou.txt",
                             description="Wordlist a usar"),
            ],
            command="hashcat",
        ))

        # Herramientas de explotación
        self.register(MCPTool(
            name="exploit.run",
            description="Ejecuta un exploit específico",
            category="exploit",
            skill="exploit",
            risk_level=2,
            parameters=[
                ToolParameter(name="target", type="string", required=True,
                             description="Objetivo del exploit"),
                ToolParameter(name="exploit_path", type="string", required=True,
                             description="Ruta al exploit o nombre del módulo"),
            ],
        ))

        # Web tools
        self.register(MCPTool(
            name="web.dir_fuzz",
            description="Fuzzing de directorios web",
            category="web",
            skill="web",
            risk_level=1,
            parameters=[
                ToolParameter(name="url", type="string", required=True,
                             description="URL base"),
                ToolParameter(name="wordlist", type="string", default="",
                             description="Wordlist de directorios"),
            ],
            command="gobuster",
        ))

        self.register(MCPTool(
            name="web.sqlmap",
            description="Test de inyección SQL automatizado",
            category="web",
            skill="web",
            risk_level=2,
            parameters=[
                ToolParameter(name="url", type="string", required=True,
                             description="URL a testear"),
                ToolParameter(name="level", type="integer", default=1,
                             description="Nivel de profundidad (1-5)"),
            ],
            command="sqlmap",
        ))

    def _discover_system_tools(self) -> None:
        """Descubre herramientas disponibles en el sistema"""

        # Verificar herramientas de red
        tools_to_check = [
            ("nmap", "network"),
            ("masscan", "network"),
            ("rustscan", "network"),
            ("gobuster", "web"),
            ("ffuf", "web"),
            ("sqlmap", "web"),
            ("nikto", "web"),
            ("hashcat", "password"),
            ("john", "password"),
            ("hydra", "password"),
            ("searchsploit", "exploit"),
            ("msfconsole", "exploit"),
            ("wireshark", "network"),
            ("tcpdump", "network"),
        ]

        discovered = []
        for tool, category in tools_to_check:
            if shutil.which(tool):
                discovered.append((tool, category))

        logger.debug("System tools discovered", tools=discovered)

    def register(self, tool: MCPTool) -> None:
        """Registra una herramienta"""
        self.tools[tool.name] = tool
        logger.debug("Tool registered", name=tool.name)

    def get_tool(self, name: str) -> Optional[MCPTool]:
        """Obtiene una herramienta por nombre"""
        return self.tools.get(name)

    def list_tools(self, category: Optional[str] = None) -> list[MCPTool]:
        """Lista herramientas, opcionalmente filtradas por categoría"""
        if category:
            return [t for t in self.tools.values() if t.category == category]
        return list(self.tools.values())

    def list_by_risk_level(self, level: int) -> list[MCPTool]:
        """Lista herramientas por nivel de riesgo"""
        return [t for t in self.tools.values() if t.risk_level == level]

    def search(self, query: str) -> list[MCPTool]:
        """Busca herramientas por nombre o descripción"""
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
            logger.debug("Tool cache miss, cached", tool=name)
        return tool

    def invalidate_cache(self, tool_name: Optional[str] = None) -> None:
        """Invalida el caché de herramientas"""
        if tool_name:
            self._cache.pop(tool_name, None)
            logger.debug("Cache invalidated for tool", tool=tool_name)
        else:
            self._cache.clear()
            logger.info("All tool cache invalidated")

    def get_cache_stats(self) -> dict:
        """Retorna estadísticas del caché"""
        return {
            "cached_tools": len(self._cache),
            "total_tools": len(self.tools),
            "cache_ttl": self._cache_ttl
        }
