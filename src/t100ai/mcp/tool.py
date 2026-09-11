"""MCP Tool Definition"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskLevel(Enum):
    """Nivel de riesgo de la herramienta"""
    PASSIVE = 0     # Solo lectura/observación
    ACTIVE = 1      # Genera tráfico o estado
    INTRUSIVE = 2   # Alto impacto


class ExecutionMode(Enum):
    """Modo de ejecución de la herramienta"""
    FAST = "fast"       # Escaneo rápido
    STEALTH = "stealth" # Oculto, lento pero sigiloso
    LOUD = "loud"       # Completo, ruidoso


@dataclass
class ToolParameter:
    """Parámetro de una herramienta MCP"""
    name: str
    type: str  # string, integer, boolean, list, enum
    description: str = ""
    required: bool = False
    default: Any = None
    enum_values: list[str] = field(default_factory=list)


@dataclass
class ToolWordlist:
    """Wordlist asociada a una herramienta"""
    name: str
    path: str
    description: str = ""
    default: bool = False


@dataclass
class ToolResult:
    """Resultado de ejecutar una herramienta MCP"""
    success: bool
    output: str = ""
    error: Optional[str] = None
    raw_output: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)


@dataclass
class MCPTool:
    """Definición de una herramienta en el protocolo MCP"""
    name: str
    description: str
    category: str
    skill: str
    risk_level: int = 0  # 0=pasive, 1=active, 2=intrusive

    # Parámetros
    parameters: list[ToolParameter] = field(default_factory=list)

    # Metadatos
    command: Optional[str] = None  # Comando base a ejecutar
    examples: list[str] = field(default_factory=list)

    # Versatilidad
    wordlists: list[ToolWordlist] = field(default_factory=list)
    execution_modes: list[str] = field(default_factory=list)  # fast, stealth, loud
    requires_scope: bool = False  # Requiere objetivo del scope
    output_parser: str = "default"
    aliases: list[str] = field(default_factory=list)

    # Chaining
    input_from: list[str] = field(default_factory=list)  # Herramientas que pueden dar input
    output_to: list[str] = field(default_factory=list)    # Herramientas que pueden recibir output

    def get_parameter(self, name: str) -> Optional[ToolParameter]:
        """Obtiene un parámetro por nombre"""
        for p in self.parameters:
            if p.name == name:
                return p
        return None

    def validate_params(self, params: dict[str, Any]) -> tuple[bool, str]:
        """Valida los parámetros proporcionados"""
        for p in self.parameters:
            if p.required and p.name not in params:
                return False, f"Parámetro requerido faltante: {p.name}"

            if p.name in params and p.enum_values:
                value = params[p.name]
                if value not in p.enum_values:
                    return False, f"Valor inválido para {p.name}: {value}"

        return True, ""

    @property
    def risk_level_enum(self) -> RiskLevel:
        """Obtiene el nivel de riesgo como enum"""
        return RiskLevel(self.risk_level)

    @property
    def requires_confirmation(self) -> bool:
        """Determina si requiere confirmación"""
        return self.risk_level >= 2 or self.risk_level == 1

    def supports_execution_mode(self, mode: str) -> bool:
        """Verifica si soporta un modo de ejecución"""
        if not self.execution_modes:
            return True  # Default
        return mode in self.execution_modes or "default" in self.execution_modes

    def get_default_wordlist(self) -> Optional[str]:
        """Obtiene la wordlist por defecto"""
        for wl in self.wordlists:
            if wl.default:
                return wl.path
        return self.wordlists[0].path if self.wordlists else None

    def can_chain_from(self, tool_name: str) -> bool:
        """Verifica si puede recibir output de otra herramienta"""
        return tool_name in self.input_from

    def can_chain_to(self, tool_name: str) -> bool:
        """Verifica si puede dar output a otra herramienta"""
        return tool_name in self.output_to

    def build_command(self, params: dict, mode: str = "default") -> str:
        """Construye el comando completo con parámetros y modo"""
        if not self.command:
            return ""

        cmd = self.command

        if mode == "fast":
            if "{{args}}" in cmd:
                cmd = cmd.replace("{{args}}", "-t 150 -p- --max-rate 1000")
        elif mode == "stealth":
            if "{{args}}" in cmd:
                cmd = cmd.replace("{{args}}", "-t 1 --max-rate 1 --randomize-hosts")
        elif mode == "loud":
            if "{{args}}" in cmd:
                cmd = cmd.replace("{{args}}", "-sV -sC -sS -A -O")

        for key, value in params.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in cmd:
                cmd = cmd.replace(placeholder, str(value))

        return cmd

    def to_dict(self) -> dict:
        """Convierte a diccionario para serialización"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "skill": self.skill,
            "risk_level": self.risk_level,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                    "default": p.default,
                    "enum_values": p.enum_values,
                }
                for p in self.parameters
            ],
        }
