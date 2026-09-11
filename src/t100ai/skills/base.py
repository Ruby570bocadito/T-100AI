"""Base Skill Framework"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskLevel(Enum):
    """Niveles de riesgo de las herramientas"""
    PASSIVE = 0  # Solo lectura
    ACTIVE = 1  # Genera tráfico/estado
    INTRUSIVE = 2  # Alto impacto


@dataclass
class SkillResult:
    """Resultado de una operación de skill"""
    success: bool
    output: str = ""
    error: Optional[str] = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)  # path -> description
    execution_time: float = 0.0

    def __str__(self) -> str:
        if self.success:
            return self.output
        return f"[red]Error:[/red] {self.error}"


class BaseSkill(ABC):
    """Clase base para todos los skills de T-100AI"""

    name: str = ""
    description: str = ""
    category: str = ""
    risk_level: RiskLevel = RiskLevel.ACTIVE

    def __init__(self):
        self.tools: list[str] = []
        self.workflows: list[str] = []

    @abstractmethod
    async def execute(self, action: str, params: dict[str, Any]) -> SkillResult:
        """
        Ejecuta una acción del skill

        Args:
            action: Nombre de la acción a ejecutar
            params: Parámetros de la acción

        Returns:
            SkillResult con el resultado de la ejecución
        """
        pass

    @abstractmethod
    async def validate_params(self, action: str, params: dict[str, Any]) -> bool:
        """
        Valida los parámetros para una acción

        Args:
            action: Nombre de la acción
            params: Parámetros a validar

        Returns:
            True si los parámetros son válidos
        """
        pass

    def get_available_actions(self) -> list[str]:
        """Retorna las acciones disponibles del skill"""
        return []

    def requires_confirmation(self, action: str) -> bool:
        """Determina si una acción requiere confirmación"""
        return self.risk_level == RiskLevel.INTRUSIVE
