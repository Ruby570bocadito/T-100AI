"""Actionable error system for T-100AI"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class ErrorSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ErrorSuggestion:
    """Sugerencia para resolver un error"""
    action: str
    command: Optional[str] = None
    docs_url: Optional[str] = None
    priority: int = 1


@dataclass
class T100AIError(Exception):
    """Error base con información accionable"""
    message: str
    code: str = "UNKNOWN"
    severity: ErrorSeverity = ErrorSeverity.ERROR
    suggestions: list[ErrorSuggestion] = field(default_factory=list)
    context: dict = field(default_factory=dict)

    def format(self) -> str:
        lines = [
            f"[bold #FF3366]Error:[/] {self.message}",
            f"[dim]Código:[/] {self.code}"
        ]

        if self.suggestions:
            lines.append("\n[bold #FFD60A]Sugerencias:[/]")
            for i, s in enumerate(self.suggestions, 1):
                lines.append(f"  {i}. {s.action}")
                if s.command:
                    lines.append(f"     [dim]$[/] {s.command}")

        return "\n".join(lines)


class CommandError(T100AIError):
    """Error en la ejecución de comandos"""

    def __init__(
        self,
        message: str,
        command: str = "",
        exit_code: int = -1,
        stderr: str = ""
    ):
        suggestions = []
        if exit_code == 127:
            suggestions.append(ErrorSuggestion(
                action="Verifica que la herramienta esté instalada",
                command=f"which {command.split()[0] if command else 'tool'}",
                docs_url="docs/instalacion.md"
            ))
        elif "timeout" in stderr.lower():
            suggestions.append(ErrorSuggestion(
                action="Aumenta el timeout o verifica conectividad",
                command="/mode expert"
            ))

        super().__init__(
            message=f"Comando falló: {message}",
            code="CMD_ERROR",
            suggestions=suggestions,
            context={"command": command, "exit_code": exit_code, "stderr": stderr}
        )


class PermissionError(T100AIError):
    """Error de permisos"""

    def __init__(self, message: str, action: str = "", required_level: str = ""):
        suggestions = [
            ErrorSuggestion(
                action="Cambia el modo de permisos",
                command="/mode standard"
            )
        ]
        if required_level:
            suggestions.append(ErrorSuggestion(
                action=f"Eleva permisos para: {required_level}",
                command=f"/permissions grant {action}" if action else "/permissions show"
            ))

        super().__init__(
            message=message,
            code="PERMISSION_DENIED",
            severity=ErrorSeverity.WARNING,
            suggestions=suggestions,
            context={"action": action, "required_level": required_level}
        )


class SkillError(T100AIError):
    """Error en la ejecución de skills"""

    def __init__(self, skill_name: str, message: str, action: str = ""):
        suggestions = [
            ErrorSuggestion(
                action=f"Verifica que el skill '{skill_name}' esté disponible",
                command="/skills list"
            ),
            ErrorSuggestion(
                action="Documentación del skill",
                docs_url=f"docs/habilidades/{skill_name}.md"
            )
        ]

        super().__init__(
            message=f"Skill '{skill_name}' falló: {message}",
            code="SKILL_ERROR",
            suggestions=suggestions,
            context={"skill": skill_name, "action": action}
        )


class ConfigError(T100AIError):
    """Error de configuración"""

    def __init__(self, message: str, config_key: str = ""):
        suggestions = [
            ErrorSuggestion(
                action="Verifica el archivo .env",
                command="cat .env"
            ),
            ErrorSuggestion(
                action="Restaura configuración por defecto",
                command="specter --config default"
            )
        ]
        if config_key:
            suggestions.append(ErrorSuggestion(
                action=f"Configura '{config_key}'",
                docs_url="docs/configuracion.md"
            ))

        super().__init__(
            message=message,
            code="CONFIG_ERROR",
            severity=ErrorSeverity.WARNING,
            suggestions=suggestions,
            context={"config_key": config_key}
        )


class LLMError(T100AIError):
    """Error en la conexión con LLM"""

    def __init__(self, message: str, model: str = "", host: str = ""):
        suggestions = [
            ErrorSuggestion(
                action="Verifica que Ollama esté ejecutándose",
                command="ollama serve"
            ),
            ErrorSuggestion(
                action="Descarga el modelo",
                command=f"ollama pull {model}" if model else "ollama pull llama3.2"
            ),
            ErrorSuggestion(
                action="Modo sin LLM (herramientas solo)",
                command="specter --no-llm"
            )
        ]

        super().__init__(
            message=message,
            code="LLM_ERROR",
            suggestions=suggestions,
            context={"model": model, "host": host}
        )


class WorkflowError(T100AIError):
    """Error en workflows"""

    def __init__(self, workflow_name: str, message: str, step: int = 0):
        suggestions = [
            ErrorSuggestion(
                action="Lista workflows disponibles",
                command="/workflow list"
            ),
            ErrorSuggestion(
                action="Documentación de workflows",
                docs_url="docs/workflows.md"
            )
        ]

        super().__init__(
            message=f"Workflow '{workflow_name}' falló: {message}",
            code="WORKFLOW_ERROR",
            suggestions=suggestions,
            context={"workflow": workflow_name, "failed_step": step}
        )


def format_error(error: Exception) -> str:
    """Formatea cualquier error para mostrar al usuario"""
    if isinstance(error, T100AIError):
        return error.format()

    return f"[bold #FF3366]Error inesperado:[/] {str(error)}\n[dim]Usa /help para comandos disponibles[/]"


class ErrorHandler:
    """Manejador centralizado de errores"""

    _handlers: dict[type, Callable] = {}

    @classmethod
    def register(cls, error_type: type, handler: Callable[[Exception], str]):
        cls._handlers[error_type] = handler

    @classmethod
    def handle(cls, error: Exception) -> str:
        error_type = type(error)
        if error_type in cls._handlers:
            return cls._handlers[error_type](error)

        for registered_type, handler in cls._handlers.items():
            if isinstance(error, registered_type):
                return handler(error)

        return format_error(error)

    @classmethod
    def register_defaults(cls):
        cls.register(CommandError, lambda e: e.format())
        cls.register(PermissionError, lambda e: e.format())
        cls.register(SkillError, lambda e: e.format())
        cls.register(ConfigError, lambda e: e.format())
        cls.register(LLMError, lambda e: e.format())
        cls.register(WorkflowError, lambda e: e.format())
