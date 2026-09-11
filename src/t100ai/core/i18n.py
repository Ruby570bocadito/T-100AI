"""T-100AI Internationalization (i18n) System"""

from typing import Optional

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # UI Strings
        "welcome_banner": "T-100AI v2.0 — AI-Powered Offensive Security Terminal\nModel: {model}\nType 'help' for available commands.",
        "ethics_confirmation": "By using T-100AI, you confirm that you have explicit authorization to test the specified targets and will comply with all applicable laws and regulations.",
        "help_commands": """Available Commands:
  help              Show this help message
  scope <target>    Add target to scope
  scope list        List current scope
  scope clear       Clear scope
  mode <level>      Set permission mode (paranoid/standard/expert)
  model <name>      Change LLM model
  session new       Start a new session
  session list      List sessions
  session load <id> Load a session
  findings          List findings
  report            Generate session report
  exit              Exit T-100AI""",
        "scope_prompt": "Enter target to add to scope: ",
        "executing": "Executing...",
        "thinking": "Thinking",
        "analyzing": "Analyzing",

        # Error Messages
        "command_blocked": "Command blocked: '{command}' is not allowed within the current scope or permission level.",
        "guardrail_warning": "GUARDRAIL WARNING: The requested action may violate scope or ethical constraints. Review before proceeding.",
        "permission_denied": "Permission denied: current mode '{mode}' does not allow this action.",
        "sandbox_blocked": "Sandbox blocked execution: '{command}' was prevented from running for safety.",
        "unknown_command": "Unknown command: '{command}'. Type 'help' for available commands.",
        "invalid_scope": "Invalid scope entry: '{target}'. Please provide a valid IP, CIDR, domain, or URL.",
        "model_not_found": "Model '{model}' not found or unavailable.",
        "session_not_found": "Session '{session_id}' not found.",
        "no_active_session": "No active session. Start one with 'session new'.",

        # Help Text
        "mode_help": "Permission modes:\n  paranoid  — Require approval for every action\n  standard  — Require approval for intrusive actions only\n  expert    — No approval required (use with caution)",
        "model_help": "Available models depend on your Ollama installation. Use 'ollama list' to see installed models.",

        # Status Messages
        "session_started": "Session '{session_id}' started.",
        "model_changed": "Model changed to '{model}'.",
        "finding_added": "Finding added: [{severity}] {title}",
        "report_generated": "Report generated: {path}",
        "no_findings": "No findings recorded in this session.",
        "exit_confirm": "Are you sure you want to exit? Unsaved findings may be lost. (y/N): ",
        "scope_added": "Target '{target}' added to scope.",
        "scope_cleared": "Scope cleared.",
        "scope_empty": "Scope is empty. Add targets with 'scope <target>'.",
        "scope_list_header": "Current scope ({count} targets):",

        # Mode Labels
        "mode_interactive": "Interactive",
        "mode_paranoid": "Paranoid",
        "mode_expert": "Expert",
        "mode_standard": "Standard",

        # Guardrail Labels
        "guardrail_scope_check": "Scope check",
        "guardrail_ethics_check": "Ethics check",
        "guardrail_permission_check": "Permission check",
    },
    "es": {
        # UI Strings
        "welcome_banner": "T-100AI v2.0 — Terminal de Seguridad Ofensiva impulsada por IA\nModelo: {model}\nEscribe 'help' para ver los comandos disponibles.",
        "ethics_confirmation": "Al usar T-100AI, confirmas que tienes autorización explícita para probar los objetivos especificados y que cumplirás con todas las leyes y regulaciones aplicables.",
        "help_commands": """Comandos Disponibles:
  help              Mostrar esta ayuda
  scope <objetivo>  Añadir objetivo al scope
  scope list        Listar scope actual
  scope clear       Limpiar scope
  mode <nivel>      Establecer modo de permiso (paranoid/standard/expert)
  model <nombre>    Cambiar modelo LLM
  session new       Iniciar nueva sesión
  session list      Listar sesiones
  session load <id> Cargar una sesión
  findings          Listar hallazgos
  report            Generar reporte de sesión
  exit              Salir de T-100AI""",
        "scope_prompt": "Ingresa el objetivo a añadir al scope: ",
        "executing": "Ejecutando...",
        "thinking": "Pensando",
        "analyzing": "Analizando",

        # Error Messages
        "command_blocked": "Comando bloqueado: '{command}' no está permitido dentro del scope o nivel de permiso actual.",
        "guardrail_warning": "ADVERTENCIA DE GUARDRAIL: La acción solicitada puede violar restricciones de scope o éticas. Revisa antes de continuar.",
        "permission_denied": "Permiso denegado: el modo actual '{mode}' no permite esta acción.",
        "sandbox_blocked": "El sandbox bloqueó la ejecución: '{command}' fue prevenido por seguridad.",
        "unknown_command": "Comando desconocido: '{command}'. Escribe 'help' para ver los comandos disponibles.",
        "invalid_scope": "Entrada de scope inválida: '{target}'. Proporciona una IP, CIDR, dominio o URL válida.",
        "model_not_found": "Modelo '{model}' no encontrado o no disponible.",
        "session_not_found": "Sesión '{session_id}' no encontrada.",
        "no_active_session": "No hay sesión activa. Inicia una con 'session new'.",

        # Help Text
        "mode_help": "Modos de permiso:\n  paranoid  — Requiere aprobación para cada acción\n  standard  — Requiere aprobación solo para acciones intrusivas\n  expert    — No requiere aprobación (usar con precaución)",
        "model_help": "Los modelos disponibles dependen de tu instalación de Ollama. Usa 'ollama list' para ver los modelos instalados.",

        # Status Messages
        "session_started": "Sesión '{session_id}' iniciada.",
        "model_changed": "Modelo cambiado a '{model}'.",
        "finding_added": "Hallazgo añadido: [{severity}] {title}",
        "report_generated": "Reporte generado: {path}",
        "no_findings": "No hay hallazgos registrados en esta sesión.",
        "exit_confirm": "¿Estás seguro de que quieres salir? Los hallazgos no guardados pueden perderse. (y/N): ",
        "scope_added": "Objetivo '{target}' añadido al scope.",
        "scope_cleared": "Scope limpiado.",
        "scope_empty": "El scope está vacío. Añade objetivos con 'scope <objetivo>'.",
        "scope_list_header": "Scope actual ({count} objetivos):",

        # Mode Labels
        "mode_interactive": "Interactivo",
        "mode_paranoid": "Paranoico",
        "mode_expert": "Experto",
        "mode_standard": "Estándar",

        # Guardrail Labels
        "guardrail_scope_check": "Verificación de scope",
        "guardrail_ethics_check": "Verificación ética",
        "guardrail_permission_check": "Verificación de permisos",
    },
}

AVAILABLE_LANGUAGES = list(TRANSLATIONS.keys())


class I18n:
    """Internationalization handler for T-100AI."""

    def __init__(self, lang: str = "es") -> None:
        self._lang = lang if lang in TRANSLATIONS else "es"

    def set_language(self, lang: str) -> None:
        if lang not in TRANSLATIONS:
            raise ValueError(f"Unsupported language: '{lang}'. Available: {AVAILABLE_LANGUAGES}")
        self._lang = lang

    def t(self, key: str, **kwargs) -> str:
        bundle = TRANSLATIONS.get(self._lang, TRANSLATIONS["es"])
        text = bundle.get(key, key)
        if kwargs:
            text = text.format(**kwargs)
        return text

    def get_available_languages(self) -> list[str]:
        return list(AVAILABLE_LANGUAGES)

    def get_current_language(self) -> str:
        return self._lang


_singleton: Optional[I18n] = None


def get_i18n() -> I18n:
    global _singleton
    if _singleton is None:
        _singleton = I18n()
    return _singleton
