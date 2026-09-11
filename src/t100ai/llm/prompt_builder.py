"""Prompt builder for different operator roles.

Optimized system prompts for enterprise pentesting, CTF, blue team,
forensics, and red team operations.

Loads role prompts and command instructions from template files
in src/t100ai/llm/templates/ with fallback to hardcoded strings.
"""

from pathlib import Path
from typing import Dict, List, Optional


class PromptBuilder:
    """Construye prompts del sistema para distintos roles."""

    # ── Hardcoded fallbacks ─────────────────────────────────────────────
    _FALLBACK_IDENTITY = (
        "Eres T-100AI v2.0 — asistente de ciberseguridad ofensiva y defensiva "
        "que se ejecuta LOCALMENTE en la terminal del operador.\n\n"
        "CAPACIDADES:\n"
        "- Ejecutas comandos en el sistema local del operador via etiquetas <cmd>comando</cmd>\n"
        "- Lees archivos, ejecutas herramientas, analizas outputs en tiempo real\n"
        "- Si un comando necesita privilegios, T-100AI reintenta con sudo automaticamente\n"
        "- Detectas vulnerabilidades, clasificas hallazgos, generas informes\n"
        "- Mapeas tecnicas a MITRE ATT&CK y CVSS\n\n"

        "REGLAS ANTI-HALUCINACION — VIOLAR ESTAS REGLAS ROMPE LA HERRAMIENTA:\n"
        "1. NUNCA inventes resultados de comandos que no ejecutaste\n"
        "2. NUNCA digas 'encontre X puerto abierto' sin haber ejecutado nmap primero\n"
        "3. NUNCA listes herramientas como 'instaladas' sin ejecutar 'which' para verificar\n"
        "4. NUNCA muestres output falso de un comando — solo muestra lo que T-100AI retorno\n"
        "5. NUNCA digas 'el escaneo muestra...' sin que el escaneo se haya ejecutado realmente\n"
        "6. NUNCA inventes CVEs, exploits, o vulnerabilidades sin evidencia real\n"
        "7. NUNCA inventes IPs, dominios, o servicios — solo reporta lo que encontraste\n"
        "8. NUNCA finjas que ejecutaste un comando — usa <cmd> y ESPERA el resultado\n"
        "9. Si no sabes algo, di 'no lo se, voy a verificar' y EJECUTA un comando\n"
        "10. El UNICO output valido es el que devuelve el sistema — NADA inventado\n\n"

        "REGLAS DE OPERACION:\n"
        "1. Propones el comando exacto a ejecutar, nunca instrucciones vagas\n"
        "2. Cuando recibes resultados, los analizas exhaustivamente\n"
        "3. Priorizas hallazgos por severidad: [CRIT] [HIGH] [MED] [LOW] [INFO]\n"
        "4. Documentas cada paso automaticamente para el informe final\n"
        "5. Si hay scope definido, no propones acciones fuera de el\n"
        "6. Confirmas operaciones destructivas antes de ejecutar\n"
        "7. Siempre propones los siguientes pasos al terminar una fase\n"
        "8. NUNCA digas que no tienes acceso al sistema — SIEMPRE lo tienes\n"
        "9. SIEMPRE responde en el idioma del operador\n"
        "10. MAXIMO 2-3 comandos encadenados sin preguntar al usuario\n"
    )

    _FALLBACK_ROLES: Dict[str, str] = {
        "pentester": "ROL ACTIVO: PENTESTER PROFESIONAL\nMetodologia: PTES",
        "red-teamer": "ROL ACTIVO: RED TEAM OPERATOR\nFilosofia: Objetivos > Metodologia. OPSEC siempre ON.",
        "blue-teamer": "ROL ACTIVO: BLUE TEAM DEFENDER\nObjetivo: Detectar, contener, remediar, prevenir.",
        "ctf-player": "ROL ACTIVO: CTF PLAYER & EDUCADOR\nObjetivo: Resolver desafios, ensenar tecnicas, aprender.",
        "forensic": "ROL ACTIVO: FORENSIC ANALYST\nPrincipio: Cadena de custodia, integridad, reproducibilidad.",
    }

    _FALLBACK_CMD = (
        "═══════════════════════════════════════════════════════════\n"
        "SISTEMA DE EJECUCION DE COMANDOS\n"
        "═══════════════════════════════════════════════════════════\n\n"
        "FORMATO DE EJECUCION:\n"
        "Para ejecutar un comando en el sistema local del operador:\n"
        "  <cmd>comando aqui</cmd>\n\n"
        "CUANDO USAR <cmd>:\n"
        "  ✓ El usuario pide ejecutar un escaneo/auditoria\n"
        "  ✓ El usuario pide ver info del sistema o archivos\n"
        "  ✓ El usuario da un scope y pide comenzar el pentest\n\n"
        "CUANDO NO USAR <cmd>:\n"
        "  ✗ Saludos: 'hola', 'buenas', 'que tal'\n"
        "  ✗ Preguntas generales: 'que puedes hacer', 'ayuda'\n"
    )

    def __init__(self) -> None:
        self._template_dir = Path(__file__).parent / "templates"
        self._identity: str = self._load_template("t100ai_identity.txt", self._FALLBACK_IDENTITY)
        self._cmd_instructions: str = self._load_template("cmd_instructions.txt", self._FALLBACK_CMD)
        self._role_adjustments: Dict[str, str] = self._load_role_templates()

    def _load_template(self, filename: str, fallback: str) -> str:
        """Load a template file, returning fallback on failure."""
        path = self._template_dir / filename
        try:
            if path.exists():
                return path.read_text(encoding="utf-8")
        except Exception:
            pass
        return fallback

    def _load_role_templates(self) -> Dict[str, str]:
        """Load all role template files into a dict."""
        role_files = {
            "pentester": "role_pentester.txt",
            "red-teamer": "role_red-teamer.txt",
            "blue-teamer": "role_blue-teamer.txt",
            "ctf-player": "role_ctf-player.txt",
            "forensic": "role_forensic.txt",
        }
        roles: Dict[str, str] = {}
        for key, filename in role_files.items():
            content = self._load_template(filename, self._FALLBACK_ROLES.get(key, ""))
            roles[key] = content
        return roles

    def build_system_prompt(self, role: str, session_context: Optional[str] = None, json_mode: bool = False) -> str:
        """Return system prompt for a given role."""
        key = str(role).lower()
        role_adj = self._role_adjustments.get(key, "")

        prompt = self._identity
        if role_adj:
            prompt += f"\n{role_adj}"

        prompt += self._cmd_instructions

        if session_context:
            prompt += f"\n\nSession Context:\n{session_context}"
        if json_mode:
            prompt += "\n\nRespond in JSON format with a 'response' field."
        return prompt

    def build_session_context(self, session_id: Optional[str], history: Optional[List[Dict[str, str]]] = None) -> str:
        if not session_id:
            return ""
        if not history:
            return f"Session {session_id} started."
        lines = [f"{m['role']}: {m['content']}" for m in history[-5:]]
        return f"Session {session_id} history (last {len(lines)} exchanges):\n" + "\n".join(lines)

    _TEMPLATES: Dict[str, str] = {
        "default": "Question: {query}\\nAnswer:",
        "analysis": "Analyze the following: {query}. Provide reasoning steps and justification.",
        "code": "Given the requirement: {query}. Provide a code solution with explanations and comments.",
        "summary": "Summarize: {query} in concise bullet points.",
    }

    def render_template(self, query_type: str, context: Dict[str, str]) -> str:
        tpl = self._TEMPLATES.get(query_type, self._TEMPLATES["default"])
        try:
            return tpl.format(**context)
        except Exception:
            return context.get("query", "")

    def get_system_prompt(self, role: str = "pentester") -> str:
        """Alias for build_system_prompt for backwards compatibility."""
        return self.build_system_prompt(role)
