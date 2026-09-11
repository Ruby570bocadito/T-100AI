"""Single source of truth for the T-100AI terminal help.

Both ``t100ai.cli.main`` (REPL) and ``t100ai.core.engine.T100AIEngine._show_help``
render THIS text, so the advertised commands can never drift from the
CommandRouter table again.
"""

from t100ai import __version__


def markdown_help(version: str | None = None) -> str:
    """Ayuda honesta: exactamente los comandos que CommandRouter soporta."""
    v = version or __version__
    return f"""
# ◈ T-100AI — Ayuda de Comandos

**T-100AI** · AI-Powered Offensive Security Terminal · v{v}

Consejo: pulsa **TAB** para autocompletar comandos y usa las flechas
↑/↓ para navegar el historial persistente.

---

## SESIÓN Y ALCANCE
| Comando | Descripción |
|---|---|
| `/session` | Información de la sesión actual |
| `/scope set [ip/cidr/domain]` | Definir el scope de la operación |
| `/scope show` | Mostrar scope actual |
| `/scope clear` | Limpiar scope |
| `/save [archivo]` | Guardar código/hallazgos de la sesión |

## ROLES Y MODOS
| Comando | Descripción |
|---|---|
| `/role set [nombre]` | Cambiar rol activo |
| `/role show` | Mostrar rol actual |
| `/role list` | Listar roles disponibles |
| `/mode paranoid` | Confirmación en TODAS las acciones |
| `/mode standard` | Modo estándar (por defecto) |
| `/mode expert` | Auto-ejecución sin confirmaciones |

Roles disponibles: `pentester` · `red-teamer` · `blue-teamer` · `ctf-player` · `forensic`

## SKILLS Y HERRAMIENTAS
| Comando | Descripción |
|---|---|
| `/skill list` | Listar skills disponibles |
| `/skill use [nombre]` | Activar skill específico |
| `/skill info [nombre]` | Info detallada de un skill |
| `/tools` | Listar herramientas MCP disponibles |

Skills: `recon` · `osint` · `web` · `exploit` · `postex` · `forense` · `ad` · `report`

## MODELO DE IA
| Comando | Descripción |
|---|---|
| `/model info` | Info del modelo activo |
| `/model switch [nombre]` | Cambiar modelo Ollama |
| `/model list` | Listar modelos instalados en Ollama |

## HALLAZGOS
| Comando | Descripción |
|---|---|
| `/findings show` | Ver todos los hallazgos registrados |
| `/findings add [sev] [título]` | Añadir hallazgo manual (ej: `HIGH MySQL expuesto`) |
| `/findings score [id] [cvss]` | Asignar score CVSS a un hallazgo |

## REPORTES Y LOGS
| Comando | Descripción |
|---|---|
| `/report generate` | Generar informe final (markdown) |
| `/report preview` | Vista previa del informe |
| `/report session` | Resumen de la sesión |
| `/report export [formato]` | Exportar informe |
| `/log show` | Ver log de acciones de sesión |
| `/log export` | Exportar log completo |

## CONTEXTO Y HISTORIAL
| Comando | Descripción |
|---|---|
| `/context show` | Ver historial conversacional en memoria |
| `/context clear` | Limpiar historial (mantiene hallazgos) |
| `/history [query]` | Historial de comandos del terminal |
| `/perf` | Estadísticas de rendimiento |

## AGENTES, WORKFLOWS Y PLUGINS
| Comando | Descripción |
|---|---|
| `/agent list` | Listar agentes disponibles |
| `/agent spawn [tarea]` | Desplegar tarea en un agente |
| `/agent status` | Estado del orquestador |
| `/workflow list` | Listar workflows disponibles |
| `/workflow run [nombre]` | Ejecutar workflow completo |
| `/workflow status` | Estado del workflow en curso |
| `/deploy task [desc]` | Desplegar tarea al orquestador |
| `/plugin list` | Listar plugins |
| `/plugin search [query]` | Buscar plugins |
| `/plugin install [nombre]` | Instalar plugin |

## UTILIDADES
| Comando | Descripción |
|---|---|
| `/wordlist <tipo>` | Wordlists integradas: dir, subdomain, user, pass, sql, xss, lfi, cve, all |
| `/read [archivo]` | Leer un archivo y mostrarlo |
| `help` / `/help` | Mostrar esta ayuda |
| `/clear` | Limpiar pantalla |
| `exit` / `quit` / `salir` | Cerrar T-100AI (también `/exit`) |

---

## CONTROL DE SISTEMA (LLM)

El LLM puede ejecutar comandos reales usando la sintaxis:

```
<cmd>nmap -sV 192.168.1.1</cmd>
```

Se pedirá confirmación antes de ejecutar cada comando (excepto en modo `expert`).
El output se analiza automáticamente y el LLM propone los siguientes pasos.
El sandbox valida scope, rate-limit y bloquea comandos destructivos.

---

## ENTRADA NATURAL

Todo lo que no sea un comando `/cmd` se procesa como lenguaje natural:

```
escanea los puertos de 192.168.1.1
tengo este hash: $2y$10$abc...
explícame el ataque Kerberoasting
inicia un pentest completo contra 10.0.0.0/24
```
"""
