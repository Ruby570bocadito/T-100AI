# T-100AI — AI-Powered Offensive Security Terminal

![CI](https://github.com/Ruby570bocadito/T-100AI/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-430%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Offline](https://img.shields.io/badge/offline-100%25%20air--gapped-black)

**T-100AI** es un terminal de operaciones ofensivas asistido por un LLM **100% local** (Ollama). Nada sale de tu máquina: sin telemetría, sin APIs en la nube, sin fugas. El modelo propone, un sandbox valida y **tú confirmas** cada comando antes de ejecutarlo.

> Diseñado para pentesting autorizado, laboratorios y CTF. Cada acción pasa por un gate de confirmación ética y por el sandbox antes de tocar el sistema.

---

## Cómo funciona

```mermaid
flowchart LR
    U[Operador] -->|prompt o /comando| T[T-100AI]
    T -->|contexto + intención| L[Ollama local]
    L -->|propuesta &lt;cmd&gt;| S[Sandbox]
    S -->|scope · rate-limit · blacklist| K[Herramientas]
    K -->|output filtrado| T
    T -->|análisis + hallazgos| U
```

1. **Propón** — escribes lenguaje natural (`escanea los puertos de 10.0.0.5`) o comandos slash (`/scope set 10.0.0.0/24`).
2. **Decide el modelo** — el LLM local responde y puede proponer comandos con `<cmd>…</cmd>`.
3. **Valida el sandbox** — scope autorizado, rate-limit, límite por sesión y blacklist de comandos destructivos (`rm -rf /`, `dd of=/dev/sd`, fork bombs…).
4. **Confirma el humano** — modo `paranoid` pide confirmación para todo; `standard` en cada comando; `expert` auto-ejecuta.
5. **Registra todo** — hallazgos, decisiones y comandos quedan en la sesión y exportables a reporte.

## Características

| | |
|---|---|
| **LLM local (Ollama)** | mistral, llama3, qwen, gemma, deepseek… cero datos fuera de la máquina |
| **Sandbox con filtros** | scope, rate-limit, límite de sesión, blacklist destructiva, kill del árbol de procesos en timeout |
| **Skills integrados** | recon, osint, web, exploit, postex, forense, active directory, reporting |
| **MCP avanzado** | registro de herramientas, chains, parsers de output, plantillas |
| **Multi-agente** | orquestador con workers paralelos: Recon → Exploit → Analyst → Reporter |
| **Workflows** | condicionales, con variables y editor interactivo; `osint_full`, `full_pentest`, `web_audit`… |
| **Guardrails** | detección de prompt injection, filtrado de datos sensibles, audit log |
| **Plugins** | loader propio + marketplace local |
| **Modo sin LLM** | `--no-llm`: skills y herramientas sin modelo, útil en CI/air-gap |

## Instalación

**Requisitos:** Python 3.10+ y [Ollama](https://ollama.ai) corriendo en local.

```bash
git clone https://github.com/Ruby570bocadito/T-100AI.git
cd T-100AI
pip install -r requirements.txt        # o: pip install -e ".[dev]"
ollama pull mistral:7b                 # modelo por defecto
```

Lanzadores: `./run.sh` (Linux/macOS) · `run.bat` (Windows) · Docker: `docker compose up`.

## Uso

```bash
python -m t100ai.cli.main              # terminal interactivo
python -m t100ai.cli.main -s 10.0.0.5  # con scope inicial
python -m t100ai.cli.main --no-llm     # sin modelo (solo skills/tools)
t100ai version && t100ai info          # entry point del paquete
```

Al arrancar se pide **confirmación de uso ético**; después, REPL:

```
⟩ [mistral:7b@t100ai] ▶ /scope set 10.0.0.0/24
⟩ [mistral:7b@t100ai] ▶ escanea los puertos de 10.0.0.5
```

### Comandos (todos operativos, verificados en el router)

| Grupo | Comandos |
|---|---|
| Sesión | `/session` · `/scope set\|show\|clear` · `/save` |
| Roles/modos | `/role set\|show\|list` · `/mode paranoid\|standard\|expert` |
| Skills/tools | `/skill list\|use\|info` · `/tools` |
| Modelo | `/model info\|switch\|list` |
| Hallazgos | `/findings show\|add\|score` |
| Reportes | `/report generate\|preview\|session\|export` · `/log show\|export` |
| Contexto | `/context show\|clear` · `/history` · `/perf` |
| Agentes | `/agent list\|spawn\|status` · `/deploy task\|status\|list` |
| Workflows | `/workflow list\|run\|status` · `/plugin list\|search\|install` |
| Utilidades | `/wordlist dir\|subdomain\|user\|pass\|sql\|xss\|lfi\|cve` · `/read` · `/help` |

## Arquitectura

```
src/t100ai/
├── cli/            # Typer + REPL (entrada honesta: help == router)
├── core/           # engine, sandbox, command router, guardrails, sesiones
├── llm/            # cliente Ollama, streaming, prompt builder, plantillas de rol
├── mcp/            # registro de herramientas + executor + registry avanzado
├── skills/         # recon, osint, web, postex, forense, ad, report
├── agents/         # orquestador multi-agente
├── workflows/      # executor + definiciones builtin
├── analysis/       # attack graph, kill chain, CVSS, IoCs, custodia
└── api/            # REST local (validación de Host, sin CORS abierto)
```

## Seguridad y ética

- **Sandbox blacklist-first**: solo bloquea lo destructivo e irreversible; el resto pasa por scope y confirmación humana. Ver `core/sandbox.py`.
- **Sin red externa obligatoria**: el LLM es local; los skills llaman a herramientas del sistema solo cuando existen.
- **API local por defecto** (`127.0.0.1`), valida cabecera `Host` y no abre CORS.
- **Audit log** de comandos ejecutados/bloqueados separado por origen (LLM vs manual).
- Úsalo **solo** en sistemas con autorización explícita. El gate de confirmación ética existe por algo.

## Tests y calidad

```bash
python -m pytest tests/ -q          # 430 tests offline
ruff check src/ tests/              # E/F/W/I sin excepciones
```

CI en GitHub Actions: lint + tests en Python 3.10/3.11/3.12.

## Changelog

Ver [CHANGELOG.md](CHANGELOG.md) — v0.2.0: CLI honesto, sandbox con kill de árbol real, API con body/Host validation, lint real y limpieza de archivos.

## Licencia

MIT — ver [LICENSE](LICENSE).
