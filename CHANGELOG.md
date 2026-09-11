# Changelog

Todos los cambios notables de T-100AI se documentan aquí.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [0.2.1] - 2026-09-12

### Corregido
- **`/session` crasheaba siempre** con `MarkupError`: tags rich malformados
  (`[ #FF3366]` con espacio tras el corchete) en el panel de sesión, el
  resumen de reporte y el resumen del executor. Corregidos los 6 tags en
  3 ficheros. Detectado ejecutando el REPL en vivo durante la captura de
  las imágenes del README.

### Añadido
- Capturas reales del terminal en `docs/captures/` (arranque, sesión,
  resumen) + GIF animado de una sesión completa con `--no-llm`.
- README: nueva sección "En acción" con las capturas.

## [0.2.0] - 2026-09-12

### Corregido
- **Sandbox**: el kill del process-group en timeout nunca se ejecutaba
  (`subprocess.TimeoutExpired` no expone `pid`) → los comandos que superaban el
  timeout quedaban huérfanos. Ahora se usa `Popen` + `start_new_session` +
  `killpg`, matando el árbol completo.
- **Engine**: `NameError` latente en `/wordlist` sin argumentos (`Table` sin importar).
- **API REST**: los endpoints POST no leían el body — ahora parsean JSON con
  límite de 1 MB y devuelven 400 en JSON inválido; escrituras sin engine
  adjunto responden 503 honesto en lugar de simular éxito.
- **API REST**: eliminado `Access-Control-Allow-Origin: *` y añadida validación
  de cabecera `Host` (mitiga DNS rebinding contra la API local).
- **Config**: las variables de entorno aceptan ambos prefijos
  (`OLLAMA_*` y `T100AI_*`); modelo por defecto alineado con la documentación.

### Añadido
- **CLI honesto**: la ayuda ya solo anuncia comandos que existen. Cableados en
  el router: `/mode`, `/context show|clear`, `/skill use|info`,
  `/findings score`, `/report preview|session|export`, `/log export`,
  `/scope <target>` y `/skill <nombre>` en forma corta.
- Router de comandos completo: toda entrada desconocida avisa y sugiere `/help`.
- `generate_password_mutations()` en el diccionario integrado (portado de la
  versión anterior) + payload LFI canónico `../../../etc/passwd`.
- Manifest de plugins del marketplace con `source` e `installed_at`.
- LICENSE MIT (el badge ya lo anunciaba; faltaba el fichero).

### Cambiado
- **Lint real en CI**: ruff con `E,F,W,I` sin excepciones (antes ignoraba
  F401/F821/F841/E722… y mypy corría con `|| true`). Eliminado el gate falso de
  mypy y el upload de codecov sin token. 0 warnings en todo `src/` y `tests/`.
- Eliminadas ~800 incidencias estáticas: imports muertos, variables sin usar,
  f-strings sin placeholders, espacios finales, imports desordenados,
  sentencias `if x: y` expandidas.
- **Limpieza de archivos**: eliminados `wordlists/` y `workflows/` duplicados
  en la raíz (el workflow `osint_full` ya vive como builtin en Python),
  `__init__.py`/`__main__.py` huérfanos de la raíz; el directorio de workflows
  de usuario se crea de forma perezosa al guardar.
- Versión del paquete y del CLI unificadas en `0.2.0`.

## [0.1.0] - 2026-08

### Añadido
- Rebrand y overhaul inicial: terminal ofensivo con LLM local (Ollama),
  sandbox con blacklist de comandos destructivos, skills de pentesting,
  MCP avanzado, orquestador multi-agente, workflows condicionales,
  guardrails y plugins.
