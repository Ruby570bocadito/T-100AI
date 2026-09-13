# Changelog

Todos los cambios notables de T-100AI se documentan aquí.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [0.3.1] - 2026-09-13

### Corregido
- **`run.bat` / `run.sh` fallaban con `ModuleNotFoundError: No module named 't100ai'`**
  si solo se había hecho `pip install -r requirements.txt` (sin `pip install -e .`).
  Ahora ambos lanzadores añaden `src/` al `PYTHONPATH` antes de ejecutar el módulo,
  así el arranque funciona directamente tras clonar + instalar dependencias.

### Eliminado
- `src/t100ai/workflows_advanced.py` (532 líneas): módulo huérfano sin ninguna
  importación en `src/` ni en `tests/` — código muerto del pre-rebrand.

### Documentación
- README renovado: banner propio, GIF de demostración regenerado con una sesión
  completa del REPL (gate ético, scope, sandbox, hallazgos, reporte) y diagramas
  compactos de pipeline y arquitectura. Las capturas grandes ahora van en tablas
  y secciones plegables para que el README no sea interminable.

## [0.3.0] - 2026-09-12

### Corregido
- **`/model switch <nombre>` ignoraba el nombre** y cambiaba a un modelo
  llamado literalmente "switch" (el router pasaba `action` en lugar de `arg`).
- **`/scope set` sin argumento** añadía el objetivo "set" al scope; ahora
  muestra el uso correcto.
- **`/skill use` sin argumento** intentaba activar un skill llamado "use";
  ahora muestra el uso correcto.
- **`/wordlist all` roto en dos capas**: el router nunca llegaba a la rama
  `all` (mostraba el menú) y, al llegar, `get_all()` devuelve un dict por
  categorías que explotaba al rebanar. Ahora se aplana y lista.
- **Ayuda desincronizada (drift)**: el engine tenía una segunda ayuda con
  comandos fantasma (`/export` no existe; rol `forensic-analyst` no aceptado).
  Ahora CLI y engine renderizan la MISMA fuente (`core/help_text.py`) y un
  test verifica que cada comando anunciado existe en `KNOWN_COMMANDS`.
- **Rutas de datos del pre-rebrand**: historial y sesiones en `~/.specter/`,
  audit/log en `src/t100ai/log/` (dentro del árbol fuente o del CWD).
  Todo migrado a `~/.t100ai/` con migración silenciosa del historial legacy.
- **RuntimeWarning de runpy** en cada `python -m t100ai.cli.main`: import
  diferido del paquete `cli` (PEP 562).
- Restos de identidad antigua en skills (`/tmp/specter_*`), registry de
  plugins (`~/.specter/tools.toml`), labels de workers y docstrings.
- `datetime.utcnow()` (deprecado en 3.12) en audit, logging, storage y
  sesiones → `datetime.now(timezone.utc)`.
- Test de secretos frágil por orden (contaba warnings ajenos del intérprete):
  ahora filtra por `RuntimeWarning` y valida el mensaje.
- La ayuda en tabla rompía la fila de `/wordlist dir|subdomain|…` (los `|`
  dentro de backticks eran separadores de columna de rich).

### Añadido
- **TAB-completion y historial persistente en el REPL** (readline en POSIX,
  fallback suave en Windows): autocompleta comandos slash, subacciones y
  nombres descubiertos; flechas ↑/↓ con historial entre sesiones.
- **`t100ai doctor`**: diagnóstico del entorno (Python, dependencias, config,
  directorios de datos, wordlists, sandbox —permite benignos / bloquea
  destructivos— y alcance TCP de Ollama) con salida tabla o `--json` y exit
  code honesto.
- **`t100ai session`**: subcomando operativo (save/load/list/export) para el
  gestor de sesiones que estaba huérfano; con guards de "no encontrado".
- **Sugerencias de comandos**: `/scop` → *¿Quisiste decir: /scope?*
  (difflib sobre `KNOWN_COMMANDS`, la misma tabla que alimenta TAB).
- **`--version` / `-V`** en el CLI raíz y **`--no-banner`** para uso
  scriptable; el banner muestra la versión y el aviso de autorización.
- **Consola honesta con tuberías**: sin `force_terminal` — output limpio sin
  secuencias ANSI al redirigir, color intacto en TTY.
- Capturas nuevas: `help.png` y `doctor.png`; GIF regenerado con la v0.3.0.

### Cambiado
- `/exit`, `/quit` y `/salir` cierran el terminal de verdad (flag
  `_exit_requested` consumida por el REPL).
- `prompt_toolkit` eliminado de dependencias (su código estaba muerto desde
  la v0.1; el REPL usaba `input()`).
- `KNOWN_COMMANDS` en `command_router` es el registro único que alimenta
  sugerencias, TAB-completion y el test anti-drift de la ayuda.

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
