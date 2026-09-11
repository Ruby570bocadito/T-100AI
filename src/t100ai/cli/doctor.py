"""Doctor — diagnósticos de entorno para T-100AI.

Comprobaciones de solo lectura (ninguna operación ofensiva ni destructiva):
Python, dependencias, config, directorios de datos, wordlists, sandbox y
alcance TCP de Ollama. Diseñado para fallar suave: un entorno incompleto
devuelve ``warn``/``skip``, nunca lanza.
"""

from __future__ import annotations

import socket
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse


def _check_python() -> tuple[str, str]:
    v = sys.version_info
    detail = f"{v.major}.{v.minor}.{v.micro} (>=3.10 requerido)"
    return ("ok" if v >= (3, 10) else "fail"), detail


def _check_dependencies() -> list[tuple[str, str, str]]:
    out = []
    for mod in ("rich", "typer", "pydantic", "structlog"):
        try:
            m = __import__(mod)
            version = getattr(m, "__version__", "?")
            out.append((f"dep:{mod}", "ok", str(version)))
        except Exception as exc:  # pragma: no cover — solo con instalacion rota
            out.append((f"dep:{mod}", "fail", str(exc)))
    return out


def _check_config() -> tuple[str, str, object]:
    try:
        from t100ai.core.config import T100AIConfig

        cfg = T100AIConfig.load()
        return "ok", f"modelo={cfg.ollama_model} host={cfg.ollama_host}", cfg
    except Exception as exc:
        return "fail", str(exc), None


def _check_data_dirs() -> tuple[str, str]:
    data_dir = Path.home() / ".t100ai"
    try:
        (data_dir / "logs").mkdir(parents=True, exist_ok=True)
        probe = data_dir / "logs" / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return "ok", str(data_dir)
    except Exception as exc:
        return "fail", f"no escribible: {exc}"


def _check_wordlists() -> tuple[str, str]:
    try:
        from t100ai.wordlists.dictionaries import AttackDictionary

        total = len(AttackDictionary().get_all())
        return ("ok" if total else "warn"), f"{total} entradas integradas"
    except Exception as exc:
        return "warn", str(exc)


def _check_sandbox() -> tuple[str, str]:
    try:
        from t100ai.core.sandbox import CommandSandbox

        with tempfile.TemporaryDirectory() as td:
            sandbox = CommandSandbox(
                timeout=5,
                dry_run=True,
                permission_mode="standard",
                max_commands=10,
                rate_limit=0.0,
                log_dir=td,
            )
            benign_allowed, _ = sandbox.validate("echo hola")
            destructive_allowed, _ = sandbox.validate("rm -rf /")
            healthy = benign_allowed and not destructive_allowed
            detail = (
                f"permite benignos={benign_allowed} · bloquea 'rm -rf /'={not destructive_allowed}"
            )
            return ("ok" if healthy else "warn"), detail
    except Exception as exc:
        return "warn", str(exc)


def _check_ollama(host: str) -> tuple[str, str]:
    parsed = urlparse(host if "//" in host else f"http://{host}")
    hostname = parsed.hostname or "localhost"
    port = parsed.port or 11434
    try:
        conn = socket.create_connection((hostname, port), timeout=1.5)
        conn.close()
        return "ok", f"{hostname}:{port} accesible (TCP)"
    except Exception as exc:
        return "warn", f"Ollama no accesible en {hostname}:{port} ({exc}) — el terminal funciona con --no-llm"


def run_checks(skip_network: bool = False) -> list[dict]:
    """Ejecuta todas las comprobaciones y devuelve resultados estructurados.

    Args:
        skip_network: omite la comprobación TCP de Ollama (tests/offline).
    """
    checks: list[dict] = []

    status, detail = _check_python()
    checks.append({"check": "python", "status": status, "detail": detail})

    for name, status, detail in _check_dependencies():
        checks.append({"check": name, "status": status, "detail": detail})

    try:
        from t100ai import __version__

        checks.append({"check": "paquete", "status": "ok", "detail": f"t100ai {__version__}"})
    except Exception as exc:  # pragma: no cover
        checks.append({"check": "paquete", "status": "fail", "detail": str(exc)})

    status, detail, _cfg = _check_config()
    checks.append({"check": "config", "status": status, "detail": detail})

    status, detail = _check_data_dirs()
    checks.append({"check": "datos", "status": status, "detail": detail})

    status, detail = _check_wordlists()
    checks.append({"check": "wordlists", "status": status, "detail": detail})

    status, detail = _check_sandbox()
    checks.append({"check": "sandbox", "status": status, "detail": detail})

    if skip_network:
        checks.append({"check": "ollama", "status": "skip", "detail": "comprobación de red omitida"})
    else:
        host = (_cfg.ollama_host if _cfg else None) or "http://localhost:11434"
        status, detail = _check_ollama(str(host))
        checks.append({"check": "ollama", "status": status, "detail": detail})

    return checks
