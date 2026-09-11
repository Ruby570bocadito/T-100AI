"""REST API for T-100AI - HTTP interface for external integrations.

Seguridad por defecto:
- Bind en 127.0.0.1 (no expone a la red salvo que se pida explícitamente).
- Valida la cabecera Host (mitiga DNS rebinding desde navegadores).
- No envía cabeceras CORS comodín: la API no está pensada para browsers.
- Los POST aceptan JSON (Content-Length acotado) y rechazan JSON inválido.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

# Cap del body aceptado en POST (1 MB)
MAX_BODY_BYTES = 1024 * 1024


@dataclass
class APIResponse:
    """Standard API response."""
    status: int
    data: Any = None
    error: str = ""

    def to_json(self) -> str:
        body = {"status": "ok" if self.status < 400 else "error"}
        if self.data is not None:
            body["data"] = self.data
        if self.error:
            body["error"] = self.error
        return json.dumps(body, default=str)


class T100AIAPI:
    """REST API server for T-100AI.

    Provides HTTP endpoints for external tools to interact with T-100AI.

    Endpoints:
        GET  /api/status           - Server status
        GET  /api/sessions         - List sessions
        POST /api/sessions         - Create session (JSON body, requiere engine)
        GET  /api/sessions/<id>    - Get session details
        GET  /api/sessions/<id>/findings - Get session findings
        POST /api/sessions/<id>/findings - Add finding (JSON body, requiere engine)
        GET  /api/iocs             - List IoCs
        POST /api/iocs             - Add IoC (JSON body, requiere engine)
        GET  /api/workflows        - List workflows
        POST /api/workflows/<name>/run - Run workflow (JSON body, requiere engine)
        GET  /api/compliance       - Compliance report
        GET  /api/attack-graph     - Attack graph
        GET  /api/kill-chain       - Kill chain status

    Los endpoints de escritura requieren un engine adaptado vía
    :meth:`attach_engine`; sin engine responden 503 en lugar de simular éxito.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._handlers: dict[str, Callable] = {}
        self._running = False
        self._engine: Optional[Any] = None

    def attach_engine(self, engine: Any) -> None:
        """Attach an engine adapter exposing sessions/iocs/workflows operations.

        Esperado (todos opcionales, se detecta con hasattr):
            create_session(data: dict) -> dict
            add_finding(session_id: str, data: dict) -> dict
            add_ioc(data: dict) -> dict
            run_workflow(name: str, data: dict) -> dict
        """
        self._engine = engine

    def register_handler(self, method: str, path: str, handler: Callable) -> None:
        """Register a custom API handler.

        El handler puede aceptar (query) o (query, body) según la firma.
        """
        self._handlers[f"{method}:{path}"] = handler

    def start(self) -> None:
        """Start the API server in a background thread."""
        api = self

        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                api._handle_request("GET", self)

            def do_POST(self):
                api._handle_request("POST", self)

            def log_message(self, format, *args):
                pass  # Suppress default logging

        self._server = HTTPServer((self.host, self.port), APIHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        """Stop the API server."""
        if self._server:
            self._server.shutdown()
            self._running = False

    @staticmethod
    def _host_allowed(host_header: str) -> bool:
        """Solo acepta Hosts que apunten al propio servidor o localhost."""
        if not host_header:
            return True  # clientes sin Host (HTTP/1.0)
        host = host_header.rsplit(":", 1)[0].strip("[]").lower()
        return host in ("localhost", "127.0.0.1", "::1")

    def _read_body(self, handler: BaseHTTPRequestHandler) -> tuple[Optional[dict], str]:
        """Lee y parsea el body JSON de un POST. Devuelve (data, error)."""
        try:
            length = int(handler.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return None, "Content-Length inválido"
        if length <= 0:
            return {}, ""
        if length > MAX_BODY_BYTES:
            return None, f"Body demasiado grande (>{MAX_BODY_BYTES} bytes)"
        raw = handler.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, f"JSON inválido: {exc}"
        if not isinstance(data, dict):
            return None, "El body debe ser un objeto JSON"
        return data, ""

    def _call_handler(self, handler: Callable, query: dict, body: Optional[dict]) -> APIResponse:
        """Invoca un handler respetando su aridad (query) o (query, body)."""
        try:
            import inspect
            accepts_two = len(inspect.signature(handler).parameters) >= 2
        except (TypeError, ValueError):
            accepts_two = False
        try:
            if accepts_two:
                return handler(query, body or {})
            return handler(query)
        except Exception as exc:  # nunca tirar un traceback al socket
            return APIResponse(500, error=f"Handler error: {exc}")

    def _handle_request(self, method: str, handler: BaseHTTPRequestHandler) -> None:
        """Route and handle an API request."""
        host = handler.headers.get("Host", "")
        if not self._host_allowed(host):
            self._send(handler, APIResponse(403, error="Host no permitido"))
            return

        parsed = urlparse(handler.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        body: Optional[dict] = None
        if method == "POST":
            body, err = self._read_body(handler)
            if err:
                self._send(handler, APIResponse(400, error=err))
                return

        # Check custom handlers
        key = f"{method}:{path}"
        if key in self._handlers:
            response = self._call_handler(self._handlers[key], query, body)
        else:
            response = self._default_handler(method, path, query, body)

        self._send(handler, response)

    def _send(self, handler: BaseHTTPRequestHandler, response: APIResponse) -> None:
        handler.send_response(response.status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(response.to_json().encode())))
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        try:
            handler.wfile.write(response.to_json().encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _default_handler(self, method: str, path: str, query: dict,
                         body: Optional[dict] = None) -> APIResponse:
        """Default handler for standard endpoints."""
        if method == "GET":
            if path == "/api/status":
                return APIResponse(200, {
                    "status": "running",
                    "version": self._get_version(),
                    "engine_attached": self._engine is not None,
                    "endpoints": sorted(self._handlers.keys()),
                })
            if path == "/api/sessions":
                if self._engine is not None and hasattr(self._engine, "list_sessions"):
                    return APIResponse(200, {"sessions": self._engine.list_sessions()})
                return APIResponse(200, {"sessions": []})
            if path == "/api/iocs":
                if self._engine is not None and hasattr(self._engine, "list_iocs"):
                    return APIResponse(200, {"iocs": self._engine.list_iocs()})
                return APIResponse(200, {"iocs": []})
            if path == "/api/workflows":
                if self._engine is not None and hasattr(self._engine, "list_workflows"):
                    return APIResponse(200, {"workflows": self._engine.list_workflows()})
                return APIResponse(200, {"workflows": []})
            if path == "/api/compliance":
                return APIResponse(200, {"compliance": {}})
            if path == "/api/attack-graph":
                return APIResponse(200, {"graph": {"nodes": 0, "edges": 0}})
            if path == "/api/kill-chain":
                return APIResponse(200, {"kill_chain": []})
            return APIResponse(404, error=f"Endpoint not found: {path}")

        if method == "POST":
            # Escritura sin engine → 503 honesto (no simulamos éxito)
            if self._engine is None:
                return APIResponse(503, error="No engine attached: usa attach_engine()")
            if path == "/api/sessions" and hasattr(self._engine, "create_session"):
                return APIResponse(201, self._engine.create_session(body or {}))
            if path.startswith("/api/sessions/") and path.endswith("/findings") \
                    and hasattr(self._engine, "add_finding"):
                session_id = path[len("/api/sessions/"):-len("/findings")]
                return APIResponse(201, self._engine.add_finding(session_id, body or {}))
            if path == "/api/iocs" and hasattr(self._engine, "add_ioc"):
                return APIResponse(201, self._engine.add_ioc(body or {}))
            if path.startswith("/api/workflows/") and path.endswith("/run") \
                    and hasattr(self._engine, "run_workflow"):
                name = path[len("/api/workflows/"):-len("/run")]
                return APIResponse(202, self._engine.run_workflow(name, body or {}))
            return APIResponse(404, error=f"Endpoint not found: {path}")

        return APIResponse(405, error="Method not allowed")

    @staticmethod
    def _get_version() -> str:
        try:
            from t100ai import __version__
            return __version__
        except Exception:
            return "unknown"

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
