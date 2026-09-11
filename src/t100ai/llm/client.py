"""Ollama client (local LLM gateway)"""

import json
import socket
import time
import urllib.error
import urllib.request
import uuid
from typing import Generator, Optional

from t100ai.core.config import T100AIConfig
from t100ai.llm.prompt_builder import PromptBuilder


class OllamaClientError(Exception):
    pass


class OllamaClient:
    """Cliente simplificado para Ollama HTTP API.

    Nota: no depende de 'requests' para evitar una dependencia extra.
    Implementa conexión suave y fallback cuando Ollama no está disponible.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        timeout: int = 120,
        num_gpu: int = -1,
        num_thread: int = 0,
        num_ctx: int = 4096,
    ):
        # Configuración por defecto (usando T100AIConfig si está disponible)
        if host is None or model is None:
            cfg = T100AIConfig()
            host = host or cfg.ollama_host
            model = model or cfg.ollama_model
            self._temperature = temperature if temperature is not None else cfg.llm_temperature
            self._timeout = 300  # 5 min – local inference can be slow, especially on first load
        else:
            self._temperature = temperature
            self._timeout = timeout

        self.host = host.rstrip("/")
        self.model = model
        self._connected = False
        # Performance options passed to Ollama
        # num_gpu=-1 → offload all possible layers to GPU/VRAM automatically
        # num_thread=0 → Ollama auto-detects optimal CPU thread count
        # num_ctx → context window (affects RAM usage)
        self._num_gpu = num_gpu
        self._num_thread = num_thread
        self._num_ctx = num_ctx
        # Caching and per-session history
        self._cache: dict[str, dict] = {}
        self._sessions: dict[str, list[dict]] = {}
        self._prompt_builder = PromptBuilder()

    def connect(self) -> bool:
        """Verifica conexión con Ollama y que el modelo esté disponible.

        Retorna True si OK. Lanza OllamaClientError si el modelo no está instalado.
        """
        # 1. Check Ollama is reachable via /api/tags
        tags_url = f"{self.host}/api/tags"
        available_models: list[str] = []
        try:
            with urllib.request.urlopen(tags_url, timeout=self._timeout) as resp:
                if resp.status == 200:
                    self._connected = True
                    data = json.loads(resp.read().decode("utf-8"))
                    models = data.get("models", [])
                    available_models = [m.get("name", "") for m in models]
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout):
            pass
        except Exception:
            pass

        if not self._connected:
            # Try /v1/models as fallback
            v1_url = f"{self.host}/v1/models"
            try:
                with urllib.request.urlopen(v1_url, timeout=self._timeout) as resp:
                    if resp.status == 200:
                        self._connected = True
            except Exception:
                self._connected = False
                return False

        if not self._connected:
            return False

        # 2. Validate that the configured model is actually available
        if available_models and self.model not in available_models:
            models_str = ", ".join(available_models) if available_models else "(ninguno)"
            raise OllamaClientError(
                f"Modelo '{self.model}' no está instalado en Ollama.\n"
                f"    Modelos disponibles: {models_str}\n"
                f"    Instálalo con: ollama pull {self.model}"
            )

        return True


    def generate(self, prompt: str, system_prompt: str, stream: bool = False):
        """Genera una respuesta para un prompt dado.

        Si 'stream' es True, intenta soportar streaming simple (líneas de texto).
        En caso de fallo, re-lanza la excepción para que el llamador pueda mostrarla.
        """
        # Try Ollama native API first
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": stream,
            "options": {
                # Performance: use GPU VRAM + CPU + RAM
                "temperature": self._temperature,
                "num_gpu": self._num_gpu,    # -1 = auto (max GPU layers)
                "num_thread": self._num_thread if self._num_thread > 0 else None,
                "num_ctx": self._num_ctx,
                "num_batch": 512,            # tokens processed in parallel
                "low_vram": False,           # allow full VRAM usage
            },
        }
        # Remove None values from options so Ollama uses its defaults
        payload["options"] = {k: v for k, v in payload["options"].items() if v is not None}
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            if stream:
                return self._generate_streaming(req)
            else:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    raw = resp.read()
                    if not raw:
                        return ""
                    result = json.loads(raw.decode("utf-8"))
                    # Ollama native API returns {"response": "..."}
                    return result.get("response", "")
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise OllamaClientError(f"Error de red al conectar con Ollama: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise OllamaClientError(f"Respuesta inválida de Ollama (JSON malformado): {exc}") from exc
        except Exception as exc:
            raise OllamaClientError(f"Error inesperado: {exc}") from exc

    def stream_generate(self, prompt: str, system_prompt: str) -> Generator[str, None, None]:
        """Streaming generator for generation results."""
        gen = self.generate(prompt, system_prompt, stream=True)
        if isinstance(gen, Generator):
            for chunk in gen:
                yield chunk
        else:
            if isinstance(gen, str):
                yield gen

    def _generate_streaming(self, req: urllib.request.Request) -> Generator[str, None, None]:
        """Internal streaming helper.

        Ollama's /api/generate returns NDJSON: one JSON object per line.
        Each line looks like: {"model":"...","response":"token","done":false}
        The last line has "done": true and an empty "response".
        """
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        # Not valid JSON — yield raw text as fallback
                        yield line
                        continue
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done", False):
                        break
        except Exception as exc:
            raise OllamaClientError(f"Error durante streaming: {exc}") from exc

    def get_model_info(self) -> Optional[dict]:
        """Devuelve info del modelo actual si está disponible."""
        # Try Ollama native API
        url = f"{self.host}/api/show"
        payload = {"name": self.model}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass

        # Fallback: return basic info
        return {"model": self.model, "host": self.host}

    def list_models(self) -> Optional[list]:
        """Lista modelos disponibles en Ollama."""
        # Try Ollama native API
        url = f"{self.host}/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    # Ollama returns {"models": [...]}
                    if isinstance(data, dict) and "models" in data:
                        return data["models"]
                    if isinstance(data, list):
                        return data
        except Exception:
            pass

        # Try OpenAI compatible endpoint
        url = f"{self.host}/v1/models"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, dict) and "data" in data:
                        return data["data"]
                    if isinstance(data, list):
                        return data
        except Exception:
            return None
        return None

    # ------------------ Enhanced features: streaming, cache, history --------------
    def _cache_get(self, key: str) -> Optional[str]:
        item = self._cache.get(key)
        if not item:
            return None
        if time.time() - item.get("ts", 0) > 60:
            # simple TTL of 60 seconds
            self._cache.pop(key, None)
            return None
        return item.get("response")

    def _cache_set(self, key: str, value: str) -> None:
        self._cache[key] = {"response": value, "ts": time.time()}

    def _ensure_session(self, session_id: Optional[str]) -> str:
        if session_id and session_id in self._sessions:
            return session_id
        new_id = session_id or uuid.uuid4().hex
        if new_id not in self._sessions:
            self._sessions[new_id] = []
        return new_id

    def _build_session_context(self, session_id: str, max_entries: int = 5) -> str:
        hist = self._sessions.get(session_id, [])[-max_entries:]
        if not hist:
            return f"Session {session_id} started."
        lines = [f"{m['role']}: {m['content']}" for m in hist]
        return f"Session {session_id} history (last {len(hist)} exchanges):\n" + "\n".join(lines)

    def _request_with_retries(self, req: urllib.request.Request, timeout: Optional[int] = None, retries: int = 3, backoff_factor: float = 0.5) -> str:
        t = timeout if timeout is not None else self._timeout
        last_exc: Optional[Exception] = None
        for i in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=t) as resp:
                    data = resp.read()
                    if not data:
                        return ""
                    return data.decode("utf-8")
            except (urllib.error.URLError, socket.timeout) as e:
                last_exc = e
                time.sleep(backoff_factor * (2 ** i))
                continue
        if last_exc:
            raise last_exc
        return ""

    def chat(self, user_input: str, session_id: Optional[str] = None, timeout: Optional[int] = None, json_mode: bool = False) -> dict:
        """Chat interface with per-session history and optional JSON output."""
        # Build or fetch session
        sid = self._ensure_session(session_id)
        history = self._sessions.setdefault(sid, [])

        # Session context + prompt construction
        session_context = self._build_session_context(sid)
        system_prompt = self._prompt_builder.build_system_prompt(role="default", session_context=session_context, json_mode=json_mode)
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in history[-10:]]) + f"\nUser: {user_input}\nAssistant:"

        # Cache key
        cache_key = f"{sid}:{self.model}:{hash(user_input)}:json={json_mode}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": cached})
            return {"session_id": sid, "response": cached, "cached": True, "tokens": len(cached.split())}

        # Generate with streaming
        gen_or_text = self.generate(prompt, system_prompt, stream=True)
        response_text = ""
        tokens_count = 0

        # Lightweight progress display if available
        bar = None
        try:
            from tqdm import tqdm
            bar = tqdm(total=None, desc="Streaming tokens", unit="tok")
        except Exception:
            bar = None

        try:
            if isinstance(gen_or_text, Generator):
                for chunk in gen_or_text:
                    if not chunk:
                        continue
                    response_text += chunk
                    tks = max(1, len(chunk.split()))
                    tokens_count += tks
                    if bar:
                        try:
                            bar.update(tks)
                        except Exception:
                            pass
            else:
                response_text = gen_or_text
        finally:
            if bar:
                try:
                    bar.close()
                except Exception:
                    pass

        # Persist and update history
        self._cache_set(cache_key, response_text)
        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": response_text})

        return {"session_id": sid, "response": response_text, "cached": False, "tokens": tokens_count}
