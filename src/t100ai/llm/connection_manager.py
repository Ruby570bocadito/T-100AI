"""Ollama Connection Manager - Persistent client with auto-reconnect, rate limiting and caching"""

import hashlib
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Generator, Optional

from t100ai.core.config import T100AIConfig
from t100ai.llm.prompt_builder import PromptBuilder


class OllamaConnectionError(Exception):
    pass


@dataclass
class RateLimiter:
    min_interval: float = 2.0
    last_request: float = 0.0
    burst_tokens: int = 5
    burst_used: int = 0
    burst_window: float = 10.0
    burst_reset: float = 0.0

    def __post_init__(self):
        self.last_request = time.time() - self.min_interval
        self.burst_reset = time.time()

    def acquire(self) -> float:
        now = time.time()

        if now - self.burst_reset > self.burst_window:
            self.burst_used = 0
            self.burst_reset = now

        if self.burst_used < self.burst_tokens:
            self.burst_used += 1
            return 0.0

        elapsed = now - self.last_request
        wait = max(0, self.min_interval - elapsed)
        return wait

    def wait(self) -> None:
        wait_time = self.acquire()
        if wait_time > 0:
            time.sleep(wait_time)
        self.last_request = time.time()


@dataclass
class ResponseCache:
    ttl: int = 300
    max_size: int = 100
    cache: dict = field(default_factory=dict)

    def _make_key(self, prompt_hash: str, model: str) -> str:
        return f"{model}:{prompt_hash}"

    def get(self, prompt: str, model: str) -> Optional[str]:
        key = self._make_key(hashlib.sha256(prompt.encode()).hexdigest()[:32], model)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry["ts"] < self.ttl:
                entry["hits"] += 1
                return entry["response"]
            del self.cache[key]
        return None

    def set(self, prompt: str, model: str, response: str) -> None:
        if len(self.cache) >= self.max_size:
            oldest = min(self.cache.items(), key=lambda x: x[1]["ts"])
            del self.cache[oldest[0]]

        key = self._make_key(hashlib.sha256(prompt.encode()).hexdigest()[:32], model)
        self.cache[key] = {"response": response, "ts": time.time(), "hits": 0}


class OllamaConnectionManager:
    """
    Persistent Ollama client with:
    - Auto-reconnection
    - Rate limiting
    - Response caching
    - Streaming support
    - Connection health monitoring
    """

    _instance: Optional["OllamaConnectionManager"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 600,
        cache_ttl: int = 300,
        rate_limit_interval: float = 2.0,
    ):
        if self._initialized:
            return

        cfg = T100AIConfig()
        self.host = (host or cfg.ollama_host).rstrip("/")
        self.model = model or cfg.ollama_model
        self.timeout = timeout
        self.temperature = cfg.llm_temperature
        self.num_ctx = cfg.llm_context_window or 4096
        self.num_gpu = -1
        self.num_thread = 0

        self._connected = False
        self._last_health_check = 0.0
        self._health_check_interval = 30.0
        self._retry_attempts = 3
        self._retry_backoff = 1.0

        self._rate_limiter = RateLimiter(min_interval=rate_limit_interval)
        self._cache = ResponseCache(ttl=cache_ttl)
        self._prompt_builder = PromptBuilder()

        self._initialized = True

    @classmethod
    def get_instance(cls) -> "OllamaConnectionManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    def update_config(self, host: Optional[str] = None, model: Optional[str] = None) -> None:
        if host:
            self.host = host.rstrip("/")
        if model:
            self.model = model
        self._connected = False

    def _check_health(self) -> bool:
        now = time.time()
        if now - self._last_health_check < self._health_check_interval:
            return self._connected
        self._last_health_check = now

        try:
            url = f"{self.host}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as resp:
                self._connected = resp.status == 200
        except Exception:
            self._connected = False
        return self._connected

    def connect(self) -> bool:
        if self._connected and self._check_health():
            return True

        for attempt in range(self._retry_attempts):
            try:
                url = f"{self.host}/api/tags"
                with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        models = [m.get("name", "") for m in data.get("models", [])]

                        if self.model not in models:
                            raise OllamaConnectionError(
                                f"Modelo '{self.model}' no disponible.\n"
                                f"Disponibles: {', '.join(models) or '(ninguno)'}\n"
                                f"Instala con: ollama pull {self.model}"
                            )
                        self._connected = True
                        return True
            except Exception as e:
                if attempt < self._retry_attempts - 1:
                    time.sleep(self._retry_backoff * (2 ** attempt))
                else:
                    raise OllamaConnectionError(f"No se pudo conectar a Ollama: {e}")
        return False

    def _reconnect(self) -> bool:
        self._connected = False
        return self.connect()

    def _do_request(self, payload: dict) -> dict:
        url = f"{self.host}/api/generate"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as e:
            if self._reconnect():
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            raise OllamaConnectionError(f"Error de red: {e}")
        except json.JSONDecodeError as e:
            raise OllamaConnectionError(f"Respuesta inválida: {e}")

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        use_cache: bool = True,
        stream: bool = False,
    ) -> str:
        if not self._connected:
            self.connect()

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

        cached = self._cache.get(full_prompt, self.model) if use_cache else None
        if cached:
            return f"[cache]{cached}[/cache]"

        self._rate_limiter.wait()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": stream,
            "options": {
                "temperature": self.temperature,
                "num_gpu": self.num_gpu,
                "num_ctx": self.num_ctx,
                "num_batch": 512,
            },
        }
        payload["options"] = {k: v for k, v in payload["options"].items() if v is not None}

        result = self._do_request(payload)
        response = result.get("response", "")

        if use_cache and response:
            self._cache.set(full_prompt, self.model, response)

        return response

    def generate_stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> Generator[str, None, None]:
        if not self._connected:
            self.connect()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": True,
            "options": {
                "temperature": self.temperature,
                "num_gpu": self.num_gpu,
                "num_ctx": self.num_ctx,
            },
        }
        payload["options"] = {k: v for k, v in payload["options"].items() if v is not None}

        url = f"{self.host}/api/generate"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done", False):
                            break
                    except json.JSONDecodeError:
                        yield line
        except Exception as e:
            if self._reconnect():
                raise OllamaConnectionError(f"Streaming falló tras reconexión: {e}")
            raise OllamaConnectionError(f"Streaming error: {e}")

    def list_models(self) -> list:
        try:
            url = f"{self.host}/api/tags"
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("models", [])
        except Exception:
            return []

    def clear_cache(self) -> int:
        size = len(self._cache.cache)
        self._cache.cache.clear()
        return size
