import contextvars
import datetime
import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import structlog

# Contextual session id used to tag logs with the current user/session
_session_id_ctx: contextvars.ContextVar = contextvars.ContextVar("specter_session_id", default=None)

def set_session_id(session_id: str) -> None:
    """Set the current session id to be attached to all log events."""
    _session_id_ctx.set(session_id)

def _get_session_id() -> str | None:
    return _session_id_ctx.get()

# --- Custom processors for structlog ---
def add_session_id(_, __, event_dict):
    sid = _get_session_id()
    if sid:
        event_dict["session_id"] = sid
    return event_dict

def add_timestamp(_, __, event_dict):
    # Timestamps are also provided by TimeStamper, but keep a deterministic UTC time here
    event_dict["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return event_dict

def mask_sensitive_data(_, __, event_dict):
    # Mask common sensitive fields found in the event payload
    from t100ai.utils import sensitive

    def _mask(value):
        if isinstance(value, str):
            # Try common masking routines
            v = value
            v = sensitive.mask_password(v)
            v = sensitive.mask_ip(v)
            v = sensitive.mask_hash(v)
            return v
        return value

    masked = {}
    for k, v in event_dict.items():
        if isinstance(k, str) and any(p in k.lower() for p in ["password", "passwd", "secret", "token", "authorization", "api_key", "secret_key"]):
            masked[k] = _mask(v)
        elif isinstance(v, dict):
            masked[k] = mask_sensitive_data(None, None, v)  # recurse for nested dicts
        else:
            masked[k] = _mask(v)
    event_dict.clear()
    event_dict.update(masked)
    return event_dict

def add_log_level(logger, method_name, event_dict):
    # Ensure the log level is always present in the event payload
    if "log_level" not in event_dict:
        event_dict["log_level"] = (getattr(logger, "__name__", "specter")) or str(method_name)
    return event_dict

# --- Logger bootstrap ---
def setup_logging(level: str = "INFO", log_file: str | None = None, json_output: bool = True):
    """Initialize a lightweight, structured logging pipeline.

    - Console output with colors (human-friendly)
    - Optional JSON lines written to a rotating file for audit/archival
    - Custom processors to add session id, timestamp and mask sensitive data
    """

    # Normalize level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.getLogger().setLevel(numeric_level)

    # Console logger with color
    console_logger = logging.getLogger("t100ai.console")
    if not console_logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric_level)
        ch.setFormatter(ColoredFormatter())
        console_logger.addHandler(ch)

    # File logger with rotating file handler (JSON payloads)
    file_logger = logging.getLogger("t100ai.file")
    if log_file:
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        if not file_logger.handlers:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
            # We emit JSON strings as the log message
            fh.setLevel(numeric_level)
            fh.setFormatter(JsonFormatter())
            file_logger.addHandler(fh)

    # Wire up a simple structlog configuration to enrich event dicts
    structlog.configure(
        processors=[
            add_session_id,
            add_timestamp,
            mask_sensitive_data,
            add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(colors=True),  # for console-friendly output if used directly
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Expose a simple facade that the rest of the code can use
    return get_logger()


class ColoredFormatter(logging.Formatter):
    # Very lightweight color mapping for common levels
    COLORS = {
        "DEBUG": "34",  # blue
        "INFO": "32",  # green
        "WARNING": "33",  # yellow
        "ERROR": "31",  # red
        "CRITICAL": "35",  # magenta
    }
    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        color = self.COLORS.get(levelname, "37")
        prefix = f"\x1b[{color}m{levelname}\x1b[0m"
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        message = super().format(record)
        return f"{timestamp} {prefix} {message}"

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        # If someone passed a dict as message, dump it as JSON
        payload = msg if isinstance(msg, (dict, list)) else {"message": msg}
        # Attach a minimal metadata snapshot for compatibility
        payload.setdefault("timestamp", datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
        payload.setdefault("level", record.levelname)
        try:
            return json.dumps(payload)
        except Exception:
            # Fallback to a safe string representation
            return json.dumps({"message": str(msg)})

def get_logger():
    """Return a minimal facade logger object compatible with the rest of the codebase.

    The facade exposes .info(), .debug(), .warning(), and .error() methods.
    Each call will emit a structured event to both the console and the log file
    (when a log_file is configured).
    """
    class _FacadeLogger:
        def __init__(self, console_logger, file_logger):
            self.console = console_logger
            self.file = file_logger

        def _emit(self, level: int, event_dict: dict, message: str = None):
            if message is None:
                message = event_dict.get("message", "log")
            # Enrich with a basic human-readable form for console
            console_text = f"{event_dict.get('timestamp', '')} [{event_dict.get('log_level', 'INFO')}] {message} | {json.dumps(event_dict)}"
            if self.console.handlers:
                self.console.log(level, console_text)
            # Always try to emit JSON payload to the file sink
            if self.file.handlers:
                self.file.log(level, json.dumps(event_dict))

        def info(self, event_dict: dict, message: str = None):
            self._emit(logging.INFO, event_dict, message)

        def debug(self, event_dict: dict, message: str = None):
            self._emit(logging.DEBUG, event_dict, message)

        def warning(self, event_dict: dict, message: str = None):
            self._emit(logging.WARNING, event_dict, message)

        def error(self, event_dict: dict, message: str = None):
            self._emit(logging.ERROR, event_dict, message)

    console_logger = logging.getLogger("t100ai.console")
    file_logger = logging.getLogger("t100ai.file")
    return _FacadeLogger(console_logger, file_logger)
