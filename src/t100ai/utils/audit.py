import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from shutil import copyfile


class AuditLogger:
    """Audit logger with rotation and simple integrity checks."""

    def __init__(self, path: str, max_bytes: int = 5 * 1024 * 1024, backup_count: int = 5):
        self.path = path
        self.logger = logging.getLogger("t100ai.audit")
        self.logger.setLevel(logging.INFO)

        os.makedirs(os.path.dirname(path), exist_ok=True)

        if not self.logger.handlers:
            fh = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count)
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(fh)

    def log(self, message: str, **payload) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "message": message,
            **payload,
        }
        self.logger.info(json.dumps(event))

    def verify_integrity(self) -> str:
        """Compute a simple SHA-256 hash of the current audit file to verify integrity."""
        sha = hashlib.sha256()
        if not os.path.exists(self.path):
            return ""  # nothing to verify yet
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def export_logs(self, destination_path: str) -> str:
        """Export current audit log to a destination path and return the path."""
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        copyfile(self.path, destination_path)
        return destination_path
