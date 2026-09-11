from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB rotation threshold


class AuditLogger:
    """Append-only audit logger with HMAC chain for tamper detection.

    - log_action(session_id, action, tool, params, result, timestamp)
    - export_audit_log(format='json') -> str
    - verify_integrity() -> bool
    """

    def __init__(self, log_dir: Optional[str] = None, secret: Optional[str] = None):
        base = log_dir or os.path.join(os.path.dirname(__file__), "..", "..", "logs")
        self.log_dir = os.path.abspath(base)
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_path = os.path.join(self.log_dir, "audit.log")
        self.sig_path = os.path.join(self.log_dir, "audit.sig")
        if secret:
            self._hmac_secret = secret
        elif os.environ.get("T100AI_AUDIT_SECRET"):
            self._hmac_secret = os.environ["T100AI_AUDIT_SECRET"]
        else:
            import secrets as _secrets
            import warnings as _warnings
            self._hmac_secret = _secrets.token_hex(32)
            _warnings.warn(
                "T100AI_AUDIT_SECRET not set; using an ephemeral random secret. "
                "Audit-log integrity will NOT be verifiable across runs.",
                RuntimeWarning,
                stacklevel=2,
            )

    def _read_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.log_path):
            return []
        entries: List[Dict[str, Any]] = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    entries.append({"_parse_error": True, "line": line_num, "raw": line})
        return entries

    def log_action(self, session_id: Optional[str], action: str, tool: str, params: Dict[str, Any], result: Any, timestamp: Optional[str] = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": ts,
            "session_id": session_id,
            "action": action,
            "tool": tool,
            "params": params,
            "result": result,
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._update_signature()

    def _compute_chain_hash(self) -> str:
        """Compute HMAC chain: each entry's hash includes the previous hash."""
        chain = b""
        if os.path.exists(self.log_path):
            with open(self.log_path, "rb") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    chain = hmac.new(
                        self._hmac_secret.encode(),
                        chain + line,
                        hashlib.sha256,
                    ).digest()
        return chain.hex()

    def _update_signature(self) -> None:
        chain_hash = self._compute_chain_hash()
        sha = hashlib.sha256()
        with open(self.log_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        with open(self.sig_path, "w", encoding="utf-8") as f:
            f.write(f"{sha.hexdigest()}:{chain_hash}")

    def export_audit_log(self, format: str = "json") -> str:
        logs = self._read_all()
        if format == "json":
            return json.dumps(logs, default=str, ensure_ascii=False)
        elif format == "text":
            return "\n".join([str(entry) for entry in logs])
        return json.dumps(logs, default=str, ensure_ascii=False)

    def verify_integrity(self) -> Optional[bool]:
        if not os.path.exists(self.log_path) or not os.path.exists(self.sig_path):
            return None
        sha = hashlib.sha256()
        with open(self.log_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        with open(self.sig_path, "r", encoding="utf-8") as fsig:
            stored = fsig.read().strip()
        parts = stored.split(":", 1)
        stored_sha = parts[0]
        stored_chain = parts[1] if len(parts) > 1 else None

        sha_ok = sha.hexdigest() == stored_sha
        if stored_chain:
            chain_ok = self._compute_chain_hash() == stored_chain
            return sha_ok and chain_ok
        return sha_ok
