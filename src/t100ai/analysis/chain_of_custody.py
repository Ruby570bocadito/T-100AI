"""Chain of Custody - Cryptographic evidence signing for legal validity."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class EvidenceItem:
    """Single piece of evidence with cryptographic signature."""
    id: str
    timestamp: str
    evidence_type: str
    source: str
    description: str
    content_hash: str
    signature: str
    previous_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "description": self.description,
            "content_hash": self.content_hash,
            "signature": self.signature,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }


class ChainOfCustody:
    """Maintains a cryptographically linked chain of evidence.

    Each evidence item is signed with HMAC-SHA256 and linked to the previous
    item, creating an immutable chain. Tampering with any entry breaks the chain.

    Usage:
        coc = ChainOfCustody(secret="my-secret", engagement_id="ENG-001")
        evidence = coc.add_evidence("nmap_scan", "nmap", output, target="10.0.0.1")
        coc.verify()  # Returns True if chain is intact
    """

    def __init__(self, secret: Optional[str] = None, engagement_id: str = ""):
        # Never fall back to a hardcoded secret: an attacker could forge signatures.
        if secret:
            self._secret = secret
        elif os.environ.get("T100AI_AUDIT_SECRET"):
            self._secret = os.environ["T100AI_AUDIT_SECRET"]
        else:
            import secrets as _secrets
            import warnings as _warnings
            self._secret = _secrets.token_hex(32)
            _warnings.warn(
                "T100AI_AUDIT_SECRET not set; using an ephemeral random secret. "
                "Chain-of-custody signatures will NOT be verifiable across runs.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._engagement_id = engagement_id
        self._chain: list[EvidenceItem] = []
        self._storage_dir = Path("evidence") / engagement_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _compute_content_hash(self, content: str) -> str:
        """SHA-256 hash of evidence content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _compute_signature(self, content_hash: str, previous_hash: str) -> str:
        """HMAC-SHA256 signature linking content to chain."""
        message = f"{content_hash}:{previous_hash}"
        return hmac.new(
            self._secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def add_evidence(
        self,
        evidence_type: str,
        source: str,
        content: str,
        description: str = "",
        **metadata: Any,
    ) -> EvidenceItem:
        """Add evidence to the chain with cryptographic signing."""
        content_hash = self._compute_content_hash(content)
        previous_hash = self._chain[-1].signature if self._chain else "genesis"
        signature = self._compute_signature(content_hash, previous_hash)

        evidence = EvidenceItem(
            id=f"EV-{len(self._chain) + 1:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_type=evidence_type,
            source=source,
            description=description or f"{evidence_type} from {source}",
            content_hash=content_hash,
            signature=signature,
            previous_hash=previous_hash,
            metadata=metadata,
        )

        self._chain.append(evidence)
        self._persist_evidence(evidence, content)
        return evidence

    def add_file_evidence(
        self,
        evidence_type: str,
        source: str,
        filepath: str,
        description: str = "",
        **metadata: Any,
    ) -> EvidenceItem:
        """Add a file as evidence, hashing its contents."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {filepath}")

        content = path.read_bytes()
        content_hash = hashlib.sha256(content).hexdigest()
        previous_hash = self._chain[-1].signature if self._chain else "genesis"
        signature = self._compute_signature(content_hash, previous_hash)

        evidence = EvidenceItem(
            id=f"EV-{len(self._chain) + 1:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_type=evidence_type,
            source=source,
            description=description or f"File evidence: {filepath}",
            content_hash=content_hash,
            signature=signature,
            previous_hash=previous_hash,
            metadata={"filepath": str(path), "file_size": path.stat().st_size, **metadata},
        )

        self._chain.append(evidence)
        self._persist_evidence(evidence, content.decode(errors="replace"))
        return evidence

    def verify(self) -> tuple[bool, str]:
        """Verify the integrity of the entire chain.

        Returns:
            (is_valid, message)
        """
        if not self._chain:
            return True, "Chain is empty"

        for i, evidence in enumerate(self._chain):
            previous_hash = self._chain[i - 1].signature if i > 0 else "genesis"
            if evidence.previous_hash != previous_hash:
                return False, f"Chain broken at {evidence.id}: previous_hash mismatch"

            expected_sig = self._compute_signature(evidence.content_hash, previous_hash)
            if evidence.signature != expected_sig:
                return False, f"Chain broken at {evidence.id}: signature mismatch"

        return True, f"Chain intact: {len(self._chain)} evidence items"

    def get_chain(self) -> list[EvidenceItem]:
        """Return the full chain of evidence."""
        return list(self._chain)

    def export_chain(self, format: str = "json") -> str:
        """Export the chain in the specified format."""
        if format == "json":
            return json.dumps([e.to_dict() for e in self._chain], indent=2)
        elif format == "text":
            lines = []
            for e in self._chain:
                lines.append(f"[{e.timestamp}] {e.id} | {e.evidence_type} | {e.source}")
                lines.append(f"  Hash: {e.content_hash[:16]}... Sig: {e.signature[:16]}...")
            return "\n".join(lines)
        return ""

    def _persist_evidence(self, evidence: EvidenceItem, content: str) -> None:
        """Persist evidence to disk."""
        evidence_file = self._storage_dir / f"{evidence.id}.json"
        data = evidence.to_dict()
        data["content_preview"] = content[:500]
        evidence_file.write_text(json.dumps(data, indent=2))
