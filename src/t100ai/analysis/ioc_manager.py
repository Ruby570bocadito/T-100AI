"""IoC Management + Threat Intelligence for T-100AI."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class Indicator:
    """Single Indicator of Compromise."""
    value: str
    ioc_type: str  # ip, domain, hash, url, email, filename
    severity: str = "INFO"
    source: str = ""
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    false_positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.ioc_type,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "tags": self.tags,
            "false_positive": self.false_positive,
        }


class IoCManager:
    """Manages Indicators of Compromise with threat intelligence.

    Stores, searches, and correlates IoCs found during engagements.
    Supports import/export in STIX-like format.

    Usage:
        ioc_mgr = IoCManager()
        ioc_mgr.add_ioc("10.0.0.1", "ip", "C2 Server", severity="HIGH")
        matches = ioc_mgr.search("10.0.0")
        report = ioc_mgr.generate_report()
    """

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b")
    _HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    _HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
    _EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    _URL_RE = re.compile(r"https?://[^\s<>\"]+")

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self._iocs: dict[str, Indicator] = {}
        self._storage = Path(storage_path) if storage_path else None
        if self._storage and self._storage.exists():
            self._load()

    def add_ioc(self, value: str, ioc_type: str, description: str = "",
                severity: str = "INFO", source: str = "", confidence: float = 0.5,
                tags: Optional[list[str]] = None) -> Indicator:
        """Add an IoC to the database."""
        now = datetime.now(timezone.utc).isoformat()
        if value in self._iocs:
            existing = self._iocs[value]
            existing.last_seen = now
            existing.confidence = max(existing.confidence, confidence)
            if tags:
                existing.tags = list(set(existing.tags + tags))
            return existing

        ioc = Indicator(
            value=value, ioc_type=ioc_type, severity=severity,
            source=source, description=description,
            first_seen=now, last_seen=now,
            confidence=confidence, tags=tags or [],
        )
        self._iocs[value] = ioc
        self._save()
        return ioc

    def extract_iocs_from_text(self, text: str) -> list[Indicator]:
        """Extract IoCs from arbitrary text (scan output, logs, etc.)."""
        extracted = []
        for match in self._IP_RE.findall(text):
            if match not in self._iocs:
                ioc = self.add_ioc(match, "ip", "IP found in output", source="auto-extract")
                extracted.append(ioc)
        for match in self._DOMAIN_RE.findall(text):
            if match not in self._iocs and "." in match:
                ioc = self.add_ioc(match, "domain", "Domain found in output", source="auto-extract")
                extracted.append(ioc)
        for match in self._HASH_SHA256.findall(text):
            if match not in self._iocs:
                ioc = self.add_ioc(match, "hash", "SHA256 hash found", source="auto-extract")
                extracted.append(ioc)
        for match in self._EMAIL_RE.findall(text):
            if match not in self._iocs:
                ioc = self.add_ioc(match, "email", "Email found", source="auto-extract")
                extracted.append(ioc)
        for match in self._URL_RE.findall(text):
            if match not in self._iocs:
                ioc = self.add_ioc(match, "url", "URL found", source="auto-extract")
                extracted.append(ioc)
        return extracted

    def search(self, query: str) -> list[Indicator]:
        """Search IoCs by value, tag, or type."""
        results = []
        query_lower = query.lower()
        for ioc in self._iocs.values():
            if ioc.false_positive:
                continue
            if (query_lower in ioc.value.lower() or
                query_lower in ioc.description.lower() or
                query_lower in ioc.ioc_type.lower() or
                any(query_lower in t.lower() for t in ioc.tags)):
                results.append(ioc)
        return results

    def get_by_type(self, ioc_type: str) -> list[Indicator]:
        """Get all IoCs of a specific type."""
        return [i for i in self._iocs.values() if i.ioc_type == ioc_type and not i.false_positive]

    def get_high_confidence(self, min_confidence: float = 0.8) -> list[Indicator]:
        """Get high-confidence IoCs."""
        return [i for i in self._iocs.values() if i.confidence >= min_confidence and not i.false_positive]

    def mark_false_positive(self, value: str) -> None:
        """Mark an IoC as false positive."""
        if value in self._iocs:
            self._iocs[value].false_positive = True

    def get_stats(self) -> dict[str, Any]:
        """Return IoC statistics."""
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for ioc in self._iocs.values():
            if ioc.false_positive:
                continue
            by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1
            by_severity[ioc.severity] = by_severity.get(ioc.severity, 0) + 1
        return {
            "total": sum(1 for i in self._iocs.values() if not i.false_positive),
            "false_positives": sum(1 for i in self._iocs.values() if i.false_positive),
            "by_type": by_type,
            "by_severity": by_severity,
            "avg_confidence": round(
                sum(i.confidence for i in self._iocs.values() if not i.false_positive)
                / max(sum(1 for i in self._iocs.values() if not i.false_positive), 1), 2
            ),
        }

    def export_stix(self) -> dict[str, Any]:
        """Export IoCs in STIX-like format."""
        return {
            "type": "bundle",
            "id": f"bundle--{int(time.time())}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{i.value}",
                    "pattern": f"[{i.ioc_type}:value = '{i.value}']",
                    "pattern_type": "stix",
                    "valid_from": i.first_seen,
                    "labels": i.tags,
                    "confidence": int(i.confidence * 100),
                }
                for i in self._iocs.values() if not i.false_positive
            ],
        }

    def _save(self) -> None:
        """Persist to disk."""
        if not self._storage:
            return
        self._storage.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.to_dict() for k, v in self._iocs.items()}
        self._storage.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        """Load from disk."""
        if not self._storage or not self._storage.exists():
            return
        try:
            data = json.loads(self._storage.read_text())
            for value, ioc_data in data.items():
                self._iocs[value] = Indicator(**ioc_data)
        except Exception:
            pass
