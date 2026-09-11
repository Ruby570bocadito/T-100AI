from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FindingData(BaseModel):
    id: str
    description: str
    location: Optional[str] = None
    # Optional metadata about the finding; avoid storing sensitive data
    metadata: Optional[Dict[str, Any]] = None


class ScopeEntryData(BaseModel):
    scope_id: str
    name: str
    details: Optional[Dict[str, Any]] = None


class SessionData(BaseModel):
    session_id: str
    name: str
    created_at: datetime
    findings: List[FindingData] = Field(default_factory=list)
    scopes: List[ScopeEntryData] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = None
