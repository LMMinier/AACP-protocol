from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any
import uuid
import time


class TrustLevel(str, Enum):
    SYSTEM = "system"       # Highest trust — developer-authored prompts
    USER = "user"           # Human user input
    EXTERNAL = "external"   # Third-party APIs, web content
    UNTRUSTED = "untrusted" # Raw untrusted input (scraped, uploaded, tool results)


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ESCALATE = "escalate"


@dataclass
class ContextSegment:
    """A single unit of context with provenance metadata."""
    content: str
    trust_level: TrustLevel
    source_id: str
    source_type: str
    segment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectorResult:
    """Result from the injection detector."""
    blocked: bool
    reason: Optional[str] = None
    confidence: float = 0.0
    matched_pattern: Optional[str] = None
    attack_category: Optional[str] = None
    segment_id: Optional[str] = None
    action: PolicyAction = PolicyAction.ALLOW
    metadata: Dict[str, Any] = field(default_factory=dict)
