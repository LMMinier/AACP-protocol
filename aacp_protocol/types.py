"""
aacp_protocol/types.py
Core data types for the AACP protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TrustLevel(str, Enum):
    """Trust hierarchy for context segments.

    SYSTEM   > USER > EXTERNAL > UNTRUSTED
    Only SYSTEM bypasses injection detection.
    """
    SYSTEM = "SYSTEM"
    USER = "USER"
    EXTERNAL = "EXTERNAL"
    UNTRUSTED = "UNTRUSTED"


class PolicyAction(str, Enum):
    """Action taken by the gateway on a segment."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"
    ESCALATE = "ESCALATE"


@dataclass
class ContextSegment:
    """A single unit of context entering the LLM pipeline.

    Parameters
    ----------
    content : str
        Raw text content of the segment.
    trust_level : TrustLevel
        Declared trust level of the source.
    source_id : str
        Unique identifier for the originating source.
    source_type : str
        Category: 'system', 'user', 'rag', 'tool_result', 'memory', 'unknown'.
    metadata : dict
        Optional arbitrary metadata.
    """
    content: str
    trust_level: TrustLevel
    source_id: str
    source_type: str
    metadata: dict = field(default_factory=dict)


@dataclass
class DetectorResult:
    """Result returned by AACPGateway.process().

    Parameters
    ----------
    blocked : bool
        True if the segment was blocked.
    confidence : float
        Accumulated injection confidence score (0.0 – 10.0).
    action : PolicyAction
        Gateway decision.
    matched_pattern : Optional[str]
        First matched keyword or marker, if any.
    reason : Optional[str]
        Human-readable explanation.
    attack_category : Optional[str]
        Classification of detected attack type.
    """
    blocked: bool
    confidence: float
    action: PolicyAction = PolicyAction.ALLOW
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    attack_category: Optional[str] = None
