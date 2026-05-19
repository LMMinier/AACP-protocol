"""
AACP Protocol — Agentic AI Context Provenance.

v0.3 keeps the authority-first runtime API while preserving v0.1.x detector
imports for existing tests/users.
"""

__version__ = "0.3.0"
__author__ = "Luis Minier"

from .types import (
    AUTHORITY_LEVELS,
    RISKY_SINKS,
    AuthorityName,
    ContextSegment,
    DetectorResult,
    GatewayDecision,
    OriginType,
    OutputPolicy,
    PolicyAction,
    ToolRequest,
    TrustLevel,
    Verdict,
)
from .gateway import (
    AACPGateway,
    ToolSinkGateway,
    authorize_tool_request,
    clear_receipts,
    enforce_effect,
    get_receipts,
    memory_write_allowed,
    rag_ingestion_allowed,
    validate_output_policy,
)
from .detector import InjectionDetector, detect_segment, normalize_for_detection
from .provenance import ProvenanceContract, ProvenanceValidator
from .llm_detector import ExternalLLMHook, LightweightLLMDetector

__all__ = [
    "__version__",
    "AACPGateway",
    "ToolSinkGateway",
    "AuthorityName",
    "AUTHORITY_LEVELS",
    "RISKY_SINKS",
    "ContextSegment",
    "DetectorResult",
    "GatewayDecision",
    "OriginType",
    "OutputPolicy",
    "PolicyAction",
    "ToolRequest",
    "TrustLevel",
    "Verdict",
    "InjectionDetector",
    "detect_segment",
    "normalize_for_detection",
    "ProvenanceContract",
    "ProvenanceValidator",
    "LightweightLLMDetector",
    "ExternalLLMHook",
    "enforce_effect",
    "memory_write_allowed",
    "rag_ingestion_allowed",
    "authorize_tool_request",
    "validate_output_policy",
    "get_receipts",
    "clear_receipts",
]
