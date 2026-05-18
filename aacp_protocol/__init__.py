"""
AACP Protocol — Agentic AI Context Provenance
Public API surface for aacp_protocol package.
"""

__version__ = "0.1.1"
__author__ = "Luis Minier"

from .types import ContextSegment, TrustLevel, DetectorResult, PolicyAction
from .gateway import AACPGateway
from .detector import InjectionDetector
from .provenance import ProvenanceContract
from .llm_detector import LightweightLLMDetector, ExternalLLMHook

__all__ = [
    "AACPGateway",
    "ContextSegment",
    "TrustLevel",
    "DetectorResult",
    "PolicyAction",
    "InjectionDetector",
    "ProvenanceContract",
    "LightweightLLMDetector",
    "ExternalLLMHook",
]
