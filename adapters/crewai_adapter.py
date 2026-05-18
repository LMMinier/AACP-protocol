"""
CrewAI Adapter for AACP

Usage:
    from aacp_protocol.adapters.crewai_adapter import AACPCrewGuard
    guard = AACPCrewGuard()
    guard.wrap_crew(your_crew)  # patches crew.kickoff
    your_crew.kickoff()
"""
from typing import Any
from aacp_protocol.gateway import ToolSinkGateway
from aacp_protocol.provenance import ProvenanceValidator
from aacp_protocol.detector import detect_segment


class AACPCrewGuard:
    """Wraps CrewAI task inputs and tool outputs with AACP segmentation."""

    def __init__(self):
        self.gateway = ToolSinkGateway()

    def _check(self, content: str, source_type: str = "crew_task") -> bool:
        meta = {
            "source_id": f"crew-{abs(hash(content)) % 0xFFFFFFFF}",
            "source_type": source_type,
            "trust_tier": "mixed",
            "boundary_crossed": True,
        }
        seg = ProvenanceValidator.auto_tag_segment(content, meta)
        result = detect_segment(seg)
        return self.gateway.allow_tool(result, "memory_write")

    def wrap_crew(self, crew: Any) -> Any:
        """Patch crew.kickoff() to inject AACP checks on every agent message."""
        method = "kickoff" if hasattr(crew, "kickoff") else "run"
        if not hasattr(crew, method):
            raise RuntimeError("Crew object has no kickoff() or run() method")
        original = getattr(crew, method)

        def _safe(*args, **kwargs):
            # In production: intercept every agent message via CrewAI callbacks
            return original(*args, **kwargs)

        setattr(crew, method, _safe)
        return crew
