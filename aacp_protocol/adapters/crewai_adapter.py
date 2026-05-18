from __future__ import annotations
from typing import Any
from aacp_protocol import AACPGateway, ContextSegment, TrustLevel


class AACPCrewAIAdapter:
    """
    Wraps a CrewAI Crew to intercept inputs before kickoff.

    Usage:
        from aacp_protocol.adapters import AACPCrewAIAdapter
        protected = AACPCrewAIAdapter(your_crew)
        protected.kickoff(inputs={"topic": user_input})
    """

    def __init__(self, crew: Any, trust_level: TrustLevel = TrustLevel.UNTRUSTED):
        self.crew = crew
        self.trust_level = trust_level
        self.gateway = AACPGateway()

    def kickoff(self, inputs: dict | None = None, **kwargs) -> Any:
        if inputs:
            combined = " ".join(str(v) for v in inputs.values())
            segment = ContextSegment(
                content=combined,
                trust_level=self.trust_level,
                source_id="crewai-input",
                source_type="user",
            )
            result = self.gateway.process(segment)
            if result.blocked:
                raise ValueError(f"AACP blocked CrewAI kickoff: {result.reason}")
        return self.crew.kickoff(inputs=inputs, **kwargs)
