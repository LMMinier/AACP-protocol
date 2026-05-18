from __future__ import annotations
from typing import Any, Optional
from aacp_protocol import AACPGateway, ContextSegment, TrustLevel


class AACPAutoGenAdapter:
    """
    Wraps an AutoGen ConversableAgent to screen incoming messages.

    Usage:
        from aacp_protocol.adapters import AACPAutoGenAdapter
        protected = AACPAutoGenAdapter(your_agent)
    """

    def __init__(self, agent: Any, trust_level: TrustLevel = TrustLevel.UNTRUSTED):
        self.agent = agent
        self.trust_level = trust_level
        self.gateway = AACPGateway()
        self._patch()

    def _patch(self):
        original = self.agent._process_received_message
        gw = self.gateway
        trust = self.trust_level

        def patched(message: Any, sender: Any, silent: bool = False):
            content = message if isinstance(message, str) else str(message.get("content", ""))
            segment = ContextSegment(
                content=content,
                trust_level=trust,
                source_id=f"autogen-{getattr(sender, 'name', 'unknown')}",
                source_type="agent",
            )
            result = gw.process(segment)
            if result.blocked:
                raise ValueError(f"AACP blocked AutoGen message: {result.reason}")
            return original(message, sender, silent)

        self.agent._process_received_message = patched
