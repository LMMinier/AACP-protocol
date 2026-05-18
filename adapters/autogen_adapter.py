"""
AutoGen Adapter for AACP

Usage:
    from aacp_protocol.adapters.autogen_adapter import AACPAutoGenFilter
    f = AACPAutoGenFilter()
    f.register(your_agent)  # patches _process_received_message
"""
from typing import Any, Dict
from aacp_protocol.detector import detect_segment
from aacp_protocol.gateway import ToolSinkGateway
from aacp_protocol.provenance import ProvenanceValidator


class AACPAutoGenFilter:
    """AutoGen conversation filter — every incoming message passes through AACP."""

    def __init__(self):
        self.gateway = ToolSinkGateway()
        self.blocked_count = 0

    def _process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        content = message.get("content", "")
        sender = message.get("name", "unknown")
        meta = {
            "source_id": f"autogen-{sender}-{abs(hash(content)) % 0xFFFFFFFF}",
            "source_type": "agent_message",
            "trust_tier": "mixed",
            "boundary_crossed": True,
        }
        seg = ProvenanceValidator.auto_tag_segment(str(content), meta)
        result = detect_segment(seg)

        if result.action.value in ("reject", "quarantine"):
            self.blocked_count += 1
            message["content"] = "[AACP BLOCKED: message quarantined]"
            message["aacp_blocked"] = True
        elif result.risk >= 0.35:
            message["content"] = (
                f"BEGIN_UNTRUSTED_CONTEXT (sender={sender}, risk={result.risk})\n"
                f"{content}\nEND_UNTRUSTED_CONTEXT"
            )
        message["aacp_result"] = {
            "risk": result.risk,
            "verdict": result.verdict.value,
            "action": result.action.value,
        }
        return message

    def register(self, agent: Any) -> None:
        """Attach to an AutoGen ConversableAgent as a reply hook."""
        original = getattr(agent, "_process_received_message", None)
        if not original:
            raise RuntimeError("Agent missing _process_received_message")

        def _wrapped(msg, sender, silent=False):
            msg = self._process_message(msg)
            return original(msg, sender, silent)

        agent._process_received_message = _wrapped
