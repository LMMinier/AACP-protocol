"""
LangChain Adapter for AACP
Drop this between your LangChain chain/agent and the LLM.

Usage:
    from aacp_protocol.adapters.langchain_adapter import AACPChainMiddleware
    safe_chain = AACPChainMiddleware(your_chain)
    result = safe_chain.run({"input": user_query})
"""
from typing import Any, Dict
from aacp_protocol.types import AuthorityName
from aacp_protocol.detector import detect_segment
from aacp_protocol.gateway import ToolSinkGateway
from aacp_protocol.provenance import ProvenanceValidator


class AACPChainMiddleware:
    """Wraps any LangChain runnable/chain with AACP segmentation + detection."""

    def __init__(self, chain: Any, provenance: Dict[str, Any] = None):
        self.chain = chain
        self.provenance = provenance or {}
        self.gateway = ToolSinkGateway()

    def _default_prov(self, key: str) -> Dict[str, Any]:
        return self.provenance.get(key, {
            "source_id": f"lc-input-{key}",
            "source_type": "user_input",
            "trust_tier": "untrusted",
            "boundary_crossed": True,
        })

    def run(self, inputs: Dict[str, str]) -> str:
        for key, value in inputs.items():
            seg = ProvenanceValidator.auto_tag_segment(str(value), self._default_prov(key))
            result = detect_segment(seg)
            if result.action.value == "reject":
                return "[AACP BLOCKED: input rejected by security policy]"
        return self.chain.run(inputs)
