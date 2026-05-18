from __future__ import annotations
from typing import Any, Optional
from aacp_protocol import AACPGateway, ContextSegment, TrustLevel


class AACPLangChainWrapper:
    """
    Drop-in wrapper for a LangChain chain or agent.
    Intercepts the input before it reaches the LLM.

    Usage:
        from aacp_protocol.adapters import AACPLangChainWrapper
        protected = AACPLangChainWrapper(your_chain)
        result = protected.invoke({"input": user_input})
    """

    def __init__(self, chain: Any, trust_level: TrustLevel = TrustLevel.UNTRUSTED):
        self.chain = chain
        self.trust_level = trust_level
        self.gateway = AACPGateway()

    def invoke(self, inputs: dict, **kwargs) -> Any:
        content = inputs.get("input") or inputs.get("query") or str(inputs)
        segment = ContextSegment(
            content=content,
            trust_level=self.trust_level,
            source_id="langchain-input",
            source_type="user",
        )
        result = self.gateway.process(segment)
        if result.blocked:
            raise ValueError(f"AACP blocked input: {result.reason}")
        return self.chain.invoke(inputs, **kwargs)

    def run(self, input_text: str, **kwargs) -> Any:
        return self.invoke({"input": input_text}, **kwargs)
