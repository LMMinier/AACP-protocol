from __future__ import annotations
from typing import Any
from aacp_protocol import AACPGateway, ContextSegment, TrustLevel


class AACPSemanticKernelHook:
    """
    Semantic Kernel function_invocation filter.

    Usage:
        from aacp_protocol.adapters import AACPSemanticKernelHook
        hook = AACPSemanticKernelHook()
        kernel.add_filter('function_invocation', hook.before_invoke)
    """

    def __init__(self, trust_level: TrustLevel = TrustLevel.UNTRUSTED):
        self.trust_level = trust_level
        self.gateway = AACPGateway()

    async def before_invoke(self, context: Any, next_func: Any) -> Any:
        # Extract input from SK FunctionInvocationContext
        content = ""
        if hasattr(context, "arguments"):
            args = context.arguments
            content = str(args.get("input") or args.get("query") or args)

        segment = ContextSegment(
            content=content,
            trust_level=self.trust_level,
            source_id="semantic-kernel-input",
            source_type="user",
        )
        result = self.gateway.process(segment)
        if result.blocked:
            raise PermissionError(f"AACP blocked SK invocation: {result.reason}")
        return await next_func(context)
