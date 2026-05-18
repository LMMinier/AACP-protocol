"""
Semantic Kernel Adapter for AACP

Usage:
    from aacp_protocol.adapters.semantic_kernel_adapter import AACPSKPlugin
    plugin = AACPSKPlugin(kernel)
    kernel.add_plugin(plugin, plugin_name="AACP")
    # Register plugin.before_invoke in SK's pre-invoke pipeline
"""
from typing import Any, Dict
from aacp_protocol.detector import detect_segment
from aacp_protocol.gateway import ToolSinkGateway
from aacp_protocol.provenance import ProvenanceValidator


class AACPSKPlugin:
    """Semantic Kernel plugin — intercepts all function inputs through AACP."""

    def __init__(self, kernel: Any, default_provenance: Dict[str, Any] = None):
        self.kernel = kernel
        self.gateway = ToolSinkGateway()
        self.default_prov = default_provenance or {
            "source_id": "sk-default",
            "source_type": "user_input",
            "trust_tier": "untrusted",
            "boundary_crossed": True,
        }

    def _sanitize(self, text: str, prov: Dict[str, Any] = None) -> str:
        seg = ProvenanceValidator.auto_tag_segment(text, prov or self.default_prov)
        result = detect_segment(seg)
        if result.action.value in ("reject", "quarantine"):
            return "[AACP BLOCKED]"
        if result.risk >= 0.35:
            return f"BEGIN_UNTRUSTED_CONTEXT\n{text}\nEND_UNTRUSTED_CONTEXT"
        return text

    def before_invoke(self, context: Any) -> Any:
        """Register with SK's pre-invoke pipeline."""
        if hasattr(context, "variables"):
            for key in context.variables:
                context.variables[key] = self._sanitize(str(context.variables[key]))
        return context
