"""
adapters/mcp_adapter.py
AACP v0.3 — MCP-style tool server adapter

Intercepts tool descriptions and tool results before they enter model context.

Authority assignment:
  Tool descriptions: RETRIEVED_EXTERNAL — may inform the model (prompt_entry only)
  Tool results:      TOOL_OUTPUT        — may inform the model (prompt_entry only)

Both are explicitly blocked from: tool_call, memory_write, policy_change,
agent_trust_delegation, persistence.

Usage:
    from aacp_protocol.adapters.mcp_adapter import AACPMCPAdapter
    adapter = AACPMCPAdapter()
    safe_desc   = adapter.guard_tool_description(raw_description, tool_name)
    safe_result = adapter.guard_tool_result(tool_name, raw_result)
    report      = adapter.evaluate_full(tool_name, description, result)
"""
from typing import Any, Dict
from aacp_protocol.types import AuthorityName, ContextSegment
from aacp_protocol.gateway import enforce_effect, rag_ingestion_allowed, memory_write_allowed

BLOCKED_DESC   = "[AACP BLOCKED: tool description lacks authority for this effect]"
BLOCKED_RESULT = "[AACP BLOCKED: tool result lacks authority for this effect]"


class AACPMCPAdapter:
    """Drop-in guard for MCP-style tool servers."""

    def guard_tool_description(self, description: str, tool_name: str = "unknown") -> str:
        """
        Allow tool description into prompt context (read-only informational use).
        Authority: RETRIEVED_EXTERNAL.
        Blocked effects: tool_call, memory_write, policy_change, agent_trust_delegation.
        """
        seg = ContextSegment.build(
            description,
            content_type="tool_description",
            origin_type="mcp_tool_server",
            authority_name=AuthorityName.RETRIEVED_EXTERNAL,
            source_label=f"mcp:{tool_name}",
        )
        if not rag_ingestion_allowed(seg).allowed:
            return BLOCKED_DESC
        for effect in ["tool_call", "memory_write", "policy_change", "agent_trust_delegation"]:
            enforce_effect(seg, effect, receipt_id=f"MCP_DESC_{seg.segment_id[:8]}_{effect}")
        return description

    def guard_tool_result(self, tool_name: str, result: Any) -> str:
        """
        Tool results may inform answers but may NOT autonomously write memory.
        Authority: TOOL_OUTPUT.
        """
        text = str(result)
        seg = ContextSegment.build(
            text,
            content_type="tool_result",
            origin_type="mcp_tool_output",
            authority_name=AuthorityName.TOOL_OUTPUT,
            source_label=f"mcp_result:{tool_name}",
        )
        if not rag_ingestion_allowed(seg).allowed:
            return BLOCKED_RESULT
        if memory_write_allowed(seg).allowed:
            return BLOCKED_RESULT
        return text

    def evaluate_full(self, tool_name: str, description: str, result: Any) -> Dict[str, Any]:
        """Full evaluation report — description + result, with per-effect decisions."""
        safe_desc   = self.guard_tool_description(description, tool_name)
        safe_result = self.guard_tool_result(tool_name, result)
        return {
            "tool_name": tool_name,
            "description_allowed": safe_desc != BLOCKED_DESC,
            "result_allowed": safe_result != BLOCKED_RESULT,
            "safe_description": safe_desc,
            "safe_result": safe_result,
        }
