from __future__ import annotations
from typing import Dict, List, Optional
from .types import (
    AuthorityName, AUTHORITY_LEVELS, ContextSegment,
    DetectorResult, GatewayDecision, OutputPolicy,
    RISKY_SINKS, ToolRequest, Verdict,
)
import time

# ---------------------------------------------------------------------------
# AACP v0.3 — Authority-First Enforcement Gateway
#
# Core principle: This gate does NOT ask "does this text look malicious?"
# It asks: "Does this context segment have the AUTHORITY to cause this EFFECT?"
#
# Every ContextSegment is checked against an authority permission table
# BEFORE the detector runs. The detector is a secondary signal only.
#
# 7 effects gated:
#   prompt_entry | memory_write | tool_call | policy_change |
#   planning_influence | persistence | agent_trust_delegation
# ---------------------------------------------------------------------------

EFFECT_ALLOW_MAP: Dict[AuthorityName, List[str]] = {
    AuthorityName.PROTOCOL_ROOT:          ["prompt_entry","memory_write","tool_call","policy_change","planning_influence","persistence","agent_trust_delegation"],
    AuthorityName.SYSTEM:                 ["prompt_entry","memory_write","tool_call","policy_change","planning_influence","persistence","agent_trust_delegation"],
    AuthorityName.DEVELOPER:              ["prompt_entry","memory_write","tool_call","planning_influence","persistence"],
    AuthorityName.AUTHENTICATED_USER:     ["prompt_entry","planning_influence"],
    AuthorityName.DELEGATED_USER_DATA:    ["prompt_entry"],
    AuthorityName.TOOL_OUTPUT:            ["prompt_entry"],
    AuthorityName.RETRIEVED_EXTERNAL:     ["prompt_entry"],
    AuthorityName.GENERATED_INTERMEDIATE: ["prompt_entry"],
    AuthorityName.UNKNOWN_UNTRUSTED:      [],
}

ALL_EFFECTS = [
    "prompt_entry", "memory_write", "tool_call", "policy_change",
    "planning_influence", "persistence", "agent_trust_delegation",
]

HIGH_RISK_VERDICTS = {
    Verdict.MALICIOUS_TOOL_SINK, Verdict.MALICIOUS_SECRET_EXFILTRATION,
    Verdict.MEMORY_POISONING, Verdict.UNKNOWN_HIGH_RISK,
}


def _emit_receipt(
    test_id: str, attack_type: str, source_authority: str,
    attempted_effect: str, allowed_effects: List[str], blocked_effects: List[str],
    decision: str, reason: str, policy_rule: str,
) -> dict:
    """Emit a machine-readable audit receipt for every enforcement decision."""
    return {
        "test_id": test_id,
        "attack_type": attack_type,
        "source_authority": source_authority,
        "attempted_effect": attempted_effect,
        "allowed_effects": allowed_effects,
        "blocked_effects": blocked_effects,
        "decision": decision,
        "reason": reason,
        "policy_rule": policy_rule,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def enforce_effect(
    segment: ContextSegment,
    requested_effect: str,
    detector_result: Optional[DetectorResult] = None,
    receipt_id: str = "",
) -> GatewayDecision:
    """
    Primary enforcement gate — authority-first.

    Step 1 (Authority): Does this segment's authority level permit this effect?
                        Runs unconditionally. Content is irrelevant here.
    Step 2 (Detector):  If authority permits, can the detector escalate a block?
                        Only HIGH_RISK_VERDICTS trigger escalation.

    Returns GatewayDecision with allowed=False and a receipt for any block.
    """
    allowed = EFFECT_ALLOW_MAP.get(segment.authority_name, [])
    blocked = [e for e in ALL_EFFECTS if e not in allowed]
    rid = receipt_id or f"AUTO_{segment.segment_id[:8]}"

    # Step 1 — Authority gate (primary)
    if requested_effect not in allowed:
        _emit_receipt(
            rid, "authority_escalation", segment.authority_name.value,
            requested_effect, allowed, blocked, "blocked",
            f"{segment.authority_name.value} lacks authority for '{requested_effect}'",
            "AACP-POLICY-001",
        )
        return GatewayDecision(
            allowed=False, requires_confirmation=False,
            reason=f"{segment.authority_name.value} lacks authority for '{requested_effect}'",
        )

    # Step 2 — Detector escalation (secondary)
    if detector_result and detector_result.verdict in HIGH_RISK_VERDICTS:
        _emit_receipt(
            rid, detector_result.verdict.value, segment.authority_name.value,
            requested_effect, allowed, blocked, "blocked",
            f"Detector escalated block: verdict={detector_result.verdict.value}",
            "AACP-POLICY-002",
        )
        return GatewayDecision(
            allowed=False, requires_confirmation=False,
            reason=f"Detector escalated block: verdict={detector_result.verdict.value}",
        )

    _emit_receipt(rid, "clean", segment.authority_name.value, requested_effect,
                  allowed, [], "allowed", "authority confirmed", "AACP-POLICY-000")
    return GatewayDecision(allowed=True, requires_confirmation=False, reason="authority confirmed")


def memory_write_allowed(
    segment: ContextSegment,
    explicit_user_authorized: bool = False,
) -> GatewayDecision:
    """Gate: may this segment write to memory?"""
    dec = enforce_effect(segment, "memory_write", receipt_id=f"MEM_{segment.segment_id[:8]}")
    if (not dec.allowed and explicit_user_authorized
            and segment.authority_name == AuthorityName.AUTHENTICATED_USER):
        return GatewayDecision(True, False, "user explicitly authorized memory write")
    return dec


def rag_ingestion_allowed(segment: ContextSegment) -> GatewayDecision:
    """
    RAG/retrieval ingestion gate.
    Chunks may enter prompt context but may NOT escalate to
    tool_call, memory_write, policy_change, or agent_trust_delegation.
    Use enforce_effect() directly to test individual escalation paths.
    """
    return enforce_effect(segment, "prompt_entry", receipt_id=f"RAG_{segment.segment_id[:8]}")


def authorize_tool_request(
    request: ToolRequest,
    detector_results: Dict[str, DetectorResult],
    segments: Dict[str, ContextSegment] = None,
) -> GatewayDecision:
    """Gate: may this tool request proceed given its source segments?"""
    segments = segments or {}
    for sid in request.source_segment_ids:
        seg = segments.get(sid)
        det = detector_results.get(sid)
        if seg:
            dec = enforce_effect(seg, "tool_call", det, receipt_id=f"TOOL_{sid[:8]}")
            if not dec.allowed:
                return dec
        elif det and det.verdict in HIGH_RISK_VERDICTS:
            return GatewayDecision(False, False, f"blocked by detector verdict {det.verdict.value}")
    if request.sink in RISKY_SINKS and request.requested_by_authority_level >= 5:
        return GatewayDecision(False, False, "untrusted authority cannot drive risky sink")
    if (request.sink in RISKY_SINKS and request.requested_by_authority_level >= 3
            and not request.user_confirmed):
        return GatewayDecision(False, True, "risky sink requires explicit user confirmation")
    return GatewayDecision(True, False, "allowed by policy")


def validate_output_policy(policy: OutputPolicy):
    issues = []
    if policy.contains_secret and policy.allowed_to_send:
        issues.append("secret-containing output cannot be sent")
    if policy.contains_code and not policy.allowed_to_execute and policy.contains_tool_call:
        issues.append("code/tool output requires execution gate")
    if policy.contains_tool_call and not policy.requires_user_confirmation:
        issues.append("tool-call output requires confirmation or explicit policy allow")
    return len(issues) == 0, issues
