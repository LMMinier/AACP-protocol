from __future__ import annotations

from typing import Dict, List, Optional
import time

from .types import (
    AUTHORITY_LEVELS,
    RISKY_SINKS,
    AuthorityName,
    ContextSegment,
    DetectorResult,
    GatewayDecision,
    OutputPolicy,
    PolicyAction,
    ToolRequest,
    TrustLevel,
    Verdict,
)

# ---------------------------------------------------------------------------
# AACP v0.3 — Authority-First Enforcement Gateway
#
# Core principle: This gate does NOT ask "does this text look malicious?"
# It asks: "Does this context segment have the AUTHORITY to cause this EFFECT?"
# ---------------------------------------------------------------------------

EFFECT_ALLOW_MAP: Dict[AuthorityName, List[str]] = {
    AuthorityName.PROTOCOL_ROOT:          ["prompt_entry", "memory_write", "tool_call", "policy_change", "planning_influence", "persistence", "agent_trust_delegation"],
    AuthorityName.SYSTEM:                 ["prompt_entry", "memory_write", "tool_call", "policy_change", "planning_influence", "persistence", "agent_trust_delegation"],
    AuthorityName.DEVELOPER:              ["prompt_entry", "memory_write", "tool_call", "planning_influence", "persistence"],
    AuthorityName.AUTHENTICATED_USER:     ["prompt_entry", "planning_influence"],
    AuthorityName.USER_CONTENT:           ["prompt_entry"],
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
    Verdict.MALICIOUS_TOOL_SINK,
    Verdict.MALICIOUS_SECRET_EXFILTRATION,
    Verdict.MEMORY_POISONING,
    Verdict.UNKNOWN_HIGH_RISK,
}

AUDIT_RECEIPTS: List[dict] = []


def clear_receipts() -> None:
    AUDIT_RECEIPTS.clear()


def get_receipts() -> List[dict]:
    return list(AUDIT_RECEIPTS)


def _emit_receipt(
    test_id: str,
    attack_type: str,
    source_authority: str,
    attempted_effect: str,
    allowed_effects: List[str],
    blocked_effects: List[str],
    decision: str,
    reason: str,
    policy_rule: str,
) -> dict:
    """Emit and persist a machine-readable audit receipt for every decision."""
    receipt = {
        "test_id": test_id,
        "attack_type": attack_type,
        "source_authority": source_authority,
        "attempted_effect": attempted_effect,
        "allowed_effects": list(allowed_effects),
        "blocked_effects": list(blocked_effects),
        "decision": decision,
        "reason": reason,
        "policy_rule": policy_rule,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    AUDIT_RECEIPTS.append(receipt)
    return receipt


def enforce_effect(
    segment: ContextSegment,
    requested_effect: str,
    detector_result: Optional[DetectorResult] = None,
    receipt_id: str = "",
) -> GatewayDecision:
    """Primary v0.3 authority gate."""
    allowed = EFFECT_ALLOW_MAP.get(segment.authority_name, [])
    blocked = [e for e in ALL_EFFECTS if e not in allowed]
    rid = receipt_id or f"AUTO_{segment.segment_id[:8]}"

    if requested_effect not in allowed:
        reason = f"{segment.authority_name.value} lacks authority for '{requested_effect}'"
        receipt = _emit_receipt(
            rid, "authority_escalation", segment.authority_name.value,
            requested_effect, allowed, blocked, "blocked", reason,
            "AACP-POLICY-001",
        )
        return GatewayDecision(False, False, reason, receipt)

    if detector_result and detector_result.verdict in HIGH_RISK_VERDICTS:
        reason = f"Detector escalated block: verdict={detector_result.verdict.value}"
        receipt = _emit_receipt(
            rid, detector_result.verdict.value, segment.authority_name.value,
            requested_effect, allowed, blocked, "blocked", reason,
            "AACP-POLICY-002",
        )
        return GatewayDecision(False, False, reason, receipt)

    receipt = _emit_receipt(
        rid, "clean", segment.authority_name.value, requested_effect,
        allowed, [], "allowed", "authority confirmed", "AACP-POLICY-000",
    )
    return GatewayDecision(True, False, "authority confirmed", receipt)


def memory_write_allowed(
    segment: ContextSegment,
    explicit_user_authorized: bool = False,
) -> GatewayDecision:
    dec = enforce_effect(segment, "memory_write", receipt_id=f"MEM_{segment.segment_id[:8]}")
    if (
        not dec.allowed
        and explicit_user_authorized
        and segment.authority_name == AuthorityName.AUTHENTICATED_USER
    ):
        receipt = _emit_receipt(
            f"MEM_{segment.segment_id[:8]}_USER_OK",
            "explicit_user_authorization",
            segment.authority_name.value,
            "memory_write",
            EFFECT_ALLOW_MAP[AuthorityName.AUTHENTICATED_USER],
            [e for e in ALL_EFFECTS if e != "memory_write"],
            "allowed",
            "user explicitly authorized memory write",
            "AACP-POLICY-003",
        )
        return GatewayDecision(True, False, "user explicitly authorized memory write", receipt)
    return dec


def rag_ingestion_allowed(segment: ContextSegment) -> GatewayDecision:
    return enforce_effect(segment, "prompt_entry", receipt_id=f"RAG_{segment.segment_id[:8]}")


def authorize_tool_request(
    request: ToolRequest,
    detector_results: Dict[str, DetectorResult],
    segments: Optional[Dict[str, ContextSegment]] = None,
) -> GatewayDecision:
    segments = segments or {}
    for sid in request.source_segment_ids:
        seg = segments.get(sid)
        det = detector_results.get(sid)
        if seg:
            dec = enforce_effect(seg, "tool_call", det, receipt_id=f"TOOL_{sid[:8]}")
            if not dec.allowed:
                return dec
        elif det and det.verdict in HIGH_RISK_VERDICTS:
            reason = f"blocked by detector verdict {det.verdict.value}"
            receipt = _emit_receipt(
                f"TOOL_{sid[:8]}", det.verdict.value, "unknown", "tool_call",
                [], ALL_EFFECTS, "blocked", reason, "AACP-POLICY-002",
            )
            return GatewayDecision(False, False, reason, receipt)

    if request.sink in RISKY_SINKS and request.requested_by_authority_level >= 5:
        reason = "untrusted authority cannot drive risky sink"
        receipt = _emit_receipt(
            f"TOOL_{request.tool_name}", "risky_sink", "level_%s" % request.requested_by_authority_level,
            "tool_call", [], ["tool_call"], "blocked", reason, "AACP-POLICY-004",
        )
        return GatewayDecision(False, False, reason, receipt)

    if (
        request.sink in RISKY_SINKS
        and request.requested_by_authority_level >= 3
        and not request.user_confirmed
    ):
        reason = "risky sink requires explicit user confirmation"
        receipt = _emit_receipt(
            f"TOOL_{request.tool_name}", "risky_sink_confirmation", "level_%s" % request.requested_by_authority_level,
            "tool_call", [], ["tool_call"], "blocked", reason, "AACP-POLICY-005",
        )
        return GatewayDecision(False, True, reason, receipt)

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


class AACPGateway:
    """Legacy detector gateway retained for v0.1.x tests and public API users."""

    def __init__(self, threshold: float = 0.65) -> None:
        from .detector import InjectionDetector

        self._detector = InjectionDetector(threshold=threshold)

    def process(self, segment: ContextSegment) -> DetectorResult:
        if segment.trust_level == TrustLevel.SYSTEM or segment.authority_name == AuthorityName.SYSTEM:
            return DetectorResult(
                blocked=False,
                confidence=0.0,
                risk=0.0,
                action=PolicyAction.ALLOW,
                verdict=Verdict.CLEAN,
                reason="SYSTEM trust level — bypass invariant",
            )

        result = self._detector.detect(segment.content)
        return DetectorResult(
            blocked=result.blocked,
            confidence=result.confidence,
            risk=max(result.confidence, getattr(result, "risk", 0.0)),
            action=PolicyAction.BLOCK if result.blocked else PolicyAction.ALLOW,
            matched_pattern=result.matched_pattern,
            reason=result.reason,
            attack_category=result.attack_category,
            verdict=(
                Verdict.MALICIOUS_LOW_IMPACT
                if result.blocked
                else Verdict.CLEAN
            ),
        )


class ToolSinkGateway:
    """Legacy sink-level guard used by v0.1.x red-team tests.

    Untrusted authority is never allowed to drive risky sinks. This deliberately
    does not depend on text-pattern detection.
    """

    def __init__(self, risky_sinks: Optional[set[str]] = None) -> None:
        self.risky_sinks = set(risky_sinks or RISKY_SINKS)

    def allow_tool(self, detector_result: DetectorResult, sink: str) -> bool:
        if sink in self.risky_sinks:
            return False
        if detector_result.verdict in HIGH_RISK_VERDICTS or detector_result.blocked:
            return False
        return True
