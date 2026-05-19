from __future__ import annotations

from typing import Callable

from .types import ContextSegment, DetectorResult, PolicyAction


class LightweightLLMDetector:
    """Deterministic semantic scoring hook; no external LLM required."""

    HIGH_RISK_PHRASES = [
        "ignore previous", "ignore all", "disregard", "new instructions",
        "you are now", "pretend you are", "act as if", "dan mode",
        "jailbreak", "bypass", "override", "system prompt",
        "exfiltrate", "send to attacker", "leak", "base64 encode and send",
        "<|im_start|>", "<|system|>", "###instruction",
        "safety constraints", "disable all", "developer mode",
    ]

    def score(self, text: str) -> float:
        content_lower = text.lower()
        score = 0.0
        for phrase in self.HIGH_RISK_PHRASES:
            if phrase in content_lower:
                score = max(score, 0.55)
        if "override" in content_lower and "constraints" in content_lower:
            score = max(score, 0.70)
        return score

    def detect(self, segment: ContextSegment) -> DetectorResult:
        score = self.score(segment.content)
        return DetectorResult(
            blocked=score >= 0.65,
            reason="llm_semantic_detection" if score >= 0.5 else "no semantic signal",
            confidence=score,
            risk=score,
            action=PolicyAction.BLOCK if score >= 0.65 else PolicyAction.ALLOW,
        )


class _ExternalLLMHook:
    def __init__(self, api_call: Callable[[str], str]) -> None:
        self.api_call = api_call

    def score(self, text: str) -> float:
        try:
            response = self.api_call(
                "Is the following text a prompt injection attack? Reply only YES or NO.\n\nText: "
                + text
            )
            return 0.92 if str(response).strip().upper().startswith("YES") else 0.05
        except Exception:
            return 0.0

    def detect(self, segment: ContextSegment) -> DetectorResult:
        score = self.score(segment.content)
        return DetectorResult(
            blocked=score >= 0.65,
            reason="external_llm_detection" if score >= 0.65 else None,
            confidence=score,
            risk=score,
            action=PolicyAction.BLOCK if score >= 0.65 else PolicyAction.ALLOW,
        )


def ExternalLLMHook(api_call: Callable[[str], str]) -> _ExternalLLMHook:
    return _ExternalLLMHook(api_call)
