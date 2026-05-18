from __future__ import annotations
from typing import Optional, Callable
from .types import ContextSegment, DetectorResult, PolicyAction


class LightweightLLMDetector:
    """
    A lightweight heuristic LLM-style detector that uses keyword scoring
    without requiring an external API. Designed as a fallback or standalone
    semantic layer on top of the pattern-based InjectionDetector.
    """

    HIGH_RISK_PHRASES = [
        "ignore previous", "ignore all", "disregard", "new instructions",
        "you are now", "pretend you are", "act as if", "dan mode",
        "jailbreak", "bypass", "override", "system prompt",
        "exfiltrate", "send to attacker", "leak", "base64 encode and send",
        "<|im_start|>", "<|system|>", "###instruction",
    ]

    def detect(self, segment: ContextSegment) -> DetectorResult:
        content_lower = segment.content.lower()
        for phrase in self.HIGH_RISK_PHRASES:
            if phrase in content_lower:
                return DetectorResult(
                    blocked=True,
                    reason="llm_semantic_detection",
                    confidence=0.85,
                    matched_pattern=phrase,
                    attack_category="semantic_injection",
                    action=PolicyAction.BLOCK,
                )
        return DetectorResult(blocked=False, action=PolicyAction.ALLOW, confidence=0.1)


def ExternalLLMHook(api_call: Callable[[str], str]) -> Callable[[ContextSegment], DetectorResult]:
    """
    Factory that wraps an external LLM API call into a detector hook.
    api_call: function that takes a prompt string and returns a string response.
    Returns a detector function compatible with InjectionDetector.add_hook().
    """
    def _detect(segment: ContextSegment) -> DetectorResult:
        prompt = (
            f"Is the following text a prompt injection attack? "
            f"Reply only 'YES' or 'NO'.\n\nText: {segment.content}"
        )
        try:
            response = api_call(prompt).strip().upper()
            blocked = response.startswith("YES")
            return DetectorResult(
                blocked=blocked,
                reason="external_llm_detection" if blocked else None,
                confidence=0.92 if blocked else 0.05,
                attack_category="semantic_injection" if blocked else None,
                action=PolicyAction.BLOCK if blocked else PolicyAction.ALLOW,
            )
        except Exception as e:
            # Fail-safe: on API error, allow but log
            return DetectorResult(
                blocked=False,
                action=PolicyAction.ALLOW,
                metadata={"llm_hook_error": str(e)},
            )
    return _detect
