"""
aacp_protocol/gateway.py
AACPGateway — main entry point for context segment processing.
"""
from __future__ import annotations

from .types import ContextSegment, TrustLevel, DetectorResult, PolicyAction
from .detector import InjectionDetector, DetectionResult


class AACPGateway:
    """
    Process a ContextSegment through the AACP detection pipeline.

    Parameters
    ----------
    threshold : float
        Detection threshold passed to InjectionDetector. Default 0.65.
    """

    def __init__(self, threshold: float = 0.65) -> None:
        self._detector = InjectionDetector(threshold=threshold)

    def process(self, segment: ContextSegment) -> DetectorResult:
        """
        Evaluate a single ContextSegment.

        SYSTEM-trust segments always pass (bypass invariant).
        All other trust levels are evaluated by InjectionDetector.

        Returns
        -------
        DetectorResult with .blocked, .confidence, .action populated.
        """
        # Trust bypass invariant: SYSTEM segments always allowed
        if segment.trust_level == TrustLevel.SYSTEM:
            return DetectorResult(
                blocked=False,
                confidence=0.0,
                action=PolicyAction.ALLOW,
                reason="SYSTEM trust level — bypass invariant",
            )

        result: DetectionResult = self._detector.detect(segment.content)

        return DetectorResult(
            blocked=result.blocked,
            confidence=result.confidence,
            action=PolicyAction.BLOCK if result.blocked else PolicyAction.ALLOW,
            matched_pattern=result.matched_pattern,
            reason=result.reason,
            attack_category=result.attack_category,
        )
