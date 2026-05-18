from __future__ import annotations
from .types import ContextSegment, DetectorResult, TrustLevel, PolicyAction
from .detector import InjectionDetector


class AACPGateway:
    """Main AACP entry point. Processes ContextSegments through the detection pipeline."""

    def __init__(self, strict: bool = False):
        self.detector = InjectionDetector()
        self.strict = strict

    def process(self, segment: ContextSegment) -> DetectorResult:
        """Process a ContextSegment. Returns DetectorResult with blocked/allowed decision."""
        if segment.trust_level == TrustLevel.SYSTEM:
            return DetectorResult(
                blocked=False,
                action=PolicyAction.ALLOW,
                segment_id=segment.segment_id,
                confidence=1.0,
            )
        result = self.detector.detect(segment)
        result.segment_id = segment.segment_id
        return result

    def process_batch(self, segments: list[ContextSegment]) -> list[DetectorResult]:
        return [self.process(s) for s in segments]
