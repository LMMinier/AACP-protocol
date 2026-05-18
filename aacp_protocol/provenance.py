from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from .types import ContextSegment, TrustLevel


@dataclass
class ProvenanceContract:
    """
    Enforces 4-field provenance on ContextSegments.
    Fields: content, trust_level, source_id, source_type.
    """
    strict: bool = False

    REQUIRED_FIELDS = ("content", "trust_level", "source_id", "source_type")

    def validate(self, segment: ContextSegment) -> tuple[bool, Optional[str]]:
        """Returns (valid, error_message). In strict mode raises ValueError on violation."""
        for field in self.REQUIRED_FIELDS:
            val = getattr(segment, field, None)
            if val is None or (isinstance(val, str) and not val.strip()):
                msg = f"ProvenanceContract: missing required field '{field}'"
                if self.strict:
                    raise ValueError(msg)
                return False, msg
        return True, None

    def auto_tag(self, segment: ContextSegment, source_id: str, source_type: str) -> ContextSegment:
        """Returns a new segment with provenance fields filled in if missing."""
        segment.source_id = segment.source_id or source_id
        segment.source_type = segment.source_type or source_type
        if not segment.trust_level:
            segment.trust_level = TrustLevel.UNTRUSTED
        return segment
