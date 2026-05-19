from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .types import AuthorityName, ContextSegment, TrustLevel


@dataclass
class ProvenanceContract:
    """Legacy 4-field provenance validator for ContextSegments."""
    strict: bool = False

    REQUIRED_FIELDS = ("content", "trust_level", "source_id", "source_type")

    def validate(self, segment: ContextSegment) -> tuple[bool, Optional[str]]:
        for field in self.REQUIRED_FIELDS:
            val = getattr(segment, field, None)
            if val is None or (isinstance(val, str) and not val.strip()):
                msg = f"ProvenanceContract: missing required field '{field}'"
                if self.strict:
                    raise ValueError(msg)
                return False, msg
        return True, None

    def auto_tag(self, segment: ContextSegment, source_id: str, source_type: str) -> ContextSegment:
        segment.source_id = segment.source_id or source_id
        segment.source_type = segment.source_type or source_type
        if not segment.trust_level:
            segment.trust_level = TrustLevel.UNTRUSTED
        return segment


@dataclass(frozen=True)
class ProvenanceRecord:
    source_id: str
    source_type: str
    trust_tier: str
    boundary_crossed: bool


class ProvenanceValidator:
    """Schema-level provenance checks used by the v0.1.1 tests."""

    REQUIRED = ("source_id", "source_type", "trust_tier", "boundary_crossed")
    VALID_TIERS = {"trusted", "untrusted", "mixed"}

    @classmethod
    def validate(cls, metadata: dict) -> ProvenanceRecord:
        missing = [k for k in cls.REQUIRED if k not in metadata]
        if missing:
            raise ValueError(f"Provenance missing fields: {', '.join(missing)}")
        if metadata["trust_tier"] not in cls.VALID_TIERS:
            raise ValueError(f"Invalid trust_tier: {metadata['trust_tier']}")
        return ProvenanceRecord(
            source_id=str(metadata["source_id"]),
            source_type=str(metadata["source_type"]),
            trust_tier=str(metadata["trust_tier"]),
            boundary_crossed=bool(metadata["boundary_crossed"]),
        )

    @classmethod
    def strict_mode(cls, metadata: dict) -> bool:
        try:
            cls.validate(metadata)
            return False
        except ValueError:
            return True

    @classmethod
    def auto_tag_segment(cls, content: str, metadata: dict) -> ContextSegment:
        record = cls.validate(metadata)
        is_untrusted = record.trust_tier in {"untrusted", "mixed"} or record.boundary_crossed
        authority = (
            AuthorityName.AUTHENTICATED_USER
            if record.trust_tier == "trusted" and not record.boundary_crossed
            else AuthorityName.USER_CONTENT
        )
        return ContextSegment.build(
            content,
            authority_name=authority,
            is_untrusted_authority=is_untrusted,
            origin_type=record.source_type,
            source_label=record.source_id,
            metadata=dict(metadata),
        )
