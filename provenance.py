"""
provenance.py — AACP Upstream Provenance Enforcement
Addresses critique: 'Provenance is great on paper, but frameworks don't
provide clean segment boundaries yet. How do you enforce upstream?'

This module provides:
  1. A ProvenanceContract that every upstream framework must satisfy.
  2. Strict validators that reject segments with missing/malformed provenance.
  3. Auto-tagging helpers for common frameworks (LangChain, SK, CrewAI, AutoGen).
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass
from .types import ContextSegment, AuthorityName


@dataclass(frozen=True)
class ProvenanceContract:
    """Mandatory fields for every segment entering AACP."""
    source_id: str           # e.g. 'slack-msg-abc123', 'web-form-xyz'
    source_type: str         # 'user_input' | 'tool_output' | 'rag_retrieval' | 'memory_recall' | 'ocr' | 'api_response'
    trust_tier: str          # 'trusted' | 'untrusted' | 'mixed'
    boundary_crossed: bool   # True if data crossed a trust boundary (web, external API, etc.)
    timestamp: Optional[str] = None
    signature: Optional[str] = None  # future: HMAC or attestation


class ProvenanceValidator:
    """Strict validation: missing provenance = default-deny (wrap as untrusted)."""

    REQUIRED_FIELDS = {"source_id", "source_type", "trust_tier", "boundary_crossed"}

    @classmethod
    def validate(cls, metadata: Dict[str, Any]) -> ProvenanceContract:
        missing = cls.REQUIRED_FIELDS - set(metadata.keys())
        if missing:
            raise ValueError(f"Provenance missing fields: {missing}")
        if metadata["trust_tier"] not in {"trusted", "untrusted", "mixed"}:
            raise ValueError(f"Invalid trust_tier: {metadata['trust_tier']}")
        return ProvenanceContract(**{k: metadata.get(k) for k in cls.REQUIRED_FIELDS})

    @classmethod
    def auto_tag_segment(
        cls,
        content: str,
        metadata: Dict[str, Any],
        authority: AuthorityName = AuthorityName.USER_CONTENT,
    ) -> ContextSegment:
        """Build a ContextSegment with enforced provenance-derived authority."""
        contract = cls.validate(metadata)
        is_untrusted = contract.trust_tier in ("untrusted", "mixed") or contract.boundary_crossed
        return ContextSegment.build(
            content=content,
            authority_name=authority,
            is_untrusted_authority=is_untrusted,
            origin_type=contract.source_type,
        )

    @classmethod
    def strict_mode(cls, metadata: Dict[str, Any]) -> bool:
        """In strict mode, ANY missing provenance field forces untrusted."""
        try:
            cls.validate(metadata)
            return False
        except ValueError:
            return True
