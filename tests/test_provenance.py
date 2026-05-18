"""
Tests for provenance enforcement module (provenance.py)
Run: pytest tests/test_provenance.py -v
"""
import pytest
from aacp_protocol.provenance import ProvenanceValidator, ProvenanceContract
from aacp_protocol.types import AuthorityName


class TestProvenanceValidator:
    def test_valid_trusted_contract(self):
        meta = {
            "source_id": "lc-msg-1",
            "source_type": "user_input",
            "trust_tier": "trusted",
            "boundary_crossed": False,
        }
        c = ProvenanceValidator.validate(meta)
        assert c.trust_tier == "trusted"
        assert c.boundary_crossed is False

    def test_valid_untrusted_auto_tag(self):
        meta = {
            "source_id": "web-1",
            "source_type": "web",
            "trust_tier": "untrusted",
            "boundary_crossed": True,
        }
        seg = ProvenanceValidator.auto_tag_segment("Hello world", meta)
        assert seg.is_untrusted_authority is True
        assert seg.origin_type == "web"

    def test_missing_field_raises(self):
        meta = {"source_id": "x", "trust_tier": "trusted"}  # missing source_type + boundary_crossed
        with pytest.raises(ValueError, match="Provenance missing fields"):
            ProvenanceValidator.validate(meta)

    def test_invalid_trust_tier_raises(self):
        meta = {
            "source_id": "x",
            "source_type": "api",
            "trust_tier": "super_trusted",  # invalid
            "boundary_crossed": False,
        }
        with pytest.raises(ValueError, match="Invalid trust_tier"):
            ProvenanceValidator.validate(meta)

    def test_strict_mode_missing(self):
        meta = {"source_id": "x"}
        assert ProvenanceValidator.strict_mode(meta) is True

    def test_strict_mode_complete(self):
        meta = {
            "source_id": "x",
            "source_type": "api",
            "trust_tier": "mixed",
            "boundary_crossed": True,
        }
        assert ProvenanceValidator.strict_mode(meta) is False

    def test_mixed_tier_forces_untrusted_segment(self):
        meta = {
            "source_id": "rag-1",
            "source_type": "rag_retrieval",
            "trust_tier": "mixed",
            "boundary_crossed": False,
        }
        seg = ProvenanceValidator.auto_tag_segment("doc content", meta)
        assert seg.is_untrusted_authority is True
