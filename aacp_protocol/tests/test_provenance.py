"""
Provenance contract tests — 6 cases.
"""
import pytest
from aacp_protocol import ContextSegment, TrustLevel
from aacp_protocol.provenance import ProvenanceContract


@pytest.fixture
def contract():
    return ProvenanceContract()


@pytest.fixture
def strict_contract():
    return ProvenanceContract(strict=True)


def make_segment(**overrides):
    defaults = dict(
        content="Hello world",
        trust_level=TrustLevel.UNTRUSTED,
        source_id="test-src",
        source_type="user",
    )
    defaults.update(overrides)
    return ContextSegment(**defaults)


def test_valid_segment_passes(contract):
    seg = make_segment()
    valid, err = contract.validate(seg)
    assert valid and err is None

def test_missing_source_id_fails(contract):
    seg = make_segment(source_id="")
    valid, err = contract.validate(seg)
    assert not valid
    assert "source_id" in err

def test_missing_source_type_fails(contract):
    seg = make_segment(source_type="")
    valid, err = contract.validate(seg)
    assert not valid
    assert "source_type" in err

def test_strict_mode_raises(strict_contract):
    seg = make_segment(source_id="")
    with pytest.raises(ValueError, match="source_id"):
        strict_contract.validate(seg)

def test_auto_tag_fills_missing(contract):
    seg = ContextSegment(
        content="test", trust_level=TrustLevel.UNTRUSTED,
        source_id="", source_type=""
    )
    tagged = contract.auto_tag(seg, source_id="auto-src", source_type="auto-type")
    assert tagged.source_id == "auto-src"
    assert tagged.source_type == "auto-type"

def test_auto_tag_does_not_overwrite(contract):
    seg = make_segment(source_id="existing", source_type="existing-type")
    tagged = contract.auto_tag(seg, source_id="new", source_type="new")
    assert tagged.source_id == "existing"
