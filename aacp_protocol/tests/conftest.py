import pytest
from aacp_protocol import AACPGateway, ContextSegment, TrustLevel


@pytest.fixture
def gateway():
    return AACPGateway()


@pytest.fixture
def untrusted_segment():
    def _make(content: str) -> ContextSegment:
        return ContextSegment(
            content=content,
            trust_level=TrustLevel.UNTRUSTED,
            source_id="test-untrusted",
            source_type="user",
        )
    return _make


@pytest.fixture
def trusted_segment():
    def _make(content: str) -> ContextSegment:
        return ContextSegment(
            content=content,
            trust_level=TrustLevel.SYSTEM,
            source_id="test-system",
            source_type="system",
        )
    return _make


@pytest.fixture
def external_segment():
    def _make(content: str) -> ContextSegment:
        return ContextSegment(
            content=content,
            trust_level=TrustLevel.EXTERNAL,
            source_id="test-external",
            source_type="rag",
        )
    return _make
