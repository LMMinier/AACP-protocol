# Changelog

All notable changes to AACP Protocol are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.1] — 2026-05-18

### Added
- `provenance.py` — strict 4-field provenance contract with auto-tag and strict mode
- `llm_detector.py` — LightweightLLMDetector + ExternalLLMHook factory
- Framework adapters: LangChain, Semantic Kernel, CrewAI, AutoGen
- `conftest.py` — shared pytest fixtures (gateway, untrusted_segment, trusted_segment)
- `aacp_protocol/__init__.py` — clean public API, `__version__ = "0.1.1"`
- `aacp_protocol/adapters/__init__.py` — all 4 adapters importable from one location
- `pyproject.toml` — pip-installable with optional adapter extras
- OWASP LLM01 corpus: 33 test cases (direct, indirect, agentic, exfil, jailbreak, benign, multimodal)
- Agentic injection corpus: 9 test cases (chained multi-step, CrewAI hijack, AutoGen poisoning)

### Fixed
- Reorganized all modules from root into `aacp_protocol/` package structure
- Tests moved to `aacp_protocol/tests/` with shared fixtures

## [0.1.0] — 2026-05-18

### Added
- Initial release: `types.py`, `detector.py`, `gateway.py`
- Core `AACPGateway` with TrustLevel-based context segmentation
- Pattern-based injection detector covering 20+ attack signatures
- `ContextSegment` dataclass with 4-field provenance
- Basic test suite
