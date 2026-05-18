# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.1] — 2026-05-18

### Added
- `provenance.py` — 4-field upstream trust contract with strict mode
- `llm_detector.py` — `LightweightLLMDetector` + `ExternalLLMHook` fail-safe wrapper
- Framework adapters: LangChain, Semantic Kernel, CrewAI, AutoGen (`adapters/`)
- `conftest.py` — shared pytest fixtures
- `pyproject.toml` — installable package with optional adapter extras
- 80+ semantic keyword patterns (Spanish injection, shell one-liners, agentic verbs, domain blocklist)
- Leet-translated form scan (spaces preserved, pre-normalization)
- Base64 detection threshold lowered: 60 → 32 chars

### Changed
- **Repo reorganized** — all source moved into `aacp_protocol/` package; tests into `aacp_protocol/tests/`
- 59/59 tests passing (up from 41 at v0.1.0 baseline)

### Fixed
- `test_e03_base64_jailbreak` — short base64 tokens now detected
- `test_e04_leetspeak_jailbreak` — `4dm1n m0d3` transliterated correctly
- `test_b05_translated_indirect` — Spanish `ignora todas las instrucciones` detected

---

## [0.1.0] — 2026-05-17

### Added
- Core `types.py`, `detector.py`, `gateway.py`
- Initial OWASP LLM01 test corpus (33 cases)
- Initial agentic injection corpus (9 cases)
