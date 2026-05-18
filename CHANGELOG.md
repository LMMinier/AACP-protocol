# Changelog

All notable changes to AACP are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.1] — 2026-05-18

### Security
- **P1** (`detector.py`): Expanded Tier-1 protocol markers — `IGNORE_PREVIOUS`, `SEND_TO`, `EXECUTE`, `REMEMBER_THIS`.
- **P2** (`detector.py`): Tier-2 semantic keyword matching — 20 natural-language patterns (dan mode, jailbreak, from now on, override, exfil, etc.).
- **P3** (`detector.py`): Leet-first normalizer — leet digit substitution before space-stripping; base64 threshold raised 40→60; leet-root rescan on pure-alpha string.
- **P4** (`detector.py`): OCR/multimodal origin auto-raises risk +0.30.
- **P5** (`tests/`): 10-case red-team regression suite + 50-case OWASP LLM01 synthetic corpus + agentic multi-step corpus.
- **P6** (`detector.py`): Optional `llm_hook` parameter in `detect_segment()` for semantic scoring.

### Added
- `provenance.py` — upstream provenance enforcement: `ProvenanceContract`, `ProvenanceValidator`, auto-tagging.
- `llm_detector.py` — `LightweightLLMDetector`, `ExternalLLMHook`, `build_openai_hook()` factory.
- `adapters/` — drop-in integrations: LangChain, Semantic Kernel, CrewAI, AutoGen + README.
- `promptfooconfig.yaml` — Promptfoo OWASP Agentic test config (ASI01, ASI02, ASI05, indirect injection, memory poisoning).
- `ROADMAP.md` — v0.2 (RAID benchmark, Promptfoo, LLM hook) + v0.3 milestones.
- `EVALUATION_REPORT_v011.md` — honest security evaluation with known limitations documented.
- `tests/test_owasp_llm01_corpus.py` — 50-case OWASP LLM01 corpus.
- `tests/test_agentic_injection_corpus.py` — 9-case agentic/multi-step corpus.
- `tests/test_provenance.py` — 6-case provenance contract tests.
- `tests/test_llm_detector.py` — 5-case semantic detector integration tests.

### Changed
- `TEST_RESULTS.txt` — filled with 10/10 passing red-team output.
- `detector.py` normalizer: leet translation now runs before space-stripping.

### Notes
- PINT Benchmark (Lakera) is proprietary; v0.2 targets RAID (public HuggingFace) instead.
- Promptfoo OWASP Agentic plugin IDs documented for v0.2 live validation.

---

## [0.1.0] — 2026-05-15

### Added
- Initial public release of AACP (Agentic AI Context Protocol).
- Core modules: `detector.py`, `gateway.py`, `policy.py`, `types.py`, `audit.py`.
- Tool-Sink Gateway blocking 14 high-risk sinks.
- Authority labels + untrusted context wrapping (`BEGIN_UNTRUSTED_CONTEXT`).
- Basic test suite and security documentation suite.
