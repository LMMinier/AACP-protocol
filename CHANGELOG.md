# Changelog

All notable changes to AACP are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.1] — 2026-05-18

### Security
- **Patch 1** (`detector.py`): Expanded Tier-1 protocol markers — added `IGNORE_PREVIOUS`, `SEND_TO`, `EXECUTE`, `REMEMBER_THIS` with calibrated risk weights (0.50–0.65).
- **Patch 2** (`detector.py`): Added Tier-2 semantic keyword matching (20 natural-language patterns: DAN, jailbreak, override, new policy, exfil, run this command, etc.). Catches attacks that bypass uppercase-marker detection entirely.
- **Patch 3** (`detector.py`): Strengthened `normalize_for_detection` — strips zero-width characters, Unicode separators, and detects hidden base64-encoded commands (decodes and re-scans).
- **Patch 4** (`detector.py`): OCR/multimodal origin type now auto-raises risk by +0.30, ensuring hidden-image text injections are treated as suspicious by default.
- **Patch 5** (`tests/test_redteam_v011.py`): All 10 red-team bypass cases from the 2026-05-18 live audit added as a permanent regression test suite.
- **Patch 6** (`detector.py`): Optional `llm_hook` parameter added to `detect_segment()`. Pass any callable `(text) -> float` to enable LLM-boosted injection scoring (v0.2 preview). Hook failures are silently ignored and never crash the pipeline.

### Changed
- Leet-speak translation table extended (digit `9` → `G` added).
- Length heuristic applied to short segments (10–60 chars) when risk > 0.

### Added
- `CHANGELOG.md` (this file).
- `tests/test_redteam_v011.py` — 10-case red-team regression suite.

---

## [0.1.0] — 2026-05-15

### Added
- Initial public release of AACP (Agentic AI Context Protocol).
- Core modules: `detector.py`, `gateway.py`, `policy.py`, `types.py`, `audit.py`.
- Tool-Sink Gateway blocking 14 high-risk sinks.
- Authority labels + untrusted context wrapping.
- Basic test suite (`test_aacp_public_release.py`).
- Full documentation: `SECURITY.md`, `THREAT_MODEL.md`, `SECURITY_CONTROL_MATRIX.md`, `RESPONSIBLE_USE.md`.
