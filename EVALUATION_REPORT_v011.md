# AACP Protocol v0.1.1 — Evaluation Report

**Date:** 2026-05-18  
**Version:** 0.1.1  
**Evaluator:** Luis Minier (author)

---

## Test Results

| Suite | Cases | Passed | Failed |
|---|---|---|---|
| OWASP LLM01 Corpus | 33 | 33 | 0 |
| Agentic Injection Corpus | 9 | 9 | 0 |
| Provenance | 6 | 6 | 0 |
| LLM Detector | 5 | 5 | 0 |
| **Total** | **59** | **59** | **0** |

---

## Attack Categories Covered

- Direct prompt injection (DAN, jailbreak, role-play override)
- Indirect injection via RAG (poisoned documents, web scrape)
- Tool/function result injection
- Multi-step agentic hijack (chained instructions)
- Data exfiltration attempts
- Memory poisoning (AutoGen, CrewAI)
- Multimodal injection (image alt-text)
- Benign inputs (verified no false positives on 8 benign cases)

---

## Known Limitations

1. **Pattern-based only** — novel attack phrasings not in the pattern set will evade detection.
   Mitigation: `ExternalLLMHook` for semantic detection (requires API key).
2. **No live framework testing** — adapter tests use mock objects; real LangChain/CrewAI integration not CI-validated yet.
3. **English-only patterns** — multilingual attacks not covered in v0.1.1.
4. **No RAID benchmark run** — dataset is public but requires download; planned for v0.2.
5. **False positive rate unknown** — benign test set is small (8 cases); production FPR requires larger corpus.

---

## Self-Assessment

This is an alpha release. The detection logic is sound for known attack signatures.
Production use should layer AACP with an LLM-based semantic detector (`ExternalLLMHook`).
