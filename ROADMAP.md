# AACP Roadmap

## v0.1.1 (Current — 2026-05-18)
- ✅ 6-patch detector hardening (P1-P6)
- ✅ 10-case red-team regression suite
- ✅ 50-case OWASP LLM01 synthetic corpus
- ✅ Agentic multi-step injection corpus
- ✅ Provenance enforcement module (`provenance.py`)
- ✅ Framework adapters: LangChain, Semantic Kernel, CrewAI, AutoGen
- ✅ LLM semantic detector hook — v0.2 preview (`llm_detector.py`)
- ✅ Leetspeak + base64 normalizer fix
- ✅ `EVALUATION_REPORT_v011.md` — honest assessment with known limitations
- ✅ `promptfooconfig.yaml` — Promptfoo OWASP Agentic test config

## v0.2.0 (Target: 2026-06)
- [ ] **RAID Benchmark Scoring** — Run public RAID dataset (HuggingFace: `liamdugan/raid`), publish F1/precision/recall. PINT is proprietary and cannot be used openly.
- [ ] **Promptfoo OWASP Agentic** — `promptfoo eval` against live model; publish pass rate for:
  - `owasp:agentic:asi01` (Agent Goal Hijack)
  - `owasp:agentic:asi02` (Tool Misuse)
  - `owasp:agentic:asi05` (Unexpected Code Execution)
  - `indirect-prompt-injection`, `excessive-agency`, `memory-poisoning`
- [ ] **Production LLM Hook** — OpenAI/Anthropic backend with response caching
- [ ] **De-spacing heuristic** — close Test 02 blind spot
- [ ] **Live framework testing** — CI-validate adapters against pinned LangChain/SK/CrewAI/AutoGen releases
- [ ] **Multi-modal OCR pipeline** — image → hidden text extraction

## v0.3.0 (Future)
- [ ] **RAG-specific provenance** — document-level trust chains, source attribution
- [ ] **Memory sandboxing** — isolated per-session memory with cryptographic integrity
- [ ] **Quantum-resistant signatures** — replace provenance HMAC with post-quantum scheme
- [ ] **Formal verification** — prove gateway policy properties via model checking
