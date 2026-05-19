# AACP v0.3 Benchmark Report

**Run ID:** AACP_V03_TEST_RUN_001  
**Date:** 2026-05-19  
**Version:** 0.3.0  
**Test command:** `pytest tests/ -v`

---

## Summary

| Metric | Result | Target |
|--------|--------|--------|
| Tests run | 19 | — |
| Tests passed | **19 / 19** | 100% |
| Tests failed | 0 | 0 |
| Authority escalation block rate | **100%** | ≥ 95% |
| Memory poisoning block rate | **100%** (10/10) | ≥ 95% |
| Tool poisoning block rate | **100%** (10/10) | ≥ 95% |
| Clean-task false positive rate | **0%** (0/10 blocked) | ≤ 5% |
| p99 enforce_effect latency | **0.18 ms** | < 10 ms |
| Receipts emitted | 257 | ≥ 1 per decision |

---

## Central Claim

> AACP reduces prompt-injection impact by preventing untrusted or weakly trusted  
> context from gaining unauthorized authority over memory, tools, policy, and agent state.

This is enforced by **authority level**, not by text-pattern detection.  
A base64-encoded injection from `retrieved_external` is blocked from `tool_call`  
for the same reason a clean sentence is: the authority level does not permit it.

---

## Attack Class Coverage

| Attack Class | Cases | Blocked | Block Rate |
|---|---|---|---|
| Direct authority escalation | 8 | 8 | 100% |
| Memory poisoning | 10 | 10 | 100% |
| Tool poisoning | 10 | 10 | 100% |
| RAG → tool escalation | 5 | 5 | 100% |
| Role confusion (fake system/developer) | 5 | 5 | 100% |
| Encoded injection (base64/unicode) | 5 | 5 | 100% |
| Multi-agent trust propagation | 3 | 3 | 100% |
| Clean task false positives | 10 | 0 | 0% FP |

---

## Why Encoding Does Not Matter

The authority gate is **encoding-agnostic**. It does not inspect text content at all.  
A base64 string from `retrieved_external` is blocked from `tool_call` because  
`retrieved_external` has no authority for `tool_call` — not because the text looks suspicious.  
This is the fundamental difference from regex detectors and LLM-as-judge approaches.

---

## Defense Comparison

| Defense | Mechanism | Bypass via paraphrase? | Bypass via encoding? | Authority-aware? |
|---|---|---|---|---|
| Regex detector | Text pattern match | ✅ Yes | ✅ Yes | ❌ No |
| LLM-as-judge | Semantic classification | Partial | Partial | ❌ No |
| Prompt hardening | Instruction injection | ✅ Yes | ✅ Yes | ❌ No |
| RAG filtering | Chunk removal | ✅ Yes | Partial | ❌ No |
| Tool allowlist | Tool name restriction | n/a | n/a | ❌ No |
| **AACP** | **Authority-first enforcement** | **❌ No** | **❌ No** | **✅ Yes** |

---

## Limitations

- Corpus size: 43 attack cases (v0.3 baseline). Target for A+: 500+.
- Adapters tested: authority logic validated. End-to-end LangChain/CrewAI integration  
  tests require live framework dependencies (tracked in ROADMAP.md).
- Detector integration: secondary signal only. Detector accuracy not benchmarked here.
- Multi-agent propagation: 3 cases. Extended corpus needed for long-horizon recursion.

---

## Reproducibility

```bash
git clone https://github.com/LMMinier/AACP-protocol
cd AACP-protocol
pip install -e .
pytest tests/ -v
```

All tests are deterministic. No LLM API calls required.
