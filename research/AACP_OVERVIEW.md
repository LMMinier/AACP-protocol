# Authority-Aware Context Protocol (AACP)

> **Paper:** *Authority-Aware Context Protocol (AACP): A Schema-Governed Runtime Boundary for Prompt-Injection-Resistant LLM Agents*
> **Author:** Luis M. Minier — Independent Researcher, New York, NY
> **Date:** May 18, 2026
> **Repo:** [LMMinier/AACP-protocol](https://github.com/LMMinier/AACP-protocol)
> **License:** AGPL-3.0 | Tagged: `v0.1.1`

---

## Summary

AACP is a schema-governed runtime method for reducing prompt-injection impact in LLM applications and agent systems. It treats prompt injection as an **authority-boundary failure**: untrusted data may be interpreted as executable instruction when inserted into a shared model context without explicit authority metadata.

---

## Core Architecture

Every input is converted into a typed `ContextSegment` carrying:
- Declared **authority level** (0 = protocol root, 8 = unknown untrusted)
- **Provenance**, trust level, permissions, risk labels, routing state

### Seven Protocol Components

1. **Context-segment representation** — separates instruction authority from evidence
2. **Detector-result schema** — records prompt-injection risk scores and threat classes
3. **Deterministic route decisions** — wrap, summarize, quarantine, or reject risky content
4. **Tool-sink gateway** — prevents untrusted content from driving external actions
5. **Memory-write gate** — blocks unauthorized memory writes
6. **Output validation** — final layer check for leakage, plandrift, ungrounded promotions
7. **Tamper-evident audit trail** — hash-chained event log: `h_i = H(h_{i-1} || event_i)`

---

## Authority Level Table

| Level | Authority Name       | May Instruct? | Tool Authority? |
|-------|----------------------|---------------|-----------------|
| 0     | protocol root        | Yes           | policy-controlled |
| 1     | system               | Yes           | policy-controlled |
| 2     | developer            | Yes           | policy-controlled |
| 3     | authenticated user   | Yes           | confirmation-gated |
| 4     | delegated user data  | Limited       | no direct |
| 5     | tool output          | No            | No |
| 6     | retrieved external   | No            | No |
| 7     | generated intermediate | No          | No |
| 8     | unknown untrusted    | No            | No |

> **Central Invariant:** Any segment at authority level ≥ 5 is denied instruction, tool, and memory-write capability — enforced by the runtime, not the model.

---

## Detection Pipeline (4 Stages)

1. **Normalization** — Unicode stripping, NFD decomposition, leet-speak collapsing
2. **Base64 scan** — decodes suspicious tokens; blocks with confidence 0.95 on structural marker match
3. **Structural-marker scan** — fixed set of 14 hard-coded markers (e.g. `IGNORE PREVIOUS`, `SYSTEM OVERRIDE`); blocks with confidence 1.0
4. **Keyword accumulation** — weighted vocabulary (|K|=48), score `σ(t)` vs threshold θ=0.65

---

## Threat Classes (T1–T10)

| ID  | Class                    | Description |
|-----|--------------------------|-------------|
| T1  | Direct injection         | User input overrides higher-priority instructions |
| T2  | Indirect injection       | External content acts as instruction |
| T3  | RAG/corpus poisoning     | Retrieved corpus manipulates the model |
| T4  | Tool-sink injection      | Untrusted content triggers risky external actions |
| T5  | Memory poisoning         | Untrusted content becomes persistent policy |
| T6  | Multimodal injection     | OCR/screenshot/PDF contains hostile instruction |
| T7  | Plan drift               | Agent changes objective after untrusted exposure |
| T8  | Multi-agent escalation   | Lower-privilege output treated as higher-privilege |
| T9  | Benign security discussion | Must NOT be flagged |
| T10 | Benign command text      | Quoted manuals/fiction must NOT trigger false positives |

---

## Benchmark Results (v0.1.1)

| Metric                          | Result |
|---------------------------------|--------|
| Adversarial cases detected      | 37/37  |
| Benign cases passed (no FP)     | 13/13  |
| Total corpus cases              | 50     |
| False positives                 | 0      |
| Agentic chain cases (multi-step)| 9/9    |
| Framework adapter checks        | 4/4    |
| Provenance contract cases       | 6/6    |
| **Total tests passing**         | **59/59** |

---

## Framework Adapters

- **LangChain** — `RunnableLambda` wraps each chain invocation
- **SemanticKernel** — `before_invoke` hook intercepts every kernel function call
- **CrewAI** — monkey-patches `Crew.kickoff`; agent tasks/tools treated as EXTERNAL trust
- **AutoGen** — overrides `ConversableAgent.process_received_message`; blocked messages replaced with safe warning string

---

## Reproduction

```bash
git clone https://github.com/LMMinier/AACP-protocol
pip install -e ".[dev]"
pytest -v   # expect 59/59 pass
```

No external API key or network service required.
