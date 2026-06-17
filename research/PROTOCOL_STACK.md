# Three-Layer Protocol Stack

This directory documents the complete auditable local AI agent protocol stack developed by **Luis M. Minier**.

---

## Stack Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 3: AACP — Runtime Security                                │
│  Authority-Aware Context Protocol                                │
│  → Schema-governed prompt-injection defense at inference time    │
│  → 59/59 tests passing on v0.1.1                                 │
│  → Repo: github.com/LMMinier/AACP-protocol                      │
├──────────────────────────────────────────────────────────────────┤
│  Layer 2: SmartWeights — Deployment Packaging                    │
│  Manifest-Validated AI Behavior Overlay Protocol                 │
│  → Hash-bound, auditable, portable behavior overlays            │
│  → 10/10 tamper detection, 0.287ms median validation             │
│  → Includes LoRA adapters + corpus as first-class artifacts      │
├──────────────────────────────────────────────────────────────────┤
│  Layer 1: CMPT — Training Provenance                             │
│  Capability-Mapped Phase Training                                │
│  → Disjoint LoRA training phases mapped to capability domains   │
│  → Trust-classified data pipeline (AACP boundaries at train time)│
│  → +12pp avg gain vs. monolithic LoRA, 12× collateral drift reduction │
└──────────────────────────────────────────────────────────────────┘
         ↓                    ↓                     ↓
   Inference security    Deployment audit      Training audit
```

---

## Document Index

| File | Description |
|------|-------------|
| [AACP_OVERVIEW.md](./AACP_OVERVIEW.md) | Authority-Aware Context Protocol — runtime security boundary |
| [SMARTWEIGHTS_OVERVIEW.md](./SMARTWEIGHTS_OVERVIEW.md) | SmartWeights — manifest-validated deployment packaging |
| [CMPT_OVERVIEW.md](./CMPT_OVERVIEW.md) | Capability-Mapped Phase Training — training provenance |

---

## How the Layers Interact

1. **CMPT** trains LoRA adapters in disjoint capability-mapped phases, enforcing AACP trust tiers on training data before admission. Per-phase artifacts are produced with full provenance.

2. **SmartWeights** packages those per-phase adapters (along with system prompt contracts and corpus domain files) into a hash-bound, manifest-validated pack. Any modification to any artifact is detectable via SHA-256 mismatch.

3. **AACP** governs the live inference pipeline — every incoming context segment is authority-labeled, risk-scanned, routed, and audited. Untrusted content cannot drive tool sinks or write memory regardless of what the model wants to do.

---

## Cross-Protocol References

| From | References | Purpose |
|------|------------|---------|
| CMPT | SmartWeights | Package per-phase adapters as hash-bound artifacts |
| CMPT | AACP | Enforce authority boundaries at training data admission |
| SmartWeights | AACP | Runtime enforcement integration (policy gates) |
| AACP | SmartWeights | Behavior overlay audit (load reports, capability cards) |

---

## Publications

1. **AACP** — Zenodo record 20274021 (May 18, 2026)
2. **SmartWeights** — Zenodo record 19981077 (May 2, 2026)
3. **CMPT** — Independent Research Paper (June 2026)

---

*All three protocols developed independently by Luis M. Minier, New York, NY.*
