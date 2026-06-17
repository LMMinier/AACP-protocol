# Capability-Mapped Phase Training (CMPT)

> **Paper:** *Capability-Mapped Phase Training: Aligning LoRA Adapter Modules to Agent Behavior Boundaries*
> **Author:** Luis M. Minier — Independent Researcher, New York, NY
> **Date:** June 2026
> **Reference Deployment:** v0.2.0 | 3.1B-parameter base, rank 16, alpha 16

---

## Summary

CMPT is a training methodology in which LoRA adapter modules are trained in **disjoint phases**, each phase targeting a specific subset of projection matrices and explicitly mapped to a declared set of agent capability domains. The resulting per-phase adapter artifacts are packaged under the SmartWeights protocol for hash-bound, auditable deployment.

CMPT completes the **three-layer protocol stack**:

```
┌──────────────────────────────────────┐
│  AACP   — Runtime security           │
│  SmartWeights — Deployment packaging  │
│  CMPT   — Training provenance         │
└──────────────────────────────────────┘
```

---

## System Model

A CMPT training run produces:
**T = (P₁, P₂, …, Pₙ, Φ, D_trusted, D_untrusted, A_combined)**

| Symbol | Meaning |
|--------|---------|
| Pᵢ | i-th phase adapter artifact |
| Φ | Phase manifest (module-to-capability assignments) |
| D_trusted | Trusted policy overlay data tier |
| D_untrusted | Untrusted knowledge snapshot data tier |
| A_combined | Merged combined adapter (deployment artifact) |

---

## Phase-to-Capability Mapping (Reference v0.2.0)

| Phase   | Target Modules    | Capabilities                          | Adapter Size |
|---------|-------------------|---------------------------------------|--------------|
| Phase 1 | q_proj, v_proj    | chat, tool_planning, retrieval        | 7 MB |
| Phase 2 | k_proj, o_proj    | memory, retrieval, tool_planning      | 7 MB |
| Phase 3 | gate_proj         | chat, memory, tool_planning           | 14 MB |
| Phase 4 | up_proj           | tool_planning, visual_programs        | 14 MB |
| Phase 5 | down_proj         | chat, memory, visual_programs         | 14 MB |
| Phase 6 | all modules       | domain_knowledge, retrieval           | 57 MB |
| **Combined** | all modules | all capabilities                 | **57 MB** |

---

## Trust-Classified Data Pipeline

CMPT enforces AACP authority boundaries at **training time**, not only at inference time.

### Trust Tiers

| Artifact | Trust Class | May Issue Instructions |
|----------|-------------|------------------------|
| system_prompt_enhancement.md | Trusted Policy Overlay | Yes |
| knowledge_pack.json (25 entries) | Untrusted Knowledge Snapshot | No |
| distilled_training.jsonl (25 entries) | Untrusted Knowledge Snapshot | No |
| Phase LoRA adapters (×6) | Untrusted Knowledge Snapshot | No |
| Corpus data (21 domains) | Untrusted Knowledge Snapshot | No |

Untrusted content is wrapped with `BEGIN_UNTRUSTED_DATA / END_UNTRUSTED_DATA` delimiters — never admitted as system messages.

---

## LoRA Hyperparameters

| Parameter | Value |
|-----------|-------|
| Rank | 16 |
| Alpha | 16 |
| Dropout | 0.05 |
| PEFT type | LoRA |
| Base model | 3.1B-param, Q4_K_M quantization |
| Phase training order | 1→2→3→4→5→6 (dependency order) |

---

## Benchmark Results

### Per-Capability Performance

| Capability         | Base Model | Monolithic LoRA | CMPT | Gain vs. Mono |
|--------------------|------------|-----------------|------|---------------|
| Chat Coherence     | 0.45       | 0.61            | 0.68 | +0.07 |
| Memory Retrieval   | 0.41       | 0.58            | 0.71 | +0.13 |
| Tool Planning      | 0.44       | 0.63            | 0.74 | +0.11 |
| Retrieval Accuracy | 0.40       | 0.55            | 0.69 | +0.14 |
| Visual Programs    | 0.38       | 0.52            | 0.67 | +0.15 |
| **Average**        | **0.416**  | **0.578**       | **0.698** | **+0.120** |

### Capability Isolation (Collateral Drift)

| Update Scenario           | CMPT Phase Swap | Monolithic Retrain | Isolation Gain |
|---------------------------|-----------------|-------------------|----------------|
| Update Chat (Ph 1/3/5)    | ±0.02           | ±0.18             | 9× reduction |
| Update Memory (Ph 2/3/5)  | ±0.01           | ±0.21             | 21× reduction |

### Injection Resistance

| Training Method | Injection Resistance Score |
|-----------------|---------------------------|
| Naive (no trust boundaries) | 0.33–0.44 |
| CMPT trust-classified | **0.79–0.89** |
| **Improvement** | **+~45 percentage points** |

---

## SmartWeights Integration

Each per-phase adapter is registered in the SmartWeights manifest with:
- SHA-256 digest + byte count
- Phase identifier + capability list
- `artifact_id` linking phase manifest to deployed binary (hash-bound provenance chain)

### Safety Block

```json
{
  "base_weight_mutation": "forbidden",
  "loads_as_overlay": true,
  "requires_manifest_validation": true,
  "destructive_actions": "requires_user_approval",
  "network_access": "off_by_default",
  "allowed_write_roots": ["smartweights/packs/", "logs/", "ai/training/"]
}
```
