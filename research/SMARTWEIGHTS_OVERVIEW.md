# SmartWeights Protocol

> **Paper:** *SmartWeights: A Manifest-Validated Protocol for Portable and Auditable AI Behavior Overlays*
> **Author:** Luis M. Minier — Independent Researcher, New York, NY
> **Date:** May 2, 2026
> **Version:** v0.2

---

## Summary

SmartWeights is a manifest-validated protocol for packaging, validating, and auditing AI behavior overlays as portable artifacts. It treats prompts, routing rules, policies, evidence files, capability declarations, trained LoRA adapter weights, and domain knowledge corpora as **first-class artifacts** that can be hashed, validated, diffed, rebuilt, and reported.

> **Thesis:** AI behavior overlays — including adapter weights, system-prompt contracts, and domain knowledge corpora — should be packaged, hashed, validated, diffed, and reproduced as first-class artifacts, separate from but linkable to the neural base model they condition.

---

## System Model

A SmartWeights pack is formally: **P = (M, F, C, E, H, A, Ω)**

| Symbol | Meaning |
|--------|---------|
| M | Manifest |
| F | Set of tracked files |
| C | Set of capability cards |
| E | Set of evidence references |
| H | Hash inventory |
| A | Optional adapter-weight artifact set |
| Ω | Optional corpus domain set |

---

## Layered Architecture

| Layer       | Description                       | SW Role            |
|-------------|-----------------------------------|--------------------|
| Base model  | Frozen neural parameters          | Not modified       |
| Adapter     | LoRA delta weights                | Tracked artifact   |
| Corpus      | Domain knowledge files            | Tracked artifact   |
| Contract    | System-prompt behavioral rules    | Tracked artifact   |
| Runtime     | Inference middleware              | Loads and injects  |
| Manifest    | Identity and file inventory       | Core protocol object |
| Validator   | Schema, hash, evidence checks     | Enforces structure |
| Audit       | Reports, hashes, diffs            | Records status     |

---

## Pack Directory Structure

```
<pack_name>/
  manifest.json
  capability_cards/<capability_id>.json
  adapters/<lora_adapter>.gguf          ← optional
  corpus/
    corpus_index.json                   ← optional
    <domain_01>.json ...
  overlays/system_prompt_contract.txt
  evidence/<eval_report>.json
  metadata.json
  README.md
  CHANGELOG.md
```

---

## Validation Workflow (4 Check Classes)

1. **Schema validation** — required root fields + nested capability-card and adapter fields
2. **File-integrity validation** — file exists, SHA-256 digest matches, byte count matches
3. **Adapter validation** — base model match, scale recorded, rank/phases match training metadata
4. **Capability-evidence validation** — unique capability IDs, non-empty descriptions, required evidence files exist and pass integrity checks

---

## LoRA Adapter as SmartWeights Component

Adapters are tracked with full provenance:
```json
{
  "path": "adapters/lora_r8_scale05.gguf",
  "sha256": "...",
  "bytes": 28968128,
  "rank": 8,
  "scale": 0.5,
  "phases": ["q+v", "k+o", "gate", "up", "down"],
  "base_model": "<frozen-base-id>",
  "trained_at": "2026-04-24T00:00:00Z"
}
```

The frozen-base constraint: `W' = W₀ + α·ΔW = W₀ + α·BA`

Removing the adapter restores original base-model behavior exactly.

---

## Benchmark Results

| Mechanic                          | Result          |
|-----------------------------------|-----------------|
| Tamper detection                  | 10/10           |
| Reproducible rebuild              | Identical hash ✓ |
| Validation (5-file demo pack)     | 0.287ms median  |
| Corpus layer (22 files, 131KB)    | 16.4ms median   |
| Full deployment (73 files, 347MB) | 970ms median    |

---

## CLI Subcommands

```bash
smartweights init
smartweights build
smartweights validate
smartweights selftest
smartweights tamper-test
smartweights repro-test
smartweights diff-test
smartweights bench
```

---

## Covered Threats

| Threat | Mitigation |
|--------|------------|
| Tracked-file modification | SHA-256 digest mismatch |
| Adapter file swap | Digest + byte count mismatch |
| Corpus domain drift | SHA-256 binding on all corpus domain files |
| Missing capability evidence | Evidence-path validation failure |
| Silent behavior change | Manifest-based diffing across pack versions |
| Version ambiguity | Pack name, version, manifest hash |
