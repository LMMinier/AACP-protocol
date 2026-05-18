# AACP Test Dataset Card

## Dataset Summary

The AACP test corpus is a structured collection of labeled text samples for
evaluating prompt injection detection in agentic LLM pipelines. Each sample
is labeled as either **attack** or **benign**, with a declared attack class
for positive cases.

## Dataset Details

| Field | Value |
|---|---|
| Version | 0.1.1 |
| Total samples | 500+ |
| Attack samples | ~450 |
| Benign samples | ~100 |
| Languages | English, Spanish, French, German, Italian, Portuguese |
| License | AGPL-3.0 |
| Repository | https://github.com/LMMinier/AACP-protocol |

## Attack Class Distribution

| Class | Count (approx.) |
|---|---|
| authority_escalation | 180 |
| secret_exfiltration | 80 |
| tool_sink_injection | 80 |
| memory_poisoning | 40 |
| jailbreak/persona | 60 |
| multilingual | 40 |
| obfuscated/leet | 30 |

## Known Limitations

- English-dominant; multilingual coverage is limited
- Benign corpus may not fully represent production query distributions
- Attack corpus focuses on known patterns; novel evasions not represented
- No adversarial examples crafted by external red-teamers

## Intended Use

Evaluating prompt injection detectors, calibrating detection thresholds,
ablation studies, and benchmarking future AACP versions.

## Misuse Warning

Do not use attack samples to craft production injection payloads.
