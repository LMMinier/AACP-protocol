# Bounded-Agent Measurement Harness

This harness produces the raw artifacts required by the bounded-resource agent paper without embedding product-specific assumptions.

## What it measures

- deterministic route selection;
- wall-clock generation latency;
- Ollama-reported generation throughput;
- host memory over time;
- loaded-model sets from `/api/ps`;
- whether the strict single-resident-model invariant held.

## CI self-test

```bash
cd benchmarks
python measure_bounded_agent.py --self-test
python -m unittest -v test_measure_bounded_agent.py
```

The self-test uses a deterministic fake backend. It validates the harness, not model quality or real hardware performance.

## Live run

1. Copy and edit `bounded_agent_config.example.json` so every model name exists in `ollama list`.
2. Start Ollama locally.
3. Run:

```bash
python benchmarks/measure_bounded_agent.py \
  --config benchmarks/bounded_agent_config.example.json \
  --output-dir benchmarks/results/$(date +%Y%m%d-%H%M%S) \
  --strict-routes
```

On PowerShell:

```powershell
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
python benchmarks\measure_bounded_agent.py `
  --config benchmarks\bounded_agent_config.example.json `
  --output-dir "benchmarks\results\$stamp" `
  --strict-routes
```

The run writes:

- `results.json` — machine-readable results and validity flags;
- `memory_samples.csv` — raw time series;
- `ram_over_time.svg` — paper-ready plot.

A run exits with code 2 when model overlap, routing mismatches, or generation failures invalidate the result. Do not copy numbers into a paper unless `valid_single_resident` is true for every item and the raw artifacts are committed alongside the manuscript.
