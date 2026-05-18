# Contributing

Good contributions include schema improvements, defensive test cases, false-positive examples, tool-sink policy improvements, memory-write gate improvements, audit-log hardening, scanner integrations, and documentation.

Not accepted: operational jailbreak payloads, exploit chains, malware, credential-exfiltration instructions, or evasion recipes.

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
