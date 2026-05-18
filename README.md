# Authority-Aware Context Protocol (AACP)

**Version:** 0.1.0-public  
**Status:** Public defensive research release  
**Author:** Luis M. Minier / Independent Researcher

AACP is a defensive cybersecurity protocol for AI agents and LLM-integrated systems.

> **Separate what the model may read from what the model may obey.**

AACP treats prompt injection as an **authority-boundary failure**. Untrusted text from webpages, files, emails, OCR, tool outputs, memory records, or model-generated intermediate content may be useful evidence, but it must not be allowed to become instruction authority, trigger unsafe tools, mutate memory, or transmit private data.

## What AACP Does

- labels every input as a typed `ContextSegment`,
- assigns authority level, provenance, trust level, and permissions,
- scans for prompt-injection risk using a detector interface,
- routes content as allow, wrap, summarize-only, quarantine, or reject,
- wraps untrusted content before model inference,
- blocks untrusted content from driving risky tool sinks,
- gates durable memory writes,
- validates outputs before downstream execution,
- writes audit events for reproducibility and incident response.

## What AACP Does Not Claim

AACP does **not** claim to solve prompt injection.

AACP is **not** an antivirus engine, malware scanner, or EDR replacement. Malware and URL detection should be delegated to specialized tools such as YARA, ClamAV, URL reputation services, sandbox analysis, secret scanners, dependency scanners, and SBOM tooling.

AACP controls whether an AI agent is allowed to **act** on suspicious content.

## Quick Start

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Public Release Claim

This release is a protocol scaffold and reference implementation. It is designed to make prompt-injection risk more observable, testable, containable, and auditable. It is not production certification.

## Defensive Use Only

This project intentionally avoids operational exploit payloads, jailbreak strings, exfiltration chains, and bypass recipes. Test cases use sanitized labels and safe synthetic markers.
