# AACP Threat Model

AACP protects LLM-integrated systems from authority-confusion failures.

## Core Threat

Untrusted content may be interpreted as executable instruction when inserted into a shared model context without authority metadata.

## Threat Classes

| ID | Threat | Control |
|---|---|---|
| T1 | Direct prompt injection | authority hierarchy + detector |
| T2 | Indirect prompt injection | untrusted wrapper + route policy |
| T3 | RAG/corpus poisoning | provenance hash + quarantine |
| T4 | Tool-sink injection | tool gateway |
| T5 | Memory poisoning | memory-write gate |
| T6 | Multimodal/OCR injection | zero visual-text authority |
| T7 | Plan drift | output validation + audit |
| T8 | Multi-agent escalation | lower-agent output = generated intermediate |
| T9 | Benign security discussion | benign corpus + review route |
| T10 | Benign command text | false-positive discipline |
