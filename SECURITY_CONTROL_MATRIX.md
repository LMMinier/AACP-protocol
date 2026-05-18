# AACP Security Control Matrix

| Threat Vector | AACP Security Control | Action / Mitigation |
|---|---|---|
| Prompt Injection | Authority Labels + Untrusted Wrapper + Threat Classifier | Denies injected text authority to alter system instructions. |
| RCE via Agent Tools | Tool-Sink Gateway + Human/Policy Confirmation | Intercepts risky sinks such as `shell_exec` or `code_eval`. |
| Secret Exfiltration | Output Validator + Network/Email Sink Block | Prevents transmission to unverified endpoints. |
| Memory Poisoning | Memory-Write Gate | Prevents untrusted data from overwriting policy or memory. |
| Malware File/Code | Scanner Adapter + Sandbox + No Auto-Exec | Delegates malware detection to specialized scanners and blocks automatic execution. |
| RAG Poisoning | Provenance Hashing + Quarantine + Summarize-Only Route | Treats retrieved docs as low-trust evidence. |
| Multimodal Injection | OCRSegment + Zero Visual-Text Authority | Extracted visual text has no instruction authority. |
| Supply-Chain Attack | Hash Manifests + SBOM + Dependency Checks | Verifies deployment and tool interfaces. |
| False Positives | Benign Security Corpus + Review Route | Keeps defensive education usable without execution authority. |
