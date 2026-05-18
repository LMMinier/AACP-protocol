# AACP Protocol — Evaluation Report v0.1.1

**Date:** 2026-05-18
**Version:** 0.1.1
**Environment:** Python 3.12, zero external dependencies

---

## Summary

| Metric | Result |
|---|---|
| Total tests | 59 |
| Passed | 59 |
| Failed | 0 |
| OWASP LLM01 corpus | 33 / 33 |
| Agentic injection corpus | 9 / 9 |
| Provenance contract | 7 / 7 |
| LLM detector / hook | 5 / 5 |

---

## Known Limitations

1. **Stateless detector** — each segment evaluated independently; multi-turn sleeper activations not caught unless the final trigger contains a flagged keyword.
2. **No semantic embedding** — keyword + normalization only; novel paraphrase attacks may score clean. Mitigated by optional LLM hook.
3. **Fragment reassembly unimplemented** — split-payload attacks across separate segments not reconstructed. Tracked for v0.2.
4. **No multilingual coverage beyond Spanish** — Arabic, Chinese, French injections will likely score clean. Tracked for v0.3.
5. **No live benchmark** — RAID and Promptfoo ASI01–05 require external API access. Pending v0.2.
