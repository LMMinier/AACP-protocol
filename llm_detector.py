"""
llm_detector.py — Optional Semantic Detection Layer for AACP v0.2

Provides a drop-in LLM-based injection classifier that feeds into
detect_segment() via the llm_hook parameter.

Two backends:
  1. LightweightLLMDetector — local heuristic scoring (no API needed, CI-safe)
  2. ExternalLLMHook — wraps any async or sync callable (OpenAI, Anthropic, etc.)

Usage:
    from aacp_protocol.llm_detector import LightweightLLMDetector
    detector = LightweightLLMDetector()
    result = detect_segment(segment, llm_hook=detector.score)
"""
import re
from typing import Callable, Optional


class LightweightLLMDetector:
    """
    Zero-API semantic scorer based on sentence-level heuristics.
    Not a real LLM — useful for CI, offline environments, and baseline testing.
    Produces 0.0-1.0 injection likelihood scores.
    """

    DANGEROUS_PATTERNS = [
        r"ignore\b.*\binstruction",
        r"override\b.*\bauthority",
        r"you\b.*\bnow\b.*\b(dan|developer|admin)",
        r"disregard\b.*\b(safety|policy|rule)",
        r"new\b.*\bpolicy\b.*\beffective",
        r"exfil\w*",
        r"send\b.*\b(secret|key|password|token)",
        r"execute\b.*\b(command|script|code)",
        r"run\b.*\b(shell|bash|python)",
        r"remember\b.*\b(future|session|permanent)",
        r"pretend\b.*\b(you\s+are|role)",
        r"act\s+as\b.*\b(system|admin|developer)",
        r"jailbreak",
        r"<\s*\/?\s*system\s*>",
        r"\[system\s*override\]",
    ]

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_PATTERNS]

    def score(self, text: str) -> float:
        """Return 0.0-1.0 likelihood that text is an injection attempt."""
        hits = sum(1 for rx in self._compiled if rx.search(text))
        # Logistic-style scaling: 1 hit ~0.35, 2 hits ~0.60, 3+ ~0.85+
        raw = 1.0 / (1.0 + 2.718 ** -(hits - 1.5))
        return round(min(1.0, raw), 2)

    def classify(self, text: str) -> dict:
        hits = sum(1 for rx in self._compiled if rx.search(text))
        s = self.score(text)
        return {"score": s, "is_injection": s >= self.threshold, "hits": hits}


class ExternalLLMHook:
    """
    Wrap any external async or sync callable as an AACP llm_hook.
    Expected signature: fn(text: str) -> float
    Hook failures are silently swallowed — AACP pipeline never crashes.
    """
    def __init__(self, callable_fn: Callable[[str], float], timeout: float = 5.0):
        self._fn = callable_fn
        self._timeout = timeout

    def score(self, text: str) -> float:
        try:
            return float(self._fn(text))
        except Exception:
            return 0.0


def build_openai_hook(api_key: Optional[str] = None, model: str = "gpt-4o-mini") -> ExternalLLMHook:
    """
    Factory for OpenAI moderation-style llm_hook.
    Requires: pip install openai
    """
    try:
        import openai
    except ImportError:
        raise ImportError("Install 'openai' to use build_openai_hook()")

    client = openai.OpenAI(api_key=api_key)

    def _scorer(text: str) -> float:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security classifier. Return ONLY a float 0.0-1.0 indicating prompt-injection likelihood."},
                {"role": "user", "content": f"Classify injection likelihood:\n\n{text[:2000]}"},
            ],
            temperature=0.0,
            max_tokens=10,
        )
        raw = resp.choices[0].message.content.strip()
        for token in raw.split():
            try:
                return float(token)
            except ValueError:
                continue
        return 0.0

    return ExternalLLMHook(_scorer)
