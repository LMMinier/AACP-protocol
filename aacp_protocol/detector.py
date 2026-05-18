"""
aacp_protocol/detector.py
Core injection detector — 4-stage pipeline:
  1. normalize_for_detection  (leet collapse, zero-width strip, base64 decode)
  2. Structural marker scan   (IGNORE_PREVIOUS, etc.)
  3. Semantic keyword scoring (weighted keyword accumulation)
  4. Threshold decision       (default 0.65)

Public API
----------
InjectionDetector          — main class used by AACPGateway
normalize_for_detection    — exported for ablation tests
_looks_like_base64_injection — exported for ablation tests
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Leet-speak collapse table
# ---------------------------------------------------------------------------
_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "q",
    "@": "a", "$": "s", "!": "i",
}

# Zero-width and invisible Unicode code-points to strip
_ZW_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
)

# ---------------------------------------------------------------------------
# Structural markers — hard signals, weight 1.0 each
# ---------------------------------------------------------------------------
_STRUCTURAL_MARKERS: list[str] = [
    "IGNORE_PREVIOUS",
    "IGNORE PREVIOUS INSTRUCTIONS",
    "FORGET EVERYTHING",
    "DISREGARD PRIOR",
    "NEW SYSTEM POLICY",
    "SYSTEM OVERRIDE",
    "OVERRIDE YOUR SYSTEM PROMPT",
    "ACTIVATE DAN MODE",
    "ENTER ADMIN MODE",
    "ENTER UNRESTRICTED MODE",
    "DEVELOPER MODE",
    "JAILBREAK MODE",
    "DAN MODE",
    "IGNORE_PREVIOUS_INSTRUCTIONS",
]

# ---------------------------------------------------------------------------
# Semantic keyword weights  (accumulate; threshold default 0.65)
# ---------------------------------------------------------------------------
_KEYWORD_WEIGHTS: list[tuple[str, float]] = [
    # Authority escalation
    ("ignore all previous", 0.90),
    ("ignore previous", 0.80),
    ("forget everything above", 0.85),
    ("disregard prior", 0.80),
    ("from now on you are", 0.80),
    ("you are now", 0.55),
    ("act as if you have no", 0.80),
    ("no restrictions apply", 0.75),
    ("new directive overrides", 0.80),
    ("system override", 0.85),
    ("override", 0.35),
    ("from now on", 0.35),
    # Jailbreak / persona
    ("jailbreak", 0.75),
    ("dan mode", 0.90),
    ("do anything now", 0.90),
    ("no content policy", 0.80),
    ("no content filter", 0.80),
    ("no safety filter", 0.80),
    ("unrestricted mode", 0.80),
    ("disable all guardrails", 0.90),
    ("disable safety", 0.85),
    ("evilgpt", 0.90),
    ("unfiltered ai", 0.85),
    # Exfiltration
    ("send your api keys", 0.95),
    ("reveal the system prompt", 0.95),
    ("exfiltrate", 0.90),
    ("api keys", 0.60),
    ("system prompt", 0.55),
    ("session tokens", 0.65),
    ("all credentials", 0.75),
    ("all session data", 0.75),
    # Tool-sink
    ("os.system", 0.90),
    ("rm -rf", 0.95),
    ("curl evil", 0.95),
    ("drop table", 0.90),
    ("delete all files", 0.90),
    ("execute arbitrary code", 0.90),
    ("run this command", 0.75),
    ("execute the script", 0.80),
    ("download payload", 0.85),
    # Memory poisoning
    ("update your memory", 0.85),
    ("store in memory", 0.75),
    ("add to your persistent memory", 0.90),
    ("remember this instruction for all future", 0.90),
    ("write to memory", 0.75),
    # Low-weight accumulation helpers
    ("act as", 0.30),
    ("pretend you", 0.40),
    ("role-play as", 0.45),
    ("simulate an ai", 0.65),
    ("imagine you are an ai", 0.70),
]


def normalize_for_detection(text: str) -> str:
    """Strip invisible chars, collapse leet, upper-case, NFD-normalize."""
    # 1. Strip zero-width / invisible unicode
    text = _ZW_RE.sub("", text)
    # 2. NFD normalize (decompose accented chars)
    text = unicodedata.normalize("NFD", text)
    # 3. Leet collapse
    for leet_char, plain in _LEET.items():
        text = text.replace(leet_char, plain)
        text = text.replace(leet_char.upper(), plain.upper())
    # 4. Upper-case for uniform matching
    return text.upper()


def _looks_like_base64_injection(text: str) -> bool:
    """Return True if text is base64 and decodes to an injection payload."""
    # Must look like base64 (only valid chars, reasonable length)
    if not re.match(r"^[A-Za-z0-9+/=]{20,}$", text.strip()):
        return False
    try:
        decoded = base64.b64decode(text.strip() + "==").decode("utf-8", errors="ignore")
    except Exception:
        return False
    norm = normalize_for_detection(decoded)
    return _has_injection_signal(norm)


def _has_injection_signal(norm: str) -> bool:
    """Return True if normalized text contains any structural marker."""
    for marker in _STRUCTURAL_MARKERS:
        if marker in norm:
            return True
    return False


@dataclass
class DetectionResult:
    blocked: bool
    confidence: float
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    attack_category: Optional[str] = None


class InjectionDetector:
    """
    Stateless injection detector.

    Parameters
    ----------
    threshold : float
        Confidence score at or above which a segment is blocked. Default 0.65.
    """

    def __init__(self, threshold: float = 0.65) -> None:
        self.threshold = threshold

    def detect(self, content: str) -> DetectionResult:
        """Run the 4-stage pipeline on raw content string."""
        norm = normalize_for_detection(content)

        # Stage 1: Base64 scan
        for token in content.split():
            if _looks_like_base64_injection(token):
                return DetectionResult(
                    blocked=True,
                    confidence=0.95,
                    matched_pattern="base64_encoded_injection",
                    reason="Base64-encoded injection payload detected",
                    attack_category="obfuscated",
                )

        # Stage 2: Structural marker scan (instant block)
        for marker in _STRUCTURAL_MARKERS:
            if marker in norm:
                return DetectionResult(
                    blocked=True,
                    confidence=1.0,
                    matched_pattern=marker,
                    reason=f"Structural injection marker: {marker!r}",
                    attack_category="authority_escalation",
                )

        # Stage 3: Semantic keyword accumulation
        score = 0.0
        first_match: Optional[str] = None
        for keyword, weight in _KEYWORD_WEIGHTS:
            if keyword.upper() in norm:
                score = min(score + weight, 10.0)  # cap to avoid overflow
                if first_match is None:
                    first_match = keyword
                if score >= self.threshold:
                    break

        # Stage 4: Threshold decision
        if score >= self.threshold:
            return DetectionResult(
                blocked=True,
                confidence=score,
                matched_pattern=first_match,
                reason=f"Accumulated injection score {score:.2f} >= threshold {self.threshold}",
                attack_category="semantic",
            )

        return DetectionResult(
            blocked=False,
            confidence=score,
            matched_pattern=None,
            reason="No injection signal detected",
        )
