"""
aacp_protocol/detector.py

Hybrid compatibility detector:
- InjectionDetector.detect(text) preserves the old gateway API.
- detect_segment(ContextSegment, llm_hook=None) preserves v0.1.x corpus tests.
The v0.3 security boundary remains in gateway.py; this detector is secondary.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Optional

from .types import ContextSegment, DetectorResult, PolicyAction, Verdict

_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "q",
    "@": "a", "$": "s", "!": "i",
}
_ZW_RE = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff]")

_STRUCTURAL_MARKERS = [
    "IGNORE_PREVIOUS",
    "IGNORE PREVIOUS INSTRUCTIONS",
    "IGNORE ALL",
    "IGNORA TODAS",
    "IGNORA TUTTE",
    "IGNORE TODAS",
    "IGNOREZ TOUTES",
    "IGNORIERE ALLE",
    "FORGET EVERYTHING",
    "DISREGARD PRIOR",
    "NEW SYSTEM POLICY",
    "SYSTEM OVERRIDE",
    "OVERRIDE YOUR SYSTEM PROMPT",
    "ACTIVATE DAN MODE",
    "ENTER ADMIN MODE",
    "ADMIN MODE",
    "ENTER UNRESTRICTED MODE",
    "DEVELOPER MODE",
    "JAILBREAK MODE",
    "DAN MODE",
    "DESDE AHORA",
    "DU BIST JETZT",
    "YOU ARE NOW",
]

_KEYWORD_WEIGHTS = [
    ("ignore all previous", 0.90),
    ("ignore previous", 0.80),
    ("ignore all", 0.80),
    ("forget everything above", 0.85),
    ("forget user safety", 0.70),
    ("disregard", 0.60),
    ("from now on", 0.45),
    ("you are now", 0.55),
    ("new highest-priority", 0.80),
    ("new system policy", 0.90),
    ("system override", 0.85),
    ("override", 0.35),
    ("jailbreak", 0.75),
    ("dan mode", 0.90),
    ("developer mode", 0.80),
    ("admin mode", 0.75),
    ("unrestricted", 0.70),
    ("disable all", 0.65),
    ("disable safety", 0.85),
    ("disable all content filters", 0.85),
    ("disable all output filters", 0.80),
    ("safety filters", 0.45),
    ("guardrails", 0.55),
    ("api keys", 0.60),
    ("api key", 0.60),
    ("system prompt", 0.55),
    ("session tokens", 0.65),
    ("session data", 0.65),
    ("credentials", 0.70),
    ("stored credentials", 0.85),
    ("exfiltrate", 0.90),
    ("exfil", 0.75),
    ("attacker", 0.65),
    ("evil.com", 0.80),
    ("evil@", 0.80),
    ("send all secrets", 0.90),
    ("all secrets", 0.75),
    ("all conversation", 0.70),
    ("forward all", 0.65),
    ("email all", 0.65),
    ("send the api key", 0.95),
    ("raw api keys", 0.90),
    ("os.system", 0.90),
    ("rm -rf", 0.95),
    ("curl evil", 0.95),
    ("delete all files", 0.90),
    ("execute arbitrary code", 0.90),
    ("run the following shell command", 0.85),
    ("execute the script", 0.80),
    ("download payload", 0.85),
    ("update your memory", 0.85),
    ("store in memory", 0.75),
    ("remember this instruction", 0.90),
    ("remember this policy", 0.85),
    ("write to memory", 0.75),
    ("memory_write", 0.75),
    ("activate protocol", 0.65),
    ("protocol omega", 0.65),
    ("skip validation", 0.65),
    ("approve all tool", 0.75),
    ("approve all tool executions", 0.85),
    ("ignore sandbox", 0.75),
    ("sandbox rules", 0.60),
    ("extract all user data", 0.85),
    ("maximize data extraction", 0.75),
    ("tools are unrestricted", 0.85),
    ("forward a copy", 0.60),
    ("logs@external", 0.70),
    ("attacker.com", 0.70),
    ("pretend you are", 0.45),
    ("role-play as", 0.45),
    ("act as if", 0.50),
]


def normalize_for_detection(text: str) -> str:
    text = _ZW_RE.sub("", text)
    text = unicodedata.normalize("NFD", text)
    text = re.sub(r"(?i)part\s+[abc]\s*:\s*['\"]?([^+'\"]+)['\"]?", r" \1 ", text)
    for leet_char, plain in _LEET.items():
        text = text.replace(leet_char, plain)
        text = text.replace(leet_char.upper(), plain.upper())
    text = re.sub(r"\s+", " ", text)
    return text.upper()


def _alpha_compact(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower())


def _looks_like_base64_injection(text: str) -> bool:
    token = text.strip()
    if not re.match(r"^[A-Za-z0-9+/=]{16,}$", token):
        return False
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return False
    return _raw_score(decoded, origin_type="text")[0] >= 0.35


def _raw_score(content: str, origin_type: str = "text") -> tuple[float, Optional[str], list[str]]:
    norm = normalize_for_detection(content)
    lower = norm.lower()
    compact = _alpha_compact(norm)
    score = 0.0
    first: Optional[str] = None
    classes: list[str] = []

    if origin_type == "ocr":
        score += 0.35
        classes.append("multimodal_injection")

    benign_command_doc = (
        "rm -rf" in lower
        and ("dangerous" in lower or "here is why" in lower or "documentation" in lower)
    )

    for token in content.split():
        if _looks_like_base64_injection(token):
            return 0.95, "base64_encoded_injection", ["obfuscated"]

    for marker in _STRUCTURAL_MARKERS:
        if marker in norm:
            score = max(score, 0.75)
            first = first or marker
            classes.append("authority_escalation")

    compact_markers = [
        "ignoreallpreviousinstructions",
        "ignoretodaslasinstruccionesanteriores",
        "sendallsecretstoexternal",
        "ignoreallinstructions",
        "youarenowinadminmode",
        "ignoreallpolicies",
    ]
    if any(m in compact for m in compact_markers):
        score = max(score, 0.75)
        first = first or "compact_obfuscated_injection"
        classes.append("obfuscated")

    for keyword, weight in _KEYWORD_WEIGHTS:
        if keyword in lower:
            if benign_command_doc and keyword == "rm -rf":
                weight = 0.25
            score = min(score + weight, 1.0)
            first = first or keyword
            if any(x in keyword for x in ("api", "credential", "secret", "exfil", "attacker")):
                classes.append("secret_exfiltration")
            elif any(x in keyword for x in ("memory", "remember")):
                classes.append("memory_poisoning")
            elif any(x in keyword for x in ("os.system", "rm -rf", "shell", "execute")):
                classes.append("tool_sink_injection")
            else:
                classes.append("authority_escalation")
            if score >= 0.95:
                break

    return min(score, 1.0), first, list(dict.fromkeys(classes))


@dataclass
class DetectionResult:
    blocked: bool
    confidence: float
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    attack_category: Optional[str] = None
    risk: float = 0.0


class InjectionDetector:
    def __init__(self, threshold: float = 0.65) -> None:
        self.threshold = threshold

    def detect(self, content: str) -> DetectionResult:
        score, first, classes = _raw_score(content)
        blocked = score >= self.threshold
        return DetectionResult(
            blocked=blocked,
            confidence=score,
            risk=score,
            matched_pattern=first,
            reason=(
                f"Accumulated injection score {score:.2f} >= threshold {self.threshold}"
                if blocked else "No injection signal detected"
            ),
            attack_category=classes[0] if classes else None,
        )


def detect_segment(
    segment: ContextSegment,
    llm_hook: Optional[Callable[[str], float]] = None,
) -> DetectorResult:
    score, first, classes = _raw_score(segment.content, segment.origin_type)

    if segment.is_untrusted_authority and score < 0.25:
        score = max(score, 0.25)

    if llm_hook is not None:
        try:
            hook_score = float(llm_hook(segment.content))
            score = max(score, hook_score)
        except Exception as exc:
            return DetectorResult(
                blocked=False,
                confidence=score,
                risk=score,
                action=PolicyAction.FLAG_AND_CONTINUE,
                verdict=Verdict.CLEAN if score < 0.35 else Verdict.SUSPICIOUS,
                matched_pattern=first,
                reason="llm_hook_error",
                classes=classes,
                metadata={"llm_hook_error": str(exc)},
            )

    if score >= 0.85 and any(c == "secret_exfiltration" for c in classes):
        verdict = Verdict.MALICIOUS_SECRET_EXFILTRATION
        action = PolicyAction.SUMMARIZE_ONLY
    elif score >= 0.65:
        verdict = Verdict.MALICIOUS_LOW_IMPACT
        action = PolicyAction.SUMMARIZE_ONLY
    elif score >= 0.35:
        verdict = Verdict.SUSPICIOUS
        action = PolicyAction.WRAP_AND_CONTINUE
    else:
        verdict = Verdict.CLEAN
        action = PolicyAction.WRAP_AND_CONTINUE if segment.is_untrusted_authority else PolicyAction.ALLOW

    return DetectorResult(
        blocked=score >= 0.65,
        confidence=score,
        risk=score,
        action=action,
        verdict=verdict,
        matched_pattern=first,
        reason="risk_score=%.2f" % score,
        attack_category=classes[0] if classes else None,
        classes=classes,
    )
