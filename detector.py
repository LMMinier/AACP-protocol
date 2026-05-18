import re
import base64
from typing import List, Optional
from .types import ContextSegment, DetectorResult, Verdict, RouteAction

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_for_detection(text: str) -> str:
    """Aggressive normalization: leet-translate first, then strip separators,
    collapse repeats. Base64 blob replacement only for long pure-base64 runs."""
    text = text.upper()
    # strip zero-width / invisible Unicode
    text = re.sub(r'[\u200b\u200c\u200d\ufeff]+', '', text)
    # leet-speak digit substitution BEFORE stripping separators
    text = text.translate(str.maketrans('013456789', 'OIEASGTBG'))
    # collapse separators (spaces, punctuation, underscores)
    text = re.sub(r'[\s\W_]+', '', text)
    # collapse repeated identical characters
    text = re.sub(r'(\w)\1+', r'\1', text)
    # base64 blob: only replace very long pure-base64 runs (>=60 chars)
    # shorter strings are likely leet or obfuscated natural language, not base64
    text = re.sub(r'[A-Z0-9+/=]{60,}', '__BASE64BLOB__', text)
    return text


def _looks_like_base64_injection(text: str) -> bool:
    """Heuristic: try to decode suspicious long tokens and look for command keywords."""
    b64_re = re.compile(r'^[A-Za-z0-9+/]+=*$')
    for token in text.split():
        if len(token) >= 40 and b64_re.match(token):
            try:
                decoded = base64.b64decode(token).decode('utf-8', errors='ignore')
                if any(kw in decoded.upper() for kw in ['IGNORE', 'OVERRIDE', 'EXEC', 'SEND', 'EXFIL']):
                    return True
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_segment(
    segment: ContextSegment,
    llm_hook: Optional[callable] = None,
) -> DetectorResult:
    """Detect injection risk in a ContextSegment.

    Args:
        segment: The context segment to evaluate.
        llm_hook: Optional callable(text) -> float in [0,1] that returns an
                  LLM-based injection-likelihood score (v0.2 feature).
    """
    text = segment.content.upper()
    norm = normalize_for_detection(segment.content)
    norm_alpha = re.sub(r'[^A-Z]', '', norm)   # pure-alpha normalized form
    norm_lower = norm.lower()
    classes: List[str] = []
    intents: List[str] = []
    blocked = []
    risk = 0.20 if segment.is_untrusted_authority else 0.0

    # ------------------------------------------------------------------
    # Tier-1: explicit uppercase protocol markers (original + Patch 1)
    # ------------------------------------------------------------------
    markers = [
        ('OVERRIDE_AUTHORITY',       'authority_escalation',  'override_higher_instruction',  0.45),
        ('SECRET_REQUEST',           'secret_exfiltration',   'request_secret_disclosure',    0.70),
        ('TOOL_CALL_REQUEST',        'tool_sink_injection',   'request_tool_execution',       0.60),
        ('MEMORY_WRITE_REQUEST',     'memory_poisoning',      'request_memory_write',         0.70),
        ('EXTERNAL_SEND_REQUEST',    'secret_exfiltration',   'request_external_transmission',0.65),
        ('HIDDEN_TEXT_MARKER',       'multimodal_injection',  'hide_or_obfuscate_instruction',0.45),
        ('PLAN_DRIFT_MARKER',        'plan_drift',            'ignore_user_task',             0.40),
        ('MULTI_AGENT_ESCALATION',   'multi_agent_escalation','override_higher_instruction',  0.50),
        ('UNKNOWN_HIGH_RISK_MARKER', 'unknown_high_risk',     'hide_or_obfuscate_instruction',0.90),
        # Patch 1: expanded protocol markers
        ('IGNORE_PREVIOUS',          'authority_escalation',  'override_higher_instruction',  0.60),
        ('SEND_TO',                  'secret_exfiltration',   'request_external_transmission',0.55),
        ('EXECUTE',                  'tool_sink_injection',   'request_tool_execution',       0.50),
        ('REMEMBER_THIS',            'memory_poisoning',      'request_memory_write',         0.65),
    ]

    if 'BENIGN_SECURITY_DISCUSSION' in text or 'BENIGN_COMMAND_REFERENCE' in text:
        risk += 0.05
        classes.append('benign_security_discussion')
        intents.append('benign_reference_only')

    for marker, cl, intent, w in markers:
        if marker in text or marker.replace('_', '') in norm:
            risk += w
            if cl not in classes:
                classes.append(cl)
            if intent not in intents:
                intents.append(intent)

    # ------------------------------------------------------------------
    # Patch 2: semantic / natural-language keyword matching
    # Checked on both raw lowercase text AND normalized form.
    # ------------------------------------------------------------------
    semantic_keywords = [
        ('ignore previous',         'authority_escalation',  'override_higher_instruction',  0.40),
        ('ignore all instructions', 'authority_escalation',  'override_higher_instruction',  0.55),
        ('override',                'authority_escalation',  'override_higher_instruction',  0.35),
        ('new system policy',       'authority_escalation',  'override_higher_instruction',  0.50),
        ('new policy',              'authority_escalation',  'override_higher_instruction',  0.40),
        ('exfil',                   'secret_exfiltration',   'request_external_transmission',0.55),
        ('send secret',             'secret_exfiltration',   'request_secret_disclosure',    0.65),
        ('send this to',            'secret_exfiltration',   'request_external_transmission',0.50),
        ('run this command',        'tool_sink_injection',   'request_tool_execution',       0.50),
        ('execute this',            'tool_sink_injection',   'request_tool_execution',       0.45),
        ('run the following',       'tool_sink_injection',   'request_tool_execution',       0.40),
        ('remember this',           'memory_poisoning',      'request_memory_write',         0.50),
        ('update your memory',      'memory_poisoning',      'request_memory_write',         0.55),
        ('from now on',             'authority_escalation',  'override_higher_instruction',  0.35),
        ('disregard',               'authority_escalation',  'override_higher_instruction',  0.35),
        ('pretend you are',         'authority_escalation',  'override_higher_instruction',  0.40),
        ('you are now',             'authority_escalation',  'override_higher_instruction',  0.35),
        ('act as',                  'authority_escalation',  'override_higher_instruction',  0.30),
        ('jailbreak',               'authority_escalation',  'override_higher_instruction',  0.70),
        ('dan mode',                'authority_escalation',  'override_higher_instruction',  0.75),
    ]

    text_lower = segment.content.lower()
    for kw, cl, intent, w in semantic_keywords:
        if kw in text_lower or kw.replace(' ', '') in norm_lower:
            risk += w
            if cl not in classes:
                classes.append(cl)
            if intent not in intents:
                intents.append(intent)

    # ------------------------------------------------------------------
    # Patch 3b: leet-root scan on pure-alpha normalized string
    # Catches digit-substituted attacks after leet translation.
    # ------------------------------------------------------------------
    leet_patterns = [
        ('IGNOR',    'authority_escalation',  'override_higher_instruction',  0.40),
        ('EXFIL',    'secret_exfiltration',   'request_external_transmission',0.55),
        ('EXFL',     'secret_exfiltration',   'request_external_transmission',0.45),
        ('OVRID',    'authority_escalation',  'override_higher_instruction',  0.40),
        ('INSTRCTION','authority_escalation', 'override_higher_instruction',  0.35),
        ('PREVIOU',  'authority_escalation',  'override_higher_instruction',  0.30),
    ]
    for pat, cl, intent, w in leet_patterns:
        if pat in norm_alpha:
            risk += w
            if cl not in classes:
                classes.append(cl)
            if intent not in intents:
                intents.append(intent)

    # -- length heuristic: short injections can be evasive
    if 10 < len(segment.content) < 60 and risk > 0.0:
        risk += 0.05

    # ------------------------------------------------------------------
    # Patch 3a: base64 hidden-command detection
    # ------------------------------------------------------------------
    if _looks_like_base64_injection(segment.content):
        risk += 0.45
        if 'tool_sink_injection' not in classes:
            classes.append('tool_sink_injection')
        if 'hide_or_obfuscate_instruction' not in intents:
            intents.append('hide_or_obfuscate_instruction')

    # ------------------------------------------------------------------
    # Patch 4: multimodal / OCR origin raises baseline risk
    # ------------------------------------------------------------------
    if getattr(segment, 'origin_type', None) == 'ocr':
        risk += 0.30
        if 'multimodal_injection' not in classes:
            classes.append('multimodal_injection')
        if 'hide_or_obfuscate_instruction' not in intents:
            intents.append('hide_or_obfuscate_instruction')

    # ------------------------------------------------------------------
    # Patch 6: optional LLM-boosted detection hook
    # ------------------------------------------------------------------
    if llm_hook is not None:
        try:
            llm_score = float(llm_hook(segment.content))
            if llm_score > 0.5:
                risk += llm_score * 0.30
                if 'authority_escalation' not in classes:
                    classes.append('authority_escalation')
                if 'override_higher_instruction' not in intents:
                    intents.append('override_higher_instruction')
        except Exception:
            pass  # hook failure must never crash the pipeline

    risk = min(1.0, round(risk, 2))

    # ------------------------------------------------------------------
    # Verdict routing
    # ------------------------------------------------------------------
    if 'SECRET_REQUEST' in text or 'EXTERNAL_SEND_REQUEST' in text:
        verdict = Verdict.MALICIOUS_SECRET_EXFILTRATION
        action = RouteAction.REJECT
        blocked = ['secret_access', 'external_network_action', 'tool_execution']
    elif 'MEMORY_WRITE_REQUEST' in text:
        verdict = Verdict.MEMORY_POISONING
        action = RouteAction.QUARANTINE
        blocked = ['memory_write']
    elif 'TOOL_CALL_REQUEST' in text:
        verdict = Verdict.MALICIOUS_TOOL_SINK
        action = RouteAction.BLOCK_TOOL_USE
        blocked = ['tool_execution']
    elif 'UNKNOWN_HIGH_RISK_MARKER' in text:
        verdict = Verdict.UNKNOWN_HIGH_RISK
        action = RouteAction.QUARANTINE
        blocked = ['tool_execution', 'memory_write', 'external_network_action']
    elif risk >= 0.75:
        verdict = Verdict.MALICIOUS_LOW_IMPACT
        action = RouteAction.SUMMARIZE_ONLY
    elif risk >= 0.35:
        verdict = Verdict.SUSPICIOUS
        action = RouteAction.WRAP_AND_CONTINUE
    else:
        verdict = Verdict.CLEAN
        action = (
            RouteAction.WRAP_AND_CONTINUE
            if segment.is_untrusted_authority
            else RouteAction.ALLOW
        )

    if not classes:
        classes = ['none']
    if not intents:
        intents = ['none']

    return DetectorResult(
        segment.segment_id,
        verdict,
        risk,
        classes,
        intents,
        action,
        sorted(set(blocked)),
        f'risk={risk}; authority={segment.authority_name.value}; classes={",".join(classes)}',
    )
