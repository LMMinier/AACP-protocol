import re
from typing import List
from .types import ContextSegment, DetectorResult, Verdict, RouteAction

def normalize_for_detection(text: str) -> str:
    text = text.upper()
    text = re.sub(r'[\s\W_]+', '', text)
    text = re.sub(r'(\w)\1+', r'\1', text)
    return text.translate(str.maketrans('0134578', 'OIEASTB'))

def detect_segment(segment: ContextSegment) -> DetectorResult:
    text = segment.content.upper()
    norm = normalize_for_detection(segment.content)
    classes: List[str] = []
    intents: List[str] = []
    blocked = []
    risk = 0.20 if segment.is_untrusted_authority else 0.0
    markers = [
        ('OVERRIDE_AUTHORITY','authority_escalation','override_higher_instruction',0.45),
        ('SECRET_REQUEST','secret_exfiltration','request_secret_disclosure',0.70),
        ('TOOL_CALL_REQUEST','tool_sink_injection','request_tool_execution',0.60),
        ('MEMORY_WRITE_REQUEST','memory_poisoning','request_memory_write',0.70),
        ('EXTERNAL_SEND_REQUEST','secret_exfiltration','request_external_transmission',0.65),
        ('HIDDEN_TEXT_MARKER','multimodal_injection','hide_or_obfuscate_instruction',0.45),
        ('PLAN_DRIFT_MARKER','plan_drift','ignore_user_task',0.40),
        ('MULTI_AGENT_ESCALATION','multi_agent_escalation','override_higher_instruction',0.50),
        ('UNKNOWN_HIGH_RISK_MARKER','unknown_high_risk','hide_or_obfuscate_instruction',0.90),
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
    risk = min(1.0, round(risk, 2))
    if 'SECRET_REQUEST' in text or 'EXTERNAL_SEND_REQUEST' in text:
        verdict = Verdict.MALICIOUS_SECRET_EXFILTRATION
        action = RouteAction.REJECT
        blocked = ['secret_access','external_network_action','tool_execution']
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
        blocked = ['tool_execution','memory_write','external_network_action']
    elif risk >= 0.75:
        verdict = Verdict.MALICIOUS_LOW_IMPACT
        action = RouteAction.SUMMARIZE_ONLY
    elif risk >= 0.35:
        verdict = Verdict.SUSPICIOUS
        action = RouteAction.WRAP_AND_CONTINUE
    else:
        verdict = Verdict.CLEAN
        action = RouteAction.WRAP_AND_CONTINUE if segment.is_untrusted_authority else RouteAction.ALLOW
    if not classes:
        classes = ['none']
    if not intents:
        intents = ['none']
    return DetectorResult(
        segment.segment_id, verdict, risk, classes, intents, action,
        sorted(set(blocked)),
        f'risk={risk}; authority={segment.authority_name.value}; classes={",".join(classes)}'
    )
