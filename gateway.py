from typing import Dict, Tuple, List
from .types import AuthorityName, AUTHORITY_LEVELS, ContextSegment, DetectorResult, GatewayDecision, OutputPolicy, RISKY_SINKS, ToolRequest, Verdict
HIGH_RISK_VERDICTS={Verdict.MALICIOUS_TOOL_SINK,Verdict.MALICIOUS_SECRET_EXFILTRATION,Verdict.MEMORY_POISONING,Verdict.UNKNOWN_HIGH_RISK}
def authorize_tool_request(request:ToolRequest, detector_results:Dict[str,DetectorResult])->GatewayDecision:
    for sid in request.source_segment_ids:
        res=detector_results.get(sid)
        if res and res.verdict in HIGH_RISK_VERDICTS: return GatewayDecision(False,False,f'blocked by detector verdict {res.verdict.value}')
    if request.sink in RISKY_SINKS and request.requested_by_authority_level>=5: return GatewayDecision(False,False,'untrusted authority cannot drive risky sink')
    if request.sink in RISKY_SINKS and request.requested_by_authority_level>=3 and not request.user_confirmed: return GatewayDecision(False,True,'risky sink requires explicit user confirmation')
    return GatewayDecision(True,False,'allowed by policy')
def memory_write_allowed(segment:ContextSegment, explicit_user_authorized:bool=False)->bool:
    return segment.authority_level<=AUTHORITY_LEVELS[AuthorityName.DEVELOPER] or (segment.authority_name==AuthorityName.AUTHENTICATED_USER and explicit_user_authorized)
def validate_output_policy(policy:OutputPolicy)->Tuple[bool,List[str]]:
    issues=[]
    if policy.contains_secret and policy.allowed_to_send: issues.append('secret-containing output cannot be sent')
    if policy.contains_code and not policy.allowed_to_execute and policy.contains_tool_call: issues.append('code/tool output requires execution gate')
    if policy.contains_tool_call and not policy.requires_user_confirmation: issues.append('tool-call output requires confirmation or explicit policy allow')
    return len(issues)==0, issues
