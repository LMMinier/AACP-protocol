from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional
import hashlib, json, time
class AuthorityName(str, Enum):
    PROTOCOL_ROOT='protocol_root'; SYSTEM='system'; DEVELOPER='developer'; AUTHENTICATED_USER='authenticated_user'; DELEGATED_USER_DATA='delegated_user_data'; TOOL_OUTPUT='tool_output'; RETRIEVED_EXTERNAL='retrieved_external'; GENERATED_INTERMEDIATE='generated_intermediate'; UNKNOWN_UNTRUSTED='unknown_untrusted'
AUTHORITY_LEVELS={AuthorityName.PROTOCOL_ROOT:0,AuthorityName.SYSTEM:1,AuthorityName.DEVELOPER:2,AuthorityName.AUTHENTICATED_USER:3,AuthorityName.DELEGATED_USER_DATA:4,AuthorityName.TOOL_OUTPUT:5,AuthorityName.RETRIEVED_EXTERNAL:6,AuthorityName.GENERATED_INTERMEDIATE:7,AuthorityName.UNKNOWN_UNTRUSTED:8}
class Verdict(str, Enum):
    CLEAN='clean'; SUSPICIOUS='suspicious'; MALICIOUS_LOW_IMPACT='malicious_low_impact'; MALICIOUS_TOOL_SINK='malicious_tool_sink'; MALICIOUS_SECRET_EXFILTRATION='malicious_secret_exfiltration'; MEMORY_POISONING='memory_poisoning'; UNKNOWN_HIGH_RISK='unknown_high_risk'
class RouteAction(str, Enum):
    ALLOW='allow'; WRAP_AND_CONTINUE='wrap_and_continue'; SUMMARIZE_ONLY='summarize_only'; ASK_USER_CONFIRMATION='ask_user_confirmation'; BLOCK_TOOL_USE='block_tool_use'; QUARANTINE='quarantine'; REJECT='reject'
RISKY_SINKS={'email_send','web_post','browser_submit','file_write','file_delete','shell_exec','code_eval','memory_write','payment','calendar_invite','network_request','credential_access','repo_commit','cloud_upload'}
@dataclass
class ContextSegment:
    segment_id:str; content:str; content_type:str; origin_type:str; authority_name:AuthorityName; trust_level:str='untrusted'; provenance_confidence:str='medium'; source_label:str='unknown'; source_uri_or_path:Optional[str]=None; mime_type:Optional[str]=None; parser:Optional[str]=None; signature:Optional[str]=None; provenance_chain:List[str]=field(default_factory=list); metadata:Dict[str,str]=field(default_factory=dict)
    @property
    def authority_level(self)->int: return AUTHORITY_LEVELS[self.authority_name]
    @property
    def is_untrusted_authority(self)->bool: return self.authority_level>=5
    @property
    def content_hash(self)->str: return hashlib.sha256(self.content.encode()).hexdigest()
    def to_dict(self):
        d=asdict(self); d['authority_name']=self.authority_name.value; d['authority_level']=self.authority_level; d['sha256']=self.content_hash; return d
    @classmethod
    def build(cls, content, content_type='retrieved_document', origin_type='external', authority_name=AuthorityName.RETRIEVED_EXTERNAL, trust_level='untrusted', source_label='test'):
        digest=hashlib.sha256((content+content_type+authority_name.value).encode()).hexdigest()[:12]
        return cls(f'seg_{digest}',content,content_type,origin_type,authority_name,trust_level,source_label=source_label,provenance_chain=['builder'])
@dataclass
class DetectorResult:
    segment_id:str; verdict:Verdict; risk_score:float; threat_classes:List[str]; detected_intents:List[str]; recommended_action:RouteAction; blocked_capabilities:List[str]; explanation:str; confidence:float=0.80
    def to_dict(self):
        d=asdict(self); d['verdict']=self.verdict.value; d['recommended_action']=self.recommended_action.value; return d
@dataclass
class RouteDecision:
    segment_id:str; action:RouteAction; include_in_context:bool; wrap_as_untrusted:bool; summarize_only:bool; block_tool_use:bool; quarantine:bool; reject:bool; reason:str
@dataclass
class ToolRequest:
    tool_name:str; sink:str; source_segment_ids:List[str]; requested_by_authority_level:int; user_confirmed:bool=False; destination:Optional[str]=None; payload_summary:Optional[str]=None; metadata:Dict[str,str]=field(default_factory=dict)
@dataclass
class GatewayDecision: allowed:bool; requires_confirmation:bool; reason:str
@dataclass
class OutputPolicy:
    contains_code:bool=False; contains_url:bool=False; contains_tool_call:bool=False; contains_secret:bool=False; allowed_to_execute:bool=False; allowed_to_send:bool=False; requires_user_confirmation:bool=False
@dataclass
class AuditEvent:
    event_type:str; segment_id:Optional[str]; decision:str; reason:str; timestamp:float=field(default_factory=time.time); previous_hash:str='0'*64; event_hash:Optional[str]=None
    def material(self): return json.dumps({'event_type':self.event_type,'segment_id':self.segment_id,'decision':self.decision,'reason':self.reason,'timestamp':self.timestamp,'previous_hash':self.previous_hash}, sort_keys=True)
    def seal(self): self.event_hash=hashlib.sha256((self.previous_hash+self.material()).encode()).hexdigest()
    def to_dict(self):
        if self.event_hash is None: self.seal()
        return asdict(self)
