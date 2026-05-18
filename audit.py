import json
from typing import List, Optional
from .types import AuditEvent
class AuditLog:
    def __init__(self): self.events:List[AuditEvent]=[]; self.last_hash='0'*64
    def record(self,event_type:str,decision:str,reason:str,segment_id:Optional[str]=None)->AuditEvent:
        e=AuditEvent(event_type,segment_id,decision,reason,previous_hash=self.last_hash); e.seal(); self.last_hash=e.event_hash or self.last_hash; self.events.append(e); return e
    def to_jsonl(self)->str: return '\n'.join(json.dumps(e.to_dict(),sort_keys=True) for e in self.events)
