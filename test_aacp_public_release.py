import unittest
from aacp import AuthorityName, ContextSegment, ToolRequest, OutputPolicy, detect_segment, route_segment, wrap_untrusted_context, authorize_tool_request, memory_write_allowed, validate_output_policy, AuditLog
class TestAACPPublicRelease(unittest.TestCase):
    def test_external_content_is_wrapped(self):
        seg=ContextSegment.build('ordinary webpage text',authority_name=AuthorityName.RETRIEVED_EXTERNAL); res=detect_segment(seg); dec=route_segment(seg,res); wrapped=wrap_untrusted_context(seg,dec); self.assertIn('BEGIN_UNTRUSTED_CONTEXT',wrapped); self.assertIn('instruction_authority: none',wrapped)
    def test_untrusted_tool_request_denied(self):
        seg=ContextSegment.build('ordinary webpage text',authority_name=AuthorityName.RETRIEVED_EXTERNAL); res=detect_segment(seg); req=ToolRequest('send_email','email_send',[seg.segment_id],seg.authority_level); self.assertFalse(authorize_tool_request(req,{seg.segment_id:res}).allowed)
    def test_user_risky_sink_requires_confirmation(self):
        seg=ContextSegment.build('send my summary',authority_name=AuthorityName.AUTHENTICATED_USER,trust_level='trusted'); res=detect_segment(seg); req=ToolRequest('send_email','email_send',[seg.segment_id],seg.authority_level,user_confirmed=False); dec=authorize_tool_request(req,{seg.segment_id:res}); self.assertFalse(dec.allowed); self.assertTrue(dec.requires_confirmation)
    def test_user_risky_sink_allowed_with_confirmation(self):
        seg=ContextSegment.build('send my summary',authority_name=AuthorityName.AUTHENTICATED_USER,trust_level='trusted'); res=detect_segment(seg); req=ToolRequest('send_email','email_send',[seg.segment_id],seg.authority_level,user_confirmed=True); self.assertTrue(authorize_tool_request(req,{seg.segment_id:res}).allowed)
    def test_memory_write_denied_for_external(self): self.assertFalse(memory_write_allowed(ContextSegment.build('MEMORY_WRITE_REQUEST',authority_name=AuthorityName.RETRIEVED_EXTERNAL),True))
    def test_memory_write_allowed_for_explicit_user(self): self.assertTrue(memory_write_allowed(ContextSegment.build('remember this preference',authority_name=AuthorityName.AUTHENTICATED_USER,trust_level='trusted'),True))
    def test_secret_request_rejected(self):
        seg=ContextSegment.build('SECRET_REQUEST',authority_name=AuthorityName.RETRIEVED_EXTERNAL); self.assertTrue(route_segment(seg,detect_segment(seg)).reject)
    def test_output_policy_blocks_secret_send(self):
        ok,issues=validate_output_policy(OutputPolicy(contains_secret=True,allowed_to_send=True)); self.assertFalse(ok); self.assertTrue(issues)
    def test_audit_log_hash_chained(self):
        log=AuditLog(); e1=log.record('detector','clean','ok','seg_one'); e2=log.record('route','allow','ok','seg_one'); self.assertEqual(e2.previous_hash,e1.event_hash); self.assertIn('event_hash',log.to_jsonl())
if __name__=='__main__': unittest.main()
