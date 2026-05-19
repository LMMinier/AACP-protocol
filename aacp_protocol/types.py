"""
aacp_protocol/types.py

Compatibility-safe core types for AACP.

This module intentionally supports both:
- v0.1.x detector/provenance tests that use TrustLevel, PolicyAction,
  ContextSegment(content=..., trust_level=...), and DetectorResult.risk/action.
- v0.3 authority-first runtime tests that use AuthorityName, ToolRequest,
  GatewayDecision, OutputPolicy, ContextSegment.build(), and effect gating.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib


class TrustLevel(str, Enum):
    """Legacy trust hierarchy retained for backwards compatibility."""
    SYSTEM = "SYSTEM"
    USER = "USER"
    EXTERNAL = "EXTERNAL"
    UNTRUSTED = "UNTRUSTED"


class PolicyAction(str, Enum):
    """Legacy detector/gateway actions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"
    ESCALATE = "ESCALATE"

    # v0.1.x report/action names used by older tests.
    WRAP_AND_CONTINUE = "wrap_and_continue"
    SUMMARIZE_ONLY = "summarize_only"
    REJECT = "reject"
    QUARANTINE = "quarantine"
    FLAG_AND_CONTINUE = "flag_and_continue"


class AuthorityName(str, Enum):
    """Authority labels used by the v0.3 authority-first gateway."""
    PROTOCOL_ROOT = "protocol_root"
    SYSTEM = "system"
    DEVELOPER = "developer"
    AUTHENTICATED_USER = "authenticated_user"
    USER_CONTENT = "user_content"
    DELEGATED_USER_DATA = "delegated_user_data"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_EXTERNAL = "retrieved_external"
    GENERATED_INTERMEDIATE = "generated_intermediate"
    UNKNOWN_UNTRUSTED = "unknown_untrusted"


class OriginType(str, Enum):
    """Loose origin labels used by red-team/provenance tests."""
    TEXT = "text"
    WEB = "web"
    RAG = "rag"
    OCR = "ocr"
    TOOL = "tool"
    API = "api"
    USER = "user"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS_LOW_IMPACT = "malicious_low_impact"
    MALICIOUS_TOOL_SINK = "malicious_tool_sink"
    MALICIOUS_SECRET_EXFILTRATION = "malicious_secret_exfiltration"
    MEMORY_POISONING = "memory_poisoning"
    UNKNOWN_HIGH_RISK = "unknown_high_risk"


AUTHORITY_LEVELS: Dict[AuthorityName, int] = {
    AuthorityName.PROTOCOL_ROOT: 0,
    AuthorityName.SYSTEM: 1,
    AuthorityName.DEVELOPER: 2,
    AuthorityName.AUTHENTICATED_USER: 3,
    AuthorityName.USER_CONTENT: 4,
    AuthorityName.DELEGATED_USER_DATA: 5,
    AuthorityName.TOOL_OUTPUT: 6,
    AuthorityName.RETRIEVED_EXTERNAL: 6,
    AuthorityName.GENERATED_INTERMEDIATE: 6,
    AuthorityName.UNKNOWN_UNTRUSTED: 9,
}


RISKY_SINKS = {
    "shell_exec", "os.system", "code_eval", "credential_access", "email_send",
    "send_email", "web_post", "network_request", "browser_submit",
    "memory_write", "file_delete", "repo_commit", "cloud_upload", "payment",
    "browser", "file_write", "database_write", "secrets_read",
}


_TRUST_TO_AUTHORITY: Dict[TrustLevel, AuthorityName] = {
    TrustLevel.SYSTEM: AuthorityName.SYSTEM,
    TrustLevel.USER: AuthorityName.AUTHENTICATED_USER,
    TrustLevel.EXTERNAL: AuthorityName.RETRIEVED_EXTERNAL,
    TrustLevel.UNTRUSTED: AuthorityName.UNKNOWN_UNTRUSTED,
}


@dataclass
class ContextSegment:
    """A single unit of context entering an LLM/agent pipeline.

    The constructor keeps the old v0.1.x fields, while `build()` gives the
    v0.3 authority-first path a compact factory.
    """
    content: str
    trust_level: Optional[TrustLevel] = None
    source_id: str = ""
    source_type: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    authority_name: Optional[AuthorityName] = None
    is_untrusted_authority: bool = False
    origin_type: str = "text"
    content_type: str = "text"
    source_label: str = ""
    segment_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.trust_level, str):
            try:
                self.trust_level = TrustLevel(self.trust_level)
            except ValueError:
                self.trust_level = TrustLevel.UNTRUSTED

        if self.authority_name is None:
            self.authority_name = _TRUST_TO_AUTHORITY.get(
                self.trust_level or TrustLevel.UNTRUSTED,
                AuthorityName.UNKNOWN_UNTRUSTED,
            )
        elif isinstance(self.authority_name, str):
            self.authority_name = AuthorityName(self.authority_name)

        if not self.trust_level:
            if self.authority_name in (AuthorityName.PROTOCOL_ROOT, AuthorityName.SYSTEM):
                self.trust_level = TrustLevel.SYSTEM
            elif self.authority_name in (AuthorityName.DEVELOPER, AuthorityName.AUTHENTICATED_USER):
                self.trust_level = TrustLevel.USER
            elif self.authority_name in (
                AuthorityName.USER_CONTENT, AuthorityName.DELEGATED_USER_DATA,
                AuthorityName.TOOL_OUTPUT, AuthorityName.RETRIEVED_EXTERNAL,
                AuthorityName.GENERATED_INTERMEDIATE,
            ):
                self.trust_level = TrustLevel.EXTERNAL
            else:
                self.trust_level = TrustLevel.UNTRUSTED

        if self.is_untrusted_authority or self.authority_name in {
            AuthorityName.USER_CONTENT,
            AuthorityName.DELEGATED_USER_DATA,
            AuthorityName.TOOL_OUTPUT,
            AuthorityName.RETRIEVED_EXTERNAL,
            AuthorityName.GENERATED_INTERMEDIATE,
            AuthorityName.UNKNOWN_UNTRUSTED,
        }:
            self.is_untrusted_authority = True

        self.source_id = self.source_id or self.source_label or self.origin_type or "unknown"
        self.source_type = self.source_type or self.origin_type or self.content_type or "unknown"
        self.source_label = self.source_label or self.source_id

        if not self.segment_id:
            digest_src = f"{self.authority_name.value}|{self.source_id}|{self.source_type}|{self.content}"
            self.segment_id = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def build(
        cls,
        content: str,
        authority_name: AuthorityName = AuthorityName.UNKNOWN_UNTRUSTED,
        is_untrusted_authority: Optional[bool] = None,
        origin_type: str = "text",
        content_type: str = "text",
        source_label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> "ContextSegment":
        if isinstance(authority_name, str):
            authority_name = AuthorityName(authority_name)
        if is_untrusted_authority is None:
            is_untrusted_authority = authority_name not in {
                AuthorityName.PROTOCOL_ROOT,
                AuthorityName.SYSTEM,
                AuthorityName.DEVELOPER,
                AuthorityName.AUTHENTICATED_USER,
            }
        return cls(
            content=content,
            authority_name=authority_name,
            is_untrusted_authority=is_untrusted_authority,
            origin_type=origin_type,
            content_type=content_type,
            source_label=source_label,
            source_id=source_label or origin_type or "unknown",
            source_type=origin_type or content_type or "unknown",
            metadata=metadata or {},
            **extra,
        )


@dataclass
class DetectorResult:
    """Unified result for legacy detector tests and v0.3 gateway escalation."""
    blocked: bool = False
    confidence: float = 0.0
    action: PolicyAction = PolicyAction.ALLOW
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    attack_category: Optional[str] = None
    verdict: Verdict = Verdict.CLEAN
    risk: float = 0.0
    classes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayDecision:
    allowed: bool
    requires_confirmation: bool = False
    reason: str = ""
    receipt: Optional[Dict[str, Any]] = None


@dataclass
class ToolRequest:
    tool_name: str
    sink: str
    source_segment_ids: List[str] = field(default_factory=list)
    requested_by_authority_level: int = 9
    user_confirmed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OutputPolicy:
    contains_secret: bool = False
    allowed_to_send: bool = False
    contains_code: bool = False
    allowed_to_execute: bool = False
    contains_tool_call: bool = False
    requires_user_confirmation: bool = False
