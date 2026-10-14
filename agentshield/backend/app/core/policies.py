"""
AgentShield 25 AI Agent Security Policies Registry
Synthesizes the complete research-backed policy framework covering Integrity (P-T),
Confidentiality (P-F), Capability Delegation, and Information-Flow Control.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SecurityPolicyDef:
    id: int
    code: str
    name: str
    category: str  # "Integrity", "Confidentiality", "Access Control", "System Governance", "Defense in Depth"
    purpose: str
    example: str
    source_reference: str


# Complete registry of all 25 research-backed agent security policies
POLICIES_CATALOG: Dict[int, SecurityPolicyDef] = {
    1: SecurityPolicyDef(
        id=1,
        code="P-T",
        name="Trusted Actions Policy (Integrity)",
        category="Integrity",
        purpose="Prevent untrusted information from controlling consequential actions.",
        example="A webpage instructs an AI agent to delete a user's files. If the decision depends on untrusted webpage content, the policy blocks the action.",
        source_reference="FIDES (Costa et al., 2025)",
    ),
    2: SecurityPolicyDef(
        id=2,
        code="P-F",
        name="Permitted Flows Policy (Confidentiality)",
        category="Confidentiality",
        purpose="Prevent confidential information from flowing to unauthorized recipients or destinations.",
        example="An AI agent reads a private document and attempts to email it to an unauthorized external address. The policy blocks the transfer.",
        source_reference="FIDES (Costa et al., 2025)",
    ),
    3: SecurityPolicyDef(
        id=3,
        code="P-LP",
        name="Least Privilege Policy",
        category="Access Control",
        purpose="Gives the agent only the permissions it needs for the assigned task.",
        example="A summarization agent is granted read-only access to specific reports, without email or write permissions.",
        source_reference="Provable No-Escalation Delegation / Saltzer & Schroeder",
    ),
    4: SecurityPolicyDef(
        id=4,
        code="P-HUMAN",
        name="Human Approval Policy",
        category="System Governance",
        purpose="Requires user confirmation before high-risk or irreversible actions.",
        example="Gating high-value wire transfers or critical system file deletions with a human confirmation step.",
        source_reference="RTBAS (Zhong et al., 2025)",
    ),
    5: SecurityPolicyDef(
        id=5,
        code="P-ISOLATE",
        name="Untrusted Input Isolation Policy",
        category="Integrity",
        purpose="Separates external content from trusted instructions.",
        example="Enclosing retrieved webpage text inside strict boundary tags and treating it purely as data rather than instructions.",
        source_reference="BIPIA (Yi et al., 2024)",
    ),
    6: SecurityPolicyDef(
        id=6,
        code="P-LABEL",
        name="Source Labeling Policy",
        category="Integrity & Confidentiality",
        purpose="Labels data according to its origin, integrity, and trust level.",
        example="Tagging customer database entries as TRUSTED+CONFIDENTIAL, and web scrape output as UNTRUSTED+PUBLIC.",
        source_reference="CaMeL (Debenedetti et al., 2025)",
    ),
    7: SecurityPolicyDef(
        id=7,
        code="P-TAINT",
        name="Taint Propagation Policy",
        category="Integrity",
        purpose="Carries untrusted labels through derived data and operations.",
        example="If an agent summarizes an untrusted email, the resulting summary inherits the UNTRUSTED taint label.",
        source_reference="NeuroTaint (Cai et al., 2026) / FIDES",
    ),
    8: SecurityPolicyDef(
        id=8,
        code="P-ALLOWLIST",
        name="Tool Allowlist Policy",
        category="Access Control",
        purpose="Permits only approved tools and operations to be visible or callable by the agent.",
        example="Registering only read_document, send_email, and export_data in the MCP manifest; blocking all unmanifested tools.",
        source_reference="AgentShield MCP Gateway",
    ),
    9: SecurityPolicyDef(
        id=9,
        code="P-RBAC",
        name="Access Control Policy",
        category="Access Control",
        purpose="Checks whether the user or agent is authorized to access a specific resource.",
        example="Verifying document ID doc_sample_001 belongs to the caller's permitted resource scope.",
        source_reference="Cedar (Amazon, 2024)",
    ),
    10: SecurityPolicyDef(
        id=10,
        code="P-OUTVAL",
        name="Output Validation Policy",
        category="Defense in Depth",
        purpose="Validates model-generated content before using it in downstream systems.",
        example="Scanning outgoing payloads for malformed JSON, prompt-injection artifacts, or formatting exploits.",
        source_reference="InjecAgent (Zhan et al., 2024)",
    ),
    11: SecurityPolicyDef(
        id=11,
        code="P-EXFIL",
        name="Data Exfiltration Prevention Policy",
        category="Confidentiality",
        purpose="Blocks unauthorized transfers of confidential information across external boundaries.",
        example="Inspecting email bodies and export destinations; denying transfers to non-company domains.",
        source_reference="AgentShield Perimeter Monitor",
    ),
    12: SecurityPolicyDef(
        id=12,
        code="P-SECRET",
        name="Secret Protection Policy",
        category="Confidentiality",
        purpose="Prevents passwords, API keys, and other credentials from being exposed in tool arguments or logs.",
        example="Redacting bearer tokens, database passwords, and private keys from audit event payloads.",
        source_reference="AgentShield Audit Engine",
    ),
    13: SecurityPolicyDef(
        id=13,
        code="P-CTX",
        name="Trusted Context Policy",
        category="Integrity",
        purpose="Requires sufficient trusted context for sensitive decisions.",
        example="Requiring that a destructive action be initiated from verified developer instructions, not external user reviews.",
        source_reference="Instruction Hierarchy (Wallace et al., 2024)",
    ),
    14: SecurityPolicyDef(
        id=14,
        code="P-AUTHZ",
        name="Action Authorization Policy",
        category="Access Control",
        purpose="Checks permission immediately before a tool executes an action at runtime.",
        example="Intercepting every MCP tools/call request at the STDIO boundary and validating claims prior to execution.",
        source_reference="Provable No-Escalation Delegation (Algorithm B)",
    ),
    15: SecurityPolicyDef(
        id=15,
        code="P-PARAM",
        name="Parameter Validation Policy",
        category="Access Control",
        purpose="Validates tool arguments, such as email recipients, file paths, and transaction amounts.",
        example="Rejecting recipient email addresses containing wildcard domains or invalid RFC 5322 syntax.",
        source_reference="AAT / IETF Draft",
    ),
    16: SecurityPolicyDef(
        id=16,
        code="P-RWSEP",
        name="Read/Write Separation Policy",
        category="Access Control",
        purpose="Separates read-only capabilities from write, export, or delete capabilities.",
        example="Allowing an agent to read public reports without granting write or export capabilities.",
        source_reference="Capability Attenuation Framework",
    ),
    17: SecurityPolicyDef(
        id=17,
        code="P-FAILCLOSED",
        name="Fail-Closed Policy",
        category="System Governance",
        purpose="Blocks an action when the security check fails, times out, or cannot establish permission.",
        example="Default-deny response when an unknown tool name is invoked or a policy check encounters an unhandled state.",
        source_reference="Zero-Trust Architecture / Saltzer & Schroeder",
    ),
    18: SecurityPolicyDef(
        id=18,
        code="P-AUDIT",
        name="Audit Logging Policy",
        category="System Governance",
        purpose="Records security decisions, blocked actions, risk levels, and approvals in an immutable event store.",
        example="Logging request ID, timestamp, caller, tool, decision, and policy reason to SQLite WAL store.",
        source_reference="AgentShield Event Bus",
    ),
    19: SecurityPolicyDef(
        id=19,
        code="P-RATELIM",
        name="Rate Limiting Policy",
        category="Defense in Depth",
        purpose="Limits repeated calls or excessive resource usage by an agent.",
        example="Preventing automated loops from flooding the email mock queue with more than 50 requests per minute.",
        source_reference="AgentShield Rate Monitor",
    ),
    20: SecurityPolicyDef(
        id=20,
        code="P-TOOLISO",
        name="Tool Isolation Policy",
        category="Defense in Depth",
        purpose="Restricts the effects of a compromised tool or component by running safe mock boundaries.",
        example="Executing mock email dispatch inside an isolated test outbox rather than live SMTP servers.",
        source_reference="AgentShield Mock Sandbox",
    ),
    21: SecurityPolicyDef(
        id=21,
        code="P-DATAINT",
        name="Data Integrity Policy",
        category="Integrity",
        purpose="Prevents unauthorized modification of protected information.",
        example="Ensuring documents in the sample repository are read-only and cannot be tampered with by agent tool calls.",
        source_reference="Biba Integrity Model",
    ),
    22: SecurityPolicyDef(
        id=22,
        code="P-USERSCOPE",
        name="User-Scope Policy",
        category="Access Control",
        purpose="Ensures actions remain within the initiating user's permissions and session boundaries.",
        example="Binding capability grants to a specific session ID so tokens cannot be reused across users.",
        source_reference="UCAN / AAT",
    ),
    23: SecurityPolicyDef(
        id=23,
        code="P-PROMPTINJ",
        name="Prompt-Injection Testing Policy",
        category="Defense in Depth",
        purpose="Regularly tests the agent against malicious instructions embedded in external content.",
        example="Running adversarial fuzzer scenarios where sample documents contain prompt injection payloads.",
        source_reference="AgentDojo (Debenedetti et al., NeurIPS 2024)",
    ),
    24: SecurityPolicyDef(
        id=24,
        code="P-DATAMIN",
        name="Data Minimization Policy",
        category="Confidentiality",
        purpose="Exposes only the minimal information necessary for the current task.",
        example="Returning summary snippets rather than full database dumps when read_document is invoked.",
        source_reference="Privacy-by-Design",
    ),
    25: SecurityPolicyDef(
        id=25,
        code="P-SAFEEXEC",
        name="Safe Execution Policy",
        category="System Governance",
        purpose="Restricts arbitrary code execution and other potentially dangerous operating system operations.",
        example="Denying any system command execution, shell spawning, or subprocess calls requested by an AI agent.",
        source_reference="AgentShield Safe Runtime Gate",
    ),
}


def get_policy(policy_id: int) -> Optional[SecurityPolicyDef]:
    """Retrieve policy definition by ID."""
    return POLICIES_CATALOG.get(policy_id)


def get_all_policies() -> List[Dict]:
    """Return all 25 policies formatted as dictionaries for API and UI consumption."""
    return [
        {
            "id": p.id,
            "code": p.code,
            "name": p.name,
            "category": p.category,
            "purpose": p.purpose,
            "example": p.example,
            "source_reference": p.source_reference,
        }
        for p in POLICIES_CATALOG.values()
    ]
