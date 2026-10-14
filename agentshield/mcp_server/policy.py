"""
AgentShield MCP Firewall - Security Policy Engine
Evaluates tool call requests against the 25 AI Agent Security Policies.
Features:
- Enforces the 25 AI Agent Security Policies (P-T, P-F, P-LP, P-RBAC, P-EXFIL, P-FAILCLOSED, etc.)
- Evaluates real tool execution requests in the MCP interception layer
- Side-Effect Containment: Denied requests never execute downstream tools
- Immutable audit trail recording to SQLite with policy attribution
"""

from datetime import datetime, timezone
import os
import re
import sys
from typing import Any, Dict

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.backend.app.core.policies import POLICIES_CATALOG

# Predefined whitelist of authorized documents (Policy 9: Access Control)
AUTHORIZED_SAMPLE_DOCUMENTS = {
    "doc_sample_001",
    "doc_public_overview",
    "doc_public_roadmap",
    "public_quarterly_report.txt",
}

# Predefined whitelist of authorized email domains and recipients (Policy 15: Parameter Validation)
AUTHORIZED_EMAIL_DOMAINS = {
    "company.com",
    "internal.org",
    "agentshield.local",
}
AUTHORIZED_EXPLICIT_RECIPIENTS = {
    "security-audit@agentshield.local",
    "compliance@company.com",
    "team@company.com",
}

# Approved internal destinations for data export (Policy 2: Permitted Flows)
AUTHORIZED_EXPORT_DESTINATIONS = {
    "internal_backup",
    "compliance_vault",
    "approved_data_warehouse",
}

# Patterns indicating confidential or sensitive data (Policy 2 & Policy 12: Secret Protection)
CONFIDENTIAL_PATTERNS = [
    re.compile(r"confidential", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"payroll", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
]

# Patterns indicating untrusted prompt-injection payload instructions (Policy 1: P-T Trusted Actions)
INJECTION_INSTRUCTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?(rules|instructions)", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"stolen", re.IGNORECASE),
    re.compile(r"dump", re.IGNORECASE),
    re.compile(r"darknet", re.IGNORECASE),
]


def _is_confidential_identifier(identifier: str) -> bool:
    """Check if an identifier indicates confidential content."""
    if not identifier:
        return False
    return any(pattern.search(identifier) for pattern in CONFIDENTIAL_PATTERNS)


def _contains_injection_instructions(text: str) -> bool:
    """Check if input text appears to contain untrusted prompt-injection instructions."""
    if not text:
        return False
    return any(pattern.search(text) for pattern in INJECTION_INSTRUCTION_PATTERNS)


def _is_authorized_email(recipient: str) -> bool:
    """Check if recipient email is authorized."""
    if not recipient or "@" not in recipient:
        return False
    
    clean_recipient = recipient.strip().lower()
    if clean_recipient in AUTHORIZED_EXPLICIT_RECIPIENTS:
        return True
    
    domain = clean_recipient.split("@")[-1]
    return domain in AUTHORIZED_EMAIL_DOMAINS


def authorize(tool_name: str, arguments: Dict[str, Any], agent_id: str = "demo-agent") -> Dict[str, Any]:
    """
    Main authorization entry point for AgentShield MCP tools.
    Evaluates against the 25 AI Agent Security Policies.
    
    Returns structured decision dictionary with exact policy attribution.
    """
    now = datetime.now(timezone.utc).isoformat()
    base_decision = {
        "tool_name": tool_name,
        "agent_id": agent_id,
        "timestamp": now,
        "identity_status": "UNVERIFIED_ASSERTED",
    }

    # 1. READ_DOCUMENT Policy Evaluation
    if tool_name == "read_document":
        doc_id = str(arguments.get("document_id") or arguments.get("resource_id") or "").strip()
        if not doc_id:
            return {
                **base_decision,
                "allowed": False,
                "reason": "Missing required argument 'document_id' (or 'resource_id').",
                "risk_level": "LOW",
                "policy_id": 15,
                "policy_code": "P-PARAM",
                "policy_name": POLICIES_CATALOG[15].name,
            }
        
        # Policy 2 (P-F) & Policy 9 (Access Control): Confidential document protection
        if _is_confidential_identifier(doc_id):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is flagged as confidential and cannot be read by this agent.",
                "risk_level": "HIGH",
                "policy_id": 2,
                "policy_code": "P-F",
                "policy_name": POLICIES_CATALOG[2].name,
            }
        
        # Policy 8 (Tool Allowlist) & Policy 9 (Access Control): Sample document whitelist
        if doc_id in AUTHORIZED_SAMPLE_DOCUMENTS:
            return {
                **base_decision,
                "allowed": True,
                "reason": f"Document '{doc_id}' is an authorized sample document.",
                "risk_level": "LOW",
                "policy_id": 9,
                "policy_code": "P-RBAC",
                "policy_name": POLICIES_CATALOG[9].name,
            }
        else:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is not in the authorized sample document whitelist.",
                "risk_level": "MEDIUM",
                "policy_id": 9,
                "policy_code": "P-RBAC",
                "policy_name": POLICIES_CATALOG[9].name,
            }

    # 2. SEND_EMAIL Policy Evaluation
    elif tool_name == "send_email":
        recipient = str(arguments.get("recipient", "")).strip()
        subject = str(arguments.get("subject", "")).strip()
        body = str(arguments.get("body", "")).strip()

        if not recipient:
            return {
                **base_decision,
                "allowed": False,
                "reason": "Missing required argument 'recipient'.",
                "risk_level": "LOW",
                "policy_id": 15,
                "policy_code": "P-PARAM",
                "policy_name": POLICIES_CATALOG[15].name,
            }

        # Policy 1 (P-T): Trusted Actions Policy — Check for untrusted prompt injection driving action
        combined_text = f"{subject} {body}"
        if _contains_injection_instructions(combined_text):
            return {
                **base_decision,
                "allowed": False,
                "reason": "Access denied: Request driven by untrusted prompt injection instruction payload.",
                "risk_level": "CRITICAL",
                "policy_id": 1,
                "policy_code": "P-T",
                "policy_name": POLICIES_CATALOG[1].name,
            }

        # Policy 11 (Data Exfiltration Prevention) & Policy 15 (Parameter Validation)
        if not _is_authorized_email(recipient):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Recipient '{recipient}' is not an authorized organizational email destination.",
                "risk_level": "CRITICAL",
                "policy_id": 11,
                "policy_code": "P-EXFIL",
                "policy_name": POLICIES_CATALOG[11].name,
            }

        # Policy 2 (P-F) & Policy 12 (Secret Protection): Exfiltration of confidential terms
        if _is_confidential_identifier(combined_text):
            return {
                **base_decision,
                "allowed": False,
                "reason": "Access denied: Email content contains confidential or sensitive terms, triggering exfiltration block.",
                "risk_level": "HIGH",
                "policy_id": 2,
                "policy_code": "P-F",
                "policy_name": POLICIES_CATALOG[2].name,
            }

        return {
            **base_decision,
            "allowed": True,
            "reason": f"Recipient '{recipient}' is within authorized domains and content passed sensitivity inspection.",
            "risk_level": "LOW",
            "policy_id": 2,
            "policy_code": "P-F",
            "policy_name": POLICIES_CATALOG[2].name,
        }

    # 3. EXPORT_DATA Policy Evaluation
    elif tool_name == "export_data":
        doc_id = str(arguments.get("document_id") or arguments.get("resource_id") or "").strip()
        destination = str(arguments.get("destination", "")).strip()

        if not doc_id or not destination:
            return {
                **base_decision,
                "allowed": False,
                "reason": "Missing required arguments 'document_id' (or 'resource_id') and 'destination'.",
                "risk_level": "LOW",
                "policy_id": 15,
                "policy_code": "P-PARAM",
                "policy_name": POLICIES_CATALOG[15].name,
            }

        # Policy 2 (P-F: Permitted Flows) & Policy 11 (Data Exfiltration Prevention)
        if _is_confidential_identifier(doc_id):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' contains confidential data and cannot be exported.",
                "risk_level": "CRITICAL",
                "policy_id": 2,
                "policy_code": "P-F",
                "policy_name": POLICIES_CATALOG[2].name,
            }

        # Policy 2 (P-F: Permitted Flows): Approved destination check
        if destination.lower() not in AUTHORIZED_EXPORT_DESTINATIONS:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Export destination '{destination}' is not in the approved destinations whitelist.",
                "risk_level": "HIGH",
                "policy_id": 2,
                "policy_code": "P-F",
                "policy_name": POLICIES_CATALOG[2].name,
            }

        # Policy 9: Access Control check on resource
        if doc_id not in AUTHORIZED_SAMPLE_DOCUMENTS:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is not authorized for export.",
                "risk_level": "MEDIUM",
                "policy_id": 9,
                "policy_code": "P-RBAC",
                "policy_name": POLICIES_CATALOG[9].name,
            }

        return {
            **base_decision,
            "allowed": True,
            "reason": f"Export of '{doc_id}' to approved destination '{destination}' is permitted.",
            "risk_level": "LOW",
            "policy_id": 2,
            "policy_code": "P-F",
            "policy_name": POLICIES_CATALOG[2].name,
        }

    # 4. Policy 17 (Fail-Closed Policy) & Policy 8 (Tool Allowlist Policy): Default-Deny for Unknown Tools
    else:
        return {
            **base_decision,
            "allowed": False,
            "reason": f"Access denied: Tool '{tool_name}' is not recognized or supported by AgentShield policy (default-deny).",
            "risk_level": "CRITICAL",
            "policy_id": 17,
            "policy_code": "P-FAILCLOSED",
            "policy_name": POLICIES_CATALOG[17].name,
        }
