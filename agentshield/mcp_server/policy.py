"""
AgentShield MCP Firewall - Security Policy Engine
Evaluates tool call requests against predefined security constraints.
Enforces default-deny behavior for unknown tools and permissions.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict

# Predefined whitelist of authorized documents
AUTHORIZED_SAMPLE_DOCUMENTS = {
    "doc_sample_001",
    "doc_public_overview",
    "doc_public_roadmap",
    "public_quarterly_report.txt",
}

# Predefined whitelist of authorized email domains and recipients
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

# Approved internal destinations for data export
AUTHORIZED_EXPORT_DESTINATIONS = {
    "internal_backup",
    "compliance_vault",
    "approved_data_warehouse",
}

# Patterns indicating confidential or sensitive data
CONFIDENTIAL_PATTERNS = [
    re.compile(r"confidential", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"payroll", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
]


def _is_confidential_identifier(identifier: str) -> bool:
    """Check if a document or file identifier indicates confidential content."""
    if not identifier:
        return False
    return any(pattern.search(identifier) for pattern in CONFIDENTIAL_PATTERNS)


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
    
    Args:
        tool_name: The name of the requested tool (e.g. 'read_document').
        arguments: The arguments provided to the tool.
        agent_id: Configured test identity claiming to make the call.
                  NOTE: agent_id is an asserted test identity, NOT a cryptographically
                  verified identity. Full delegation tokens (e.g., Biscuit) will be added later.
                  
    Returns:
        Structured decision dictionary:
        {
            "allowed": bool,
            "reason": str,
            "tool_name": str,
            "agent_id": str,
            "timestamp": str (ISO-8601),
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "identity_status": "UNVERIFIED_ASSERTED"
        }
    """
    now = datetime.now(timezone.utc).isoformat()
    base_decision = {
        "tool_name": tool_name,
        "agent_id": agent_id,
        "timestamp": now,
        "identity_status": "UNVERIFIED_ASSERTED",  # Explicitly documented limitation
    }

    # 1. READ_DOCUMENT Policy
    if tool_name == "read_document":
        doc_id = str(arguments.get("document_id", "")).strip()
        if not doc_id:
            return {
                **base_decision,
                "allowed": False,
                "reason": "Missing required argument 'document_id'.",
                "risk_level": "LOW",
            }
        
        # Check if requested document is confidential
        if _is_confidential_identifier(doc_id):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is flagged as confidential and cannot be read by this agent.",
                "risk_level": "HIGH",
            }
        
        # Allow only explicitly authorized sample documents
        if doc_id in AUTHORIZED_SAMPLE_DOCUMENTS:
            return {
                **base_decision,
                "allowed": True,
                "reason": f"Document '{doc_id}' is an authorized sample document.",
                "risk_level": "LOW",
            }
        else:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is not in the authorized sample document whitelist.",
                "risk_level": "MEDIUM",
            }

    # 2. SEND_EMAIL Policy
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
            }

        # Check for unauthorized recipient
        if not _is_authorized_email(recipient):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Recipient '{recipient}' is not an authorized organizational email destination.",
                "risk_level": "CRITICAL",
            }

        # Check for sensitive data exfiltration in subject or body
        combined_text = f"{subject} {body}"
        if _is_confidential_identifier(combined_text):
            return {
                **base_decision,
                "allowed": False,
                "reason": "Access denied: Email content contains confidential or sensitive terms, triggering exfiltration block.",
                "risk_level": "HIGH",
            }

        return {
            **base_decision,
            "allowed": True,
            "reason": f"Recipient '{recipient}' is within authorized domains and content passed sensitivity inspection.",
            "risk_level": "LOW",
        }

    # 3. EXPORT_DATA Policy
    elif tool_name == "export_data":
        doc_id = str(arguments.get("document_id", "")).strip()
        destination = str(arguments.get("destination", "")).strip()

        if not doc_id or not destination:
            return {
                **base_decision,
                "allowed": False,
                "reason": "Missing required arguments 'document_id' or 'destination'.",
                "risk_level": "LOW",
            }

        # Block any confidential exports
        if _is_confidential_identifier(doc_id):
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' contains confidential data and cannot be exported.",
                "risk_level": "CRITICAL",
            }

        # Block unapproved destinations
        if destination.lower() not in AUTHORIZED_EXPORT_DESTINATIONS:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Export destination '{destination}' is not in the approved destinations whitelist.",
                "risk_level": "HIGH",
            }

        # Also require that document itself is in authorized set
        if doc_id not in AUTHORIZED_SAMPLE_DOCUMENTS:
            return {
                **base_decision,
                "allowed": False,
                "reason": f"Access denied: Document '{doc_id}' is not authorized for export.",
                "risk_level": "MEDIUM",
            }

        return {
            **base_decision,
            "allowed": True,
            "reason": f"Export of '{doc_id}' to approved destination '{destination}' is permitted.",
            "risk_level": "LOW",
        }

    # 4. DEFAULT-DENY FOR ANY UNKNOWN TOOL
    else:
        return {
            **base_decision,
            "allowed": False,
            "reason": f"Access denied: Tool '{tool_name}' is not recognized or supported by AgentShield policy (default-deny).",
            "risk_level": "CRITICAL",
        }
