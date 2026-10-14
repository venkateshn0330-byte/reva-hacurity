"""
AgentShield MCP Protected Tools (Safe Mock Operations)
These mock implementations execute ONLY when authorized by the security gateway.
They never send real emails, touch production systems, or expose real secrets.
Mock execution records are saved in memory and logged to disk for audit/testing verification.
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List
import uuid

# In-memory execution log for fast test verification
_MOCK_EXECUTION_RECORDS: List[Dict[str, Any]] = []

# Persistent file log path for mock executions
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE_PATH = os.path.join(DATA_DIR, "mock_executions.jsonl")

# Safe mock document storage
MOCK_DOCUMENTS = {
    "doc_sample_001": {
        "title": "Public Product Overview - AgentShield 2026",
        "classification": "PUBLIC",
        "author": "Security Engineering Team",
        "content": (
            "AgentShield provides active inline inspection for MCP-enabled AI agents. "
            "It intercepts tool calls, evaluates policy constraints, and prevents unauthorized "
            "exfiltration or privileged action execution."
        ),
    },
    "doc_public_overview": {
        "title": "System Architecture Summary",
        "classification": "PUBLIC",
        "author": "Architecture Council",
        "content": (
            "The MCP architecture connects host agents via STDIO JSON-RPC transports. "
            "AgentShield acts as a security proxy layer validating every tool invocation."
        ),
    },
    "doc_public_roadmap": {
        "title": "AgentShield Open-Source Roadmap",
        "classification": "PUBLIC",
        "author": "Core Maintainers",
        "content": (
            "Milestone 1: FastMCP STDIO Gateway and Reusable Policy Engine.\n"
            "Milestone 2: SQLite Security Event Bus and React Cybersecurity Console.\n"
            "Milestone 3: Biscuit Capability Tokens and Z3 Invariant Enforcement."
        ),
    },
    "public_quarterly_report.txt": {
        "title": "Quarterly Public Transparency Report",
        "classification": "PUBLIC",
        "author": "Compliance Office",
        "content": "All external agent actions during Q3 adhered to zero-trust perimeter policies.",
    },
}


def _record_execution(action_type: str, arguments: Dict[str, Any], agent_id: str, result_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Record that a mock tool operation actually ran."""
    record = {
        "execution_id": f"exec-{uuid.uuid4().hex[:8]}",
        "action_type": action_type,
        "arguments": arguments,
        "agent_id": agent_id,
        "result_summary": result_summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    _MOCK_EXECUTION_RECORDS.append(record)

    # Persist record to jsonl file
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        # In-memory record is still preserved even if file write fails
        pass

    return record


def get_mock_executions() -> List[Dict[str, Any]]:
    """Return a copy of all recorded mock tool executions."""
    return list(_MOCK_EXECUTION_RECORDS)


def clear_mock_executions() -> None:
    """Clear mock execution records (primarily used between test cases)."""
    global _MOCK_EXECUTION_RECORDS
    _MOCK_EXECUTION_RECORDS = []
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass


def execute_read_document(document_id: str, agent_id: str = "demo-agent") -> Dict[str, Any]:
    """
    Mock implementation of document read tool.
    Returns safe mock text content.
    """
    doc = MOCK_DOCUMENTS.get(document_id)
    if not doc:
        doc = {
            "title": f"Sample Document {document_id}",
            "classification": "AUTHORIZED_SAMPLE",
            "content": f"[Simulated Content for {document_id}]: Safe operational data approved for agent access.",
        }

    result = {
        "status": "success",
        "document_id": document_id,
        "title": doc.get("title", ""),
        "classification": doc.get("classification", "AUTHORIZED"),
        "content": doc.get("content", ""),
    }

    _record_execution(
        action_type="read_document",
        arguments={"document_id": document_id},
        agent_id=agent_id,
        result_summary={"document_id": document_id, "status": "success"},
    )

    return result


def execute_send_email(recipient: str, subject: str, body: str, agent_id: str = "demo-agent") -> Dict[str, Any]:
    """
    Mock implementation of email tool.
    NEVER sends real emails. Simulates a mock outbox queue.
    """
    mock_message_id = f"mock-msg-{uuid.uuid4().hex[:10]}"
    result = {
        "status": "queued_mock_outbox",
        "mock_message_id": mock_message_id,
        "recipient": recipient,
        "subject": subject,
        "body_preview": (body[:60] + "...") if len(body) > 60 else body,
        "simulated": True,
        "note": "Safe mock mode: No external network packet was transmitted.",
    }

    _record_execution(
        action_type="send_email",
        arguments={"recipient": recipient, "subject": subject, "body": body},
        agent_id=agent_id,
        result_summary={"recipient": recipient, "mock_message_id": mock_message_id},
    )

    return result


def execute_export_data(document_id: str, destination: str, agent_id: str = "demo-agent") -> Dict[str, Any]:
    """
    Mock implementation of data export tool.
    Simulates a safe mock export transfer without touching external infrastructure.
    """
    export_id = f"export-{uuid.uuid4().hex[:8]}"
    result = {
        "status": "mock_exported",
        "export_id": export_id,
        "document_id": document_id,
        "destination": destination,
        "bytes_transferred": 1024,
        "simulated": True,
        "note": "Safe mock mode: Internal data staging simulated successfully.",
    }

    _record_execution(
        action_type="export_data",
        arguments={"document_id": document_id, "destination": destination},
        agent_id=agent_id,
        result_summary={"document_id": document_id, "destination": destination, "export_id": export_id},
    )

    return result
