"""
AgentShield Event Logger Service
Wraps database persistence for security decisions and tool executions.
"""

import os
import sys
import uuid
from typing import Any, Dict, Optional

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.backend.app.database import db

# Initialize database tables on import
db.init_db()


def log_decision(
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    decision: Dict[str, Any],
    downstream_status: str,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Log an authorization decision to SQLite.
    
    Args:
        agent_id: The asserted agent caller identity.
        tool_name: Name of tool requested.
        arguments: Tool invocation arguments.
        decision: Decision dict containing 'allowed', 'reason', 'risk_level'.
        downstream_status: "EXECUTED" or "BLOCKED".
        request_id: Unique request identifier.
    """
    if not request_id:
        request_id = f"req-{uuid.uuid4().hex[:10]}"

    resource_or_dest = (
        arguments.get("document_id")
        or arguments.get("resource_id")
        or arguments.get("recipient")
        or arguments.get("destination")
        or "N/A"
    )

    return db.log_security_event(
        request_id=request_id,
        agent_id=agent_id,
        tool_name=tool_name,
        resource_or_destination=str(resource_or_dest),
        arguments=arguments,
        allowed=decision.get("allowed", False),
        reason=decision.get("reason", ""),
        risk_level=decision.get("risk_level", "HIGH"),
        downstream_status=downstream_status,
        timestamp=decision.get("timestamp"),
    )


def log_execution(
    action_type: str,
    agent_id: str,
    arguments: Dict[str, Any],
    result_summary: Dict[str, Any],
    execution_id: Optional[str] = None,
) -> None:
    """Record that a downstream mock action actually executed."""
    if not execution_id:
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"

    db.log_mock_execution(
        execution_id=execution_id,
        action_type=action_type,
        agent_id=agent_id,
        arguments=arguments,
        result_summary=result_summary,
    )
