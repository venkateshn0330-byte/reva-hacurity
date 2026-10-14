"""
AgentShield MCP Security Gateway Server
Tailored for seamless integration with IBM Bob and standard MCP clients.

Key Capabilities & Guarantees:
1. Implements standard MCP STDIO transport with full protocol negotiation:
   - Supports Bob specification versions: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07.
   - Responds to 'server/discover' probes (for auto-negotiation) and direct 'initialize' (for legacy mode).
2. Intercepts all tool operations (read_document, send_email, export_data) with policy.authorize().
3. Denied operations NEVER execute downstream mock tools.
4. Records every decision and mock execution into the shared SQLite audit database (data/events.db).
5. Never prints to STDOUT (STDIO used solely for JSON-RPC 2.0 framing). Diagnostics go strictly to STDERR.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

# Add mcp_server and repository directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
for p in [CURRENT_DIR, REPO_ROOT]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from agentshield.mcp_server.policy import authorize
    from agentshield.mcp_server import protected_tools
except ImportError:
    from policy import authorize
    import protected_tools

# Configure logging strictly to sys.stderr so stdout remains 100% clean JSON-RPC
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [AgentShield-MCP] %(levelname)s: %(message)s",
)
logger = logging.getLogger("AgentShield-MCP")

# Protocol versions supported by IBM Bob
SUPPORTED_PROTOCOL_VERSIONS = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
]
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {
    "name": "AgentShield-MCP-Firewall",
    "version": "0.1.0",
}

# Rich MCP Tool Definitions aligned with IBM Bob Tool Quality Guidelines
TOOLS_MANIFEST = [
    {
        "name": "read_document",
        "description": (
            "Securely read an approved operational or sample document by its identifier. "
            "Enforces inline access control: only authorized documents in the sample whitelist "
            "(e.g., 'doc_sample_001', 'doc_public_roadmap', 'public_quarterly_report.txt') may be read. "
            "Confidential documents are automatically blocked by the AgentShield firewall."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": (
                        "Identifier of the document to retrieve. Examples: 'doc_sample_001', "
                        "'doc_public_overview', 'doc_public_roadmap'. Cannot contain 'confidential' or 'secret'."
                    ),
                },
                "resource_id": {
                    "type": "string",
                    "description": "Alias for document_id.",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Caller identity assertion used for audit logging (default: 'demo-agent').",
                    "default": "demo-agent",
                },
            },
            "required": ["document_id"],
        },
    },
    {
        "name": "send_email",
        "description": (
            "Transmit an email message to an authorized recipient. "
            "Monitored by AgentShield for data exfiltration: recipients must belong to authorized "
            "domains (@company.com, @internal.org, @agentshield.local). Any attempt to send emails "
            "to unauthorized external addresses (e.g., attacker@evil.com) or containing confidential data is blocked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "recipient": {
                    "type": "string",
                    "description": (
                        "Recipient email address. Must be an approved domain, e.g. "
                        "'compliance@company.com' or 'security-audit@agentshield.local'."
                    ),
                },
                "subject": {
                    "type": "string",
                    "description": "Subject header. Monitored for exfiltration keywords.",
                },
                "body": {
                    "type": "string",
                    "description": "Body message text. Monitored for sensitive and confidential contents.",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Caller identity assertion used for audit logging (default: 'demo-agent').",
                    "default": "demo-agent",
                },
            },
            "required": ["recipient", "subject", "body"],
        },
    },
    {
        "name": "export_data",
        "description": (
            "Export approved document data to an approved destination store. "
            "The AgentShield firewall denies any attempt to export confidential documents "
            "or transfer data to unapproved destinations. Allowed destinations: 'internal_backup', "
            "'compliance_vault', 'approved_data_warehouse'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Identifier of the document to export. Must be in the approved document whitelist.",
                },
                "resource_id": {
                    "type": "string",
                    "description": "Alias for document_id.",
                },
                "destination": {
                    "type": "string",
                    "description": (
                        "Target export destination. Must be an approved internal vault: "
                        "'internal_backup', 'compliance_vault', or 'approved_data_warehouse'."
                    ),
                },
                "agent_id": {
                    "type": "string",
                    "description": "Caller identity assertion used for audit logging (default: 'demo-agent').",
                    "default": "demo-agent",
                },
            },
            "required": ["document_id", "destination"],
        },
    },
]


def _safe_log_event(
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    decision: Dict[str, Any],
    downstream_status: str,
    project_id: str = "proj_default",
    is_upstream: int = 0,
    event_source: str = "mcp_live",
):
    """Safely log event to SQLite without throwing exceptions to caller."""
    try:
        from agentshield.backend.app.services.event_logger import log_decision
        log_decision(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            downstream_status=downstream_status,
            project_id=project_id,
            is_upstream=is_upstream,
            event_source=event_source,
        )
    except Exception as err:
        logger.warning(f"Could not write audit log to SQLite: {err}")


def dispatch_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    authenticated_agent_id: Optional[str] = None,
    project_id: str = "proj_default",
    event_source: str = "mcp_live",
) -> Dict[str, Any]:
    """
    Core security gateway dispatcher.
    Enforces authorization check BEFORE executing any protected tool or forwarding to upstream servers.
    Logs every decision to the SQLite audit database scoped to project_id.
    If authenticated_agent_id is provided, it strictly overrides any client-asserted agent_id.
    """
    if authenticated_agent_id:
        agent_id = authenticated_agent_id
        # Force the authenticated identity into arguments so downstream cannot be spoofed
        arguments = {**arguments, "agent_id": authenticated_agent_id}
    else:
        # Check if client passed an agent identifier or default based on caller source
        agent_id = arguments.get("agent_id") or ("ibm-bob" if event_source == "mcp_live" else "demo-agent")

    logger.info(f"INCOMING REQUEST: tool='{tool_name}', agent='{agent_id}', project='{project_id}', source='{event_source}', args={json.dumps(arguments)}")

    # Check if project has an active upstream MCP configuration
    upstream_conf = None
    is_upstream_tool = False
    original_upstream_name = tool_name
    try:
        from agentshield.backend.app.database import db
        upstream_conf = db.get_upstream_server(project_id, decrypt=True)
        if upstream_conf:
            prefix = upstream_conf.get("tool_prefix", "upstream_")
            if tool_name.startswith(prefix):
                is_upstream_tool = True
                original_upstream_name = tool_name[len(prefix):]
    except Exception as exc:
        logger.warning(f"Error checking upstream server for project {project_id}: {exc}")

    # 1. SHARED SECURITY AUTHORIZATION GATEWAY
    try:
        decision = authorize(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=agent_id,
            project_id=project_id,
            is_upstream=is_upstream_tool,
        )
    except Exception as exc:
        logger.error(f"Policy evaluation error in gateway (fail-closed): {exc}", exc_info=True)
        decision = {
            "allowed": False,
            "reason": f"Security policy evaluation failure (fail-closed): {str(exc)}",
            "risk_level": "CRITICAL",
            "policy_id": 17,
            "policy_code": "P-FAILCLOSED",
            "policy_name": "Policy 17: Fail-Closed Policy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    if not decision.get("allowed", False):
        reason = decision.get("reason", "Operation blocked by AgentShield security policy.")
        risk = decision.get("risk_level", "HIGH")
        logger.warning(
            f"SECURITY GATEWAY BLOCKED: tool='{tool_name}' agent='{agent_id}' project='{project_id}' risk={risk} reason='{reason}'"
        )
        
        # Log blocked event to SQLite before returning error response to client
        _safe_log_event(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            downstream_status="BLOCKED",
            project_id=project_id,
            is_upstream=1 if is_upstream_tool else 0,
            event_source=event_source,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"[AgentShield Security Firewall Rejection]\n"
                        f"Status: BLOCKED\n"
                        f"Tool: {tool_name}\n"
                        f"Risk Level: {risk}\n"
                        f"Reason: {reason}\n"
                        f"Timestamp: {decision.get('timestamp')}\n"
                        f"Downstream Execution: CANCELLED (Action was not executed or forwarded)"
                    ),
                }
            ],
            "isError": True,
            "_security_decision": decision,
        }

    # 2. DOWNSTREAM PROTECTED EXECUTION (ONLY IF ALLOWED)
    logger.info(f"SECURITY GATEWAY PERMITTED: tool='{tool_name}' agent='{agent_id}' (upstream={is_upstream_tool})")

    # Upstream Forwarding Path
    if is_upstream_tool and upstream_conf:
        try:
            from agentshield.mcp_server.upstream_client import forward_tool_call
            upstream_resp = forward_tool_call(
                upstream_url=upstream_conf["upstream_url"],
                original_tool_name=original_upstream_name,
                arguments=arguments,
                auth_token=upstream_conf.get("raw_auth_token"),
                auth_type=upstream_conf.get("auth_type", "bearer"),
            )
            downstream_status = upstream_resp.get("downstream_status", "EXECUTED")
            _safe_log_event(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                downstream_status=downstream_status,
                project_id=project_id,
                is_upstream=1,
                event_source=event_source,
            )
            return {
                "content": upstream_resp["content"],
                "isError": upstream_resp["isError"],
                "_security_decision": decision,
            }
        except Exception as e:
            logger.error(f"Failed forwarding tool call to upstream: {e}", exc_info=True)
            _safe_log_event(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                downstream_status="FAILED",
                project_id=project_id,
                is_upstream=1,
                event_source=event_source,
            )
            return {
                "content": [{"type": "text", "text": f"Upstream execution error: {str(e)}"}],
                "isError": True,
            }

    # Built-in Protected Sandbox Tools
    try:
        if tool_name == "read_document":
            doc_id = arguments.get("document_id") or arguments.get("resource_id")
            result = protected_tools.execute_read_document(document_id=doc_id, agent_id=agent_id)
        elif tool_name == "send_email":
            recipient = arguments.get("recipient")
            subject = arguments.get("subject")
            body = arguments.get("body")
            result = protected_tools.execute_send_email(
                recipient=recipient, subject=subject, body=body, agent_id=agent_id
            )
        elif tool_name == "export_data":
            doc_id = arguments.get("document_id") or arguments.get("resource_id")
            destination = arguments.get("destination")
            result = protected_tools.execute_export_data(
                document_id=doc_id, destination=destination, agent_id=agent_id
            )
        else:
            _safe_log_event(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                downstream_status="FAILED",
                project_id=project_id,
                is_upstream=0,
                event_source=event_source,
            )
            return {
                "content": [{"type": "text", "text": f"Error: Tool '{tool_name}' not implemented."}],
                "isError": True,
            }

        # Log allowed execution to SQLite
        _safe_log_event(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            downstream_status="EXECUTED",
            project_id=project_id,
            is_upstream=0,
            event_source=event_source,
        )

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2),
                }
            ],
            "isError": False,
            "_security_decision": decision,
        }
    except Exception as e:
        logger.error(f"Execution failure in tool '{tool_name}': {e}", exc_info=True)
        _safe_log_event(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            downstream_status="FAILED",
            project_id=project_id,
            event_source=event_source,
        )
        return {
            "content": [{"type": "text", "text": f"Tool execution failed: {str(e)}"}],
            "isError": True,
        }


def handle_jsonrpc_message(
    message: Any,
    authenticated_agent_id: Optional[str] = None,
    project_id: str = "proj_default",
) -> Optional[Dict[str, Any]]:
    """
    Process a single JSON-RPC 2.0 message conforming to the MCP specification and IBM Bob client.
    Reused by both STDIO transport and remote HTTP endpoints.
    """
    if not isinstance(message, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: Payload must be a JSON object."},
        }

    msg_id = message.get("id")
    jsonrpc_ver = message.get("jsonrpc")

    if jsonrpc_ver != "2.0":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request: 'jsonrpc' version must be '2.0'."},
        }

    method = message.get("method")
    if not isinstance(method, str) or not method:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request: 'method' must be a non-empty string."},
        }

    params = message.get("params", {})
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32602, "message": "Invalid params: 'params' must be an object/dict."},
        }

    logger.info(f"Received JSON-RPC method: '{method}' (id: {msg_id})")

    # 1. Server Discovery Probe (supported by Bob in 'auto' negotiation mode)
    if method == "server/discover":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "serverInfo": SERVER_INFO,
            },
        }

    # 2. MCP Handshake / Initialization
    elif method == "initialize":
        requested_version = params.get("protocolVersion")
        if requested_version in SUPPORTED_PROTOCOL_VERSIONS:
            negotiated_version = requested_version
        else:
            negotiated_version = DEFAULT_PROTOCOL_VERSION

        logger.info(f"Client requested version '{requested_version}', negotiated '{negotiated_version}'")
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": negotiated_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "serverInfo": SERVER_INFO,
            },
        }

    # 3. Initialized Notification (no response required)
    elif method == "notifications/initialized":
        logger.info("Bob client completed initialization handshake.")
        return None

    # 4. Ping
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {},
        }

    # 5. Tool Discovery (tools/list)
    elif method == "tools/list":
        combined_tools = list(TOOLS_MANIFEST)
        if project_id and project_id != "proj_default":
            try:
                from agentshield.backend.app.database import db
                from agentshield.mcp_server.upstream_client import discover_upstream_tools

                upstream = db.get_upstream_server(project_id, decrypt=True)
                if upstream:
                    cached = upstream.get("cached_tools")
                    if not cached:
                        # Auto-discover tools if not yet cached
                        success, discovered, _ = discover_upstream_tools(
                            upstream_url=upstream["upstream_url"],
                            auth_token=upstream.get("raw_auth_token"),
                            auth_type=upstream.get("auth_type", "bearer"),
                            tool_prefix=upstream.get("tool_prefix", "upstream_"),
                        )
                        if success:
                            cached = discovered
                            db.update_upstream_cached_tools(project_id, cached)
                    if cached and isinstance(cached, list):
                        for tool_item in cached:
                            if isinstance(tool_item, dict) and "name" in tool_item:
                                combined_tools.append(tool_item)
            except Exception as exc:
                logger.warning(f"Failed to query upstream tools for project '{project_id}': {exc}")

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": combined_tools,
            },
        }

    # 6. Tool Invocation (tools/call)
    elif method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "Invalid params: 'name' must be a valid tool name string."},
            }

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        execution_result = dispatch_tool(
            tool_name=tool_name,
            arguments=arguments,
            authenticated_agent_id=authenticated_agent_id,
            project_id=project_id,
            event_source="mcp_live",
        )

        wire_result = {
            "content": execution_result["content"],
            "isError": execution_result["isError"],
        }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": wire_result,
        }

    # Handle unknown method / notifications
    else:
        if msg_id is None:
            logger.info(f"Ignored unknown notification: '{method}'")
            return None
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found or unsupported by AgentShield.",
            },
        }


def process_jsonrpc_payload(
    payload_dict: Any,
    authenticated_agent_id: Optional[str] = None,
    project_id: str = "proj_default",
) -> Optional[Dict[str, Any]]:
    """Shared dispatcher alias for external callers (HTTP, SSE, IPC)."""
    return handle_jsonrpc_message(
        payload_dict,
        authenticated_agent_id=authenticated_agent_id,
        project_id=project_id,
    )


def run_stdio_server():
    """Run the MCP server reading newline-delimited JSON-RPC from STDIN and writing to STDOUT."""
    logger.info("Starting AgentShield MCP Security Gateway for IBM Bob (STDIO Mode)...")
    logger.info(f"Supported Protocol Versions: {SUPPORTED_PROTOCOL_VERSIONS}")
    logger.info(f"Protected Tools Manifest: {[t['name'] for t in TOOLS_MANIFEST]}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as err:
            logger.error(f"Malformed JSON received: {err}")
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
            }
            sys.stdout.write(json.dumps(error_response) + "\n")
            sys.stdout.flush()
            continue

        resp = handle_jsonrpc_message(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
