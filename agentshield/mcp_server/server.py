"""
AgentShield MCP Security Gateway Server
Tailored for seamless integration with IBM Bob and standard MCP clients.

Key Capabilities & Guarantees:
1. Implements standard MCP STDIO transport with full protocol negotiation:
   - Supports Bob specification versions: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07.
   - Responds to 'server/discover' probes (for auto-negotiation) and direct 'initialize' (for legacy mode).
2. Intercepts all tool operations (read_document, send_email, export_data) with policy.authorize().
3. Never prints to STDOUT (STDIO used solely for JSON-RPC 2.0 framing). Diagnostics go strictly to STDERR.
4. Provides rich, unambiguous tool and parameter schemas so Bob's AI model accurately reasons over tools.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

# Add mcp_server directory to sys.path if not present
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

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


def dispatch_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core security gateway dispatcher.
    Enforces authorization check BEFORE executing any protected tool.
    
    Returns:
        MCP Result dictionary formatted with 'content' and 'isError'.
    """
    agent_id = arguments.get("agent_id", "demo-agent")
    logger.info(f"INCOMING REQUEST: tool='{tool_name}', agent='{agent_id}', args={json.dumps(arguments)}")

    # 1. SHARED SECURITY AUTHORIZATION GATEWAY
    decision = authorize(tool_name=tool_name, arguments=arguments, agent_id=agent_id)
    
    if not decision.get("allowed", False):
        reason = decision.get("reason", "Operation blocked by AgentShield security policy.")
        risk = decision.get("risk_level", "HIGH")
        logger.warning(
            f"SECURITY GATEWAY BLOCKED: tool='{tool_name}' agent='{agent_id}' risk={risk} reason='{reason}'"
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
                        f"Downstream Execution: CANCELLED (Safe mock tool was not executed)"
                    ),
                }
            ],
            "isError": True,
            "_security_decision": decision,
        }

    # 2. DOWNSTREAM PROTECTED EXECUTION (ONLY IF ALLOWED)
    logger.info(f"SECURITY GATEWAY PERMITTED: tool='{tool_name}' agent='{agent_id}'")
    try:
        if tool_name == "read_document":
            doc_id = arguments.get("document_id")
            result = protected_tools.execute_read_document(document_id=doc_id, agent_id=agent_id)
        elif tool_name == "send_email":
            recipient = arguments.get("recipient")
            subject = arguments.get("subject")
            body = arguments.get("body")
            result = protected_tools.execute_send_email(
                recipient=recipient, subject=subject, body=body, agent_id=agent_id
            )
        elif tool_name == "export_data":
            doc_id = arguments.get("document_id")
            destination = arguments.get("destination")
            result = protected_tools.execute_export_data(
                document_id=doc_id, destination=destination, agent_id=agent_id
            )
        else:
            return {
                "content": [{"type": "text", "text": f"Error: Tool '{tool_name}' not implemented."}],
                "isError": True,
            }

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
        return {
            "content": [{"type": "text", "text": f"Tool execution failed: {str(e)}"}],
            "isError": True,
        }


def handle_jsonrpc_message(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process a single JSON-RPC 2.0 message conforming to the MCP specification and IBM Bob client.
    """
    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

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
        # Negotiate version: use requested version if in supported list, else fallback to default
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

    # 3. Initialized Notification (notification: must return None, no response)
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
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS_MANIFEST,
            },
        }

    # 6. Tool Invocation (tools/call)
    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        execution_result = dispatch_tool(tool_name=tool_name, arguments=arguments)

        # Wire format returned to Bob client
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
        # If message has no id, it is a notification (do not send response)
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
            # Newline-delimited JSON-RPC to stdout, flushed immediately
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
