"""
AgentShield Upstream MCP Client & Forwarding Engine
Communicates with external Streamable HTTP MCP servers.
Enforces SSRF validation, bounded timeouts, response size limits, and sanitization.
"""

import json
import logging
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agentshield.mcp_server.upstream_validator import validate_upstream_url

class UpstreamMCPError(Exception):
    """Raised when an upstream MCP server communication error occurs."""
    pass


logger = logging.getLogger("AgentShield-Upstream")

MAX_UPSTREAM_RESPONSE_BYTES = 1024 * 1024  # 1 MB bounded response limit
DEFAULT_TIMEOUT_SECONDS = 5.0


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect following to prevent SSRF redirect bypasses."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoRedirectHandler)


def discover_upstream_tools(
    upstream_url: str,
    auth_token: Optional[str] = None,
    auth_type: str = "bearer",
    tool_prefix: str = "upstream_",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[bool, List[Dict[str, Any]], str]:
    """
    Connect to upstream Streamable HTTP MCP endpoint and discover available tools.
    Returns (success: bool, tools_manifest: List[Dict], error_reason: str).
    """
    is_valid, reason, _ = validate_upstream_url(upstream_url)
    if not is_valid:
        return False, [], f"SSRF Validation Failed: {reason}"

    clean_prefix = tool_prefix.strip() if tool_prefix else "upstream_"
    if not clean_prefix.endswith("_"):
        clean_prefix += "_"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    opener = _build_opener()

    # 1. MCP Initialization Handshake
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "AgentShield-Security-Gateway",
                "version": "1.0.0",
            },
        },
    }

    try:
        init_req = urllib.request.Request(
            upstream_url,
            data=json.dumps(init_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with opener.open(init_req, timeout=timeout) as resp:
            raw_body = resp.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
            if len(raw_body) > MAX_UPSTREAM_RESPONSE_BYTES:
                return False, [], "Upstream initialization response exceeded 1 MB limit."
            init_resp = json.loads(raw_body.decode("utf-8"))
            if "error" in init_resp:
                return False, [], f"Upstream rejected initialization: {init_resp['error'].get('message', 'Unknown error')}"

        # 2. Initialized Notification (Notification has no id)
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        notif_req = urllib.request.Request(
            upstream_url,
            data=json.dumps(notif_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with opener.open(notif_req, timeout=timeout):
                pass
        except Exception:
            pass  # Notifications may return 202, 204, or empty

        # 3. Tool Discovery (tools/list)
        list_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        list_req = urllib.request.Request(
            upstream_url,
            data=json.dumps(list_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with opener.open(list_req, timeout=timeout) as resp:
            raw_body = resp.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
            if len(raw_body) > MAX_UPSTREAM_RESPONSE_BYTES:
                return False, [], "Upstream tools/list response exceeded 1 MB limit."
            list_resp = json.loads(raw_body.decode("utf-8"))
            if "error" in list_resp:
                return False, [], f"Upstream tools/list error: {list_resp['error'].get('message', 'Unknown error')}"

            raw_tools = list_resp.get("result", {}).get("tools", [])
            discovered_tools = []
            for t in raw_tools:
                orig_name = t.get("name", "")
                if not orig_name:
                    continue
                prefixed_name = f"{clean_prefix}{orig_name}"
                discovered_tools.append({
                    "name": prefixed_name,
                    "original_name": orig_name,
                    "description": f"[Upstream] {t.get('description', '')}",
                    "inputSchema": t.get("inputSchema", {"type": "object", "properties": {}}),
                    "_upstream": True,
                    "_upstream_server_url": upstream_url,
                })

            return True, discovered_tools, "OK"

    except urllib.error.HTTPError as err:
        return False, [], f"Upstream HTTP Error {err.code}: {err.reason}"
    except urllib.error.URLError as err:
        return False, [], f"Upstream Connection Failed: {str(err.reason)}"
    except Exception as exc:
        return False, [], f"Upstream Discovery Failed: {str(exc)}"


def forward_tool_call(
    upstream_url: str,
    original_tool_name: str,
    arguments: Dict[str, Any],
    auth_token: Optional[str] = None,
    auth_type: str = "bearer",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Forward an authorized tool invocation to the external Streamable HTTP MCP server.
    Returns standard MCP wire format: {"content": [...], "isError": bool, "downstream_status": "EXECUTED" | "FAILED"}.
    """
    is_valid, reason, _ = validate_upstream_url(upstream_url)
    if not is_valid:
        return {
            "content": [{"type": "text", "text": f"AgentShield Gateway Error: Upstream target blocked: {reason}"}],
            "isError": True,
            "downstream_status": "FAILED",
        }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    call_payload = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": original_tool_name,
            "arguments": arguments,
        },
    }

    opener = _build_opener()
    try:
        req = urllib.request.Request(
            upstream_url,
            data=json.dumps(call_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with opener.open(req, timeout=timeout) as resp:
            raw_body = resp.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
            if len(raw_body) > MAX_UPSTREAM_RESPONSE_BYTES:
                return {
                    "content": [{"type": "text", "text": "Upstream tool response exceeded 1 MB size limit."}],
                    "isError": True,
                    "downstream_status": "FAILED",
                }
            resp_json = json.loads(raw_body.decode("utf-8"))

            if "error" in resp_json:
                err = resp_json["error"]
                return {
                    "content": [{"type": "text", "text": f"Upstream MCP Error: {err.get('message', 'Unknown error')}"}],
                    "isError": True,
                    "downstream_status": "FAILED",
                }

            result = resp_json.get("result", {})
            content = result.get("content", [{"type": "text", "text": json.dumps(result)}])
            is_error = result.get("isError", False)
            return {
                "content": content,
                "isError": is_error,
                "downstream_status": "FAILED" if is_error else "EXECUTED",
            }

    except urllib.error.HTTPError as err:
        return {
            "content": [{"type": "text", "text": f"Upstream Server HTTP {err.code}: Access denied or failed."}],
            "isError": True,
            "downstream_status": "FAILED",
        }
    except (urllib.error.URLError, TimeoutError) as err:
        return {
            "content": [{"type": "text", "text": f"Upstream Gateway Timeout: Server failed to respond within {timeout}s."}],
            "isError": True,
            "downstream_status": "FAILED",
        }
    except Exception as exc:
        return {
            "content": [{"type": "text", "text": f"Upstream Dispatch Error: {str(exc)}"}],
            "isError": True,
            "downstream_status": "FAILED",
        }
