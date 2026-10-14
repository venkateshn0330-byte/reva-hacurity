"""
AgentShield Backend REST API Server
Provides real-time event streaming, statistics, 25-Policy definitions, and on-demand adversarial test execution.
Supports both standard library ThreadingHTTPServer (zero external dependencies) and FastAPI/Uvicorn.
"""

from datetime import datetime, timezone
import hmac
import json
import os
import secrets
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, List, Optional

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.backend.app.database import db
from agentshield.backend.app.core.policies import get_all_policies
from agentshield.fuzzer.runner import run_test_suite
from agentshield.mcp_server.server import dispatch_tool, handle_jsonrpc_message, process_jsonrpc_payload
from agentshield.mcp_server.upstream_validator import assert_valid_upstream_url, SSRFValidationError
from agentshield.mcp_server.upstream_client import discover_upstream_tools, UpstreamMCPError

# Ensure database tables exist
db.init_db()

# Security Configurations
START_TIME = datetime.now(timezone.utc).isoformat()
ADMIN_KEY = os.environ.get("AGENTSHIELD_ADMIN_KEY", "ash_admin_sec_master_2026")
MAX_REQUEST_BODY_SIZE = int(os.environ.get("AGENTSHIELD_MAX_BODY_SIZE", 1048576))  # 1 MB

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
ALLOWED_ORIGINS = set(filter(None, [
    o.strip() for o in os.environ.get("AGENTSHIELD_ALLOWED_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS)).split(",")
]))

ALLOWED_HOSTS = set(filter(None, [
    h.strip().lower() for h in os.environ.get("AGENTSHIELD_ALLOWED_HOSTS", "127.0.0.1,localhost,::1,testclient").split(",")
]))


def is_production_mode() -> bool:
    return (
        os.environ.get("AGENTSHIELD_ENV", "development").lower() in ("production", "prod")
        or bool(os.environ.get("RENDER"))
        or bool(os.environ.get("DYNO"))
    )


def is_dev_mode_enabled() -> bool:
    """Development fallback mode is disabled by default and requires AGENTSHIELD_DEV_MODE=1 in non-production."""
    if is_production_mode():
        return False
    return os.environ.get("AGENTSHIELD_DEV_MODE", "0") == "1"


def is_allowed_origin(origin: str) -> bool:
    if not origin:
        return False
    if "*" in ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS:
        return True
    parsed = urlparse(origin)
    if parsed.hostname and (parsed.hostname.endswith(".onrender.com") or parsed.hostname.endswith(".render.com")):
        return True
    if not is_production_mode():
        if parsed.hostname in ("127.0.0.1", "localhost", "::1"):
            return True
    return False


def validate_host_header(handler: BaseHTTPRequestHandler) -> bool:
    host_header = handler.headers.get("Host", "").strip().lower()
    if not host_header:
        return True
    host_name = host_header.split(":")[0]
    if "*" in ALLOWED_HOSTS:
        return True
    if host_name.endswith(".onrender.com") or host_name.endswith(".render.com"):
        return True
    return (host_name in ALLOWED_HOSTS) or (host_name in ("127.0.0.1", "localhost", "::1", "testclient"))


def get_session_cookie_flags(handler: BaseHTTPRequestHandler) -> str:
    is_secure = (
        os.environ.get("AGENTSHIELD_SECURE_COOKIES") == "1"
        or is_production_mode()
        or handler.headers.get("X-Forwarded-Proto") == "https"
    )
    secure_flag = "; Secure" if is_secure else ""
    return f"Path=/; HttpOnly; SameSite=Lax{secure_flag}"


def get_csrf_cookie_flags(handler: BaseHTTPRequestHandler) -> str:
    is_secure = (
        os.environ.get("AGENTSHIELD_SECURE_COOKIES") == "1"
        or is_production_mode()
        or handler.headers.get("X-Forwarded-Proto") == "https"
    )
    secure_flag = "; Secure" if is_secure else ""
    return f"Path=/; SameSite=Lax{secure_flag}"


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter for brute-force and DoS defense."""
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.records: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            timestamps = self.records.get(key, [])
            cutoff = now - self.window
            active = [t for t in timestamps if t > cutoff]
            if len(active) >= self.limit:
                self.records[key] = active
                return False
            active.append(now)
            self.records[key] = active
            return True

    def allow(self, key: str) -> bool:
        return self.is_allowed(key)

    def reset(self, key: Optional[str] = None):
        with self._lock:
            if key:
                self.records.pop(key, None)
            else:
                self.records.clear()


login_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)
mcp_limiter = SlidingWindowRateLimiter(limit=int(os.environ.get("AGENTSHIELD_MCP_RATE_LIMIT", 120)), window_seconds=60)


def validate_csrf_token(handler: BaseHTTPRequestHandler, auth_info: Dict[str, Any]) -> bool:
    """
    Validate CSRF token for state-changing requests authenticated via developer session cookie.
    Bearer API tokens are inherently immune to CSRF and bypass this check.
    """
    if not auth_info.get("session_token"):
        return True

    expected_csrf = auth_info.get("csrf_token")
    if not expected_csrf:
        return False

    received_csrf = handler.headers.get("X-CSRF-Token", "").strip()
    if not received_csrf:
        return False
    return hmac.compare_digest(received_csrf, expected_csrf)


def extract_token_from_handler(handler: BaseHTTPRequestHandler) -> str:
    """Extract Bearer token or X-AgentShield-Key header."""
    auth_header = handler.headers.get("Authorization", "").strip()
    api_key_header = handler.headers.get("X-AgentShield-Key", "").strip()
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    if auth_header:
        return auth_header
    if api_key_header:
        return api_key_header
    return ""


def check_admin_auth(handler: BaseHTTPRequestHandler) -> bool:
    """Verify administrator bearer key."""
    token = extract_token_from_handler(handler)
    if not token:
        return False
    return hmac.compare_digest(token, ADMIN_KEY)


def resolve_auth_info(handler: BaseHTTPRequestHandler) -> Optional[Dict[str, Any]]:
    """
    Authenticate caller identity using hashed database credentials or secure developer session.
    Returns dict with project_id, agent_id, role, csrf_token, and developer identity.
    Strictly prevents client identity assertion spoofing.
    """
    # 1. Check HttpOnly developer session cookie (for browser session authentication)
    cookie_header = handler.headers.get("Cookie", "")
    if "agentshield_session=" in cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("agentshield_session="):
                sess_token = part.split("=", 1)[1].strip()
                sess = db.verify_developer_session(sess_token)
                if sess:
                    return {
                        "is_admin": sess.get("role") == "admin",
                        "role": sess.get("role", "developer_admin"),
                        "developer_identity": sess.get("developer_identity", "external-developer"),
                        "owner_identity": sess.get("developer_identity", "external-developer"),
                        "project_id": "proj_session",
                        "agent_id": "dev-browser-user",
                        "session_token": sess_token,
                        "csrf_token": sess.get("csrf_token"),
                    }

    token = extract_token_from_handler(handler)
    if not token:
        return None

    # Check if admin key
    if hmac.compare_digest(token, ADMIN_KEY):
        return {
            "is_admin": True,
            "role": "admin",
            "project_id": "proj_admin",
            "agent_id": "admin-agent",
            "developer_identity": "system-administrator",
            "owner_identity": "system-administrator",
        }

    # Verify against hashed database credentials using constant-time check
    cred = db.verify_credential(token)
    if cred:
        return {
            "is_admin": False,
            "role": cred.get("role", "agent"),
            "project_id": cred["project_id"],
            "agent_id": cred["agent_id"],
            "key_id": cred["key_id"],
            "developer_identity": cred.get("owner_identity", "project-owner"),
            "owner_identity": cred.get("owner_identity", "project-owner"),
        }

    # Development fallback: loopback-only and only when explicitly enabled
    client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
    is_loopback = client_ip in ("127.0.0.1", "::1", "localhost", "testclient")
    if is_dev_mode_enabled() and is_loopback:
        if token == "agentshield-dev-key":
            return {
                "is_admin": False,
                "role": "developer_admin",
                "project_id": "proj_default",
                "agent_id": "dev-agent",
                "key_id": "dev-loopback-key",
                "developer_identity": "local-developer",
                "owner_identity": "local-developer",
            }

    return None


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for concurrent UI updates."""
    daemon_threads = True


class AgentShieldAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "").strip()
        if origin and is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgentShield-Key, X-CSRF-Token, Accept, Mcp-Session-Id, Mcp-Protocol-Version")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version, Retry-After")

    def _send_json_response(
        self,
        status_code: int,
        data: Any,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[str]] = None,
    ):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        if not validate_host_header(self):
            self._send_json_response(400, {"error": "Invalid Host header: Request rejected by AgentShield DNS rebinding firewall."})
            return
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_DELETE(self):
        """Handle DELETE requests (MCP streamable HTTP session termination, Upstream MCP server removal)."""
        if not validate_host_header(self):
            self._send_json_response(400, {"error": "Invalid Host header: Request rejected by AgentShield DNS rebinding firewall."})
            return
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        if path in ("/mcp", "/mcp/", "/mcp/v1"):
            session_id = self.headers.get("Mcp-Session-Id") or self.headers.get("mcp-session-id")
            self.send_response(405)
            self._send_cors_headers()
            if session_id:
                self.send_header("Mcp-Session-Id", session_id)
            self.end_headers()
            return

        parts = [p for p in path.split("/") if p]
        # DELETE /api/projects/<project_id>/upstream
        if len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "upstream":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project upstream access denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Developer management authorization required."})
                return

            db.delete_upstream_server(target_proj_id)
            self._send_json_response(200, {"status": "deleted", "project_id": target_proj_id})
            return

        self._send_json_response(404, {"error": "Not Found", "path": path})

    def do_GET(self):
        if not validate_host_header(self):
            self._send_json_response(400, {"error": "Invalid Host header: Request rejected by AgentShield DNS rebinding firewall."})
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        parts = [p for p in path.split("/") if p]

        # GET /health
        if path == "/health":
            db_ok = True
            try:
                db.get_stats()
            except Exception:
                db_ok = False
            self._send_json_response(200 if db_ok else 503, {
                "status": "healthy" if db_ok else "unhealthy",
                "service": "AgentShield Security Gateway Backend",
                "version": "1.0.0",
                "production_mode": is_production_mode(),
                "started_at": START_TIME,
                "current_time": datetime.now(timezone.utc).isoformat(),
                "database_accessible": db_ok,
                "dev_mode_enabled": is_dev_mode_enabled(),
                "security_controls": {
                    "csrf_protection": True,
                    "dns_rebinding_firewall": True,
                    "rate_limiting": True,
                    "mcp_session_binding": True,
                    "request_body_size_limit_bytes": MAX_REQUEST_BODY_SIZE,
                }
            })

        # GET /api/stats
        elif path == "/api/stats":
            auth_info = resolve_auth_info(self)
            requested_project_id = query_params.get("project_id", [None])[0]
            if requested_project_id:
                if not auth_info:
                    self._send_json_response(401, {"error": "Unauthorized: Authentication required to inspect project statistics."})
                    return
                if not auth_info.get("is_admin"):
                    proj = db.get_project(requested_project_id)
                    dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                    if not proj or (proj.get("owner_identity") != dev_id and auth_info.get("project_id") != requested_project_id):
                        self._send_json_response(403, {"error": "Forbidden: Cannot access another tenant's statistics."})
                        return
                stats = db.get_stats(project_id=requested_project_id)
            elif auth_info and not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                user_projs = db.list_projects(owner_identity=dev_id)
                if user_projs:
                    stats = db.get_stats(project_id=user_projs[0]["project_id"])
                else:
                    stats = db.get_stats(project_id=auth_info.get("project_id"))
            else:
                stats = db.get_stats()
            self._send_json_response(200, stats)

        # GET /api/policies
        elif path == "/api/policies":
            policies = get_all_policies()
            stats = db.get_stats()
            p_breakdown = stats.get("policy_breakdown", {})

            enriched = []
            for p in policies:
                counts = p_breakdown.get(p["code"], {"allowed": 0, "blocked": 0})
                enriched.append({
                    **p,
                    "allowed_count": counts.get("allowed", 0),
                    "blocked_count": counts.get("blocked", 0),
                    "total_enforcements": counts.get("allowed", 0) + counts.get("blocked", 0),
                })

            self._send_json_response(200, {
                "count": len(enriched),
                "policies": enriched,
            })

        # GET /api/events
        elif path == "/api/events":
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Authentication required to inspect audit events."})
                return

            limit = int(query_params.get("limit", [50])[0])
            offset = int(query_params.get("offset", [0])[0])

            # Strictly scope to requested authorized project or caller's project
            requested_proj = query_params.get("project_id", [None])[0]
            if requested_proj:
                if not auth_info.get("is_admin"):
                    proj = db.get_project(requested_proj)
                    dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                    if not proj or (proj.get("owner_identity") != dev_id and auth_info.get("project_id") != requested_proj):
                        self._send_json_response(403, {"error": "Forbidden: Cross-project event access denied."})
                        return
                project_id = requested_proj
            elif not auth_info.get("is_admin"):
                project_id = auth_info.get("project_id")
            else:
                project_id = None

            events = db.get_recent_events(limit=limit, offset=offset, project_id=project_id)
            self._send_json_response(200, {
                "count": len(events),
                "project_scope": project_id or "all",
                "events": events,
            })

        # GET /api/tests
        elif path == "/api/tests":
            latest = db.get_latest_test_run()
            if latest:
                self._send_json_response(200, latest)
            else:
                self._send_json_response(200, {
                    "run_id": None,
                    "total_tests": 0,
                    "passed_tests": 0,
                    "failed_tests": 0,
                    "results": [],
                    "message": "No test runs executed yet. Click 'Run Security Tests' to execute.",
                })

        # GET /mcp (Metadata discovery for Remote MCP clients)
        elif path in ("/mcp", "/mcp/", "/mcp/v1"):
            accept_header = self.headers.get("Accept", "")
            if "text/event-stream" in accept_header and "application/json" not in accept_header:
                self.send_response(405)
                self._send_cors_headers()
                self.end_headers()
                return

            self._send_json_response(200, {
                "endpoint": "/mcp",
                "transport": "streamable-http",
                "protocolVersions": ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"],
                "serverInfo": {
                    "name": "AgentShield-MCP-Firewall",
                    "version": "0.1.0"
                },
                "authRequired": True,
                "supportedAuth": ["Bearer token", "X-AgentShield-Key"],
                "protectedTools": ["read_document", "send_email", "export_data"],
            })

        # GET /api/auth/session (Current developer session and projects)
        elif path == "/api/auth/session":
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(200, {
                    "authenticated": False,
                    "message": "No active developer session.",
                })
                return

            dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity") or "developer"
            is_admin = bool(auth_info.get("is_admin", False))
            projects = db.list_projects(owner_identity=None if is_admin else dev_id)
            self._send_json_response(200, {
                "authenticated": True,
                "developer_identity": dev_id,
                "role": auth_info.get("role", "developer_admin"),
                "is_admin": is_admin,
                "csrf_token": auth_info.get("csrf_token"),
                "projects": projects,
            })

        # GET /api/projects (Scoped to authenticated developer identity, or all for admin)
        elif len(parts) == 2 and parts == ["api", "projects"]:
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Developer session or administrator authorization required."})
                return
            if auth_info.get("role") == "agent":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot list projects."})
                return

            if auth_info.get("is_admin"):
                projects = db.list_projects()
            else:
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                projects = db.list_projects(owner_identity=dev_id)
            self._send_json_response(200, {"count": len(projects), "projects": projects})

        # GET /api/projects/<project_id>
        elif len(parts) == 3 and parts[:2] == ["api", "projects"]:
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return
            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project access denied."})
                    return
            self._send_json_response(200, proj)

        # GET /api/projects/<project_id>/connect (Developer Connect endpoint metadata & SDK example)
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "connect":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid developer session or project token required."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project connection access denied."})
                    return

            events = db.get_recent_events(limit=1, project_id=target_proj_id)
            has_activity = len(events) > 0
            host_header = self.headers.get("Host", "127.0.0.1:8000")
            mcp_url = f"http://{host_header}/mcp"

            self._send_json_response(200, {
                "project_id": target_proj_id,
                "project_name": proj["name"],
                "owner_identity": proj["owner_identity"],
                "mcp_endpoint": mcp_url,
                "transport": "streamable-http",
                "status": "ACTIVE" if has_activity else "READY_FOR_CONNECTION",
                "last_activity": events[0]["timestamp"] if has_activity else None,
                "protocol_versions": ["2025-11-25", "2024-11-05"],
                "protected_tools": [
                    {
                        "name": "read_document",
                        "description": "Read approved operational documents with inline confidentiality firewall.",
                        "policy": "Policy 9 (P-RBAC) & Policy 2 (P-F Confidentiality)"
                    },
                    {
                        "name": "send_email",
                        "description": "Send emails to whitelisted recipient domains with prompt injection filtering.",
                        "policy": "Policy 11 (P-EXFIL) & Policy 1 (P-T Trusted Actions)"
                    },
                    {
                        "name": "export_data",
                        "description": "Export approved data to compliance vaults with side-effect containment.",
                        "policy": "Policy 2 (P-F Permitted Flows) & Policy 17 (P-FAILCLOSED)"
                    }
                ],
                "connection_instructions": [
                    "1. Install the official Model Context Protocol Client SDK: npm install @modelcontextprotocol/sdk",
                    "2. Generate an agent execution credential from the credentials manager below.",
                    f"3. Connect StreamableHTTPClientTransport to {mcp_url} with Authorization: Bearer <AGENT_KEY>.",
                    "4. Discover and call protected tools — all invocations are intercepted and verified against the 25 policies."
                ],
                "sdk_snippet": (
                    'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
                    'import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";\n\n'
                    f'const transport = new StreamableHTTPClientTransport(new URL("{mcp_url}"), {{\n'
                    '  requestInit: {\n'
                    '    headers: {\n'
                    '      "Authorization": "Bearer YOUR_AGENT_KEY",\n'
                    '      "Accept": "application/json, text/event-stream"\n'
                    '    }\n'
                    '  }\n'
                    '});\n\n'
                    'const client = new Client({ name: "my-ai-agent", version: "1.0.0" }, { capabilities: {} });\n'
                    'await client.connect(transport);\n\n'
                    '// Discover protected tools\n'
                    'const { tools } = await client.listTools();\n'
                    'console.log("Connected to AgentShield! Tools:", tools.map(t => t.name));\n\n'
                    '// Safely execute an approved tool\n'
                    'const result = await client.callTool({\n'
                    '  name: "read_document",\n'
                    '  arguments: { document_id: "doc_sample_001" }\n'
                    '});\n'
                    'console.log("Result:", result.content[0].text);'
                )
            })

        # GET /api/projects/<project_id>/policies
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "policies":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project policy access denied."})
                    return

            policies = get_all_policies()
            stats = db.get_stats(project_id=target_proj_id)
            p_breakdown = stats.get("policy_breakdown", {})
            enriched = []
            for p in policies:
                counts = p_breakdown.get(p["code"], {"allowed": 0, "blocked": 0})
                enriched.append({
                    **p,
                    "project_id": target_proj_id,
                    "allowed_count": counts.get("allowed", 0),
                    "blocked_count": counts.get("blocked", 0),
                    "total_enforcements": counts.get("allowed", 0) + counts.get("blocked", 0),
                })
            self._send_json_response(200, {
                "project_id": target_proj_id,
                "count": len(enriched),
                "policies": enriched,
            })

        # GET /api/projects/<project_id>/credentials
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "credentials":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project credential access denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot inspect credential records. Developer management credentials required."})
                return

            creds = db.list_credentials(target_proj_id)
            self._send_json_response(200, {"project_id": target_proj_id, "credentials": creds})

        # GET /api/projects/<project_id>/events
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "events":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project event access denied."})
                    return

            limit = int(query_params.get("limit", [50])[0])
            offset = int(query_params.get("offset", [0])[0])
            events = db.get_recent_events(limit=limit, offset=offset, project_id=target_proj_id)
            self._send_json_response(200, {"project_id": target_proj_id, "count": len(events), "events": events})

        # GET /api/projects/<project_id>/upstream
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "upstream":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project upstream access denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Developer management authorization required to inspect upstream configurations."})
                return

            srv = db.get_upstream_server(target_proj_id)
            if not srv:
                self._send_json_response(200, {"project_id": target_proj_id, "configured": False, "server": None})
                return

            has_token = bool(srv.get("auth_token_encrypted"))
            cached_tools = []
            if srv.get("cached_tools_json"):
                try:
                    cached_tools = json.loads(srv["cached_tools_json"]) if isinstance(srv["cached_tools_json"], str) else srv["cached_tools_json"]
                except Exception:
                    cached_tools = []

            self._send_json_response(200, {
                "project_id": target_proj_id,
                "configured": True,
                "server": {
                    "server_id": srv["server_id"],
                    "project_id": srv["project_id"],
                    "name": srv["name"],
                    "upstream_url": srv["upstream_url"],
                    "auth_type": srv["auth_type"],
                    "has_auth_token": has_token,
                    "masked_token": "••••••••••••" if has_token else None,
                    "tool_prefix": srv.get("tool_prefix", "upstream_"),
                    "is_active": bool(srv.get("is_active", 1)),
                    "created_at": srv.get("created_at"),
                    "updated_at": srv.get("updated_at"),
                    "last_discovered_at": srv.get("last_discovered_at"),
                    "cached_tools": cached_tools,
                    "tools_count": len(cached_tools),
                }
            })

        else:
            self._send_json_response(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        if not validate_host_header(self):
            self._send_json_response(400, {"error": "Invalid Host header: Request rejected by AgentShield DNS rebinding firewall."})
            return

        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_len = 0

        if content_len > MAX_REQUEST_BODY_SIZE:
            self.close_connection = True
            try:
                self.rfile.read(min(content_len, 65536))
            except Exception:
                pass
            self._send_json_response(413, {
                "error": f"Payload Too Large: Request body exceeds maximum allowed size of {MAX_REQUEST_BODY_SIZE} bytes."
            }, extra_headers={"Connection": "close"})
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path
        parts = [p for p in path.split("/") if p]
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # POST /mcp (Remote Streamable HTTP MCP Endpoint with Project-Scoped Auth)
        if path in ("/mcp", "/mcp/", "/mcp/v1"):
            # 1. Enforce localhost constraint during development
            if not is_production_mode() and client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
                self._send_json_response(403, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32003,
                        "message": "Access denied: Remote MCP endpoint restricted to localhost in development mode.",
                    },
                })
                return

            # 2. Enforce Project-Scoped Credential Verification
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32001,
                        "message": "Unauthorized: Missing, invalid, expired, or revoked AgentShield API key.",
                    },
                })
                return

            authenticated_project_id = auth_info["project_id"]
            authenticated_agent_id = auth_info["agent_id"]
            key_id = auth_info.get("key_id", "unspecified")

            # 3. Per-project and per-credential rate limiting
            if not mcp_limiter.allow(f"project:{authenticated_project_id}"):
                self._send_json_response(429, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": f"Rate limit exceeded for project '{authenticated_project_id}'.",
                    },
                }, extra_headers={"Retry-After": "60"})
                return

            if key_id and not mcp_limiter.allow(f"cred:{key_id}"):
                self._send_json_response(429, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": f"Rate limit exceeded for credential '{key_id}'.",
                    },
                }, extra_headers={"Retry-After": "60"})
                return

            # 5. MCP Session Binding & Cross-Project Hijacking Rejection
            incoming_session_id = self.headers.get("Mcp-Session-Id") or self.headers.get("mcp-session-id")
            if incoming_session_id:
                existing_sess = db.get_mcp_session(incoming_session_id)
                if existing_sess:
                    if existing_sess["project_id"] != authenticated_project_id:
                        self._send_json_response(403, {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32003,
                                "message": f"Forbidden: Session '{incoming_session_id}' is bound to project '{existing_sess['project_id']}' and cannot be reused by project '{authenticated_project_id}'.",
                            },
                        }, extra_headers={"Mcp-Session-Id": incoming_session_id})
                        return
                    db.touch_mcp_session(incoming_session_id)
                    session_id = incoming_session_id
                else:
                    db.bind_mcp_session(
                        session_id=incoming_session_id,
                        project_id=authenticated_project_id,
                        agent_id=authenticated_agent_id,
                        key_id=key_id,
                    )
                    session_id = incoming_session_id
            else:
                session_id = f"mcp_sess_{secrets.token_hex(8)}"
                db.bind_mcp_session(
                    session_id=session_id,
                    project_id=authenticated_project_id,
                    agent_id=authenticated_agent_id,
                    key_id=key_id,
                )

            extra_headers = {"Mcp-Session-Id": session_id}

            # 6. Verify active project status
            proj = db.get_project(authenticated_project_id)
            if proj and proj.get("status") in ("suspended", "revoked"):
                self._send_json_response(403, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32003,
                        "message": f"Forbidden: Project '{authenticated_project_id}' is {proj.get('status')} and cannot execute tools.",
                    },
                }, extra_headers=extra_headers)
                return

            # 7. Read and parse JSON-RPC payload
            try:
                if content_len <= 0:
                    self._send_json_response(400, {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error: Empty request body."},
                    }, extra_headers=extra_headers)
                    return
                body = self.rfile.read(content_len)
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self._send_json_response(400, {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error: Invalid JSON payload."},
                }, extra_headers=extra_headers)
                return

            # 8. Dispatch through shared MCP handler with project scoping
            try:
                resp = handle_jsonrpc_message(
                    payload,
                    authenticated_agent_id=authenticated_agent_id,
                    project_id=authenticated_project_id,
                )
                if resp is None:
                    # MCP notification (no id) -> 202 Accepted
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self._send_cors_headers()
                    self.send_header("Mcp-Session-Id", session_id)
                    self.end_headers()
                    self.wfile.write(b'{"status": "accepted"}')
                    return

                self._send_json_response(200, resp, extra_headers=extra_headers)
            except Exception as exc:
                sys.stderr.write(f"[Remote MCP Error] Internal processing error: {exc}\n")
                self._send_json_response(500, {
                    "jsonrpc": "2.0",
                    "id": payload.get("id") if isinstance(payload, dict) else None,
                    "error": {
                        "code": -32603,
                        "message": "Internal gateway error: An unexpected error occurred.",
                    },
                }, extra_headers=extra_headers)

        # POST /api/auth/login (Establish secure HttpOnly developer session with CSRF protection)
        elif path == "/api/auth/login":
            if not login_limiter.allow(f"login:{client_ip}"):
                self._send_json_response(429, {"error": "Too many login attempts. Please wait before retrying."})
                return

            try:
                body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                payload = json.loads(body.decode("utf-8")) if body else {}
                dev_id = payload.get("developer_identity", "").strip() or "dev_primary"
                role = "developer_admin"
                sess = db.create_developer_session(developer_identity=dev_id, role=role)
                session_cookie = f"agentshield_session={sess['session_token']}; {get_session_cookie_flags(self)}"
                csrf_cookie = f"agentshield_csrf={sess['csrf_token']}; {get_csrf_cookie_flags(self)}"
                self._send_json_response(200, {
                    "status": "authenticated",
                    "developer_identity": dev_id,
                    "role": role,
                    "csrf_token": sess["csrf_token"],
                    "expires_at": sess["expires_at"],
                }, cookies=[session_cookie, csrf_cookie])
            except Exception as e:
                self._send_json_response(400, {"error": f"Login failed: {str(e)}"})

        # POST /api/auth/logout (Terminate developer session and clear cookies)
        elif path == "/api/auth/logout":
            cookie_header = self.headers.get("Cookie", "")
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith("agentshield_session="):
                    token = part.split("=", 1)[1].strip()
                    db.invalidate_developer_session(token)
            session_cookie = f"agentshield_session=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; {get_session_cookie_flags(self)}"
            csrf_cookie = f"agentshield_csrf=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; {get_csrf_cookie_flags(self)}"
            self._send_json_response(200, {"status": "logged_out"}, cookies=[session_cookie, csrf_cookie])

        # POST /api/projects (Create new project - Admin or authenticated developer)
        elif len(parts) == 2 and parts == ["api", "projects"]:
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Authentication required to create projects."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return
            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Developer management authorization required."})
                return
            try:
                body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                payload = json.loads(body.decode("utf-8"))
                name = payload.get("name")
                owner_identity = auth_info.get("developer_identity") or payload.get("owner_identity", "external-developer")
                project_id = payload.get("project_id")
                if not name:
                    self._send_json_response(400, {"error": "Project 'name' is required."})
                    return
                proj = db.create_project(name=name, owner_identity=owner_identity, project_id=project_id)
                self._send_json_response(201, proj)
            except Exception as exc:
                self._send_json_response(400, {"error": f"Failed to create project: {str(exc)}"})

        # POST /api/projects/<project_id>/credentials (Issue new high-entropy credential)
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "credentials":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project credential issuance denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot issue credentials. Developer management credentials required."})
                return

            try:
                body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                payload = json.loads(body.decode("utf-8"))
                agent_id = payload.get("agent_id", f"{target_proj_id}-agent")
                role = payload.get("role", "agent")
                expires_in_days = payload.get("expires_in_days", 30)

                cred = db.create_credential(
                    project_id=target_proj_id,
                    agent_id=agent_id,
                    role=role,
                    expires_in_days=expires_in_days,
                )
                self._send_json_response(201, cred)
            except Exception as exc:
                self._send_json_response(400, {"error": f"Failed to issue credential: {str(exc)}"})

        # POST /api/projects/<project_id>/credentials/<key_id>/revoke (Revoke credential)
        elif len(parts) == 6 and parts[:2] == ["api", "projects"] and parts[3] == "credentials" and parts[5] == "revoke":
            target_proj_id = parts[2]
            key_id = parts[4]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project credential revocation denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot revoke credentials. Developer management credentials required."})
                return

            success = db.revoke_credential(key_id=key_id, project_id=target_proj_id)
            if success:
                self._send_json_response(200, {"status": "revoked", "key_id": key_id, "project_id": target_proj_id})
            else:
                self._send_json_response(404, {"error": f"Credential '{key_id}' not found for project '{target_proj_id}'."})

        # POST /api/projects/<project_id>/credentials/<key_id>/rotate (Rotate credential)
        elif len(parts) == 6 and parts[:2] == ["api", "projects"] and parts[3] == "credentials" and parts[5] == "rotate":
            target_proj_id = parts[2]
            key_id = parts[4]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project credential rotation denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot rotate credentials. Developer management credentials required."})
                return

            new_cred = db.rotate_credential(key_id=key_id, project_id=target_proj_id)
            if new_cred:
                self._send_json_response(200, new_cred)
            else:
                self._send_json_response(404, {"error": f"Credential '{key_id}' not found for rotation."})

        # POST /api/projects/<project_id>/upstream/test (Test upstream connectivity & discover tools)
        elif len(parts) == 5 and parts[:2] == ["api", "projects"] and parts[3] == "upstream" and parts[4] == "test":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project upstream access denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Developer management authorization required."})
                return

            srv = db.get_upstream_server(target_proj_id)
            if not srv:
                self._send_json_response(404, {"error": f"No upstream MCP server configured for project '{target_proj_id}'."})
                return

            try:
                assert_valid_upstream_url(srv["upstream_url"])
            except SSRFValidationError as e:
                self._send_json_response(400, {"error": f"SSRF security rejection: {str(e)}"})
                return

            token = ""
            if srv.get("auth_token_encrypted"):
                token = db.decrypt_upstream_secret(srv["auth_token_encrypted"])

            prefix = srv.get("tool_prefix", "upstream_")
            try:
                ok, tools, reason = discover_upstream_tools(srv["upstream_url"], auth_token=token, tool_prefix=prefix)
                if not ok:
                    raise UpstreamMCPError(reason)
                db.update_upstream_cached_tools(target_proj_id, tools)
                self._send_json_response(200, {
                    "status": "connected",
                    "project_id": target_proj_id,
                    "upstream_url": srv["upstream_url"],
                    "tool_prefix": prefix,
                    "tools_count": len(tools),
                    "tools": tools,
                })
            except UpstreamMCPError as e:
                self._send_json_response(502, {"error": f"Upstream MCP connection failed: {str(e)}"})
            except Exception as e:
                self._send_json_response(500, {"error": f"Upstream test error: {str(e)}"})

        # POST /api/projects/<project_id>/upstream (Configure / update upstream server)
        elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "upstream":
            target_proj_id = parts[2]
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Valid project or admin token required."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return

            proj = db.get_project(target_proj_id)
            if not proj:
                self._send_json_response(404, {"error": f"Project '{target_proj_id}' not found."})
                return

            if not auth_info.get("is_admin"):
                dev_id = auth_info.get("developer_identity") or auth_info.get("owner_identity")
                if proj.get("owner_identity") != dev_id and auth_info.get("project_id") != target_proj_id:
                    self._send_json_response(403, {"error": "Forbidden: Cross-project upstream access denied."})
                    return

            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Developer management authorization required."})
                return

            try:
                body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                payload = json.loads(body.decode("utf-8")) if body else {}
                upstream_url = payload.get("upstream_url", "").strip()
                name = payload.get("name", "External MCP Server").strip()
                auth_type = payload.get("auth_type", "bearer")
                auth_token = payload.get("auth_token", "")
                tool_prefix = payload.get("tool_prefix", "upstream_").strip()
                is_active = bool(payload.get("is_active", True))

                if not upstream_url:
                    self._send_json_response(400, {"error": "Upstream URL is required."})
                    return

                # Strict SSRF validation
                try:
                    assert_valid_upstream_url(upstream_url)
                except SSRFValidationError as e:
                    self._send_json_response(400, {"error": f"SSRF security rejection: {str(e)}"})
                    return

                # If auth_token not provided in payload but already exists, preserve existing token
                existing = db.get_upstream_server(target_proj_id)
                final_token = auth_token
                if not auth_token and existing and existing.get("auth_token_encrypted"):
                    final_token = db.decrypt_upstream_secret(existing["auth_token_encrypted"])

                saved = db.save_upstream_server(
                    project_id=target_proj_id,
                    name=name,
                    upstream_url=upstream_url,
                    auth_type=auth_type,
                    auth_token=final_token,
                    tool_prefix=tool_prefix,
                    is_active=is_active,
                )

                # Attempt tool discovery immediately
                discovered_tools = []
                discovery_warning = None
                try:
                    ok, tools, reason = discover_upstream_tools(upstream_url, auth_token=final_token, tool_prefix=tool_prefix)
                    if ok:
                        discovered_tools = tools
                        db.update_upstream_cached_tools(target_proj_id, discovered_tools)
                    else:
                        discovery_warning = f"Server configuration saved, but initial tool discovery failed: {reason}"
                except Exception as disc_err:
                    discovery_warning = f"Server configuration saved, but initial tool discovery failed: {str(disc_err)}"

                has_auth = bool(final_token or saved.get("masked_token"))
                resp = {
                    "status": "configured",
                    "project_id": target_proj_id,
                    "server": {
                        "server_id": saved["server_id"],
                        "name": saved["name"],
                        "upstream_url": saved["upstream_url"],
                        "auth_type": saved["auth_type"],
                        "has_auth_token": has_auth,
                        "masked_token": "••••••••••••" if has_auth else None,
                        "tool_prefix": saved.get("tool_prefix", "upstream_"),
                        "is_active": bool(saved.get("is_active", 1)),
                        "tools_count": len(discovered_tools),
                        "cached_tools": discovered_tools,
                    }
                }
                if discovery_warning:
                    resp["warning"] = discovery_warning
                self._send_json_response(200, resp)
            except Exception as exc:
                self._send_json_response(400, {"error": f"Failed to save upstream configuration: {str(exc)}"})

        # POST /api/tests/run
        elif path == "/api/tests/run":
            auth_info = resolve_auth_info(self)
            if not auth_info:
                self._send_json_response(401, {"error": "Unauthorized: Authentication required to execute security test runner."})
                return
            if not validate_csrf_token(self, auth_info):
                self._send_json_response(403, {"error": "Forbidden: CSRF validation failed. Missing or invalid X-CSRF-Token header."})
                return
            if not auth_info.get("is_admin") and auth_info.get("role") != "developer_admin":
                self._send_json_response(403, {"error": "Forbidden: Agent execution keys cannot trigger security test runner."})
                return

            suite_result = run_test_suite()
            self._send_json_response(200, suite_result)

        # POST /api/gateway/intercept (Manual simulation endpoint - disabled in production)
        elif path == "/api/gateway/intercept":
            if is_production_mode() and not is_dev_mode_enabled():
                self._send_json_response(403, {"error": "Forbidden: Simulation endpoint disabled in production mode."})
                return
            try:
                body = self.rfile.read(content_len) if content_len > 0 else b"{}"
                payload = json.loads(body.decode("utf-8")) if body else {}
                tool_name = payload.get("tool_name", "")
                arguments = payload.get("arguments", {})
                result = dispatch_tool(tool_name=tool_name, arguments=arguments)
                self._send_json_response(200, result)
            except Exception as e:
                self._send_json_response(400, {"error": f"Invalid request: {str(e)}"})

        else:
            self._send_json_response(404, {"error": "Not Found", "path": path})

    def log_message(self, format, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sys.stderr.write(f"[{ts}] [AgentShield] {self.address_string()} - {format % args}\n")


def run_backend(port: int = None, host: str = None):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", "8000"))
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, AgentShieldAPIHandler)
    sys.stderr.write(f"\n🚀 AgentShield Security API running at http://{host}:{port}\n")
    sys.stderr.write(f"Health Check: http://{host}:{port}/health\n")
    sys.stderr.write(f"25 Policies:  http://{host}:{port}/api/policies\n")
    sys.stderr.write(f"Live Events:  http://{host}:{port}/api/events\n")
    sys.stderr.write(f"Real Stats:   http://{host}:{port}/api/stats\n\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down backend server...\n")
        httpd.server_close()


if __name__ == "__main__":
    env_port = int(os.environ.get("PORT", "8000"))
    env_host = os.environ.get("HOST", "0.0.0.0")
    run_backend(port=env_port, host=env_host)

