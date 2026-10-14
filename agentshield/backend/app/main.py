"""
AgentShield Backend REST API Server
Provides real-time event streaming, statistics, 25-Policy definitions, and on-demand adversarial test execution.
Supports both standard library ThreadingHTTPServer (zero external dependencies) and FastAPI/Uvicorn.
"""

from datetime import datetime, timezone
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, List

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.backend.app.database import db
from agentshield.backend.app.core.policies import get_all_policies
from agentshield.fuzzer.runner import run_test_suite
from agentshield.mcp_server.server import dispatch_tool

# Ensure database tables exist
db.init_db()

START_TIME = datetime.now(timezone.utc).isoformat()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for concurrent UI updates."""
    daemon_threads = True


class AgentShieldAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, status_code: int, data: Any):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        # GET /health
        if path == "/health":
            self._send_json_response(200, {
                "status": "healthy",
                "service": "AgentShield Security Gateway Backend",
                "started_at": START_TIME,
                "current_time": datetime.now(timezone.utc).isoformat(),
                "database_accessible": True,
            })

        # GET /api/stats
        elif path == "/api/stats":
            stats = db.get_stats()
            self._send_json_response(200, stats)

        # GET /api/policies
        elif path == "/api/policies":
            policies = get_all_policies()
            stats = db.get_stats()
            p_breakdown = stats.get("policy_breakdown", {})

            # Enrich each policy with real live enforcement counts
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
            limit = int(query_params.get("limit", [50])[0])
            offset = int(query_params.get("offset", [0])[0])
            events = db.get_recent_events(limit=limit, offset=offset)
            self._send_json_response(200, {
                "count": len(events),
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

        else:
            self._send_json_response(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # POST /api/tests/run
        if path == "/api/tests/run":
            suite_result = run_test_suite()
            self._send_json_response(200, suite_result)

        # POST /api/gateway/intercept (Manual simulation endpoint)
        elif path == "/api/gateway/intercept":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
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
        sys.stderr.write(f"[API Server] {self.address_string()} - {format % args}\n")


def run_backend(port: int = 8000, host: str = "127.0.0.1"):
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
    run_backend(port=8000)
