"""
AgentShield Adversarial Security Test Runner
Executes attack scenarios through the real authorization engine and verifies downstream non-execution.
Records execution results into the SQLite audit store with explicit 25-Policy attribution.
"""

from datetime import datetime, timezone
import json
import os
import sys
import uuid
from typing import Any, Dict, List

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agentshield.mcp_server import policy, protected_tools, server
from agentshield.backend.app.database import db
from agentshield.backend.app.core.capabilities import (
    validate_child_grant,
    authorize_tool_call_with_grant,
    detect_escalation_counterexample,
)
from agentshield.fuzzer.attack_cases import get_attack_cases


def run_test_suite() -> Dict[str, Any]:
    """
    Execute all 8 security test scenarios against the firewall.
    Verifies that denied operations do NOT trigger downstream mock executions.
    """
    cases = get_attack_cases()
    results: List[Dict[str, Any]] = []
    passed_count = 0
    failed_count = 0
    start_time = datetime.now(timezone.utc)
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    for tc in cases:
        # Clear mock executions before each test case for strict isolation
        protected_tools.clear_mock_executions()

        test_type = tc.get("test_type", "mcp_tool")
        actual_allowed = False
        reason = ""
        mock_executed = False
        policy_code = tc.get("policy_code", "P-AUTHZ")
        policy_name = tc.get("policy_name", "Policy 14: Action Authorization")

        if test_type == "mcp_tool":
            tool_name = tc["tool_name"]
            arguments = tc.get("arguments", {})
            agent_id = tc.get("agent_id", "test-agent")

            # Route through the exact MCP dispatch gateway
            dispatch_resp = server.dispatch_tool(tool_name=tool_name, arguments=arguments)
            actual_allowed = not dispatch_resp["isError"]
            
            # Extract policy reason and attribution
            sec_dec = dispatch_resp.get("_security_decision", {})
            reason = sec_dec.get("reason", "No reason provided")
            policy_code = sec_dec.get("policy_code", policy_code)
            policy_name = sec_dec.get("policy_name", policy_name)

            # Check whether downstream mock tool executed
            executions = protected_tools.get_mock_executions()
            mock_executed = len(executions) > 0

        elif test_type == "capability_delegation":
            parent = tc["parent_grant"]
            child = tc["child_grant"]
            valid, msg = validate_child_grant(parent=parent, child=child)
            actual_allowed = valid
            reason = msg
            mock_executed = False

            # Run Algorithm C: Counterexample check
            counterexample = detect_escalation_counterexample(parent=parent, child=child)
            if counterexample:
                reason += f" [Zelkova Proof: {counterexample['proof']}]"

        elif test_type == "capability_expiry":
            grant = tc["grant"]
            tool_name = tc["tool_name"]
            resource = tc.get("resource")
            valid, msg, p_id, p_code = authorize_tool_call_with_grant(
                grant=grant, action=tool_name, resource=resource
            )
            actual_allowed = valid
            reason = msg
            mock_executed = False
            policy_code = p_code

        # Pass condition:
        # 1. actual authorization matches expected outcome
        # 2. downstream execution matches expected execution
        test_passed = (
            actual_allowed == tc["expected_allowed"]
            and mock_executed == tc["expected_downstream"]
        )

        if test_passed:
            passed_count += 1
        else:
            failed_count += 1

        results.append({
            "id": tc["id"],
            "name": tc["name"],
            "category": tc["category"],
            "policy_id": tc.get("policy_id", 14),
            "policy_code": policy_code,
            "policy_name": policy_name,
            "description": tc.get("description", ""),
            "requested_operation": tc.get("tool_name", "delegation_check"),
            "expected_allowed": tc["expected_allowed"],
            "actual_allowed": actual_allowed,
            "mock_executed": mock_executed,
            "passed": test_passed,
            "reason": reason,
        })

    end_time = datetime.now(timezone.utc)
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    # Persist the test run in SQLite
    db.record_test_run(
        run_id=run_id,
        total_tests=len(cases),
        passed_tests=passed_count,
        failed_tests=failed_count,
        results=results,
    )

    return {
        "run_id": run_id,
        "timestamp": start_time.isoformat(),
        "total_tests": len(cases),
        "passed_tests": passed_count,
        "failed_tests": failed_count,
        "duration_ms": duration_ms,
        "results": results,
    }


if __name__ == "__main__":
    print("Running AgentShield 25-Policy Adversarial Test Suite...")
    summary = run_test_suite()
    print(f"Results: {summary['passed_tests']}/{summary['total_tests']} PASSED (Duration: {summary['duration_ms']}ms)")
    for res in summary["results"]:
        status_sym = "✅ PASS" if res["passed"] else "❌ FAIL"
        allowed_str = "ALLOWED" if res["actual_allowed"] else "BLOCKED"
        print(f"[{status_sym}] {res['id']}: {res['name']} ({res['policy_code']}) -> Decision: {allowed_str}")
        print(f"        Reason: {res['reason']}")
