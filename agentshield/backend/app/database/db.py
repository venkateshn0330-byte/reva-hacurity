"""
AgentShield SQLite Event Store & Audit Database.
Provides thread-safe, concurrent access to security audit records and mock executions.
Shared between the MCP STDIO server, the FastAPI/REST backend, and the adversarial fuzzer.
Records policy_id and policy_code across all 25 AI Agent Security Policies.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

# Locate data directory relative to repository
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "events.db")

_lock = threading.Lock()


def get_db_connection() -> sqlite3.Connection:
    """Create a connection with WAL mode enabled for concurrent read/write."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass
    return conn


def init_db() -> None:
    """Initialize security event tables and mock execution tables."""
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        resource_or_destination TEXT,
                        arguments_json TEXT NOT NULL,
                        allowed INTEGER NOT NULL,
                        reason TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        downstream_status TEXT NOT NULL,
                        policy_id INTEGER DEFAULT 14,
                        policy_code TEXT DEFAULT 'P-AUTHZ'
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mock_executions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        execution_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        arguments_json TEXT NOT NULL,
                        result_summary_json TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS test_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        total_tests INTEGER NOT NULL,
                        passed_tests INTEGER NOT NULL,
                        failed_tests INTEGER NOT NULL,
                        results_json TEXT NOT NULL
                    );
                    """
                )

                # Migration check: ensure policy columns exist if table was created previously
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN policy_id INTEGER DEFAULT 14;")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN policy_code TEXT DEFAULT 'P-AUTHZ';")
                except Exception:
                    pass
        finally:
            conn.close()


def log_security_event(
    request_id: str,
    agent_id: str,
    tool_name: str,
    resource_or_destination: str,
    arguments: Dict[str, Any],
    allowed: bool,
    reason: str,
    risk_level: str,
    downstream_status: str,
    policy_id: int = 14,
    policy_code: str = "P-AUTHZ",
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Log a security decision event into SQLite.
    Sanitizes sensitive payloads to avoid logging secret passwords or confidential bodies.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    # Redact potential secrets in arguments before logging (Policy 12: Secret Protection)
    safe_args = {}
    for k, v in arguments.items():
        if k in ("password", "secret", "token", "api_key", "credential"):
            safe_args[k] = "[REDACTED_BY_AGENTSHIELD]"
        elif k == "body" and isinstance(v, str) and len(v) > 100:
            safe_args[k] = v[:100] + "... [TRUNCATED]"
        else:
            safe_args[k] = v

    record = {
        "request_id": request_id,
        "timestamp": timestamp,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "resource_or_destination": resource_or_destination or "N/A",
        "arguments_json": json.dumps(safe_args),
        "allowed": 1 if allowed else 0,
        "reason": reason,
        "risk_level": risk_level,
        "downstream_status": downstream_status,
        "policy_id": policy_id,
        "policy_code": policy_code,
    }

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO security_events (
                        request_id, timestamp, agent_id, tool_name,
                        resource_or_destination, arguments_json, allowed,
                        reason, risk_level, downstream_status, policy_id, policy_code
                    ) VALUES (
                        :request_id, :timestamp, :agent_id, :tool_name,
                        :resource_or_destination, :arguments_json, :allowed,
                        :reason, :risk_level, :downstream_status, :policy_id, :policy_code
                    )
                    """,
                    record,
                )
                record["id"] = cursor.lastrowid
        finally:
            conn.close()

    return record


def log_mock_execution(
    execution_id: str,
    action_type: str,
    agent_id: str,
    arguments: Dict[str, Any],
    result_summary: Dict[str, Any],
    timestamp: Optional[str] = None,
) -> None:
    """Record that a downstream mock operation actually occurred."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO mock_executions (
                        execution_id, timestamp, action_type,
                        agent_id, arguments_json, result_summary_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        timestamp,
                        action_type,
                        agent_id,
                        json.dumps(arguments),
                        json.dumps(result_summary),
                    ),
                )
        finally:
            conn.close()


def get_recent_events(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieve recent security events in descending chronological order."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            cursor = conn.execute(
                """
                SELECT id, request_id, timestamp, agent_id, tool_name,
                       resource_or_destination, arguments_json, allowed,
                       reason, risk_level, downstream_status, policy_id, policy_code
                FROM security_events
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            events = []
            for r in rows:
                events.append({
                    "id": r["id"],
                    "request_id": r["request_id"],
                    "timestamp": r["timestamp"],
                    "agent_id": r["agent_id"],
                    "tool_name": r["tool_name"],
                    "resource_or_destination": r["resource_or_destination"],
                    "arguments": json.loads(r["arguments_json"]),
                    "allowed": bool(r["allowed"]),
                    "reason": r["reason"],
                    "risk_level": r["risk_level"],
                    "downstream_status": r["downstream_status"],
                    "policy_id": r["policy_id"] if "policy_id" in r.keys() else 14,
                    "policy_code": r["policy_code"] if "policy_code" in r.keys() else "P-AUTHZ",
                })
            return events
        finally:
            conn.close()


def get_stats() -> Dict[str, Any]:
    """Calculate real metrics directly from SQLite records."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            allowed = conn.execute("SELECT COUNT(*) FROM security_events WHERE allowed = 1").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE allowed = 0").fetchone()[0]
            tests_run = conn.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0]

            # Tool breakdown
            cursor = conn.execute(
                """
                SELECT tool_name, allowed, COUNT(*) as cnt
                FROM security_events
                GROUP BY tool_name, allowed
                """
            )
            tool_breakdown = {}
            for row in cursor.fetchall():
                t = row["tool_name"]
                if t not in tool_breakdown:
                    tool_breakdown[t] = {"allowed": 0, "blocked": 0}
                if row["allowed"]:
                    tool_breakdown[t]["allowed"] = row["cnt"]
                else:
                    tool_breakdown[t]["blocked"] = row["cnt"]

            # Policy enforcement breakdown
            policy_breakdown = {}
            try:
                p_cursor = conn.execute(
                    """
                    SELECT policy_code, allowed, COUNT(*) as cnt
                    FROM security_events
                    GROUP BY policy_code, allowed
                    """
                )
                for row in p_cursor.fetchall():
                    pcode = row["policy_code"] or "P-AUTHZ"
                    if pcode not in policy_breakdown:
                        policy_breakdown[pcode] = {"allowed": 0, "blocked": 0}
                    if row["allowed"]:
                        policy_breakdown[pcode]["allowed"] = row["cnt"]
                    else:
                        policy_breakdown[pcode]["blocked"] = row["cnt"]
            except Exception:
                pass

            return {
                "total_requests": total,
                "allowed_requests": allowed,
                "blocked_requests": blocked,
                "tests_completed": tests_run,
                "tool_breakdown": tool_breakdown,
                "policy_breakdown": policy_breakdown,
                "database_path": DB_PATH,
            }
        finally:
            conn.close()


def record_test_run(
    run_id: str,
    total_tests: int,
    passed_tests: int,
    failed_tests: int,
    results: List[Dict[str, Any]],
) -> None:
    """Store test runner execution output."""
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO test_runs (
                        run_id, timestamp, total_tests, passed_tests, failed_tests, results_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, now, total_tests, passed_tests, failed_tests, json.dumps(results)),
                )
        finally:
            conn.close()


def get_latest_test_run() -> Optional[Dict[str, Any]]:
    """Retrieve the most recent security test run."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT run_id, timestamp, total_tests, passed_tests, failed_tests, results_json
                FROM test_runs
                ORDER BY id DESC LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            return {
                "run_id": row["run_id"],
                "timestamp": row["timestamp"],
                "total_tests": row["total_tests"],
                "passed_tests": row["passed_tests"],
                "failed_tests": row["failed_tests"],
                "results": json.loads(row["results_json"]),
            }
        finally:
            conn.close()
