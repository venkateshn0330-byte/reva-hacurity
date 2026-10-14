"""
AgentShield SQLite Event Store & Audit Database.
Provides thread-safe, concurrent access to security audit records and mock executions.
Shared between the MCP STDIO server, the FastAPI/REST backend, and the adversarial fuzzer.
Records policy_id and policy_code across all 25 AI Agent Security Policies.
"""

import base64
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from typing import Any, Dict, List, Optional

# Locate data directory relative to repository (configurable via AGENTSHIELD_DB_PATH)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DEFAULT_DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.environ.get("AGENTSHIELD_DB_PATH") or os.path.join(DEFAULT_DATA_DIR, "events.db")
DATA_DIR = os.path.dirname(os.path.abspath(DB_PATH))

_lock = threading.Lock()


def _derive_encryption_key() -> bytes:
    master_secret = os.environ.get("AGENTSHIELD_ADMIN_KEY", "agentshield-upstream-keystore-secret-key")
    return hashlib.sha256((master_secret + ":upstream_v1").encode("utf-8")).digest()


def encrypt_upstream_secret(plaintext: str) -> str:
    """Authenticated keystore encryption using CTR-stream with HMAC-SHA256."""
    if not plaintext:
        return ""
    key = _derive_encryption_key()
    iv = secrets.token_bytes(16)
    data = plaintext.encode("utf-8")
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(key + iv + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    ciphertext = bytes(b ^ k for b, k in zip(data, keystream[:len(data)]))
    tag = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(iv + tag + ciphertext).decode("ascii")


def decrypt_upstream_secret(token_encrypted: str) -> str:
    """Authenticated keystore decryption with constant-time HMAC verification."""
    if not token_encrypted:
        return ""
    try:
        raw = base64.b64decode(token_encrypted.encode("ascii"))
        if len(raw) < 48:
            return ""
        iv = raw[:16]
        tag = raw[16:48]
        ciphertext = raw[48:]
        key = _derive_encryption_key()
        expected_tag = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            return ""
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(ciphertext):
            block = hashlib.sha256(key + iv + counter.to_bytes(4, "big")).digest()
            keystream.extend(block)
            counter += 1
        plaintext = bytes(b ^ k for b, k in zip(ciphertext, keystream[:len(ciphertext)]))
        return plaintext.decode("utf-8")
    except Exception:
        return ""


def get_db_connection() -> sqlite3.Connection:
    """Create a connection with WAL mode and security pragmas enabled."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        pass
    return conn


def hash_credential(raw_key: str) -> str:
    """Compute cryptographic SHA-256 digest of API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def init_db() -> None:
    """Initialize security event tables, projects, credentials, and mock execution tables."""
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                # 1. Projects table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS projects (
                        project_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        owner_identity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )

                # 2. Project credentials table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS project_credentials (
                        key_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        key_prefix TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'agent',
                        status TEXT NOT NULL DEFAULT 'active',
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        revoked_at TEXT,
                        FOREIGN KEY (project_id) REFERENCES projects(project_id)
                    );
                    """
                )

                # 3. Security events table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id TEXT DEFAULT 'proj_default',
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

                # 4. Mock executions table
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

                # 5. Test runs table
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

                # 6. Developer sessions table (for secure HttpOnly browser session authentication)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS developer_sessions (
                        session_token TEXT PRIMARY KEY,
                        developer_identity TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'developer_admin',
                        csrf_token TEXT,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    );
                    """
                )

                # 7. MCP sessions table (binds session_id to project to prevent cross-project hijacking)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mcp_sessions (
                        session_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        key_id TEXT,
                        created_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL
                    );
                    """
                )

                # 8. Upstream MCP servers table (configurable per-project proxy destinations)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS upstream_servers (
                        server_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        upstream_url TEXT NOT NULL,
                        auth_type TEXT NOT NULL DEFAULT 'bearer',
                        auth_token_encrypted TEXT,
                        tool_prefix TEXT NOT NULL DEFAULT 'upstream_',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_discovered_at TEXT,
                        cached_tools_json TEXT,
                        FOREIGN KEY (project_id) REFERENCES projects(project_id)
                    );
                    """
                )

                # Migration checks for existing databases
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN policy_id INTEGER DEFAULT 14;")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN policy_code TEXT DEFAULT 'P-AUTHZ';")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN project_id TEXT DEFAULT 'proj_default';")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE security_events ADD COLUMN is_upstream INTEGER DEFAULT 0;")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE project_credentials ADD COLUMN role TEXT DEFAULT 'agent';")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE developer_sessions ADD COLUMN csrf_token TEXT;")
                except Exception:
                    pass

                # Seed default project if absent
                now_iso = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT OR IGNORE INTO projects (project_id, name, owner_identity, status, created_at, updated_at)
                    VALUES ('proj_default', 'Default Local Project', 'dev_primary', 'active', ?, ?)
                    """,
                    (now_iso, now_iso),
                )
                conn.execute(
                    """
                    UPDATE projects SET owner_identity = 'dev_primary'
                    WHERE project_id = 'proj_default' AND owner_identity = 'system-admin';
                    """
                )
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
    project_id: str = "proj_default",
    is_upstream: int = 0,
) -> Dict[str, Any]:
    """
    Log a security decision event into SQLite.
    Sanitizes sensitive payloads to avoid logging secret passwords or confidential bodies.
    Scopes the event strictly to the authenticated project.
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
        "project_id": project_id,
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
        "is_upstream": 1 if is_upstream else 0,
    }

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO security_events (
                        project_id, request_id, timestamp, agent_id, tool_name,
                        resource_or_destination, arguments_json, allowed,
                        reason, risk_level, downstream_status, policy_id, policy_code, is_upstream
                    ) VALUES (
                        :project_id, :request_id, :timestamp, :agent_id, :tool_name,
                        :resource_or_destination, :arguments_json, :allowed,
                        :reason, :risk_level, :downstream_status, :policy_id, :policy_code, :is_upstream
                    )
                    """,
                    record,
                )
                record["id"] = cursor.lastrowid
        finally:
            conn.close()

    return record


# =========================================================================
# PROJECT & CREDENTIAL MANAGEMENT
# =========================================================================

def create_project(name: str, owner_identity: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    """Create a new project tenant in SQLite."""
    init_db()
    if not project_id:
        project_id = f"proj_{secrets.token_hex(6)}"

    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO projects (project_id, name, owner_identity, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', ?, ?)
                    """,
                    (project_id, name, owner_identity, now_iso, now_iso),
                )
            return {
                "project_id": project_id,
                "name": name,
                "owner_identity": owner_identity,
                "status": "active",
                "created_at": now_iso,
                "updated_at": now_iso,
            }
        finally:
            conn.close()


def get_project(project_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve project metadata by project_id."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT project_id, name, owner_identity, status, created_at, updated_at FROM projects WHERE project_id = ?",
                (project_id,),
            ).fetchone()
            if not row:
                return None
            return dict(row)
        finally:
            conn.close()


def list_projects(owner_identity: Optional[str] = None) -> List[Dict[str, Any]]:
    """List registered projects, optionally filtered by owner identity for tenant scoping."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            if owner_identity:
                rows = conn.execute(
                    "SELECT project_id, name, owner_identity, status, created_at, updated_at FROM projects WHERE owner_identity = ? ORDER BY created_at DESC",
                    (owner_identity,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT project_id, name, owner_identity, status, created_at, updated_at FROM projects ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# =========================================================================
# DEVELOPER SESSION MANAGEMENT (FOR SECURE BROWSER AUTHENTICATION)
# =========================================================================

def create_developer_session(
    developer_identity: str,
    role: str = "developer_admin",
    duration_hours: int = 24,
) -> Dict[str, Any]:
    """
    Issue a cryptographically secure session token and CSRF token for browser authentication.
    Stored in SQLite developer_sessions table.
    """
    init_db()
    session_token = f"sess_{secrets.token_urlsafe(32)}"
    csrf_token = secrets.token_hex(24)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires_at_iso = (now + timedelta(hours=duration_hours)).isoformat()

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO developer_sessions (session_token, developer_identity, role, csrf_token, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (session_token, developer_identity, role, csrf_token, now_iso, expires_at_iso),
                )
            return {
                "session_token": session_token,
                "developer_identity": developer_identity,
                "role": role,
                "csrf_token": csrf_token,
                "created_at": now_iso,
                "expires_at": expires_at_iso,
            }
        finally:
            conn.close()


def verify_developer_session(session_token: str) -> Optional[Dict[str, Any]]:
    """
    Verify an incoming session token.
    Returns session dict with csrf_token if valid and not expired.
    """
    if not isinstance(session_token, str) or not session_token:
        return None

    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()

    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT session_token, developer_identity, role, csrf_token, created_at, expires_at
                FROM developer_sessions
                WHERE session_token = ? AND expires_at > ?
                """,
                (session_token, now_iso),
            ).fetchone()
            if not row:
                return None
            return dict(row)
        finally:
            conn.close()


def invalidate_developer_session(session_token: str) -> bool:
    """Invalidate a developer session (logout)."""
    if not isinstance(session_token, str) or not session_token:
        return False

    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cur = conn.execute(
                    "DELETE FROM developer_sessions WHERE session_token = ?",
                    (session_token,),
                )
                return cur.rowcount > 0
        finally:
            conn.close()


# =========================================================================
# MCP SESSION BINDING & HIJACKING PREVENTION
# =========================================================================

def bind_mcp_session(
    session_id: str,
    project_id: str,
    agent_id: str,
    key_id: Optional[str] = None,
) -> bool:
    """
    Bind an MCP session ID to an authenticated project.
    Prevents cross-project session reuse and session hijacking.
    """
    if not session_id or not project_id:
        return False
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO mcp_sessions (session_id, project_id, agent_id, key_id, created_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        last_seen_at = excluded.last_seen_at
                    """,
                    (session_id, project_id, agent_id, key_id, now_iso, now_iso),
                )
            return True
        except Exception:
            return False
        finally:
            conn.close()


def get_mcp_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve metadata for an active MCP session."""
    if not isinstance(session_id, str) or not session_id:
        return None
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT session_id, project_id, agent_id, key_id, created_at, last_seen_at FROM mcp_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def touch_mcp_session(session_id: str) -> None:
    """Update last_seen_at for an active MCP session."""
    if not session_id:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute("UPDATE mcp_sessions SET last_seen_at = ? WHERE session_id = ?", (now_iso, session_id))
        except Exception:
            pass
        finally:
            conn.close()


def update_project_status(project_id: str, status: str) -> bool:
    """Update status of a project ('active', 'suspended', 'revoked')."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cur = conn.execute(
                    "UPDATE projects SET status = ?, updated_at = ? WHERE project_id = ?",
                    (status, now_iso, project_id),
                )
                return cur.rowcount > 0
        finally:
            conn.close()


def create_credential(
    project_id: str,
    agent_id: str,
    role: str = "agent",
    expires_in_days: Optional[int] = 30,
) -> Dict[str, Any]:
    """
    Generate high-entropy API key for project.
    Stores only the SHA-256 digest in SQLite.
    Returns the raw API key once to the caller.
    Roles:
      - 'agent': MCP tool execution only (cannot manage credentials or read admin records).
      - 'developer_admin': Developer management role (can issue/rotate/revoke keys, inspect project).
    """
    init_db()
    project = get_project(project_id)
    if not project:
        raise ValueError(f"Cannot issue credential: Project '{project_id}' not found.")
    if project["status"] != "active":
        raise ValueError(f"Cannot issue credential: Project '{project_id}' is not active ({project['status']}).")

    if role not in ("agent", "developer_admin", "admin"):
        role = "agent"

    raw_entropy = secrets.token_urlsafe(32)
    raw_key = f"ash_live_{raw_entropy}"
    key_hash = hash_credential(raw_key)
    key_id = f"key_{secrets.token_hex(6)}"
    key_prefix = f"{raw_key[:12]}..."

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires_at_iso = (now + timedelta(days=expires_in_days)).isoformat() if expires_in_days else None

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO project_credentials (
                        key_id, project_id, key_hash, key_prefix, agent_id, role, status, created_at, expires_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL)
                    """,
                    (key_id, project_id, key_hash, key_prefix, agent_id, role, now_iso, expires_at_iso),
                )
            return {
                "key_id": key_id,
                "project_id": project_id,
                "raw_key": raw_key,  # High-entropy plaintext secret: only returned upon creation
                "key_prefix": key_prefix,
                "agent_id": agent_id,
                "role": role,
                "status": "active",
                "created_at": now_iso,
                "expires_at": expires_at_iso,
            }
        finally:
            conn.close()


def revoke_credential(key_id: str, project_id: Optional[str] = None) -> bool:
    """Revoke a project credential immediately."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                if project_id:
                    cur = conn.execute(
                        "UPDATE project_credentials SET status = 'revoked', revoked_at = ? WHERE key_id = ? AND project_id = ?",
                        (now_iso, key_id, project_id),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE project_credentials SET status = 'revoked', revoked_at = ? WHERE key_id = ?",
                        (now_iso, key_id),
                    )
                return cur.rowcount > 0
        finally:
            conn.close()


def rotate_credential(
    key_id: str,
    project_id: str,
    expires_in_days: Optional[int] = 30,
) -> Optional[Dict[str, Any]]:
    """Revoke old credential and issue a new high-entropy replacement with preserved role."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT agent_id, role FROM project_credentials WHERE key_id = ? AND project_id = ?",
                (key_id, project_id),
            ).fetchone()
            if not row:
                return None
            agent_id = row["agent_id"]
            role = row["role"] if "role" in row.keys() else "agent"
        finally:
            conn.close()

    revoke_credential(key_id, project_id=project_id)
    return create_credential(project_id=project_id, agent_id=agent_id, role=role, expires_in_days=expires_in_days)


def list_credentials(project_id: str) -> List[Dict[str, Any]]:
    """
    List credentials for a project.
    Never exposes raw keys or hashes.
    """
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            rows = conn.execute(
                """
                SELECT key_id, project_id, key_prefix, agent_id, role, status, created_at, expires_at, revoked_at
                FROM project_credentials
                WHERE project_id = ?
                ORDER BY created_at DESC
                """,
                (project_id,),
            ).fetchall()
            return [
                {
                    **dict(r),
                    "masked_key": f"{r['key_prefix']}****",
                }
                for r in rows
            ]
        finally:
            conn.close()


def get_credential_by_id(key_id: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve non-sensitive metadata for a specific credential."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            if project_id:
                row = conn.execute(
                    """
                    SELECT key_id, project_id, key_prefix, agent_id, role, status, created_at, expires_at, revoked_at
                    FROM project_credentials
                    WHERE key_id = ? AND project_id = ?
                    """,
                    (key_id, project_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT key_id, project_id, key_prefix, agent_id, role, status, created_at, expires_at, revoked_at
                    FROM project_credentials
                    WHERE key_id = ?
                    """,
                    (key_id,),
                ).fetchone()
            if not row:
                return None
            return dict(row)
        finally:
            conn.close()


def verify_credential(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Validate raw API key against stored cryptographic hashes.
    Returns authenticated project, agent identity, and role if valid.
    Uses constant-time comparison to prevent timing side-channels.
    """
    if not isinstance(raw_key, str) or not raw_key:
        return None

    init_db()
    candidate_hash = hash_credential(raw_key)

    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT c.key_id, c.project_id, c.key_hash, c.agent_id, c.role, c.status, c.expires_at,
                       p.name as project_name, p.status as project_status, p.owner_identity
                FROM project_credentials c
                JOIN projects p ON c.project_id = p.project_id
                WHERE c.key_hash = ?
                """,
                (candidate_hash,),
            ).fetchone()

            if not row:
                return None

            # Constant-time comparison
            if not hmac.compare_digest(row["key_hash"], candidate_hash):
                return None

            # Check credential status
            if row["status"] != "active":
                return None

            # Check project status
            if row["project_status"] != "active":
                return None

            # Check expiration
            expires_at = row["expires_at"]
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    if datetime.now(timezone.utc) > exp_dt:
                        return None
                except Exception:
                    return None

            return {
                "key_id": row["key_id"],
                "project_id": row["project_id"],
                "project_name": row["project_name"],
                "agent_id": row["agent_id"],
                "role": row["role"] if "role" in row.keys() and row["role"] else "agent",
                "owner_identity": row["owner_identity"],
            }
        finally:
            conn.close()


def get_recent_events(limit: int = 50, offset: int = 0, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve recent security events, optionally scoped to an authenticated project."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            if project_id:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, request_id, timestamp, agent_id, tool_name,
                           resource_or_destination, arguments_json, allowed,
                           reason, risk_level, downstream_status, policy_id, policy_code,
                           COALESCE(is_upstream, 0) as is_upstream
                    FROM security_events
                    WHERE project_id = ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (project_id, limit, offset),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, project_id, request_id, timestamp, agent_id, tool_name,
                           resource_or_destination, arguments_json, allowed,
                           reason, risk_level, downstream_status, policy_id, policy_code,
                           COALESCE(is_upstream, 0) as is_upstream
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
                    "project_id": r["project_id"] if "project_id" in r.keys() else "proj_default",
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
                    "is_upstream": bool(r["is_upstream"] if "is_upstream" in r.keys() else 0),
                })
            return events
        finally:
            conn.close()


def get_stats(project_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculate real metrics directly from SQLite records, optionally scoped to a project."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            if project_id:
                total = conn.execute("SELECT COUNT(*) FROM security_events WHERE project_id = ?", (project_id,)).fetchone()[0]
                allowed = conn.execute("SELECT COUNT(*) FROM security_events WHERE project_id = ? AND allowed = 1", (project_id,)).fetchone()[0]
                blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE project_id = ? AND allowed = 0", (project_id,)).fetchone()[0]
                tests_run = conn.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0]
                
                cursor = conn.execute(
                    """
                    SELECT tool_name, allowed, COUNT(*) as cnt
                    FROM security_events
                    WHERE project_id = ?
                    GROUP BY tool_name, allowed
                    """,
                    (project_id,),
                )
            else:
                total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
                allowed = conn.execute("SELECT COUNT(*) FROM security_events WHERE allowed = 1").fetchone()[0]
                blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE allowed = 0").fetchone()[0]
                tests_run = conn.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0]

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


# =========================================================================
# UPSTREAM MCP SERVER CONFIGURATION
# =========================================================================

def save_upstream_server(
    project_id: str,
    name: str,
    upstream_url: str,
    auth_type: str = "bearer",
    auth_token: Optional[str] = None,
    tool_prefix: str = "upstream_",
    is_active: bool = True,
) -> Dict[str, Any]:
    """Register or update an upstream MCP server for a project."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    clean_prefix = tool_prefix.strip() if tool_prefix else "upstream_"
    if not clean_prefix.endswith("_"):
        clean_prefix += "_"

    encrypted_token = encrypt_upstream_secret(auth_token) if auth_token else None
    active_int = 1 if is_active else 0

    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                existing = conn.execute(
                    "SELECT server_id, auth_token_encrypted FROM upstream_servers WHERE project_id = ?",
                    (project_id,),
                ).fetchone()

                if existing:
                    server_id = existing["server_id"]
                    # If auth_token not provided on update, retain existing encrypted token
                    token_to_save = encrypted_token if auth_token is not None else existing["auth_token_encrypted"]
                    conn.execute(
                        """
                        UPDATE upstream_servers
                        SET name = ?, upstream_url = ?, auth_type = ?, auth_token_encrypted = ?,
                            tool_prefix = ?, is_active = ?, updated_at = ?
                        WHERE project_id = ?
                        """,
                        (name, upstream_url, auth_type, token_to_save, clean_prefix, active_int, now_iso, project_id),
                    )
                else:
                    server_id = f"up_{secrets.token_hex(6)}"
                    conn.execute(
                        """
                        INSERT INTO upstream_servers (
                            server_id, project_id, name, upstream_url, auth_type,
                            auth_token_encrypted, tool_prefix, is_active, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (server_id, project_id, name, upstream_url, auth_type, encrypted_token, clean_prefix, active_int, now_iso, now_iso),
                    )

            masked_token = (auth_token[:8] + "..." + "****") if auth_token else None
            return {
                "server_id": server_id,
                "project_id": project_id,
                "name": name,
                "upstream_url": upstream_url,
                "auth_type": auth_type,
                "tool_prefix": clean_prefix,
                "is_active": True,
                "masked_token": masked_token,
                "updated_at": now_iso,
            }
        finally:
            conn.close()


def get_upstream_server(project_id: str, decrypt: bool = False) -> Optional[Dict[str, Any]]:
    """Retrieve upstream MCP server configuration for a project."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT server_id, project_id, name, upstream_url, auth_type,
                       auth_token_encrypted, tool_prefix, is_active,
                       created_at, updated_at, last_discovered_at, cached_tools_json
                FROM upstream_servers
                WHERE project_id = ? AND is_active = 1
                """,
                (project_id,),
            ).fetchone()
            if not row:
                return None

            enc_token = row["auth_token_encrypted"]
            raw_token = decrypt_upstream_secret(enc_token) if enc_token else ""

            cached_tools = []
            if row["cached_tools_json"]:
                try:
                    cached_tools = json.loads(row["cached_tools_json"])
                except Exception:
                    cached_tools = []

            masked_token = None
            if raw_token:
                masked_token = (raw_token[:6] + "..." + "****") if len(raw_token) >= 6 else "****"

            res = {
                "server_id": row["server_id"],
                "project_id": row["project_id"],
                "name": row["name"],
                "upstream_url": row["upstream_url"],
                "auth_type": row["auth_type"],
                "auth_token_encrypted": enc_token,
                "tool_prefix": row["tool_prefix"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_discovered_at": row["last_discovered_at"],
                "cached_tools": cached_tools,
                "masked_token": masked_token,
            }
            if decrypt:
                res["raw_auth_token"] = raw_token
            return res
        finally:
            conn.close()


def delete_upstream_server(project_id: str) -> bool:
    """Delete or deactivate upstream MCP server configuration."""
    init_db()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.execute(
                    "DELETE FROM upstream_servers WHERE project_id = ?",
                    (project_id,),
                )
                return cursor.rowcount > 0
        finally:
            conn.close()


def update_upstream_cached_tools(project_id: str, tools_list: List[Dict[str, Any]]) -> bool:
    """Store discovered upstream tools for fast gateway discovery."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE upstream_servers
                    SET cached_tools_json = ?, last_discovered_at = ?, updated_at = ?
                    WHERE project_id = ?
                    """,
                    (json.dumps(tools_list), now_iso, now_iso, project_id),
                )
                return cursor.rowcount > 0
        finally:
            conn.close()
