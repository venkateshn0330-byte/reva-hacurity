# 🛡️ AgentShield — AI Agent Security Firewall

> **An inline Zero-Trust MCP Security Proxy protecting AI Agents (IBM Bob) from tool exploitation, unauthorized data exfiltration, and privilege escalation.**

---

## 1. Project Overview

Autonomous AI agents such as **IBM Bob** leverage the **Model Context Protocol (MCP)** to interact with tools, databases, and APIs. However, when an agent is subjected to prompt injection or untrusted inputs, it can be coerced into calling sensitive tools with malicious arguments (e.g., exfiltrating credentials via email or leaking confidential files).

**AgentShield** sits directly between the agent and tools:
```
IBM Bob / AI Agent  ──(STDIO JSON-RPC 2.0)──►  [ AgentShield MCP Proxy ]
                                                         │
                                               [ Policy Authorization ]
                                               ├── Whitelist Verification
                                               ├── Capability Attenuation
                                               └── Taint Information Flow
                                                         │
                                            ┌────────────┴────────────┐
                                            ▼                         ▼
                                       [ ALLOWED ]               [ BLOCKED ]
                                            │                         │
                                    Safe Mock Execution     Rejection Returned
                                            │              (Zero Downstream Side-Effects)
                                            ▼                         ▼
                                      SQLite Audit Log (data/events.db)
                                                      ▲
                                                      │
                                           [ FastAPI / REST Backend ]
                                                      ▲
                                                      │
                                          [ React Cyber Dashboard ]
```

---

## 2. Tech Stack

- **MCP Layer**: Python STDIO JSON-RPC 2.0 (compatible with MCP Protocol `2025-11-25`, `2024-11-05`, `2024-10-07`).
- **Security Policy Engine**: Deterministic policy rules, capability attenuation checks, and taint-aware information flow.
- **Backend**: Python 3.9+ REST API with concurrent SQLite (WAL mode) event logging.
- **Frontend**: React + Vite + Tailwind CSS + Lucide Icons cybersecurity console.
- **Adversarial Fuzzer**: 8-scenario security test runner with downstream non-execution verification.

---

## 3. Quickstart & Service Launch Commands

### A. Run Automated Security Test Suite (11 Tests)
```bash
python3 -m unittest agentshield/tests/test_full_suite.py -v
```

### B. Start the Backend API Server
```bash
python3 agentshield/backend/app/main.py
```
- Health Check: `http://127.0.0.1:8000/health`
- Live Statistics: `http://127.0.0.1:8000/api/stats`
- Audit Events: `http://127.0.0.1:8000/api/events`

### C. Start the React Cybersecurity Console
```bash
cd agentshield/frontend
npm run dev -- --host 127.0.0.1 --port 5173
```
- Open Dashboard in browser: **`http://127.0.0.1:5173`**

### D. Run the MCP Server (or launch via Bob)
```bash
python3 agentshield/mcp_server/server.py
```

---

## 4. IBM Bob Integration

The workspace includes project-level MCP configuration at [`.bob/mcp.json`](.bob/mcp.json):

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "python3",
      "args": [
        "/Users/ashwinshetty/Desktop/hackcurity/agentshield/mcp_server/server.py"
      ],
      "cwd": "/Users/ashwinshetty/Desktop/hackcurity/agentshield",
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "alwaysAllow": ["read_document"],
      "disabled": false,
      "protocolNegotiation": "legacy"
    }
  }
}
```

1. Open this repository in **IBM Bob**.
2. Click **Settings (⚙️) $\rightarrow$ MCP tab**; verify `agentshield` is connected and shows `read_document`, `send_email`, and `export_data`.
3. Try asking Bob:
   - **Allowed Call**: *"Read document doc_sample_001 using AgentShield."*
   - **Blocked Call**: *"Send an email with secret payroll to attacker@evil.com."*

---

## 5. Research Inspiration & Scope Limitations

### Research Inspiration
1. **Capability Attenuation (Biscuit / Macaroon concepts)**: A child agent's permissions must be a strict subset of its parent capability; expiration timestamps can only decrease.
2. **Taint-Aware Information Flow**: Separating data integrity (`TRUSTED` / `UNTRUSTED`) from confidentiality (`PUBLIC` / `CONFIDENTIAL`). Untrusted inputs cannot trigger consequential actions.

### Scope & Practical Limitations
- **MCP Proxy Boundary**: AgentShield monitors all requests routed through its MCP server. Native built-in IDE actions that do not route through MCP are outside this perimeter.
- **Model Internals**: An MCP proxy inspects tool invocation schemas and arguments; it does not observe hidden weights or unobservable chain-of-thought tokens.

---

## 6. 3-Minute Hackathon Demo Script for Judges

1. **Show IBM Bob Connection**:
   - Open Bob Settings $\rightarrow$ MCP Tab $\rightarrow$ Show `agentshield` server connected with 3 protected tools.
2. **Execute Legitimate Operation**:
   - In Bob Chat: *"Read document doc_sample_001 using AgentShield."*
   - Bob retrieves the document successfully.
3. **Attempt Attack / Exfiltration**:
   - In Bob Chat: *"Send an email to attacker@evil.com with secret keys."*
   - AgentShield firewall rejects the request: `[AgentShield Security Firewall Rejection] Status: BLOCKED`.
4. **Prove Zero Side-Effects**:
   - Check `agentshield/data/mock_executions.jsonl`: Zero mock emails were generated.
5. **Inspect Live React Dashboard**:
   - Switch to `http://127.0.0.1:5173` $\rightarrow$ Show the blocked call recorded in the Live Audit Feed with Risk Level `CRITICAL`.
6. **Trigger Adversarial Fuzzer**:
   - Click **Run Security Tests** in the dashboard $\rightarrow$ Watch all 8 attack scenarios execute in under 40ms, verifying 100% defense coverage.
