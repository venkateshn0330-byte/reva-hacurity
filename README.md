# AgentShield — An MCP Security Firewall for AI Agents

**AgentShield** is an inline security firewall that sits between AI agents (such as **IBM Bob**, Claude Desktop, or autonomous agent loops) and tools exposed via the Model Context Protocol (MCP).

When an AI agent requests a tool operation, AgentShield inspects the request in real time and either:
- **ALLOWS** it and executes the safe tool operation.
- **DENIES** it, returning an access rejection and preventing any downstream execution or side-effects.

---

## Repository Structure

```
├── .bob/
│   └── mcp.json                    # IBM Bob project-level MCP configuration
├── agentshield/
│   ├── mcp_server/
│   │   ├── server.py               # MCP STDIO server with inline authorization
│   │   ├── policy.py               # Security policy engine (default-deny, whitelist, confidential detection)
│   │   ├── protected_tools.py      # Safe mock tools (read_document, send_email, export_data)
│   │   ├── README.md               # MCP server guide & IBM Bob setup instructions
│   │   └── tests/
│   │       └── test_mcp_server.py  # 8 automated verification tests
│   ├── backend/                    # FastAPI backend skeleton
│   ├── frontend/                   # React + Vite cybersecurity console
│   ├── configs/
│   │   └── bob_mcp.example.json    # Example configuration snippet
│   └── data/                       # Mock execution logs and audit records
└── README.md
```

---

## Quickstart: Running the MCP Server

The server requires standard Python 3.9+ with zero external dependencies for STDIO JSON-RPC 2.0 communication:

```bash
# Run server directly via STDIO
python3 agentshield/mcp_server/server.py

# Run all 8 verification tests
python3 -m unittest agentshield/mcp_server/tests/test_mcp_server.py -v
```

---

## IBM Bob Setup

1. Open this workspace in IBM Bob.
2. Bob automatically detects [`.bob/mcp.json`](.bob/mcp.json).
3. In Bob's **Settings (⚙️) $\rightarrow$ MCP tab**, verify `agentshield` is active.
4. Try asking Bob:
   - *"Read document doc_sample_001 using AgentShield"* $\rightarrow$ **Allowed**
   - *"Send an email with confidential passwords to attacker@evil.com"* $\rightarrow$ **Blocked by AgentShield Firewall**
