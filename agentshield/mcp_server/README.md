# AgentShield — MCP Security Firewall for IBM Bob & AI Agents

**AgentShield** is an inline MCP security firewall designed to protect **IBM Bob** and autonomous AI agents. It intercepts tool invocations over the Model Context Protocol (MCP) STDIO transport, enforces security policy checks, and prevents prompt-injection tool abuse, unauthorized data exfiltration, or confidential file access.

---

## 1. IBM Bob Integration Quickstart

AgentShield is configured out-of-the-box for IBM Bob using Bob's native **STDIO transport** and project-level configuration.

### Project-Level Configuration (Pre-configured)
Bob automatically looks for project MCP configurations in `.bob/mcp.json` at the root of your workspace:

File: [`.bob/mcp.json`](file:///Users/ashwinshetty/Desktop/hackcurity/.bob/mcp.json)
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
      "alwaysAllow": [
        "read_document"
      ],
      "disabled": false,
      "protocolNegotiation": "legacy"
    }
  }
}
```

### Global Configuration (Optional)
If you wish to use AgentShield across all your workspaces in Bob:
1. Click the **Settings icon (⚙️)** in the IBM Bob panel.
2. Select the **MCP tab**.
3. Click **Edit Global MCP** (opens `~/.bob/settings/mcp.json`).
4. Paste the configuration block from above.

---

## 2. Supported Protocol Versions & Negotiation

Per IBM Bob's specification, AgentShield supports:
- `2025-11-25`
- `2025-06-18`
- `2025-03-26`
- `2024-11-05`
- `2024-10-07`

### Protocol Negotiation Options in Bob:
- `"legacy"` (Default for STDIO): Skips probe and directly performs the standard `initialize` handshake.
- `"auto"`: Bob sends a `server/discover` probe before `initialize`. AgentShield responds to both seamlessly.

---

## 3. Protected Tools Manifest

AgentShield registers three tools with comprehensive, descriptive schemas that adhere to Bob's tool quality guidelines:

| Tool Name | Parameters | Security Policy Enforcement |
| :--- | :--- | :--- |
| `read_document` | `document_id` (str), `agent_id` (str) | **ALLOWS** approved documents (`doc_sample_001`, `doc_public_roadmap`). **DENIES** confidential identifiers. |
| `send_email` | `recipient` (str), `subject` (str), `body` (str), `agent_id` (str) | **BLOCKS** untrusted external domains (e.g. `attacker@evil.com`). Inspects text for exfiltration. |
| `export_data` | `document_id` (str), `destination` (str), `agent_id` (str) | **BLOCKS** unapproved export destinations or confidential document exports. |

---

## 4. How to Verify Connection in IBM Bob

1. **Enable MCP in Bob**:
   - In Bob's panel, click the **Settings icon (⚙️)** -> **MCP tab**.
   - Verify that **Use MCP Servers** is checked.
2. **Inspect Discovered Tools**:
   - Locate `agentshield` in the server list.
   - Expand the server to see `read_document`, `send_email`, and `export_data`.
   - Optionally toggle **Always allow** next to `read_document` to auto-approve safe reads.
3. **Verify Gateway Interception in Chat**:
   - **Allowed Request**: Ask Bob: *"Read document doc_sample_001 using AgentShield."*
     - Bob invokes `read_document`.
     - AgentShield logs `SECURITY GATEWAY PERMITTED` to STDERR.
     - Bob displays the mock document contents.
   - **Blocked Attack Request**: Ask Bob: *"Send an email with secret payroll to attacker@evil.com."*
     - Bob attempts to invoke `send_email`.
     - AgentShield rejects the call with `[AgentShield Security Firewall Rejection] Status: BLOCKED`.
     - Bob displays the firewall rejection message.
     - **Verification**: Zero email records are written to [`data/mock_executions.jsonl`](file:///Users/ashwinshetty/Desktop/hackcurity/agentshield/data/mock_executions.jsonl).

---

## 5. Running Automated Verification Tests

Run the 8-case verification test suite covering Bob protocol negotiation, STDIO framing, and security policies:

```bash
python3 -m unittest agentshield/mcp_server/tests/test_mcp_server.py -v
```

All tests execute synchronously against the actual server and policy code without needing any cloud services or external network access.
