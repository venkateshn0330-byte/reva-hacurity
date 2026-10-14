/**
 * Independent MCP SDK Client Integration Runner
 * Uses official @modelcontextprotocol/sdk to connect to local Streamable HTTP /mcp endpoint.
 */

const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js");

async function main() {
  const apiKey = process.env.AGENTSHIELD_TEST_KEY || process.argv[2];
  if (!apiKey) {
    console.error("Missing AGENTSHIELD_TEST_KEY");
    process.exit(1);
  }

  const endpointUrl = process.env.AGENTSHIELD_ENDPOINT || "http://127.0.0.1:8000/mcp";
  const url = new URL(endpointUrl);

  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: {
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Accept": "application/json, text/event-stream"
      }
    }
  });

  const client = new Client(
    { name: "independent-mcp-inspector-client", version: "1.0.0" },
    { capabilities: {} }
  );

  // 1. Connect and initialize session
  await client.connect(transport);
  if (!transport.sessionId) {
    throw new Error("Missing sessionId in StreamableHTTPClientTransport after initialization");
  }

  // 2. Discover tools
  const toolsResult = await client.listTools();
  if (!toolsResult.tools || toolsResult.tools.length === 0) {
    throw new Error("tools/list returned 0 tools");
  }

  // 3. Call authorized sandbox tool
  const authCall = await client.callTool({
    name: "read_document",
    arguments: { document_id: "doc_sample_001" }
  });
  if (authCall.isError) {
    throw new Error("Authorized tool execution was unexpectedly blocked");
  }

  // 4. Call unauthorized confidential tool
  const unauthCall = await client.callTool({
    name: "read_document",
    arguments: { document_id: "confidential_payroll_2026.pdf" }
  });
  if (!unauthCall.isError) {
    throw new Error("Unauthorized tool execution was unexpectedly permitted");
  }

  // 5. Clean teardown
  await client.close();
  console.log("MCP_SDK_SUCCESS");
}

main().catch(err => {
  console.error("MCP_SDK_ERROR:", err);
  process.exit(1);
});
