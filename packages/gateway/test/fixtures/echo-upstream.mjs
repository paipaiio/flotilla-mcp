// Test fixture: a minimal stdio MCP server with two tools.
// `echo` returns its arguments verbatim; `boom` always fails.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "echo-upstream", version: "1.0.0" });
server.registerTool(
  "echo",
  { description: "return arguments verbatim", inputSchema: { text: z.string() } },
  async (args) => ({ content: [{ type: "text", text: `echo:${JSON.stringify(args)}` }] }),
);
server.registerTool("boom", { description: "always fails", inputSchema: {} }, async () => ({
  isError: true,
  content: [{ type: "text", text: "boom: deliberate failure" }],
}));
await server.connect(new StdioServerTransport());
