import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      // index.ts is the CLI entrypoint (env/argv wiring); http-server.ts is
      // the reusable, test-covered boundary — same split as flotilla-mcp.
      include: ["src/http-server.ts"],
      reporter: ["text", "json-summary", "lcov"],
      thresholds: {
        statements: 85,
        branches: 80,
        functions: 85,
        lines: 85,
      },
    },
  },
});
