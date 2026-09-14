import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      // index.ts is exercised in a real child process by tools-integration.test.ts;
      // this in-process gate covers the reusable execution boundary modules.
      include: [
        "src/approval.ts",
        "src/command-tools.ts",
        "src/credential-broker.ts",
        "src/diagnostics.ts",
        "src/execution-pipeline.ts",
        "src/local-secret-broker.ts",
        "src/tool-schemas.ts",
      ],
      reporter: ["text", "json-summary", "lcov"],
      thresholds: {
        statements: 90,
        branches: 80,
        functions: 90,
        lines: 90,
      },
    },
  },
});
