#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-/Users/muskzhou/Documents/kimi/tasks/2026-09-11/02-15-58-f473e680/flotilla-mcp}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
tar -xzf "$HERE/originals.tar.gz" -C "$ROOT"
python3 - "$ROOT" <<'PY2'
from pathlib import Path
import sys
root=Path(sys.argv[1])
for rel in (
    'docs/operations-v0.9.html',
    'packages/core/src/config-apply.ts',
    'packages/core/src/change-set.ts',
    'packages/core/src/credentials.ts',
    'packages/core/src/io.ts',
    'packages/core/src/redaction.ts',
    'packages/core/src/setup-repair.ts',
    'packages/core/test/credentials.test.ts',
    'packages/core/test/config-apply.test.ts',
    'packages/core/test/change-set.test.ts',
    'packages/core/test/fuzz-regression.test.ts',
    'packages/core/test/io.test.ts',
    'packages/core/test/redaction.test.ts',
    'packages/core/test/setup-repair.test.ts',
    'packages/core/test/ssh-memory-transfer.test.ts',
    'packages/core/vitest.config.ts',
    'packages/mcp-stdio/src/command-tools.ts',
    'packages/mcp-stdio/src/credential-broker.ts',
    'packages/mcp-stdio/src/diagnostics.ts',
    'packages/mcp-stdio/src/execution-pipeline.ts',
    'packages/mcp-stdio/src/local-secret-broker.ts',
    'packages/mcp-stdio/src/tool-schemas.ts',
    'packages/mcp-stdio/test/cli-diagnostics.test.ts',
    'packages/mcp-stdio/test/command-tools.test.ts',
    'packages/mcp-stdio/test/config-apply-integration.test.ts',
    'packages/mcp-stdio/test/credential-broker.test.ts',
    'packages/mcp-stdio/test/diagnostics.test.ts',
    'packages/mcp-stdio/test/docs-html.test.ts',
    'packages/mcp-stdio/test/execution-pipeline.test.ts',
    'packages/mcp-stdio/test/local-secret-broker.test.ts',
    'packages/mcp-stdio/test/setup-repair-integration.test.ts',
    'packages/mcp-stdio/test/tools-integration.test.ts',
    'packages/mcp-stdio/vitest.config.ts',
):
    path=root/rel
    if path.exists():path.unlink()
print(f"Restored Flotilla baseline files under {root}")
PY2
