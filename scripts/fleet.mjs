#!/usr/bin/env node
// Dev shim: the real CLI ships inside the npm package as the "flotilla" bin.
// Keeping this so existing muscle memory (`node scripts/fleet.mjs ...`) works.
import "../packages/mcp-stdio/bin/fleet.mjs";
