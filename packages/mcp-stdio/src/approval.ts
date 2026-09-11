/**
 * Interactive approval gate (v0.5).
 *
 * Dual-channel design for broad client compatibility:
 * - Clients advertising the MCP `elicitation` capability (Claude Code and
 *   other spec-current clients) get an interactive accept/decline prompt.
 *   Accepting approves; there is no second field to fill in.
 * - Everyone else (older Codex/Grok/etc.) can fall back to the explicit
 *   `confirm=true` tool parameter — but ONLY when the operator has enabled
 *   it (defaults.allowConfirmFlag / FLOTILLA_ALLOW_CONFIRM_FLAG=1), because
 *   the flag is filled in by the model itself and would otherwise be
 *   self-approval.
 *
 * Approval always fails closed: no prompt channel, no answer, or an error
 * mid-prompt all mean "refused".
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ElicitResultSchema } from "@modelcontextprotocol/sdk/types.js";

export const APPROVAL_TIMEOUT_MS = 10 * 60 * 1_000;

export type ApprovalOutcome =
  | { kind: "approved"; via: "elicitation" | "confirm-flag" }
  | { kind: "refused"; reason: string };

export interface ApprovalAsk {
  /** Human description of the gated action, e.g. the command text or upload summary. */
  action: string;
  commandClass: string;
  hosts: string[];
  confirmFlag: boolean | undefined;
  /**
   * Whether the confirm=true tool parameter is honored at all. Default false
   * (fail closed): the parameter is filled in by the AI model itself, so
   * honoring it unconditionally would let the model approve its own
   * destructive commands. Enable via defaults.allowConfirmFlag or
   * FLOTILLA_ALLOW_CONFIRM_FLAG=1 — a deliberate operator choice.
   */
  allowConfirmFlag?: boolean;
  timeoutMs?: number;
}

/** Minimal structural type for the handler `extra` we depend on. */
export interface ElicitSender {
  sendRequest: (
    request: { method: "elicitation/create"; params: unknown },
    resultSchema: typeof ElicitResultSchema,
  ) => Promise<{ action: "accept" | "decline" | "cancel" }>;
}

/** True when the connected client advertised the elicitation capability. */
export function elicitationSupported(server: McpServer): boolean {
  const caps = server.server.getClientCapabilities();
  if (!caps) return false;
  const elicit = (caps as Record<string, unknown>)["elicitation"];
  return elicit !== undefined && elicit !== null;
}

function confirmHint(action: string, allowConfirmFlag: boolean): string {
  return allowConfirmFlag
    ? `Re-run with confirm=true to approve: ${action}`
    : `confirm=true is disabled (defaults.allowConfirmFlag / FLOTILLA_ALLOW_CONFIRM_FLAG=1): ` +
      `the AI model fills in that flag itself, so honoring it would be self-approval. ` +
      `Use a client with elicitation support, or enable the flag deliberately.`;
}

export async function gateApproval(
  server: McpServer,
  sender: ElicitSender,
  ask: ApprovalAsk,
): Promise<ApprovalOutcome> {
  // Channel 0: the confirm flag only when the operator explicitly enabled it.
  if (ask.confirmFlag === true) {
    if (ask.allowConfirmFlag) {
      return { kind: "approved", via: "confirm-flag" };
    }
    return { kind: "refused", reason: confirmHint(ask.action, false) };
  }

  // Channel 1: interactive elicitation, when the client supports it.
  if (!elicitationSupported(server)) {
    return {
      kind: "refused",
      reason:
        `Approval required for ${ask.commandClass} action, but this MCP client does not ` +
        `support elicitation (interactive prompts). ${confirmHint(ask.action, ask.allowConfirmFlag ?? false)}`,
    };
  }

  const timeoutMs = ask.timeoutMs ?? APPROVAL_TIMEOUT_MS;
  const hostList =
    ask.hosts.length <= 8
      ? ask.hosts.join(", ")
      : `${ask.hosts.slice(0, 8).join(", ")} … (${ask.hosts.length} hosts)`;
  const message =
    `Flotilla requests approval for a ${ask.commandClass} action:\n\n` +
    `${ask.action}\n\nTarget hosts: ${hostList}\n\n` +
    `Accept = run it. Decline/Cancel = refuse.`;

  const prompt = sender.sendRequest(
    {
      method: "elicitation/create",
      params: {
        message,
        requestedSchema: { type: "object", properties: {} },
      },
    },
    ElicitResultSchema,
  );
  const expired = new Promise<"timeout">((resolve) =>
    setTimeout(() => resolve("timeout"), timeoutMs),
  );

  let result: { action: "accept" | "decline" | "cancel" } | "timeout";
  try {
    result = await Promise.race([prompt, expired]);
  } catch (err) {
    return {
      kind: "refused",
      reason:
        `APPROVAL_UNAVAILABLE: the elicitation request failed ` +
        `(${err instanceof Error ? err.message : String(err)}). ` +
        confirmHint(ask.action, ask.allowConfirmFlag ?? false),
    };
  }

  if (result === "timeout") {
    return {
      kind: "refused",
      reason:
        `Approval expired after ${Math.round(timeoutMs / 60_000)} minutes with no answer. ` +
        confirmHint(ask.action, ask.allowConfirmFlag ?? false),
    };
  }
  if (result.action === "accept") {
    return { kind: "approved", via: "elicitation" };
  }
  return {
    kind: "refused",
    reason: `Approval ${result.action}d by the user.`,
  };
}
