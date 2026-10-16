/**
 * `flotilla-gateway token create|list|revoke` — offline management of scoped
 * /mcp tokens (only hashes are stored).
 */
import { dirname, join, resolve as resolvePath } from "node:path";
import { defaultConfigPath } from "flotilla-core";
import { addToken, listTokens, revokeToken, type TokenRole } from "./tokens.js";

export function resolveTokensFile(explicit: string | undefined, fleetConfig: string | undefined): string {
  return resolvePath(
    explicit ??
      process.env.FLOTILLA_GATEWAY_TOKENS ??
      join(dirname(fleetConfig ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath()), "gateway-tokens.json"),
  );
}

/** `flotilla-gateway token create|list|revoke` — manage scoped tokens offline. */
export function tokenCommand(argv: string[]): number {
  const [action, ...rest] = argv;
  const flag = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const path = resolveTokensFile(flag("--tokens-file"), flag("--config"));
  const name = rest[0] && !rest[0].startsWith("--") ? rest[0] : undefined;
  try {
    switch (action) {
      case "create": {
        const role = flag("--role") as TokenRole | undefined;
        if (!name || !role) {
          console.error("用法: flotilla-gateway token create <name> --role viewer|operator|admin (--targets a,b | --all)");
          return 2;
        }
        // Whole-fleet access must be asked for explicitly: forgetting --targets
        // must not silently mean "every server".
        const wantsAll = rest.includes("--all");
        if (wantsAll === rest.includes("--targets")) {
          console.error(
            wantsAll
              ? "--targets 和 --all 只能选一个"
              : '请指定范围：--targets "tag:web,group:edge"（只看这些机器），或 --all（全舰队）',
          );
          return 2;
        }
        const targets = wantsAll ? undefined : (flag("--targets") ?? "").split(",").map((t) => t.trim()).filter(Boolean);
        const { token, entry } = addToken(path, { name, maxRole: role, targets });
        console.log(`已创建 token "${entry.name}"（maxRole=${entry.maxRole}${entry.targets ? `, targets=${entry.targets.join(",")}` : ", 全舰队"}）→ ${path}`);
        console.log("明文只显示这一次，请立即保存：");
        console.log(token);
        return 0;
      }
      case "list": {
        const tokens = listTokens(path);
        if (tokens.length === 0) console.log(`(没有受限 token) ${path}`);
        for (const t of tokens) {
          console.log(`${t.name}\tmaxRole=${t.maxRole}\ttargets=${t.targets?.join(",") ?? "(全舰队)"}\tcreated=${t.createdAt ?? "?"}`);
        }
        return 0;
      }
      case "revoke": {
        if (!name) {
          console.error("用法: flotilla-gateway token revoke <name>");
          return 2;
        }
        const removed = revokeToken(path, name);
        console.log(removed ? `已吊销 "${name}"（运行中的网关下一个请求即生效）` : `没有名为 "${name}" 的 token`);
        return removed ? 0 : 1;
      }
      default:
        console.error("用法: flotilla-gateway token create|list|revoke ...");
        return 2;
    }
  } catch (err) {
    console.error(`flotilla-gateway token: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}
