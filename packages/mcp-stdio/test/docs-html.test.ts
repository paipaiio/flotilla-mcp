import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

const htmlPath = resolve(import.meta.dirname, "../../../docs/operations-v0.9.html");
const html = readFileSync(htmlPath, "utf8");

function loadLogic() {
  const source = html.match(/<script id="flotilla-doc-logic">([\s\S]*?)<\/script>/)?.[1];
  expect(source, "embedded documentation logic script").toBeTruthy();
  const context: { window: Record<string, any> } = { window: {} };
  runInNewContext(source!, context);
  return context.window.FlotillaDocs as {
    resolveTargetPreview: (servers: unknown[], groups: unknown[], input: string) => {
      ok: boolean; names: string[]; message: string;
    };
    generateServerConfig: (values: Record<string, unknown>) => { config: string; command: string };
  };
}

describe("interactive operations HTML", () => {
  it("ships one self-contained document app with deep-link tabs and both interactive tools", () => {
    expect(html).toContain('class="doc-shell"');
    expect(html).toContain('data-doc-tab="tools"');
    expect(html).toContain('id="target-expression"');
    expect(html).toContain('id="target-result"');
    expect(html).toContain('id="config-builder"');
    expect(html).toContain('id="generated-config"');
    expect(html).toContain('id="generated-command"');
    expect(html).toContain('id="mcp-repair"');
    expect(html).toContain('credential-status { "target": "all", "repair": true }');
    expect(html).toContain("原来的 SSH 调用重新读取凭证并自动继续");
    expect(html).toContain('id="key-migration"');
    expect(html).toContain('setup-repair { "target": "group:prod", "apply": true }');
    expect(html).toContain("只有验证成功的节点才写入配置");
    expect(html).toContain('id="config-transaction"');
    expect(html).toContain('config-apply { "target": "group:prod"');
    expect(html).toContain("安装后的任一步失败都会恢复备份");
    expect(html).toContain('id="change-sets"');
    expect(html).toContain("生产变更按资源范围审批");
    expect(html).toContain("旧 JIT grant 不会复用");
    expect(html).toContain('id="trusted-secret-flow"');
    expect(html).toContain('"valueFromLocal": true');
    expect(html).toContain("一次性本地页面 → 进程内存 → SHA-256 指纹 → 目标机");
    expect(html).toContain("公开上下文会保留，敏感片段替换为带 SHA-256 指纹和长度的占位符");
    expect(html).toContain("window.addEventListener('hashchange'");
    expect(html).not.toMatch(/<link[^>]+stylesheet|<script[^>]+src=/);
  });

  it("resolves unions, configured groups, tier groups, tags, and exclusions like core", () => {
    const { resolveTargetPreview } = loadLogic();
    const servers = [
      { name: "web-1", group: "prod", tags: ["web", "east"] },
      { name: "web-2", group: "prod", tags: ["web", "west"] },
      { name: "build-1", group: "dev", tags: ["ci", "east"] },
    ];
    const groups = [{ name: "web-prod", match: { group: "prod", tags: ["web"] } }];

    expect(resolveTargetPreview(servers, groups, "group:web-prod !web-2")).toMatchObject({
      ok: true, names: ["web-1"],
    });
    expect(resolveTargetPreview(servers, groups, "group:dev tag:west")).toMatchObject({
      ok: true, names: ["build-1", "web-2"],
    });
  });

  it("returns actionable target errors instead of silently producing an empty fleet", () => {
    const { resolveTargetPreview } = loadLogic();
    const servers = [{ name: "web-1", group: "prod", tags: ["web"] }];
    expect(resolveTargetPreview(servers, [], "!web-1")).toMatchObject({ ok: false, names: [] });
    expect(resolveTargetPreview(servers, [], "group:missing").message).toMatch(/未知分组/);
    expect(resolveTargetPreview(servers, [], "all !web-1").message).toMatch(/没有服务器/);
  });

  it("generates valid-looking TOML and an auth-specific onboarding command without secrets", () => {
    const { generateServerConfig } = loadLogic();
    const generated = generateServerConfig({
      name: 'web-1"quoted', host: "10.0.0.8", user: "deploy", auth: "key",
      keyRef: "~/.ssh/fleet_ed25519", group: "prod", role: "operator",
      serviceManager: "systemd", readOnly: false,
    });
    expect(generated.config).toContain('name = "web-1\\"quoted"');
    expect(generated.config).toContain('keyRef = "~/.ssh/fleet_ed25519"');
    expect(generated.config).toContain('serviceManager = "systemd"');
    expect(generated.command).toContain("--auth key --key ~/.ssh/fleet_ed25519");
    expect(generated.config).not.toMatch(/password\s*=/i);
  });
});
