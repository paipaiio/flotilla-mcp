/**
 * Flotilla 控制台 SPA — talks only to the same-origin gateway:
 *   MCP tool calls over POST /mcp (Streamable HTTP, stateless)
 *   enrollment management  /api/enroll/tokens*
 *   compliance export      /api/audit/export
 * The bearer token lives in sessionStorage and is never sent anywhere else.
 */

const $ = (sel) => document.querySelector(sel);
const token = () => sessionStorage.getItem("flotilla.token");

let rpcId = 0;

/** One stateless MCP JSON-RPC round trip; normalizes SSE/JSON responses. */
async function mcp(method, params) {
  const res = await fetch("/mcp", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token()}`,
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  if (res.status === 401) throw new Error("401: token 无效");
  const text = await res.text();
  const dataLine = text.split(/\r?\n/).find((l) => l.startsWith("data: "));
  const payload = JSON.parse(dataLine ? dataLine.slice(6) : text);
  if (payload.error) throw new Error(`${payload.error.code}: ${payload.error.message}`);
  return payload.result;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      authorization: `Bearer ${token()}`,
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers ?? {}),
    },
  });
  if (res.status === 401) throw new Error("401: token 无效");
  // 403 = token 有效但不是管理员 token（受限 token 只能用 /mcp）——不是登录失效。
  if (res.status === 403) throw new Error("403: 需要管理员 token");
  return res;
}

const isForbidden = (err) => String(err).includes("403");
const FORBIDDEN_ROW = (cols) =>
  `<tr><td colspan="${cols}" class="muted">当前 token 是受限 token，只能执行命令；入网管理和审计导出需要管理员 token。</td></tr>`;

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("zh-CN", { hour12: false });
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ── auth gate ───────────────────────────────────────────────────────────────

function showLogin(message) {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-error").textContent = message ?? "";
}

function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  refreshDashboard();
  refreshEnroll();
}

/** 受限 token 看不到管理员页面：直接隐藏入网/审计导航，而不是点进去才报错。 */
function markScoped(scoped) {
  document.querySelectorAll('#nav button[data-view="enroll"], #nav button[data-view="audit"]').forEach((b) => {
    b.hidden = scoped;
  });
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  sessionStorage.setItem("flotilla.token", $("#login-token").value.trim());
  try {
    // tools/list doubles as the auth check.
    await mcp("tools/list", {});
    showApp();
  } catch (err) {
    sessionStorage.removeItem("flotilla.token");
    showLogin(String(err instanceof Error ? err.message : err));
  }
});

$("#logout").addEventListener("click", () => {
  sessionStorage.removeItem("flotilla.token");
  showLogin();
});

// ── navigation ──────────────────────────────────────────────────────────────

$("#nav").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-view]");
  if (!button) return;
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b === button));
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${button.dataset.view}`).classList.remove("hidden");
  if (button.dataset.view === "dashboard") refreshDashboard();
  if (button.dataset.view === "exec") loadTargetPicker();
  if (button.dataset.view === "enroll") refreshEnroll();
  if (button.dataset.view === "audit") refreshAudit();
});

// ── dashboard ───────────────────────────────────────────────────────────────

async function refreshDashboard() {
  const state = $("#conn-state");
  try {
    const health = await (await fetch("/healthz")).json();
    const list = await mcp("tools/call", { name: "fleet-list", arguments: {} });
    const text = list.content?.[0]?.text ?? "";
    let fleet = null;
    try { fleet = JSON.parse(text); } catch { /* unconfigured engine returns an error text */ }

    const cards = [
      ["引擎", health.engineVersion?.startsWith("configured") ? "已配置" : "未配置"],
      ["服务器", health.servers ?? 0],
      ["入网令牌", health.enrollTokens ?? 0],
      ["审计 sink", health.auditSinks ?? 0],
      ["版本", health.version ?? "—"],
      ["运行", `${health.uptimeSec ?? 0}s`],
    ];
    $("#health-cards").innerHTML = cards
      .map(([k, v]) => `<div class="card"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`)
      .join("");

    const servers = fleet?.servers ?? [];
    $("#fleet-count").textContent = servers.length ? `共 ${servers.length} 台` : "";
    $("#fleet-table tbody").innerHTML = servers
      .map(
        (s) => `<tr>
          <td class="mono">${esc(s.name)}</td>
          <td class="mono">${esc(s.host)}${s.port && s.port !== 22 ? `:${esc(s.port)}` : ""}</td>
          <td>${esc(s.user)}</td>
          <td><span class="tag">${esc(s.group ?? s.tier ?? "")}</span></td>
          <td>${esc(s.role)}</td>
          <td>${(s.tags ?? []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</td>
          <td>${s.readOnly ? "✓" : ""}</td>
        </tr>`,
      )
      .join("");
    state.textContent = "已连接";
    state.className = "pill ok";
  } catch (err) {
    state.textContent = "连接失败";
    state.className = "pill fail";
    if (String(err).includes("401")) showLogin("token 已失效，请重新连接");
  }
}

// ── exec ────────────────────────────────────────────────────────────────────

/** 目标点选器：从 fleet-list 拉服务器，渲染 快捷/服务器/群组/标签 四组 chip，
 *  多选后自动把逗号表达式写回 #exec-target（表达式输入框仍保留，可手改高级语法）。 */
async function loadTargetPicker() {
  const box = $("#target-picker");
  try {
    const list = await mcp("tools/call", { name: "fleet-list", arguments: {} });
    const text = list.content?.[0]?.text ?? "";
    let fleet = null;
    try { fleet = JSON.parse(text); } catch { /* 引擎未配置时返回的是错误文本 */ }
    const servers = fleet?.servers ?? [];
    if (!servers.length) {
      box.innerHTML = `<span class="muted">舰队为空——先入网（flotilla add / join.sh）再回来点选</span>`;
      return;
    }
    const groups = [...new Set(servers.map((s) => s.group ?? s.tier).filter(Boolean))];
    const tags = [...new Set(servers.flatMap((s) => s.tags ?? []))];
    const chip = (value, label, title) =>
      `<button type="button" class="chip" data-target="${esc(value)}" title="${esc(title ?? value)}">${esc(label)}</button>`;
    const groupHtml = (label, chips) =>
      chips.length ? `<span class="chip-group"><span class="chip-label">${esc(label)}</span>${chips.join("")}</span>` : "";
    box.innerHTML =
      groupHtml("快捷", [chip("all", "全部 all")]) +
      groupHtml("服务器", servers.map((s) => chip(s.name, s.name, `${s.user}@${s.host}`))) +
      groupHtml("群组", groups.map((g) => chip(`group:${g}`, g, `group:${g}`))) +
      groupHtml("标签", tags.map((t) => chip(`tag:${t}`, t, `tag:${t}`)));
    renderSelection();
  } catch {
    box.innerHTML = `<span class="muted">加载失败——仍可手动输入目标表达式</span>`;
  }
}

function currentTargets() {
  return $("#exec-target").value.split(",").map((s) => s.trim()).filter(Boolean);
}

/** 唯一状态源是表达式输入框：任何时候 chip 选中态都从它重新推导，
 *  不存在「类名漂移」——悬浮/点选/手改/重新渲染后看到的一定是真的。 */
function renderSelection() {
  const current = currentTargets();
  document.querySelectorAll("#target-picker .chip").forEach((c) => {
    const on = current.includes(c.dataset.target);
    c.classList.toggle("on", on);
    c.setAttribute("aria-pressed", on ? "true" : "false");
  });
}

/** 点选变更 → 拼表达式 + fleet-resolve 实时预览作用范围（防误炸防呆）。
 *  每次预览带序号：慢的旧响应回来时直接丢弃，不会盖住新目标的预览。
 *  返回 { target, hosts } 或 { target, error }，执行前用它做闸门。 */
let previewTimer = null;
let previewSeq = 0;
async function previewTarget(target) {
  const el = $("#target-preview");
  const seq = ++previewSeq;
  const show = (text) => {
    if (seq === previewSeq) el.textContent = text;
  };
  if (!target) {
    show("");
    return { target, error: "请先选择或输入目标" };
  }
  try {
    const res = await mcp("tools/call", { name: "fleet-resolve", arguments: { target } });
    if (res.isError) {
      const error = `目标无效：${res.content?.[0]?.text ?? "unknown"}`;
      show(`⚠ ${error}`);
      return { target, error };
    }
    const hosts = JSON.parse(res.content?.[0]?.text ?? "[]");
    if (!hosts.length) {
      show("⚠ 表达式合法但没有匹配任何服务器");
      return { target, error: "没有匹配任何服务器" };
    }
    show(`将作用于 ${hosts.length} 台：${hosts.map((h) => h.name).join(", ")}`);
    return { target, hosts };
  } catch (err) {
    show("");
    return { target, error: `无法解析目标：${String(err instanceof Error ? err.message : err)}` };
  }
}

function schedulePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(() => previewTarget($("#exec-target").value.trim()), 250);
}

$("#target-picker").addEventListener("click", (event) => {
  const chip = event.target.closest("button.chip");
  if (!chip) return;
  const value = chip.dataset.target;
  let current = currentTargets();
  const i = current.indexOf(value);
  if (i >= 0) current.splice(i, 1);
  // 「全部」和细选互斥：点单台时去掉 all，点 all 时清掉其它——否则 all,web-1 仍是全舰队。
  else if (value === "all") current = ["all"];
  else current = [...current.filter((t) => t !== "all"), value];
  $("#exec-target").value = current.join(",");
  resetApproval();
  renderSelection();
  schedulePreview();
});

/** 批准只对当次命令有效：换目标、换命令、提交后都清掉，不会被下一条继承。 */
function resetApproval() {
  $("#exec-confirm").checked = false;
}

$("#exec-target").addEventListener("input", () => {
  resetApproval();
  renderSelection();
  schedulePreview();
});

$("#exec-command").addEventListener("input", resetApproval);

let execInFlight = false;
$("#exec-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  // 防连点 / Enter 后又点：上一条没回来之前不发第二条。
  if (execInFlight) return;
  const out = $("#exec-output");
  const button = $("#exec-form button[type=submit]");
  const target = $("#exec-target").value.trim();
  const command = $("#exec-command").value.trim();
  const readOnly = $("#exec-readonly").checked;
  const confirm = $("#exec-confirm").checked;
  execInFlight = true;
  button.disabled = true;
  try {
    // 执行前强制用同一个表达式重新解析：看到的范围就是要执行的范围，解析失败不执行。
    clearTimeout(previewTimer);
    out.textContent = `解析目标 ${target} …`;
    const scope = await previewTarget(target);
    if (scope.error) {
      out.textContent = `✗ 未执行：${scope.error}`;
      return;
    }
    const names = scope.hosts.map((h) => h.name).join(", ");
    out.textContent = `▶ ${readOnly ? "exec-read" : "exec"} ${target}（${scope.hosts.length} 台：${names}）:: ${command}\n\n执行中…`;
    const result = await mcp("tools/call", {
      name: readOnly ? "exec-read" : "exec",
      arguments: { target, command, ...(confirm ? { confirm: true } : {}) },
    });
    const text = result.content?.map((c) => c.text ?? "").join("\n") ?? "(无输出)";
    out.textContent = result.isError ? `✗ 被拒绝/失败\n\n${text}` : text;
  } catch (err) {
    out.textContent = `✗ ${String(err instanceof Error ? err.message : err)}`;
  } finally {
    resetApproval();
    execInFlight = false;
    button.disabled = false;
  }
});

// ── enrollment ──────────────────────────────────────────────────────────────

async function refreshEnroll() {
  document.querySelectorAll(".origin").forEach((el) => { el.textContent = location.origin; });
  // 通过 SSH 隧道 / 本机打开时，命令里的地址新机器访问不到——明确提示要换成公网地址。
  const local = /^(localhost|127\.|\[::1\])/.test(location.hostname);
  const warnEl = $("#origin-warning");
  if (warnEl) warnEl.hidden = !local;
  try {
    const res = await api("/api/enroll/tokens");
    const { tokens } = await res.json();
    $("#enroll-table tbody").innerHTML = tokens
      .slice()
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(
        (t) => `<tr>
          <td>${esc(t.name)}</td>
          <td class="mono">${fmtTime(t.createdAt)}</td>
          <td class="mono">${fmtTime(t.expiresAt)}</td>
          <td class="mono">${t.usedCount}/${t.maxUses}</td>
          <td class="mono ${t.revoked ? "outcome-failed" : t.expiresAt < Date.now() ? "muted" : "outcome-ok"}">
            ${t.revoked ? "已吊销" : t.expiresAt < Date.now() ? "已过期" : "有效"}
          </td>
          <td>${t.revoked ? "" : `<button class="danger" data-revoke="${esc(t.id)}">吊销</button>`}</td>
        </tr>`,
      )
      .join("");
    markScoped(false);
  } catch (err) {
    if (isForbidden(err)) {
      markScoped(true);
      $("#enroll-table tbody").innerHTML = FORBIDDEN_ROW(6);
    } else if (String(err).includes("401")) showLogin("token 已失效，请重新连接");
  }
}

$("#enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const res = await api("/api/enroll/tokens", {
    method: "POST",
    body: JSON.stringify({
      name: $("#enroll-name").value.trim(),
      ttlMs: Number($("#enroll-ttl").value) * 60_000,
      maxUses: Number($("#enroll-max").value),
    }),
  });
  const created = await res.json();
  const box = $("#enroll-created");
  box.textContent = `新令牌（只显示这一次）：${created.token}`;
  box.classList.remove("hidden");
  refreshEnroll();
});

$("#enroll-table").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-revoke]");
  if (!button) return;
  await api(`/api/enroll/tokens/${button.dataset.revoke}`, { method: "DELETE" });
  refreshEnroll();
});

// ── audit ───────────────────────────────────────────────────────────────────

function auditQuery(format) {
  const params = new URLSearchParams({ format });
  const tool = $("#audit-tool").value.trim();
  const host = $("#audit-host").value.trim();
  const outcome = $("#audit-outcome").value;
  if (tool) params.set("tool", tool);
  if (host) params.set("host", host);
  if (outcome) params.set("outcome", outcome);
  return params;
}

async function refreshAudit() {
  try {
    const res = await api(`/api/audit/export?${auditQuery("json")}`);
    const records = await res.json();
    $("#audit-table tbody").innerHTML = records
      .map(
        (r) => `<tr>
          <td class="mono">${esc(r.ts)}</td>
          <td><span class="tag">${esc(r.kind)}</span></td>
          <td class="mono">${esc(r.tool)}</td>
          <td class="mono">${esc((r.hosts ?? []).join(", "))}</td>
          <td class="mono outcome-${esc(r.outcome)}">${esc(r.outcome)}</td>
          <td class="mono">${esc(r.command ?? r.reason ?? "")}</td>
        </tr>`,
      )
      .join("");
  } catch (err) {
    if (isForbidden(err)) $("#audit-table tbody").innerHTML = FORBIDDEN_ROW(6);
    else if (String(err).includes("401")) showLogin("token 已失效，请重新连接");
  }
}

$("#audit-form").addEventListener("submit", (event) => {
  event.preventDefault();
  refreshAudit();
});

$("#audit-csv").addEventListener("click", async () => {
  const res = await api(`/api/audit/export?${auditQuery("csv")}`);
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `flotilla-audit-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// ── boot ────────────────────────────────────────────────────────────────────

if (token()) {
  mcp("tools/list", {}).then(showApp).catch(() => showLogin("token 已失效，请重新连接"));
} else {
  showLogin();
}
