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
  return res;
}

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

$("#exec-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("#exec-output");
  const target = $("#exec-target").value.trim();
  const command = $("#exec-command").value.trim();
  const readOnly = $("#exec-readonly").checked;
  const confirm = $("#exec-confirm").checked;
  out.textContent = `▶ ${readOnly ? "exec-read" : "exec"} ${target} :: ${command}\n\n执行中…`;
  try {
    const result = await mcp("tools/call", {
      name: readOnly ? "exec-read" : "exec",
      arguments: { target, command, ...(confirm ? { confirm: true } : {}) },
    });
    const text = result.content?.map((c) => c.text ?? "").join("\n") ?? "(无输出)";
    out.textContent = result.isError ? `✗ 被拒绝/失败\n\n${text}` : text;
  } catch (err) {
    out.textContent = `✗ ${String(err instanceof Error ? err.message : err)}`;
  }
});

// ── enrollment ──────────────────────────────────────────────────────────────

async function refreshEnroll() {
  document.querySelectorAll(".origin").forEach((el) => { el.textContent = location.origin; });
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
  } catch (err) {
    if (String(err).includes("401")) showLogin("token 已失效，请重新连接");
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
    if (String(err).includes("401")) showLogin("token 已失效，请重新连接");
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
