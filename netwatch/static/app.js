/* Network Watchdog dashboard — vanilla JS, polls the JSON API. */
"use strict";

const SPARKS = {
  wan: { metric: "wan.ping.latency_ms", label: "ping latency (ms, 24h)" },
  unifi: { metric: "unifi.www.latency_ms", label: "gateway latency (ms, 24h)" },
  ha: { metric: "ha.api_latency_ms", label: "API latency (ms, 24h)" },
  adguard: { metric: "adguard.avg_processing_ms", label: "DNS processing (ms, 24h)" },
  docker: { metric: "docker.containers_running", label: "running containers (24h)" },
  truenas: { metric: "truenas.host.cpu_pct", label: "host CPU % (24h)" },
};

const CHIPS = {
  wan: [["wan.ping.latency_ms", "ping", "ms"]],
  unifi: [
    ["unifi.clients", "clients", ""],
    ["unifi.devices_upgradable", "updates", ""],
    ["unifi.www.xput_down_mbps", "down", "Mbps"],
  ],
  ha: [
    ["ha.entities_total", "entities", ""],
    ["ha.entities_unavailable", "unavailable", ""],
    ["ha.updates_available", "updates", ""],
  ],
  adguard: [
    ["adguard.queries_24h", "queries/24h", ""],
    ["adguard.blocked_pct", "blocked", "%"],
    ["adguard.avg_processing_ms", "avg", "ms"],
  ],
  docker: [
    ["docker.containers_running", "running", ""],
    ["docker.containers_total", "total", ""],
  ],
  truenas: [
    ["truenas.host.cpu_pct", "CPU", "%"],
    ["truenas.host.mem_pct", "RAM", "%"],
    ["truenas.pool.used_pct", "pool", "%"],
  ],
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function ago(ts, now) {
  const s = Math.max(0, (now ?? Date.now() / 1000) - ts);
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172800) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}
const fmtNum = (v) => Math.abs(v) >= 1000
  ? Math.round(v).toLocaleString()
  : (Math.abs(v) >= 10 || Number.isInteger(v) ? Math.round(v) : v.toFixed(1));

function sparkline(series) {
  const all = series.flatMap((s) => s.points);
  if (all.length < 2) return "";
  const xs = all.map((p) => p[0]), ys = all.map((p) => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const y0 = Math.min(...ys), y1 = Math.max(...ys);
  const W = 600, H = 42, PAD = 2;
  const sx = (x) => PAD + (x - x0) / (x1 - x0 || 1) * (W - 2 * PAD);
  const sy = (y) => H - PAD - (y - y0) / (y1 - y0 || 1) * (H - 2 * PAD - 10);
  const lines = series.slice(0, 4).map((s) => {
    const pts = s.points.map((p) => `${sx(p[0]).toFixed(1)},${sy(p[1]).toFixed(1)}`).join(" ");
    return `<polyline points="${pts}"/>`;
  }).join("");
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    ${lines}<text x="${PAD}" y="10">${fmtNum(y1)}</text>
    <text x="${PAD}" y="${H - 3}">${fmtNum(y0)}</text></svg>`;
}

function chipHtml(metrics, gid) {
  const defs = CHIPS[gid] || [];
  const chips = [];
  for (const [metric, label, unit] of defs) {
    const entries = metrics[metric];
    if (!entries) continue;
    if (entries.length === 1) {
      chips.push(`<span class="chip">${esc(label)} <b>${fmtNum(entries[0].value)}${unit}</b></span>`);
    } else {
      for (const e of entries.slice(0, 4)) {
        const lv = Object.values(e.labels)[0] || "";
        chips.push(`<span class="chip">${esc(label)} ${esc(lv)} <b>${fmtNum(e.value)}${unit}</b></span>`);
      }
    }
  }
  return chips.length ? `<div class="chips">${chips.join("")}</div>` : "";
}

function checksHtml(checks, now) {
  const bad = checks.filter((c) => c.status !== "ok");
  const ok = checks.filter((c) => c.status === "ok");
  const row = (c) => `
    <div class="check">
      <span class="dot ${c.status}"></span>
      <span class="name">${esc(c.meta.name || c.key)}</span>
      <span class="msg">${esc(c.message)} · ${ago(c.since, now)}${c.flapping ? ' <span class="flap">⚡flapping</span>' : ""}</span>
    </div>`;
  let html = `<div class="checks">${bad.map(row).join("")}`;
  if (ok.length) {
    html += `<button class="more-toggle" data-n="${ok.length}">▸ ${ok.length} healthy check${ok.length > 1 ? "s" : ""}</button>
      <div class="checks hidden">${ok.map(row).join("")}</div>`;
  }
  return html + "</div>";
}

function renderGroups(data, sparkData) {
  const now = data.app.now;
  $("groups").innerHTML = data.groups.map((g) => {
    const spark = SPARKS[g.id];
    const series = spark && sparkData[spark.metric];
    return `<div class="card">
      <h3><span class="dot ${g.status}"></span>${esc(g.label)}</h3>
      ${chipHtml(data.metrics, g.id)}
      ${checksHtml(g.checks, now)}
      ${series && series.length ? sparkline(series) + `<div class="muted">${esc(spark.label)}</div>` : ""}
    </div>`;
  }).join("");
  document.querySelectorAll(".more-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const div = btn.nextElementSibling;
      div.classList.toggle("hidden");
      btn.textContent = (div.classList.contains("hidden") ? "▸ " : "▾ ") +
        `${btn.dataset.n} healthy check${btn.dataset.n > 1 ? "s" : ""}`;
    });
  });
}

function detailCell(i) {
  let html = esc(i.detail);
  if (i.analysis) html += `<div class="analysis">🧠 ${esc(i.analysis)}</div>`;
  return html;
}

function renderIncidents(data) {
  const now = data.app.now;
  const open = data.incidents.open.filter((i) => i.kind !== "prediction");
  const rows = [];
  for (const i of open) {
    rows.push(`<tr class="sev-${i.severity}">
      <td>🔴 ${esc(i.title)} <button class="ai-btn" data-id="${i.id}" title="AI analysis">🧠</button></td>
      <td>${detailCell(i)}</td>
      <td>open ${ago(i.opened, now)}${i.root_cause ? ` · caused by ${esc(i.root_cause)}` : ""}</td></tr>`);
  }
  for (const i of data.incidents.recent) {
    rows.push(`<tr>
      <td>✅ ${esc(i.title)}</td><td>${detailCell(i)}</td>
      <td>resolved ${ago(i.closed, now)} ago after ${ago(i.opened, i.closed)}</td></tr>`);
  }
  $("incidents").innerHTML = rows.length
    ? `<table><tr><th>Incident</th><th>Detail</th><th>When</th></tr>${rows.join("")}</table>`
    : `<div class="empty">No incidents. All quiet. 🌙</div>`;
  document.querySelectorAll(".ai-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "⏳";
      const r = await fetch(`/api/incidents/${btn.dataset.id}/analyze`, { method: "POST" });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) alert(body.message || "analysis failed");
      refresh();
    });
  });
}

function renderPredictions(data) {
  const preds = data.incidents.open.filter((i) => i.kind === "prediction");
  $("predictions-section").classList.toggle("hidden", preds.length === 0);
  $("predictions").innerHTML = preds.map((p) =>
    `<div class="prediction"><strong>${esc(p.title)}</strong><br>${esc(p.detail)}</div>`
  ).join("");
}

function renderApprovals(data) {
  const now = data.app.now;
  $("approvals-section").classList.toggle("hidden", data.approvals.length === 0);
  $("approvals").innerHTML = data.approvals.map((a) => `
    <div class="approval">
      <div><strong>${esc(a.label)}</strong>
        <div class="muted">requested ${ago(a.created, now)} ago · expires in ${ago(now, a.expires)}</div></div>
      <div class="btns">
        <button class="approve" data-id="${a.id}" data-token="${esc(a.token)}" data-act="approve">Approve</button>
        <button class="deny" data-id="${a.id}" data-token="${esc(a.token)}" data-act="deny">Deny</button>
      </div>
    </div>`).join("");
  document.querySelectorAll(".approval button").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const r = await fetch(`/api/actions/${btn.dataset.id}/${btn.dataset.act}?token=${encodeURIComponent(btn.dataset.token)}`,
        { method: "POST" });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) alert(body.message || "failed");
      refresh();
    });
  });
}

function renderAudit(data) {
  const now = data.app.now;
  $("audit").innerHTML = data.audit.length
    ? `<table><tr><th>When</th><th>Action</th><th>Tier</th><th>Status</th><th>Result</th></tr>` +
      data.audit.map((a) => `<tr>
        <td>${ago(a.created, now)} ago</td><td>${esc(a.label)}</td>
        <td>${esc(a.tier)}</td><td>${esc(a.status)}</td><td>${esc(a.result || "")}</td>
      </tr>`).join("") + "</table>"
    : `<div class="empty">No remediation actions yet.</div>`;
}

function renderHeader(data) {
  const counts = { fail: 0, warn: 0 };
  for (const g of data.groups) if (counts[g.status] !== undefined) counts[g.status]++;
  const overall = $("overall");
  if (counts.fail) { overall.textContent = `${counts.fail} DOWN`; overall.className = "pill fail"; }
  else if (counts.warn) { overall.textContent = `${counts.warn} degraded`; overall.className = "pill warn"; }
  else { overall.textContent = "All systems go"; overall.className = "pill ok"; }
  $("meta").textContent =
    `up ${ago(data.app.started, data.app.now)} · ntfy ${data.app.ntfy ? "on" : "off"}` +
    (data.app.notify_queue ? ` · ${data.app.notify_queue} queued` : "");
  $("banner").classList.toggle("hidden", data.app.ntfy);
  if (!data.app.ntfy) $("banner").textContent =
    "ntfy notifications are disabled or no topic is configured — alerts only appear on this dashboard.";
}

async function refresh() {
  try {
    const data = await (await fetch("/api/overview")).json();
    const metricsWanted = [...new Set(
      data.groups.map((g) => SPARKS[g.id]?.metric).filter(Boolean)
    )].join(",");
    let sparkData = {};
    if (metricsWanted) {
      sparkData = await (await fetch(`/api/metrics?names=${encodeURIComponent(metricsWanted)}&hours=24`)).json();
    }
    renderHeader(data);
    renderGroups(data, sparkData);
    renderPredictions(data);
    renderApprovals(data);
    renderIncidents(data);
    renderAudit(data);
    $("refreshed").textContent = new Date().toLocaleTimeString();
  } catch (e) {
    $("overall").textContent = "dashboard error";
    $("overall").className = "pill fail";
    console.error(e);
  }
}

refresh();
setInterval(refresh, 10000);
