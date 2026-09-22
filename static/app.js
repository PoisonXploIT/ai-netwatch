function esc(v) {
  return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function themeToggle() {
  const cur = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", cur);
  try { localStorage.setItem("anw-theme", cur); } catch (e) { /* private mode */ }
}

const VERDICT_META = {
  expected_ai_use: { cls: "v-expected", label: "Uso IA esperado" },
  background_exfil_suspect: { cls: "v-exfil", label: "Exfiltración sospechosa" },
  telemetry_noise: { cls: "v-telemetry", label: "Telemetría / ruido" },
  unrelated: { cls: "v-unrelated", label: "No relacionado" },
};

function verdictBadge(v) {
  const m = VERDICT_META[v] || { cls: "v-none", label: v || "—" };
  return `<span class="vbadge ${m.cls}">${esc(m.label)}</span>`;
}

// Celda numerica: valor arriba, barra debajo (alineado a la derecha).
function numCell(value, pct) {
  if (value == null) return `<td class="num">—</td>`;
  const bar = pct == null ? "" : `<div class="bar"><div style="width:${Math.max(2, Math.min(100, Math.round(pct * 100)))}%"></div></div>`;
  return `<td class="num"><div class="cellnum"><span class="val">${esc(String(value))}</span>${bar}</div></td>`;
}

function sevCell(score) {
  if (score == null) return `<td class="num">—</td>`;
  const s = Math.max(0, Math.min(3, Math.round(Number(score) || 0)));
  let bars = "";
  for (let i = 1; i <= 3; i++) bars += `<i class="${i <= s ? `on-${i}` : ""}"></i>`;
  return `<td class="num"><div class="cellnum"><span class="val">${Number(score).toFixed(2)} / 3</span><span class="sevbar">${bars}</span></div></td>`;
}

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

function toast(msg, type = "") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "show " + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = ""), 3600);
}

function eventsTableHtml(events) {
  if (!events.length) return `<div class="hint">Sin eventos todavía (monitor activo).</div>`;
  const rows = events.map((e) => `<tr>
    <td>${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}</td>
    <td class="mono">${esc(e.dest_host || e.dest_ip)}:${e.dest_port}</td>
    <td>${esc(e.protocol || "tcp")}</td>
    <td class="mono">${esc(e.sni_domain || "")}</td>
    <td>${esc(e.catalog_domain || "")}</td>
    <td class="num">${e.seen_count}</td>
    <td class="mono small">${esc(e.first_seen)}</td>
    <td class="mono small">${esc(e.last_seen)}</td>
  </tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Destino</th><th>Proto</th><th>Dominio (SNI)</th><th>Catálogo</th><th class="num">Veces</th><th>Primera vez</th><th>Última vez</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function refreshStats() {
  try {
    const d = await api("/api/stats?days=7");
    const max = Math.max(1, ...d.daily.map((x) => x.events));
    const rows = d.daily.map((x) => `<tr>
      <td class="mono">${esc(x.date)}</td>
      <td class="num">${x.events}</td>
      <td class="num">${x.triages}</td>
      <td><div class="bar"><div style="width:${Math.round((x.events / max) * 100)}%"></div></div></td>
    </tr>`).join("");
    document.getElementById("stats-wrap").innerHTML = `<table>
      <thead><tr><th>Día</th><th>Eventos</th><th>Triajes</th><th width="40%"></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } catch (e) { /* sin stats */ }
}

function triageHtml(data) {
  if (!data) return "";
  const parts = [];
  const jev = data.jev || {};
  if (jev.status === "ok") {
    const rows = (data.events || []).map((e, i) => {
      const v = (jev.verdicts || {})[String(i)] || {};
      return `<tr>
        <td>${esc(e.process)}</td>
        <td class="mono">${esc(e.dest)}</td>
        <td>${verdictBadge(v.verdict)}</td>
        ${numCell(v.confidence, v.confidence)}
        ${numCell(v.prob_false_positive == null ? null : Math.round(v.prob_false_positive * 100) + "%", v.prob_false_positive)}
        ${sevCell(v.severity_score)}
        ${numCell(v.immediate_action, v.immediate_action)}
      </tr>`;
    }).join("");
    parts.push(`<h3>Veredictos Jev</h3><table>
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificación</th><th class="num">Confianza</th><th class="num">Prob. falso positivo</th><th class="num">Criticidad</th><th class="num">Acción inmediata</th></tr></thead>
      <tbody>${rows}</tbody></table>`);
  } else if (jev.status === "skipped") {
    parts.push(`<div class="hint">Jev no disponible (${esc(jev.reason || "")}). Vista clásica intacta.</div>`);
  } else if (jev.status === "error") {
    parts.push(`<div class="hint error">Error Jev: ${esc(jev.reason || "")}</div>`);
  }
  const expls = data.llm_explanations || [];
  if (expls.length) {
    parts.push(`<h3>Explicaciones técnicas (LLM local)</h3>` + expls.map((x) => x.status === "ok"
      ? `<details><summary>${esc(x.process)} → ${esc(x.dest)}</summary>
          <p><b>Qué es:</b> ${esc(x.resumen)}</p>
          <p><b>Por qué importa:</b> ${esc(x.porque)}</p>
          <p><b>Sugerencia:</b> ${esc(x.sugerencia)}</p>
        </details>`
      : `<div class="hint">${esc(x.process || "")} — explicación no disponible (${esc(x.reason || "")})</div>`
    ).join(""));
  }
  return parts.join("");
}

async function refreshEvents() {
  try {
    const d = await api("/api/events?limit=200");
    document.getElementById("events-wrap").innerHTML = eventsTableHtml(d.events);
  } catch (e) { /* server caído */ }
}

function llmCallsHtml(calls) {
  if (!calls.length) return `<div class="hint">Sin llamadas registradas. Con el inspector activo, apunta el cliente al puerto del proxy.</div>`;
  return calls.map((c) => `<details>
    <summary class="mono">${esc(c.ts)} · ${esc(c.method || "")} ${esc(c.path || "")} · ${esc(c.model || "—")} · HTTP ${esc(String(c.status == null ? "?" : c.status))}${c.streaming ? " · stream" : ""}${c.latency_ms != null ? ` · ${c.latency_ms} ms` : ""}</summary>
    <div class="small mono">PID cliente: ${c.client_pid != null ? esc(String(c.client_pid)) : "—"} · ${esc(c.client_addr || "")} · prompt ${esc(String(c.prompt_chars == null ? 0 : c.prompt_chars))} chars${c.prompt_tokens != null ? ` (${esc(String(c.prompt_tokens))} tokens)` : ""} · respuesta ${esc(String(c.response_chars == null ? 0 : c.response_chars))} chars${c.completion_tokens != null ? ` (${esc(String(c.completion_tokens))} tokens)` : ""}</div>
    <h4>Prompt</h4><pre class="small">${esc(c.prompt || "")}</pre>
    <h4>Respuesta</h4><pre class="small">${esc(c.response || "")}</pre>
  </details>`).join("");
}

async function refreshLlmCalls() {
  try {
    const d = await api("/api/llm/calls?limit=100");
    document.getElementById("llm-calls-wrap").innerHTML = llmCallsHtml(d.calls);
  } catch (e) { /* server caído */ }
}

async function loadConfig() {
  try {
    const c = await api("/api/config");
    document.getElementById("jev-key").value = c.jev_api_key || "";
    document.getElementById("llm-url").value = c.llm_base_url || "";
    document.getElementById("llm-model").value = c.llm_model || "";
    document.getElementById("llm-proxy-port").value = c.llm_proxy_port || 8098;
    document.getElementById("llm-proxy-target").value = c.llm_proxy_target || "127.0.0.1:8099";
    const pt = document.getElementById("llm-proxy-toggle");
    pt.checked = !!c.llm_proxy_enabled;
    document.getElementById("sysmon-toggle").checked = !!c.sysmon_enabled;
    const t = document.getElementById("tshark-toggle");
    t.checked = !!c.tshark_enabled;
    if (!c.tshark_available) {
      t.disabled = true;
      t.title = "tshark no encontrado en el sistema";
    }
  } catch (e) { /* sin config */ }
}

async function loadLatestTriage() {
  try {
    const t = await api("/api/triages/latest");
    document.getElementById("triage-results").innerHTML = triageHtml(t.payload);
  } catch (e) { /* sin triajes aún */ }
}

function bind() {
  const $ = (id) => document.getElementById(id);

  $("btn-theme").addEventListener("click", themeToggle);
  $("btn-guide").addEventListener("click", () => {
    const g = document.getElementById("guide-card");
    if (g) g.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  // Exports: rutas GET fijas; ninguna entrada del usuario viaja en la URL.
  $("btn-exp-json").addEventListener("click", () => {
    window.location.href = "/api/export/json";
  });
  $("btn-exp-csv").addEventListener("click", () => {
    window.location.href = "/api/export/csv";
  });
  $("btn-exp-pdf").addEventListener("click", () => {
    window.location.href = "/api/export/pdf";
  });
  $("btn-save-jev").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ jev_api_key: $("jev-key").value.trim() }) });
      toast("Config Jev guardada (persistente).", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-test-jev").addEventListener("click", async () => {
    try {
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ target: "jev" }) });
      toast(r.ok ? `Jev OK (modelo ${r.model || "?"}).` : `Jev fallo: ${r.error}`, r.ok ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-save-llm").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({
        llm_enabled: true, llm_base_url: $("llm-url").value.trim(), llm_model: $("llm-model").value.trim() }) });
      toast("Config LLM local guardada (persistente).", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-test-llm").addEventListener("click", async () => {
    try {
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ target: "llm" }) });
      toast(r.status === "ok" ? `LLM local OK (modelo ${r.model || "?"}).` : `LLM local fallo: ${r.reason}`, r.status === "ok" ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-save-extra").addEventListener("click", async () => {
    const hosts = $("extra-hosts").value.split(",").map((s) => s.trim()).filter(Boolean);
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ extra_hosts: hosts }) });
      toast("Hosts extra guardados.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("sysmon-toggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ sysmon_enabled: ev.target.checked }) });
      toast(ev.target.checked ? "Sysmon fuente activada." : "Sysmon fuente desactivada.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("tshark-toggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ tshark_enabled: ev.target.checked }) });
      toast(ev.target.checked
        ? "Captura SNI (tshark) activada."
        : "Captura SNI (tshark) desactivada.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("llm-proxy-toggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ llm_proxy_enabled: ev.target.checked }) });
      toast(ev.target.checked ? "Inspector LLM activo (proxy en loopback)." : "Inspector LLM desactivado.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-save-proxy").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({
        llm_proxy_port: parseInt($("llm-proxy-port").value, 10),
        llm_proxy_target: $("llm-proxy-target").value.trim() }) });
      toast("Config del proxy inspector guardada (persistente).", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-reset-llmcalls").addEventListener("click", async () => {
    if (!confirm("Borrar todas las llamadas LLM registradas?")) return;
    try {
      const r = await api("/api/llm/calls/reset", { method: "POST", body: JSON.stringify({ confirm: true }) });
      toast(`Borradas ${r.calls_removed} llamadas.`, "ok");
      refreshLlmCalls();
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-reset").addEventListener("click", async () => {
    if (!confirm("Borrar todos los eventos y triajes vivos? El histórico diario (7+ días) se conserva.")) return;
    try {
      const r = await api("/api/reset", { method: "POST", body: JSON.stringify({ confirm: true }) });
      toast(`Reset: ${r.events_removed} eventos y ${r.triages_removed} triajes borrados. Histórico conservado.`, "ok");
      refreshEvents();
      refreshStats();
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-triage").addEventListener("click", async () => {
    const btn = $("btn-triage");
    btn.disabled = true;
    $("triage-status").textContent = "En curso... puede tardar un par de minutos.";
    try {
      const data = await api("/api/triage", { method: "POST", body: JSON.stringify({}) });
      document.getElementById("triage-results").innerHTML = triageHtml(data);
      $("triage-status").textContent = "Completado.";
      toast("Triaje guardado.", "ok");
    } catch (e) {
      $("triage-status").textContent = "";
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
    }
  });

  loadConfig();
  loadLatestTriage();
  refreshEvents();
  refreshStats();
  refreshLlmCalls();
  setInterval(refreshEvents, 5000);
  setInterval(refreshStats, 60000);
  setInterval(refreshLlmCalls, 10000);
}

document.addEventListener("DOMContentLoaded", bind);
