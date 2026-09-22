function esc(v) {
  return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
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
    <td>${esc(e.catalog_domain || "")}</td>
    <td class="num">${e.seen_count}</td>
    <td class="mono small">${esc(e.first_seen)}</td>
    <td class="mono small">${esc(e.last_seen)}</td>
  </tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Destino</th><th>Proto</th><th>Catálogo</th><th>Veces</th><th>Primera vez</th><th>Última vez</th></tr></thead>
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
      const fp = v.prob_false_positive == null ? "—" : Math.round(v.prob_false_positive * 100) + "%";
      return `<tr>
        <td>${esc(e.process)}</td>
        <td class="mono">${esc(e.dest)}</td>
        <td class="mono">${esc(v.verdict || "—")}</td>
        <td class="num">${v.confidence == null ? "—" : esc(String(v.confidence))}</td>
        <td class="num"><b>${fp}</b></td>
        <td class="num">${v.severity_score == null ? "—" : esc(String(v.severity_score))} / 3</td>
        <td class="num">${v.immediate_action == null ? "—" : esc(String(v.immediate_action))}</td>
      </tr>`;
    }).join("");
    parts.push(`<h3>Veredictos Jev</h3><table>
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificación</th><th>Confianza</th><th>Prob. falso positivo</th><th>Criticidad</th><th>Acción inmediata</th></tr></thead>
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

async function loadConfig() {
  try {
    const c = await api("/api/config");
    document.getElementById("jev-key").value = c.jev_api_key || "";
    document.getElementById("llm-url").value = c.llm_base_url || "";
    document.getElementById("llm-model").value = c.llm_model || "";
    document.getElementById("sysmon-toggle").checked = !!c.sysmon_enabled;
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

  $("btn-save-jev").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ jev_api_key: $("jev-key").value.trim() }) });
      toast("Config Jev guardada (solo memoria).", "ok");
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
      toast("Config LLM local guardada (solo memoria).", "ok");
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
  setInterval(refreshEvents, 5000);
  setInterval(refreshStats, 60000);
}

document.addEventListener("DOMContentLoaded", bind);
