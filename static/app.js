// #10: refresco acotado a la pestaña visible. Cada tarea solo corre cuando su
// pestaña es la activa (y la pagina esta abierta), de modo que la carga de la
// pestaña activa queda por debajo de 12 req/min. Antes: 38 req/min globales.
async function refreshAttention() {
  const wrap = document.getElementById("attention-wrap");
  if (!wrap) return;
  try {
    const d = await api("/api/findings");
    const top = (d.findings || []).filter((f) => f.score >= 30 || f.unapproved || f.beaconing)
      .sort((a, b) => b.score - a.score).slice(0, 5);
    if (!top.length) {
      wrap.innerHTML = `<p class="hint">Nada que revisar: ningún hallazgo con score 30 o más, sin aprobar o con beaconing.</p>`;
      return;
    }
    wrap.innerHTML = `<ul class="attention">` + top.map((f) =>
      `<li><span class="score-badge ${scoreClass(f.score)}">${f.score}</span> ` +
      `<b>${esc(f.process)}</b> → <span class="mono">${esc(f.provider || "-")}</span>` +
      `${f.unapproved ? ` <span class="badge-bad">no aprobado</span>` : ""}` +
      `${f.beaconing ? ` <span class="badge-bad">beacon</span>` : ""}</li>`).join("") +
      `</ul><button class="linkbtn" id="btn-go-findings">Ver todos los hallazgos</button>`;
    document.getElementById("btn-go-findings").addEventListener("click", () => showTab("hallazgos"));
  } catch (e) {
    wrap.innerHTML = `<p class="hint error">No se pudieron cargar los hallazgos (${esc(e.message || e)}).</p>`;
  }
}

const REFRESH_JOBS = [
  { tab: "eventos", fn: refreshEvents, every: 10000 },    // 6/min
  { tab: "eventos", fn: refreshAutonomy, every: 30000 },  // 2/min
  { tab: "hallazgos", fn: refreshFindings, every: 15000 }, // 4/min
  { tab: "hallazgos", fn: refreshShadow, every: 30000 },   // 2/min
  { tab: "hallazgos", fn: refreshBaseline, every: 120000 }, // 0.5/min
  { tab: "ia", fn: refreshLlmCalls, every: 30000 },       // 2/min
  { tab: "config", fn: refreshRules, every: 60000 },      // 1/min
  { tab: "resumen", fn: refreshStats, every: 60000 },     // 1/min
  { tab: "resumen", fn: refreshDashboard, every: 60000 }, // 1/min
  { tab: "resumen", fn: refreshHealth, every: 60000 },    // 1/min
  { tab: "resumen", fn: refreshAttention, every: 60000 },    // 1/min
  // Global: las alertas salen como toast, no dependen de la pestaña.
  { tab: null, fn: refreshAlerts, every: 60000 },         // 1/min
];

function activeTabName() {
  const a = document.querySelector(".tab.active");
  return a ? a.dataset.tab : "";
}

function startRefreshJobs() {
  REFRESH_JOBS.forEach((job) => {
    setInterval(() => {
      if (document.hidden) return;
      if (job.tab && activeTabName() !== job.tab) return;
      job.fn();
    }, job.every);
  });
}

function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
  });
  document.querySelectorAll(".tab-panel").forEach((s) =>
    s.classList.toggle("active", s.dataset.tab === name));
  // #10: al cambiar de pestaña, se cargan una vez los datos de esa pestaña.
  REFRESH_JOBS.forEach((j) => { if (j.tab === name) j.fn(); });
}

function scoreClass(s) { return s >= 60 ? "sc-high" : s >= 30 ? "sc-mid" : "sc-low"; }
function scoreLabel(s) { return s >= 60 ? "alto" : s >= 30 ? "medio" : "bajo"; }


// Contador en la pestana: permite ver donde hay datos sin abrir la pestana.
function setTabCount(name, n) {
  const tab = document.querySelector(`.tab[data-tab="${name}"]`);
  if (!tab) return;
  let c = tab.querySelector(".count");
  if (!c) {
    c = document.createElement("span");
    c.className = "count";
    tab.appendChild(c);
  }
  c.textContent = n ? `(${n})` : "";
}

// Strip de estado bajo el header: evita el "no hay datos" sin explicacion.
async function refreshHealth() {
  const strip = document.getElementById("status-strip");
  if (!strip) return;
  try {
    const h = await api("/api/health");
    const dot = h.status === "ok" ? ""
      : (h.monitoring_enabled === false ? "warn" : "bad");
    const src = Object.entries(h.sources || {}).filter(([k, v]) => {
      if (k === "monitor" || k === "jev_key_set") return false;
      return v === true;
    }).map(([k]) => k);
    const paused = h.monitoring_enabled === false
      ? `<b>monitor pausado</b> (kill switch: no es un fallo)` : "monitor activo";
    strip.innerHTML = `<span class="dot ${dot}"></span>` +
      `<span>v${esc(h.version || "?")} · estado <b>${esc(h.monitoring_enabled === false ? "en pausa" : h.status)}</b></span>` +
      `<span>${paused}</span>` +
      `<span title="${esc(h.last_event || "")}">último evento: <b>${esc(ago(h.last_event))}</b></span>` +
      `<span>eventos <b>${h.events ?? 0}</b></span>` +
      `<span>llamadas LLM <b>${h.llm_calls ?? 0}</b></span>` +
      `<span>fuentes: ${src.length ? esc(src.join(", ")) : "ninguna"}</span>` +
      `<span>Jev: ${(h.sources || {}).jev_key_set ? "key OK" : "sin key"}</span>` +
      `<span>inspector LLM: ${(h.sources || {}).llm_proxy ? "activo" : "parado"}</span>`;
  } catch (e) {
    strip.innerHTML = `<span class="dot bad"></span><span>sin respuesta del servidor (${esc(String(e.message || e))})</span>`;
  }
}

// E-06: sub-pestañas dentro de un panel. Solo muestran u ocultan tarjetas;
// el refresco sigue ligado a la pestaña principal.
function wireSubtabs() {
  document.querySelectorAll("nav.subtabs").forEach((nav) => {
    const btns = [...nav.querySelectorAll("button[data-sub]")];
    const show = (id) => {
      btns.forEach((b) => {
        const on = b.dataset.sub === id;
        b.classList.toggle("active", on);
        b.setAttribute("aria-pressed", String(on));
        const card = document.getElementById(b.dataset.sub);
        if (card) card.hidden = !on;
      });
    };
    btns.forEach((b) => b.addEventListener("click", () => show(b.dataset.sub)));
    if (btns.length) show(btns[0].dataset.sub);
  });
}

function bind() {
  const $ = (id) => document.getElementById(id);
  wireSubtabs();

  // Las pestanas de triaje se generan en HTML dinamic: la CSP (script-src
  // 'self') bloquea los onclick inline, asi que se atan por delegacion.
  document.addEventListener("click", (ev) => {
    const t = ev.target && ev.target.closest && ev.target.closest(".ttab");
    if (t) ttabShow(t.dataset.tt);
  });

  $("btn-theme").addEventListener("click", themeToggle);
  // A1: la guia es ya una pestana; el boton del header lleva a ella.

  // Kill switch global: pausa/reanuda el monitoreo sin reiniciar el server.
  $("btn-monitor").addEventListener("click", async () => {
    const btn = $("btn-monitor");
    const next = btn.classList.contains("paused");
    if (!next) {
      const okBtn = document.getElementById("confirm-ok");
      if (okBtn) okBtn.textContent = "Pausar";
      const yes = await askConfirm("Con el monitoreo en pausa no se registran conexiones, SNI, bytes ni llamadas LLM. ¿Pausar?");
      if (okBtn) okBtn.textContent = "Borrar";
      if (!yes) return;
    }
    btn.disabled = true;
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ monitoring_enabled: next }) });
      renderMonitorState(next);
      toast(next ? "Monitoreo reanudado" : "Monitoreo pausado", "ok");
    } catch (e) {
      toast("Error: " + (e.message || e), "err");
    } finally {
      btn.disabled = false;
    }
  });
  // Exports: rutas GET fijas; ninguna entrada del usuario viaja en la URL.
  $("btn-exp-json").addEventListener("click", () => {
    download("/api/export/json");
  });
  $("btn-exp-csv").addEventListener("click", () => {
    download("/api/export/csv");
  });
  $("btn-exp-pdf").addEventListener("click", () => {
    download("/api/export/pdf");
  });
  // Evidencia (v2.3): days sale del select de opciones fijas (1/7/30/90).
  const evDays = () => {
    const v = parseInt($("ev-days").value, 10);
    return [1, 7, 30, 90].includes(v) ? v : 7;
  };
  $("btn-ev-chain").addEventListener("click", () => {
    download(`/api/evidence/chain?days=${evDays()}`);
  });
  $("btn-ev-stix").addEventListener("click", () => {
    download(`/api/evidence/stix?days=${evDays()}`);
  });
  $("btn-save-jev").addEventListener("click", async () => {
    try {
      const key = $("jev-key").value.trim();
      if (!key) { toast("No se ha escrito ninguna key: la guardada no se toca.", "ok"); return; }
      await api("/api/config", { method: "POST", body: JSON.stringify({ jev_api_key: key }) });
      $("jev-key").value = "";
      toast("Config Jev guardada (persistente, cifrada con DPAPI).", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-clear-jev").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ jev_api_key_clear: true }) });
      toast("Key Jev borrada de la config.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-test-jev").addEventListener("click", async () => {
    try {
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ target: "jev" }) });
      toast(r.ok ? `Jev OK (modelo ${r.model || "?"}).` : `Jev fallo: ${r.error}`, r.ok ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-save-laya").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({
        laya_base_url: $("laya-url").value.trim(), laya_model: $("laya-model").value.trim() }) });
      toast("Config LAY\u00c1 guardada (persistente).", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-test-laya").addEventListener("click", async () => {
    try {
      const r = await api("/api/test", { method: "POST", body: JSON.stringify({ target: "laya" }) });
      toast(r.status === "ok" ? `LAY\u00c1 local OK (modelo ${r.model || "?"}, veredicto ${r.verdict || "?"}).` : `LAY\u00c1 local fallo: ${r.reason || r.status}`, r.status === "ok" ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); }
  });
  $("laya-toggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ laya_enabled: ev.target.checked }) });
      toast(ev.target.checked ? "Segunda opini\u00f3n LAY\u00c1 activada." : "Segunda opini\u00f3n LAY\u00c1 desactivada.", "ok");
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
  $("netbytes-toggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ net_bytes_enabled: ev.target.checked }) });
      toast(ev.target.checked
        ? "Bytes remotos activados: el colector elevado se dispara cada ciclo."
        : "Bytes remotos apagados: no se lanzan procesos elevados.", "ok");
      loadConfig();
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
  $("btn-save-alerts").addEventListener("click", async () => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({
        alerts_enabled: $("alerts-toggle").checked,
        alert_webhook_url: $("alert-webhook").value.trim() }) });
      toast("Config de alertas guardada.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-save-retention").addEventListener("click", async () => {
    const days = parseInt($("retention-days").value, 10);
    const llmDays = parseInt($("retention-llm-days").value, 10);
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({
        retention_days: days, retention_days_llm: llmDays }) });
      toast(`Retención guardada: eventos ${days} d, LLM calls ${llmDays} d.`, "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("llm-content-store").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ llm_store_content: ev.target.checked }) });
      toast(ev.target.checked ? "Contenido LLM se guarda (claro)." : "Solo metadatos y bytes; el contenido LLM ya no se persiste.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("jev-minimal").addEventListener("change", async (ev) => {
    try {
      await api("/api/config", { method: "POST", body: JSON.stringify({ jev_minimal: ev.target.checked }) });
      toast(ev.target.checked
        ? "Modo solo dominios: Jev ya no recibe proceso, IP ni puerto."
        : "Modo completo: Jev recibe proceso, IP, puerto y dominio.", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  // S-18: export de las llamadas del inspector como log legible (txt) o CSV.
  $("btn-llm-log-txt").addEventListener("click", () => download("/api/llm/calls/export?format=txt&limit=1000"));
  $("btn-llm-log-csv").addEventListener("click", () => download("/api/llm/calls/export?format=csv&limit=1000"));
  $("btn-reset-llmcalls").addEventListener("click", async () => {
    if (!(await askConfirm("Se borran todas las llamadas LLM registradas (prompts y respuestas). No se puede deshacer."))) return;
    try {
      const r = await api("/api/llm/calls/reset", { method: "POST", body: JSON.stringify({ confirm: true }) });
      toast(`Borradas ${r.calls_removed} llamadas.`, "ok");
      refreshLlmCalls();
    } catch (e) { toast(e.message, "err"); }
  });
  $("btn-reset").addEventListener("click", async () => {
    if (!(await askConfirm("Se borran todos los eventos y triajes vivos. El histórico diario de estadísticas se conserva. No se puede deshacer."))) return;
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
    const label = btn.textContent;
    btn.textContent = "Triando…";
    btn.setAttribute("aria-busy", "true");
    $("triage-status").textContent = "En curso... puede tardar un par de minutos.";
    try {
      const data = await api("/api/triage", { method: "POST", body: JSON.stringify({}) });
      const wrap = document.getElementById("triage-results");
      wrap.innerHTML = triageHtml(data);
      wireInvestigate(wrap); // A2: boton Investigar en la tabla de triaje.
      $("triage-status").textContent = "Completado.";
      const dd = data.dedup;
      toast(dd ? `Triaje guardado: ${plural(dd.fresh, "evento nuevo", "eventos nuevos")}, ${plural(dd.reused, "reutilizado", "reutilizados")}.` : "Triaje guardado.", "ok");
    } catch (e) {
      $("triage-status").textContent = "";
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
      btn.textContent = label;
      btn.removeAttribute("aria-busy");
    }
  });

  const evRefresh = () => refreshEvents();
  ["ev-group", "ev-org", "ev-layer", "ev-verdict", "ev-shadow", "ev-hide-cdn"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", evRefresh);
  });
  ["ev-process", "ev-dest"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", evRefresh);
  });
  let evSearchTimer = null;
  $("ev-search").addEventListener("input", () => {
    clearTimeout(evSearchTimer);
    evSearchTimer = setTimeout(refreshEvents, 300);
  });
  $("btn-ev-clear").addEventListener("click", () => {
    $("ev-search").value = "";
    $("ev-group").checked = true;
    $("ev-org").checked = true;
    $("ev-layer").value = "";
    $("ev-verdict").value = "";
    $("ev-shadow").checked = false;
    $("ev-hide-cdn").checked = false;
    $("ev-process").value = "";
    $("ev-dest").value = "";
    refreshEvents();
  });
  // Filtros de hallazgos (client-side, sin peticiones extra).
  ["f-noise", "f-unapproved", "f-order"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", renderFindings);
  });
  $("btn-findings-reset").addEventListener("click", () => {
    $("f-noise").checked = true;
    $("f-unapproved").checked = false;
    $("f-order").value = "score";
    findingsShown = 25;
    renderFindings();
  });
  // A3: filtros de la tarjeta Autonomía (veredicto/proceso/proveedor/grupo).
  ["aut-verdict", "aut-group"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", refreshAutonomy);
  });
  ["aut-process", "aut-provider"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", refreshAutonomy);
  });
  $("btn-aut-clear").addEventListener("click", () => {
    $("aut-verdict").value = "";
    $("aut-process").value = "";
    $("aut-provider").value = "";
    $("aut-group").checked = true;
    refreshAutonomy();
  });
  // A4: ventana del panel (1/7/30 dias).
  $("dash-days").addEventListener("change", (ev) => {
    const v = Number(ev.target.value);
    dashDays = [1, 7, 30].includes(v) ? v : 7;
    refreshDashboard();
  });
  // B: revision LLM por lote (display-only; sin auto-ejecucion).
  [["btn-rev-aut", "autonomous"],
   ["btn-rev-unapproved", "unapproved"],
   ["btn-rev-flagged", "flagged"],
   ["btn-rev-untriaged", "untriaged"],
   ["btn-rev-quarantine", "quarantine"]].forEach(([id, scope]) => {
    $(id).addEventListener("click", () => runReview({ scope }));
  });
  $("btn-review-selected").addEventListener("click", () => {
    const ids = [...document.querySelectorAll(".ev-check:checked")]
      .map(c => Number(c.dataset.evid)).filter(n => !Number.isNaN(n));
    if (!ids.length) {
      toast("Marca eventos en la tabla (casilla) antes de revisar.");
      return;
    }
    runReview({ event_ids: ids });
  });

  const tabList = [...document.querySelectorAll(".tab")];
  tabList.forEach((t, i) => {
    t.addEventListener("click", () => showTab(t.dataset.tab));
    t.addEventListener("keydown", (e) => {
      let j = -1;
      if (e.key === "ArrowRight") j = (i + 1) % tabList.length;
      else if (e.key === "ArrowLeft") j = (i - 1 + tabList.length) % tabList.length;
      else if (e.key === "Home") j = 0;
      else if (e.key === "End") j = tabList.length - 1;
      if (j < 0) return;
      e.preventDefault();
      showTab(tabList[j].dataset.tab);
      tabList[j].focus();
    });
  });

  // Atajos 1..6 para moverse entre pestanas (ignorados dentro de un campo).
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = (e.target && e.target.tagName) || "";
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(tag)) return;
    const map = { "1": "resumen", "2": "hallazgos", "3": "eventos", "4": "ia", "5": "config", "6": "guia" };
    const t = map[e.key];
    if (t) showTab(t);
  });

  loadConfig();
  loadLatestTriage();
  loadReviewHistory();
  loadFacets();
  refreshAlerts();
  showTab("resumen");
  startRefreshJobs();
}

document.addEventListener("DOMContentLoaded", () => {
  try {
    bind();
  } catch (e) {
    // Fail-safe: si la UI no arranca, el strip lo dice en vez de quedar
    // en blanco (el bug de "no hay pestanas" era dificil de diagnosticar).
    const strip = document.getElementById("status-strip");
    if (strip) strip.textContent = "Error al inicializar la UI: " + (e.message || e);
    console.error("bind() fallo", e);
  }
});
