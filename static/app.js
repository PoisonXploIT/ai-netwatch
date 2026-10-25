function esc(v) {
  return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
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

// Puerta de confianza (2026-10-01): un argmax con confianza < CONF_GATE no se
// presenta como veredicto definitivo; se muestra 'Indeterminado' y el label
// argmax queda en el tooltip. La columna Confianza sigue mostrando el valor.
const CONF_GATE = 0.5;
function verdictBadge(v, confidence) {
  const m = VERDICT_META[v] || { cls: "v-none", label: v || "—" };
  if (confidence != null && confidence < CONF_GATE) {
    return `<span class="vbadge v-undetermined" title="veredicto argmax con confianza baja (<${CONF_GATE}): ${esc(m.label)} (conf ${confidence}). Ver columna Confianza.">Indeterminado</span>`;
  }
  return `<span class="vbadge ${m.cls}">${esc(m.label)}</span>`;
}

// Celda numerica: valor arriba, barra debajo (alineado a la derecha).
function numCell(value, pct) {
  if (value == null) return `<td class="num">—</td>`;
  // La CSP no permite style="...": el ancho se aplica con JS sobre el CSSOM.
  const bar = pct == null ? "" : `<div class="bar"><div data-pct="${Math.max(2, Math.min(100, Math.round(pct * 100)))}"></div></div>`;
  return `<td class="num"><div class="cellnum"><span class="val">${esc(String(value))}</span>${bar}</div></td>`;
}

function sevCell(score) {
  if (score == null) return `<td class="num">—</td>`;
  const s = Math.max(0, Math.min(3, Math.round(Number(score) || 0)));
  let bars = "";
  for (let i = 1; i <= 3; i++) bars += `<i class="${i <= s ? `on-${i}` : ""}"></i>`;
  return `<td class="num"><div class="cellnum"><span class="val">${Number(score).toFixed(2)} / 3</span><span class="sevbar">${bars}</span></div></td>`;
}

const SESSION_TOKEN = (document.querySelector('meta[name="netwatch-token"]') || {}).content || "";

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (SESSION_TOKEN) headers["X-NetWatch-Token"] = SESSION_TOKEN;
  const res = await fetch(path, { headers, ...opts });
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

function aiLayerHtml(layer) {
  const map = {
    catalog: ["catálogo", "Capa 1: en el catálogo (evidencia directa)."],
    heuristic: ["heurística", "Capa 2: señal por token/TLD .ai (revisar, no afirmado)."],
    llm: ["LLM local", "Capa 3: clasificado por LLM local."],
    unlisted: ["sin clasificar", "No cae en ninguna capa; visible para revisar."],
  };
  if (!layer) return "";
  const pair = map[layer] || [layer, ""];
  return `<span title="${esc(pair[1])}">${esc(pair[0])}</span>`;
}

function beaconBadge(e) {
  if (e.iat_cv == null || !e.sessions || e.sessions < 5) return "";
  const cv = Number(e.iat_cv);
  if (!(cv <= 0.3)) return "";
  return ` <span class="badge-bad" title="Beaconing: ${e.sessions} sesiones con CV ${cv.toFixed(3)} (<=0.3 = periodicidad regular)">beacon</span>`;
}

function autonomyBadge(verdict, score) {
  const map = {
    user_driven: ["usuario", "El usuario estaba activo (entrada reciente, sin bloqueo)."],
    autonomous: ["autónomo", "Salida a IA con el usuario ausente/bloqueado o linaje de servicio."],
    scheduled: ["programado", "Linaje indica tarea programada / Task Scheduler."],
  };
  const pair = map[verdict];
  if (!pair) return "";
  const s = score != null ? ` · score ${score}` : "";
  return `<span title="${esc(pair[1])}${s}">${esc(pair[0])}</span>`;
}

function fmtBytes(n) {
  if (n == null) return "?";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

function kindBadge(kind) {
  const m = { api: "API", web: "web", cdn: "CDN" };
  return m[kind] ? ` <span class="hint">[${m[kind]}]</span>` : "";
}

// #11 (U2): el payload de /api/events trae el registro completo; se muestra
// en el detalle expandible de cada fila.
function detailDl(pairs) {
  const rows = pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(String(v))}</dd></div>`);
  return `<dl class="detail-dl">${rows.join("")}</dl>`;
}

function eventDetailHtml(e) {
  const flags = (e.pre_flags || []).map((x) => `${x.flag} (${x.porque})`).join("; ");
  const mitre = (e.mitre || []).map((m) => `${m.id} ${m.name}`).join(", ");
  return detailDl([
    ["id", e.id], ["registro", e.ts], ["proceso", e.process], ["imagen", e.image],
    ["destino", `${e.dest_ip}:${e.dest_port}`], ["dest_host", e.dest_host],
    ["protocolo", e.protocol], ["SNI", e.sni_domain], ["catalogo", e.catalog_domain],
    ["capa IA", e.ai_layer], ["veredicto", e.autonomy_verdict], ["score", e.autonomy_score],
    ["sesiones", e.sessions], ["polls", e.seen_count],
    ["primera vez", e.first_seen], ["ultima vez", e.last_seen],
    ["anomalia", e.pre_score], ["flags", flags], ["MITRE", mitre],
  ]);
}

function groupDetailHtml(g) {
  const mitre = (g.mitre || []).map((m) => `${m.id} ${m.name}`).join(", ");
  const members = (g.members || []).map((m) => `<tr>
    <td class="mono">${esc(m.dest_ip)}:${esc(m.dest_port)}</td>
    <td class="mono">${esc(m.sni_domain || "")}</td>
    <td class="mono">${esc(m.catalog_domain || "")}</td>
    <td class="num">${m.sessions ?? 0}</td>
    <td class="num">${m.seen_count ?? 0}</td>
    <td class="mono small">${esc(m.first_seen || "")}</td>
    <td class="mono small">${esc(m.last_seen || "")}</td>
  </tr>`).join("");
  const more = (g.member_total || 0) > (g.members || []).length
    ? `<p class="hint">... y ${(g.member_total || 0) - (g.members || []).length} registros mas (limitado a 10 por grupo).</p>`
    : "";
  const head = detailDl([
    ["proceso", g.process], ["imagen", g.image], ["proveedor", g.provider],
    ["capa IA", g.ai_layer], ["veredicto", g.autonomy_verdict], ["score", g.autonomy_score],
    ["sesiones", g.sessions], ["polls", g.seen_count], ["#IPs", g.ip_count],
    ["primera vez", g.first_seen], ["ultima vez", g.last_seen],
    ["anomalia", g.pre_score], ["MITRE", mitre],
  ]);
  const table = members
    ? `<table class="subtable"><thead><tr><th>IP:puerto</th><th>SNI</th><th>Catalogo</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Primera vez</th><th>Ultima vez</th></tr></thead><tbody>${members}</tbody></table>${more}`
    : "";
  return head + table;
}

function groupedEventsTableHtml(events) {
  if (!events.length) return `<div class="hint">Sin eventos con los filtros actuales.</div>`;
  const rows = events.map((e, i) => `<tr>
    <td>${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}</td>
    <td class="mono">${esc(e.provider || "-")}${kindBadge(e.kind)}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 0}${beaconBadge(e)}</td>
    <td class="num" title="IPs distintas para este proceso y proveedor (CDN rotatorio).">${e.ip_count ?? 0}</td>
    <td class="mono small">${esc(e.last_seen || "")}</td>
    <td><button class="linklike" data-detail="ev-d-g${i}" aria-expanded="false">detalle</button></td>
  </tr>
  <tr class="ev-detail" id="ev-d-g${i}" hidden><td colspan="8">${groupDetailHtml(e)}</td></tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Proveedor</th><th>IA (capa)</th><th>Autonomía</th><th class="num" title="Sesiones = transiciones ausente→presente.">Sesiones</th><th class="num">#IPs</th><th>Última vez</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function eventsTableHtml(events, grouped) {
  if (grouped) return groupedEventsTableHtml(events);
  if (!events.length) return `<div class="hint">Sin eventos todavía (monitor activo).</div>`;
  const rows = events.map((e, i) => `<tr>
    <td><label class="check small" title="Seleccionar para Revisar (batch)"><input type="checkbox" class="ev-check" data-evid="${e.id}"></label> ${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}${LLM_ENABLED ? `<div class="small"><button class="small" data-investigate="${e.id}">Investigar con LLM local</button></div>` : ""}</td>
    <td class="mono">${esc(e.dest_host || e.dest_ip)}:${e.dest_port}</td>
    <td class="mono">${esc(e.sni_domain || "")}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 1}${beaconBadge(e)}</td>
    <td class="mono small">${esc(e.last_seen)}</td>
    <td><button class="linklike" data-detail="ev-d-${i}" aria-expanded="false">detalle</button></td>
  </tr>
  <tr class="ev-detail" id="ev-d-${i}" hidden><td colspan="8">${eventDetailHtml(e)}</td></tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Destino</th><th>Dominio (SNI)</th><th title="Capa de deteccion: catalogo, heuristica o LLM local.">IA (capa)</th><th>Autonomía</th><th class="num" title="Sesiones = transiciones ausente→presente (F1). Polls y primera vez estan en el detalle.">Sesiones</th><th>Última vez</th><th></th></tr></thead>
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
      <td><div class="bar"><div data-pct="${Math.round((x.events / max) * 100)}"></div></div></td>
    </tr>`).join("");
    document.getElementById("stats-wrap").innerHTML = `<table>
      <thead><tr><th>Día</th><th>Eventos</th><th>Triajes</th><th width="40%"></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
    paintBars(document.getElementById("stats-wrap"));
  } catch (e) { /* sin stats */ }
}

function ttabShow(which) {
  const j = document.getElementById("ttab-jev");
  const l = document.getElementById("ttab-laya");
  if (j) j.hidden = which !== "jev";
  if (l) l.hidden = which !== "laya";
  document.querySelectorAll(".ttab").forEach((b) => b.classList.toggle("active", b.dataset.tt === which));
}

const TRIAGE_ROWS = 25;  // Filas visibles por tabla de triaje; el resto, desplegable.

function triageHtml(data) {
  if (!data) return "";
  const parts = [];
  let jevHtml = "";
  let layaHtml = "";
  const jev = data.jev || {};
  if (jev.status === "ok") {
    const evs = data.events || [];
    let triaged = 0;
    const rowList = evs.map((e, i) => {
      // Soft-delete en UI: fila oculta si (proceso|proveedor) esta suprimido.
      if (SUPPRESSED.has(`${e.process}|${providerFromDest(e.dest)}`)) return null;
      const v = (jev.verdicts || {})[String(i)] || {};
      if (v.verdict != null) triaged++;
      // Sin veredicto: 'no triado' explicito (no un vacio que parezca fallo).
      const reuseMark = e.reused
        ? ` <span class="hint" title="veredicto reutilizado: la firma del evento no cambio desde el ultimo triaje (I1)">(reutilizado)</span>`
        : "";
      const cls = v.verdict != null ? verdictBadge(v.verdict, v.confidence) + reuseMark
        : `<span class="hint">no triado</span>`;
      const inv = LLM_ENABLED
        ? `<div class="small"><button class="small" data-investigate="${e.id}">Investigar</button></div>`
        : "";
      return {
        sev: Number(v.severity_score || 0),
        html: `<tr>
        <td>${esc(e.process)}${inv}</td>
        <td class="mono">${esc(e.dest)}</td>
        <td>${cls}</td>
        ${numCell(v.confidence, v.confidence)}
        ${numCell(v.prob_false_positive == null ? null : Math.round(v.prob_false_positive * 100) + "%", v.prob_false_positive)}
        ${sevCell(v.severity_score)}
        ${numCell(v.immediate_action, v.immediate_action)}
      </tr>`};
    }).filter(Boolean);
    rowList.sort((a, b) => b.sev - a.sev);
    const rows = rowList.map((r, i) => i < TRIAGE_ROWS ? r.html : r.html.replace("<tr", "<tr class=\"extra extra-jev\" hidden")).join("");
    const moreJev = rowList.length > TRIAGE_ROWS
      ? `<div class="row"><button class="linkbtn" data-more="jev">Mostrar los ${rowList.length - TRIAGE_ROWS} restantes</button></div>`
      : "";
    const countNote = triaged < evs.length
      ? ` <span class="hint">(triados ${triaged} de ${evs.length})</span>` : "";
    jevHtml = `<h3>Veredictos Jev${countNote}</h3><table>
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificación</th><th class="num">Confianza</th><th class="num">Prob. falso positivo</th><th class="num">Criticidad</th><th class="num">Acción inmediata</th></tr></thead>
      <tbody>${rows}</tbody></table>${moreJev}`;
  } else if (jev.status === "skipped") {
    jevHtml = `<div class="hint">Jev no disponible (${esc(jev.reason || "")}). Vista clásica intacta.</div>`;
  } else if (jev.status === "error") {
    jevHtml = `<div class="hint error">Error Jev: ${esc(jev.reason || "")}</div>`;
  }
  const laya = data.laya || {};
  if (laya.status === "ok") {
    const evs = data.events || [];
    const jvAll = jev.verdicts || {};
    let cmpOk = 0, cmpN = 0;
    const lrowList = evs.map((e, i) => {
      if (SUPPRESSED.has(`${e.process}|${providerFromDest(e.dest)}`)) return null;
      const v = (laya.verdicts || {})[String(i)] || {};
      const jv = jvAll[String(i)] || {};
      const cls = v.verdict != null ? verdictBadge(v.verdict, v.confidence) : `<span class="hint">no triado</span>`;
      let cmp = `<span class="hint">-</span>`;
      if (v.verdict != null && jv.verdict != null) {
        cmpN++;
        if (v.verdict === jv.verdict) { cmp = `<span class="cmp-ok">coincide</span>`; }
        else { cmp = `<span class="cmp-bad">difiere</span> <span class="hint">(Jev: ${esc(jv.verdict)})</span>`; }
      }
      return { sev: Number(v.severity_score || 0),
        html: `<tr><td>${esc(e.process)}</td><td class="mono">${esc(e.dest)}</td><td>${cls}</td><td>${cmp}</td>${numCell(v.confidence, v.confidence)}${sevCell(v.severity_score)}${numCell(v.immediate_action, v.immediate_action)}</tr>` };
    }).filter(Boolean);
    lrowList.sort((a, b) => b.sev - a.sev);
    const lrows = lrowList.map((r, i) => i < TRIAGE_ROWS ? r.html : r.html.replace("<tr", "<tr class=\"extra extra-laya\" hidden")).join("");
    const moreLaya = lrowList.length > TRIAGE_ROWS
      ? `<div class="row"><button class="linkbtn" data-more="laya">Mostrar los ${lrowList.length - TRIAGE_ROWS} restantes</button></div>`
      : "";
    const pct = cmpN ? Math.round((cmpOk / cmpN) * 100) : 0;
    layaHtml = `<h3>Veredictos LAY\u00c1 (local) <span class="hint">${esc(laya.model || "")} \u00b7 acuerdo con Jev: ${cmpOk}/${cmpN} (${pct}%)</span></h3><table>
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificaci\u00f3n</th><th>vs Jev</th><th class="num">Confianza</th><th class="num">Criticidad</th><th class="num">Acci\u00f3n inmediata</th></tr></thead>
      <tbody>${lrows}</tbody></table>${moreLaya}`;
  } else if (laya.status === "error") {
    layaHtml = `<div class="hint error">LAY\u00c1 local: ${esc(laya.reason || "")}</div>`;
  }
  if (jevHtml || layaHtml) {
    parts.push(`<div class="ttabs">
      <button class="btn ttab active" data-tt="jev" onclick="ttabShow('jev')">Jev (juez)</button>
      <button class="btn ttab" data-tt="laya" onclick="ttabShow('laya')">LAY\u00c1 (local)</button>
    </div>
    <div id="ttab-jev">${jevHtml}</div>
    <div id="ttab-laya" hidden>${layaHtml}</div>`);
  }
  const dd = data.dedup;
  if (dd && typeof dd.reused === "number" && typeof dd.fresh === "number") {
    parts.push(`<div class="hint">Dedup por firma: ${dd.reused} reutilizados / ${dd.fresh} nuevos (Jev solo ve lo nuevo)</div>`);
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

function eventsQuery() {
  const $ = (id) => document.getElementById(id);
  const p = new URLSearchParams();
  p.set("limit", "200");
  p.set("group", $("ev-group") && $("ev-group").checked ? "provider" : "none");
  const layer = $("ev-layer") && $("ev-layer").value;
  if (layer) p.set("layer", layer);
  const verdict = $("ev-verdict") && $("ev-verdict").value;
  if (verdict) p.set("verdict", verdict);
  if ($("ev-shadow") && $("ev-shadow").checked) p.set("shadow", "true");
  if ($("ev-hide-cdn") && $("ev-hide-cdn").checked) p.set("hide_cdn", "true");
  const proc = $("ev-process") && $("ev-process").value.trim();
  if (proc) p.set("process", proc);
  const dest = $("ev-dest") && $("ev-dest").value.trim();
  if (dest) p.set("dest", dest);
  return p.toString();
}

let EVENTS = { events: [], grouped: false };
let eventsShown = 40;

async function refreshEvents() {
  try {
    const d = await api("/api/events?" + eventsQuery());
    EVENTS = { events: d.events || [], grouped: !!d.grouped };
    renderEvents();
  } catch (e) { /* server caído */ }
}

function renderEvents() {
  const wrap = document.getElementById("events-wrap");
  if (!wrap) return;
  const list = EVENTS.events.slice(0, eventsShown);
  const more = EVENTS.events.length > list.length
    ? `<div class="row"><button class="linkbtn" id="btn-events-more">Mostrar ${EVENTS.events.length - list.length} mas (${EVENTS.events.length} en total)</button></div>`
    : "";
  wrap.innerHTML = eventsTableHtml(list, EVENTS.grouped) + more;
  setTabCount("eventos", EVENTS.events.length);
  wireInvestigate(wrap);
  wireEventDetail(wrap);
  const mb = document.getElementById("btn-events-more");
  if (mb) mb.onclick = () => { eventsShown += 60; renderEvents(); };
}

async function loadFacets() {
  try {
    const d = await api("/api/facets");
    const fill = (id, items, allLabel) => {
      const sel = document.getElementById(id);
      if (!sel) return;
      const cur = sel.value;
      sel.innerHTML = `<option value="">${allLabel}</option>` +
        (items || []).map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
      if (cur) sel.value = cur;
    };
    fill("ev-process", d.processes, "Todos los procesos");
    fill("ev-dest", d.destinations, "Todos los destinos");
    fill("aut-process", d.processes, "Todos los procesos");
    fill("aut-provider", d.providers, "Todos los proveedores");
  } catch (e) { /* sin facets */ }
}

// #10: refresco acotado a la pestaña visible. Cada tarea solo corre cuando su
// pestaña es la activa (y la pagina esta abierta), de modo que la carga de la
// pestaña activa queda por debajo de 12 req/min. Antes: 38 req/min globales.
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
  });
  document.querySelectorAll(".tab-panel").forEach((s) =>
    s.classList.toggle("active", s.dataset.tab === name));
  // #10: al cambiar de pestaña, se cargan una vez los datos de esa pestaña.
  REFRESH_JOBS.forEach((j) => { if (j.tab === name) j.fn(); });
}

function scoreClass(s) { return s >= 60 ? "sc-high" : s >= 30 ? "sc-mid" : "sc-low"; }

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
      `<span>v${esc(h.version || "?")} · estado <b>${esc(h.status)}</b></span>` +
      `<span>${paused}</span>` +
      `<span>eventos <b>${h.events ?? 0}</b></span>` +
      `<span>llamadas LLM <b>${h.llm_calls ?? 0}</b></span>` +
      `<span>fuentes: ${src.length ? esc(src.join(", ")) : "ninguna"}</span>` +
      `<span>Jev: ${h.jev_key_set ? "key OK" : "sin key"}</span>`;
  } catch (e) {
    strip.innerHTML = `<span class="dot bad"></span><span>sin respuesta del servidor (${esc(String(e.message || e))})</span>`;
  }
}

function findingDetail(f) {
  const parts = [];
  if ((f.pre_flags || []).length) {
    parts.push("<b>Anomalía (" + f.pre_score + "):</b> " +
      f.pre_flags.map((x) => `${esc(x.flag)} (${esc(x.porque)})`).join("; "));
  }
  if (f.jev_verdict) {
    parts.push(`<b>Jev:</b> ${esc(f.jev_verdict)} (criticidad ${f.jev_severity})`);
  }
  if (f.review) {
    const acc = f.review.accion ? ` · accion: ${esc(f.review.accion)}` : "";
    parts.push(`<b>Revisión LLM:</b> ${esc(f.review.evaluacion || "")}${acc} — ${esc(f.review.porque || "")}`);
  }
  if ((f.mitre || []).length) {
    parts.push(`<b>MITRE ATT&CK:</b> ` +
      f.mitre.map((m) => `${esc(m.id)} ${esc(m.name)}`).join(", "));
  }
  parts.push(`<b>IPs:</b> ${f.ip_count} · <b>event_ids:</b> ${(f.event_ids || []).join(", ")}`);
  return parts.join("<br>");
}

// Ocultacion en UI (soft-delete): conjunto vivo de claves "proceso|proveedor"
// cargado desde /api/config. Los eventos siguen en la base de datos.
let SUPPRESSED = new Set();
function providerFromDest(dest) {
  if (!dest) return "";
  const m = String(dest).match(/^(.*):\d+$/);
  return m ? m[1] : dest;
}

function reviewBadge(rev) {
  if (!rev) return `<span class="hint">sin revision</span>`;
  const ev = typeof rev === "string" ? rev : rev.evaluacion;
  if (!ev) return `<span class="hint">sin revision</span>`;
  const cls = ev === "confirm" ? "badge-ok" : ev === "refuta" ? "badge-bad" : "badge-warn";
  let out = `<span class="${cls}">${esc(ev)}</span>`;
  const acc = typeof rev === "object" ? rev.accion : null;
  if (acc) {
    const acls = acc === "sacar" ? "badge-ok" : "badge-bad";
    out += ` <span class="${acls}">${esc(acc)}</span>`;
  }
  return out;
}

function findingsHtml(findings, suppressed, blacklisted) {
  const suppSet = new Set(suppressed || []);
  const head = `<tr><th class="num">Score</th><th>Proceso</th><th>Proveedor</th><th>Señales</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Última vez</th><th></th></tr>`;
  const activeRows = findings.map((f, i) => {
    const badges = [
      f.unapproved ? `<span class="badge-bad">no aprobado</span>` : "",
      f.beaconing ? `<span class="badge-bad">beacon</span>` : "",
      (f.autonomy_verdict === "autonomous" || f.autonomy_verdict === "scheduled")
        ? `<span class="badge-warn">${esc(f.autonomy_verdict)}</span>` : "",
    ].filter(Boolean).join(" ");
    const jev = f.jev_verdict ? verdictBadge(f.jev_verdict) : `<span class="hint">sin Jev</span>`;
    return `<tr class="finding-row" data-fi="${i}">
      <td><span class="score-badge ${scoreClass(f.score)}">${f.score}</span></td>
      <td>${esc(f.process)}</td>
      <td class="mono">${esc(f.provider || "-")}${kindBadge(f.kind)}</td>
      <td>${jev} ${badges}</td>
      <td class="num">${f.sessions ?? 0}</td>
      <td class="num">${f.seen_count ?? 0}</td>
      <td class="mono small">${esc(f.last_seen || "")}</td>
      <td>
        <button class="small blacklist-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Lista negra (cuarentena): aislar hasta revision LLM">⊘</button>
        <button class="small suppress-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Ocultar fila: los eventos se mantienen en la base de datos">×</button>
      </td>
    </tr>
    <tr class="finding-detail" data-fd="${i}" hidden><td colspan="8">${findingDetail(f)}</td></tr>`;
  }).join("");
  let hiddenSection = "";
  if (suppSet.size) {
    hiddenSection = `<details><summary>Ocultos (${suppSet.size})</summary><table>
      <tbody>${[...suppSet].sort().map((s) => {
        const cut = s.indexOf("|");
        const p = cut >= 0 ? s.slice(0, cut) : s;
        const prov = cut >= 0 ? s.slice(cut + 1) : "";
        return `<tr><td>${esc(p)}</td><td class="mono">${esc(prov || "-")}</td><td><button class="small restore-finding" data-process="${esc(p)}" data-provider="${esc(prov)}">restaurar</button></td></tr>`;
      }).join("")}</tbody></table></details>`;
  }
  let quarantineSection = "";
  if (blacklisted && blacklisted.length) {
    const qrows = blacklisted.map((f, i) => {
      const jev = f.jev_verdict ? verdictBadge(f.jev_verdict) : `<span class="hint">sin Jev</span>`;
      return `<tr class="finding-row" data-qi="${i}">
        <td><span class="score-badge ${scoreClass(f.score)}">${f.score}</span></td>
        <td>${esc(f.process)}</td>
        <td class="mono">${esc(f.provider || "-")}${kindBadge(f.kind)}</td>
        <td>${jev} ${reviewBadge(f.review)}</td>
        <td class="num">${f.sessions ?? 0}</td>
        <td class="num">${f.seen_count ?? 0}</td>
        <td class="mono small">${esc(f.last_seen || "")}</td>
        <td>
          <button class="small unblacklist-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Sacar de cuarentena">sacar</button>
          <button class="small review-finding" data-eids="${(f.event_ids || []).join(",")}" title="Revisar estos eventos con el LLM local">revisar</button>
        </td>
      </tr>
      <tr class="finding-detail" data-qd="${i}" hidden><td colspan="8">${findingDetail(f)}</td></tr>`;
    }).join("");
    quarantineSection = `<details><summary>Cuarentena (${blacklisted.length})</summary>
      <p class="hint">En lista negra: aislados a la espera de revision LLM. Los eventos siguen en la base de datos.</p>
      <table><thead>${head}</thead><tbody>${qrows}</tbody></table>
      <div class="row"><button class="primary review-quarantine">Revisar toda la cuarentena (LLM local)</button></div></details>`;
  }
  const main = findings.length
    ? `<table><thead>${head}</thead><tbody>${activeRows}</tbody></table>`
    : `<div class="hint">Sin hallazgos activos.</div>`;
  return main + hiddenSection + quarantineSection;
}

async function refreshFindings() {
  try {
    const d = await api("/api/findings");
    FINDINGS = { findings: d.findings || [], suppressed: d.suppressed || [], blacklisted: d.blacklisted || [] };
    renderFindings();
  } catch (e) { /* sin hallazgos */ }
}

// Filtros y paginacion client-side: la lista completa ya esta en memoria,
// no hace falta otra peticion.
let FINDINGS = { findings: [], suppressed: [], blacklisted: [] };
let findingsShown = 25;

function filteredFindings() {
  const hideNoise = !!document.getElementById("f-noise")?.checked;
  const onlyUnapproved = !!document.getElementById("f-unapproved")?.checked;
  const order = document.getElementById("f-order")?.value || "score";
  const list = (FINDINGS.findings || []).filter((f) => {
    if (hideNoise && f.score < 10 && (f.sessions ?? 0) <= 1) return false;
    if (onlyUnapproved && !f.unapproved) return false;
    return true;
  });
  if (order === "last") list.sort((a, b) => String(b.last_seen || "").localeCompare(String(a.last_seen || "")));
  else if (order === "sessions") list.sort((a, b) => (b.sessions || 0) - (a.sessions || 0));
  else list.sort((a, b) => (b.score || 0) - (a.score || 0));
  return list;
}

function renderFindings() {
  const wrap = document.getElementById("findings-wrap");
  if (!wrap) return;
  const list = filteredFindings();
  const shown = list.slice(0, findingsShown);
  const total = (FINDINGS.findings || []).length;
  const more = list.length > shown.length
    ? `<div class="row"><button class="linkbtn" id="btn-findings-more">Mostrar ${list.length - shown.length} mas (${list.length} de ${total})</button></div>`
    : `<p class="hint">${list.length} hallazgos mostrados de ${total} (filtrados).</p>`;
  wrap.innerHTML = findingsHtml(shown, FINDINGS.suppressed, FINDINGS.blacklisted) + more;
  setTabCount("hallazgos", list.length);
  wireFindings(wrap);
  const mb = document.getElementById("btn-findings-more");
  if (mb) mb.onclick = () => { findingsShown += 25; renderFindings(); };
}

function wireFindings(wrap) {
    wrap.querySelectorAll("tr.finding-row").forEach((r) => {
      r.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) return;
        const sel = r.dataset.fi != null
          ? `tr.finding-detail[data-fd="${r.dataset.fi}"]`
          : `tr.finding-detail[data-qd="${r.dataset.qi}"]`;
        const det = wrap.querySelector(sel);
        if (det) det.hidden = !det.hidden;
      });
    });
    wrap.querySelectorAll("button.suppress-finding").forEach((b) => {
      b.onclick = async (ev) => {
        ev.stopPropagation();
        b.disabled = true;
        const p = b.dataset.process, prov = b.dataset.provider;
        try {
          await api(`/api/findings/suppress?process=${encodeURIComponent(p)}&provider=${encodeURIComponent(prov)}`, { method: "POST" });
          SUPPRESSED.add(`${p}|${prov}`);
          refreshFindings();
          loadLatestTriage();
        } catch (e) { toast(String(e), "error"); b.disabled = false; }
      };
    });
    wrap.querySelectorAll("button.blacklist-finding").forEach((b) => {
      b.onclick = async (ev) => {
        ev.stopPropagation();
        b.disabled = true;
        const p = b.dataset.process, prov = b.dataset.provider;
        try {
          await api(`/api/findings/blacklist?process=${encodeURIComponent(p)}&provider=${encodeURIComponent(prov)}`, { method: "POST" });
          refreshFindings();
        } catch (e) { toast(String(e), "error"); b.disabled = false; }
      };
    });
    wrap.querySelectorAll("button.unblacklist-finding").forEach((b) => {
      b.onclick = async () => {
        b.disabled = true;
        const p = b.dataset.process, prov = b.dataset.provider;
        try {
          await api(`/api/findings/unblacklist?process=${encodeURIComponent(p)}&provider=${encodeURIComponent(prov)}`, { method: "POST" });
          refreshFindings();
        } catch (e) { toast(String(e), "error"); b.disabled = false; }
      };
    });
    wrap.querySelectorAll("button.review-finding").forEach((b) => {
      b.onclick = async () => {
        const ids = (b.dataset.eids || "").split(",").map(Number).filter((n) => !Number.isNaN(n));
        if (!ids.length) { toast("Sin eventos para revisar."); return; }
        runReview({ event_ids: ids });
      };
    });
    const qb = wrap.querySelector("button.review-quarantine");
    if (qb) qb.onclick = () => runReview({ scope: "quarantine" });
    wrap.querySelectorAll("button.restore-finding").forEach((b) => {
      b.onclick = async () => {
        b.disabled = true;
        const p = b.dataset.process, prov = b.dataset.provider;
        try {
          await api(`/api/findings/restore?process=${encodeURIComponent(p)}&provider=${encodeURIComponent(prov)}`, { method: "POST" });
          SUPPRESSED.delete(`${p}|${prov}`);
          refreshFindings();
          loadLatestTriage();
        } catch (e) { toast(String(e), "error"); b.disabled = false; }
      };
    });
}

function paintBars(root) {
  // Aplica los anchos de las barras sin style inline (bloqueado por la CSP).
  if (!root) return;
  root.querySelectorAll(".bar > div[data-pct]").forEach((el) => {
    el.style.width = el.dataset.pct + "%";
  });
}

function wireEventDetail(wrap) {
  // #11: expandir/cerrar el registro completo de cada fila.
  wrap.querySelectorAll("button[data-detail]").forEach((b) => {
    b.onclick = () => {
      const row = document.getElementById(b.dataset.detail);
      if (!row) return;
      const open = row.hidden;
      row.hidden = !open;
      b.setAttribute("aria-expanded", String(open));
    };
  });
}

function wireInvestigate(wrap) {
  // v2.4: asesoria LLM local por evento (display-only; Jev sigue siendo el
  // juez). Solo si llm_enabled; el resultado se inserta como fila debajo.
  if (!LLM_ENABLED) return;
  wrap.querySelectorAll("button[data-investigate]").forEach((b) => {
    b.onclick = async () => {
      const id = Number(b.dataset.investigate);
      b.disabled = true;
      const old = b.textContent;
      b.textContent = "Investigando...";
      try {
        const r = await api("/api/investigate", { method: "POST", body: JSON.stringify({ event_id: id }) });
        if (r.status === "ok") {
          const badge = r.evaluacion === "confirm"
            ? `<span class="badge-ok">${esc(r.evaluacion)}</span>`
            : r.evaluacion === "refuta"
              ? `<span class="badge-warn">${esc(r.evaluacion)}</span>`
              : `<span class="hint">${esc(r.evaluacion)}</span>`;
          const tr = b.closest("tr");
          if (tr) {
            const row = document.createElement("tr");
            row.innerHTML = `<td colspan="11"><details open>
              <summary>Asesoría LLM local — ${badge}</summary>
              <p><b>Porque:</b> ${esc(r.porque || "")}</p>
              <p><b>Evidencia faltante:</b> ${esc(r.evidencia_faltante || "—")}</p>
              <p class="hint">Asesoría display-only: no altera veredictos ni aprobaciones; Jev sigue siendo el juez.</p>
            </details></td>`;
            tr.insertAdjacentElement("afterend", row);
          }
        } else {
          b.disabled = false;
          b.textContent = old;
          toast(`Investigación no disponible (${r.reason || ""})`, "err");
        }
      } catch (e2) {
        b.disabled = false;
        b.textContent = old;
        toast(e2.message, "err");
      }
    };
  });
}

function llmCallsHtml(calls) {
  if (!calls.length) return `<div class="empty">Sin llamadas registradas. Con el inspector activo, apunta el cliente al puerto del proxy.</div>`;
  const totReq = calls.reduce((s, c) => s + (c.request_bytes || 0), 0);
  const totResp = calls.reduce((s, c) => s + (c.response_bytes || 0), 0);
  const head = `<div class="small mono">Total (últimas ${calls.length}): egress ${fmtBytes(totReq)} hacia el LLM · ${fmtBytes(totResp)} de vuelta</div>`;
  return head + calls.map((c) => {
    const status = c.status == null ? "?" : (c.status === 0 ? "sin respuesta" : `HTTP ${c.status}`);
    const proc = c.client_process ? ` · proceso: ${esc(c.client_process)}` : "";
    const rel = (c.related_event_ids && c.related_event_ids.length)
      ? ` · eventos relacionados: ${c.related_event_ids.map((id) => esc(String(id))).join(", ")}`
      : "";
    return `<details>
    <summary class="mono">${esc(c.ts)} · ${esc(c.method || "")} ${esc(c.path || "")} · ${esc(c.model || "—")} · ${status}${c.streaming ? " · stream" : ""}${c.latency_ms != null ? ` · ${c.latency_ms} ms` : ""}</summary>
    <div class="small mono">PID cliente: ${c.client_pid != null ? esc(String(c.client_pid)) : "—"}${proc} · ${esc(c.client_addr || "")}${rel} · prompt ${esc(String(c.prompt_chars == null ? 0 : c.prompt_chars))} chars${c.prompt_tokens != null ? ` (${esc(String(c.prompt_tokens))} tokens)` : ""} · respuesta ${esc(String(c.response_chars == null ? 0 : c.response_chars))} chars${c.completion_tokens != null ? ` (${esc(String(c.completion_tokens))} tokens)` : ""}</div>
    <div class="small mono">Egress medido: ${fmtBytes(c.request_bytes)} hacia el LLM · ${fmtBytes(c.response_bytes)} de vuelta</div>
    <h4>Prompt</h4><pre class="small">${esc(c.prompt || "")}</pre>
    <h4>Respuesta</h4><pre class="small">${esc(c.response || "")}</pre>
  </details>`;
  }).join("");
}

let LLM_CALLS = [];
let llmCallsShown = 25;

function renderLlmCalls() {
  const wrap = document.getElementById("llm-calls-wrap");
  if (!wrap) return;
  const shown = LLM_CALLS.slice(0, llmCallsShown);
  const rest = LLM_CALLS.length - shown.length;
  const pager = rest > 0
    ? `<div class="pager"><button class="linkbtn" id="btn-llm-more">Mostrar las ${rest} restantes (${LLM_CALLS.length} en total)</button></div>`
    : "";
  wrap.innerHTML = llmCallsHtml(shown) + pager;
  const mb = document.getElementById("btn-llm-more");
  if (mb) mb.onclick = () => { llmCallsShown += 25; renderLlmCalls(); };
}

async function refreshLlmCalls() {
  try {
    const d = await api("/api/llm/calls?limit=100");
    LLM_CALLS = d.calls || [];
    setTabCount("ia", LLM_CALLS.length);
    renderLlmCalls();
  } catch (e) { /* server caído */ }
}

let LLM_ENABLED = false;
let lastAlertId = 0;
async function refreshAlerts() {
  try {
    const d = await api(`/api/alerts?since_id=${lastAlertId}`);
    for (const a of d.alerts) {
      lastAlertId = Math.max(lastAlertId, a.id);
      toast(`ALERTA ${a.kind}: ${a.message}`, "err");
    }
  } catch (e) { /* server caído */ }
}

let approvedProviders = [];

async function refreshShadow() {
  const wrap = document.getElementById("shadow-wrap");
  if (!wrap) return;
  try {
    const s = await api("/api/shadow");
    if (!s.shadow.length) {
      wrap.innerHTML = '<p class="hint">Sin shadow AI: todo lo detectado está aprobado.</p>';
      return;
    }
    wrap.innerHTML = s.shadow.map(g => `
      <div class="row">
        <span class="mono">${esc(g.provider)}</span>
        <span class="hint">capa ${g.layers.join("/")} · ${g.processes.length} proceso(s) · ${g.seen_count} veces · último ${esc(g.last_seen)}</span>
        <button data-approve="${esc(g.provider)}" class="primary small">Aprobar proveedor</button>
      </div>`).join("");
    wrap.querySelectorAll("button[data-approve]").forEach(b => {
      b.onclick = async () => {
        const p = b.dataset.approve;
        const list = [...new Set([...approvedProviders, p])].filter(Boolean);
        await api("/api/config", { method: "POST", body: JSON.stringify({ approved_providers: list }) });
        approvedProviders = list;
        toast(`Proveedor ${p} aprobado`);
        refreshShadow();
      };
    });
  } catch (e) { /* sin datos aún */ }
}

function autQuery() {
  const $ = (id) => document.getElementById(id);
  const p = new URLSearchParams();
  p.set("limit", "100");
  const v = $("aut-verdict") && $("aut-verdict").value;
  if (v) p.set("verdict", v);
  const proc = $("aut-process") && $("aut-process").value.trim();
  if (proc) p.set("process", proc);
  const prov = $("aut-provider") && $("aut-provider").value.trim();
  if (prov) p.set("provider", prov);
  if ($("aut-group") && $("aut-group").checked) p.set("group", "provider");
  return p.toString();
}

let autShown = 25;

async function refreshAutonomy() {
  const wrap = document.getElementById("autonomy-wrap");
  if (!wrap) return;
  try {
    const a = await api("/api/autonomy?" + autQuery());
    const sig = a.signals || {};
    const lockedTxt = sig.locked == null ? "?" : (sig.locked ? "bloqueada" : "activa");
    // v2.6(3): etiquetar el estado de la senal (no un '?' mudo ni un
    // numero sin contexto).
    const idleNotes = {
      counter_frozen: "sin senal: contador congelado (sesion sin entrada)",
      api_error: "sin senal: API no disponible",
      idle_gt_uptime: "sin senal: valor imposible (idle > uptime)",
      no_win: "sin senal: solo Windows",
      no_input_since_boot: "sin entrada desde el arranque (sesion sin HID)",
    };
    const note = sig.idle_note && idleNotes[sig.idle_note]
      ? ` (${idleNotes[sig.idle_note]})` : "";
    const idleTxt = sig.idle_seconds != null
      ? `${sig.idle_seconds} s${note}` : `?${note || ""}`;
    let html = `<p class="hint">Sesión: <b>${esc(lockedTxt)}</b> · usuario inactivo: <b>${esc(idleTxt)}</b> · foreground PID: <b>${sig.foreground_pid != null ? esc(String(sig.foreground_pid)) : "?"}</b></p>`;
    // A3: contadores de veredicto sobre TODOS los eventos vivos (sin filtros).
    const c = a.counts || {};
    const counters = document.getElementById("autonomy-counters");
    if (counters) {
      counters.textContent = `Veredictos (eventos vivos): autónomo ${c.autonomous ?? 0} · programado ${c.scheduled ?? 0} · usuario ${c.user_driven ?? 0} · desconocido ${c.unknown ?? 0}`;
    }
    if (!a.events.length) {
      html += '<div class="empty">Sin eventos con los filtros actuales. Si el monitoreo está pausado (kill switch), reanúdalo desde la cabecera.</div>';
    } else if (a.grouped) {
      // v2.6(4): colapsar por proveedor — un proveedor recibe de varios
      // procesos (y de muchos pid:XXXX sin resolver); una fila por
      // proveedor con el peor veredicto y la lista de procesos.
      const byProv = new Map();
      for (const e of a.events) {
        const p = e.provider || "-";
        let b = byProv.get(p);
        if (!b) {
          b = {provider: p, kind: e.kind, procs: new Set(),
               verdict: "unknown", sessions: 0, polls: 0, last: ""};
          byProv.set(p, b);
        }
        b.procs.add(e.process);
        const v = e.autonomy_verdict || "unknown";
        if (v === "autonomous" || v === "scheduled") b.verdict = v;
        b.sessions += e.sessions || 0;
        b.polls += e.seen_count || 0;
        if ((e.last_seen || "") > b.last) b.last = e.last_seen || "";
      }
      const ordered = [...byProv.values()].sort(
        (x, y) => (x.verdict === "unknown") - (y.verdict === "unknown"));
      const shown = ordered.slice(0, autShown);
      const rest = ordered.length - shown.length;
      html += `<table class="aut-table">
        <thead><tr><th>Proveedor</th><th>Veredicto</th><th>Procesos</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Último</th></tr></thead>
        <tbody>${shown.map((b) => {
          const vb = autonomyBadge(b.verdict, null)
            || '<span class="hint">desconocido</span>';
          const procs = [...b.procs];
          const shownProcs = procs.slice(0, 4).join(", ");
          const more = procs.length - Math.min(4, procs.length);
          return `<tr>
            <td class="mono">${esc(b.provider)}${kindBadge(b.kind)}</td>
            <td>${vb}</td>
            <td class="small">${esc(shownProcs)}${more > 0 ? ` (+${more})` : ""}</td>
            <td class="num">${b.sessions}</td>
            <td class="num">${b.polls}</td>
            <td class="mono small">${esc(b.last)}</td>
          </tr>`;
        }).join("")}</tbody></table>` +
        (rest > 0 ? `<div class="pager"><button class="linkbtn" id="btn-aut-more">Mostrar ${rest} más (${ordered.length} proveedores)</button></div>` : "");
    } else {
      html += a.events.slice(0, autShown).map(e => {
        const left = `${esc(e.process)} → ${esc(e.dest_host || e.dest_ip)}:${e.dest_port}`;
        const vb = autonomyBadge(e.autonomy_verdict, e.autonomy_score)
          || '<span class="hint">desconocido</span>';
        return `<div class="row">
        <span class="mono">${left}</span>
        <span class="hint">${vb} · flags ${esc(e.autonomy_flags || "")} · score ${e.autonomy_score ?? "?"} · último ${esc(e.last_seen)}</span>
      </div>`;
      }).join("") + (a.events.length > autShown
        ? `<div class="pager"><button class="linkbtn" id="btn-aut-more">Mostrar ${a.events.length - autShown} más</button></div>`
        : "");
    }
    wrap.innerHTML = html;
    const mb = document.getElementById("btn-aut-more");
    if (mb) mb.onclick = () => { autShown += 25; refreshAutonomy(); };
  } catch (e) { /* sin datos aún */ }
}

// v2.6(4): colapsar eventos vivos que comparten (puerto, protocolo,
// pre_score, flags) en una sola fila con recuento. Los proveedores
// rotan IP anycast (p. ej. Cloudflare IPv6), asi que 100+ IPs distintas
// del mismo proveedor darian 100+ filas identicas; la fila colapsada
// muestra el recuento, una muestra de IPs y los flags una sola vez.
function collapseCurrent(cur) {
  const bySig = new Map();
  for (const c of cur) {
    const fsig = (c.pre_flags || []).map(f => f.flag).join(",");
    const key = `${c.dest_port}|${c.protocol}|${c.pre_score}|${fsig}`;
    let b = bySig.get(key);
    if (!b) {
      b = {count: 0, ips: [], pre_score: c.pre_score,
           dest_port: c.dest_port, protocol: c.protocol,
           pre_flags: c.pre_flags};
      bySig.set(key, b);
    }
    b.count += 1;
    b.ips.push(c.dest_ip);
  }
  return [...bySig.values()];
}

let BASELINE = null;
let baselineShown = 20;

function baselineHtml(b) {
  const groupsAll = b.groups || [];
  if (!groupsAll.length) {
    return '<p class="hint">Sin eventos vivos: sin baseline.</p>';
  }
  const groups = groupsAll.slice(0, baselineShown);
  const rest = groupsAll.length - groups.length;
  let rows = "";
  for (const g of groups) {
    const cur = collapseCurrent(g.current || []);
    const maxScore = (g.current || []).reduce(
      (m, c) => Math.max(m, c.pre_score || 0), 0);
    const badge = maxScore >= 40 ? "badge-bad"
      : maxScore > 0 ? "badge-warn" : "";
    const score = maxScore > 0
      ? `<span class="badge ${badge}">${maxScore}</span>` : "0";
    const detail = cur.map(c => {
      const many = c.count > 1;
      const shown = c.ips.slice(0, 5).join(", ");
      const rest = c.count - Math.min(5, c.count);
      const flags = c.pre_flags.length
        ? c.pre_flags.map(f => `${f.flag}: ${esc(f.porque)}`).join("; ")
        : "sin flags (dentro de lo esperado)";
      return `<div class="small mono">${many ? `${c.count} × ` : ""}` +
        `${esc(c.ips[0])}:${c.dest_port} (${esc(c.protocol)}) — ${flags}` +
        (many
          ? ` · muestra: ${esc(shown)}${rest > 0 ? ` (+${rest} mas)` : ""}`
          : "") +
        `</div>`;
    }).join("") || '<span class="hint">sin eventos vivos</span>';
    const typ = (g.typical_hours || []).length
      ? g.typical_hours.map(h => h + "h").join(", ") : "&mdash;";
    const rate = g.sessions_per_hour != null ? g.sessions_per_hour : "&mdash;";
    rows += `<tr>
      <td><details><summary>${esc(g.process)}</summary>${detail}</details></td>
      <td>${esc(g.provider)} <span class="hint">${esc(g.kind || "")}</span></td>
      <td class="num">${g.first_seen ? g.first_seen.slice(0, 10) : "&mdash;"}</td>
      <td class="num">${g.sessions_total}</td>
      <td class="num">${rate}</td>
      <td class="num">${g.days_active}</td>
      <td>${typ}</td>
      <td class="num">${score}</td>
    </tr>`;
  }
  return `<table class="tbl">
    <thead><tr>
      <th>Proceso</th><th>Proveedor</th>
      <th class="num">1&ordf; aparici&oacute;n</th>
      <th class="num">Sesiones</th>
      <th class="num">Ratio /h</th>
      <th class="num">D&iacute;as activos</th>
      <th>Horas t&iacute;picas (UTC)</th>
      <th class="num">pre_score</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>` + (rest > 0
    ? `<div class="row"><button class="linkbtn" id="btn-baseline-more">Mostrar ${rest} grupos mas (${groupsAll.length} en total)</button></div>`
    : "");
}

async function refreshBaseline() {
  const wrap = document.getElementById("baseline-wrap");
  if (!wrap) return;
  try {
    const r = await fetch("/api/baseline");
    if (r.status === 404) { wrap.innerHTML = ""; return; }
    BASELINE = await r.json();
    wrap.innerHTML = baselineHtml(BASELINE);
    const mb = document.getElementById("btn-baseline-more");
    if (mb) mb.onclick = () => { baselineShown += 20; wrap.innerHTML = baselineHtml(BASELINE); };
  } catch (e) { /* sin datos a&uacute;n */ }
}

async function refreshRules() {
  const wrap = document.getElementById("rules-wrap");
  if (!wrap) return;
  try {
    const r = await api("/api/rules");
    wrap.innerHTML = (r.rules || []).map(x => {
      let badge, txt;
      if (!x.available) { badge = "badge-warn"; txt = `pendiente: ${esc(x.reason || "")}`; }
      else if (x.fired) { badge = "badge-bad"; txt = `DISPARADA · ${esc(x.detail || "")}`; }
      else { badge = "badge-ok"; txt = "no dispara"; }
      return `<div class="row"><span class="mono">${esc(x.id)}</span>
        <span class="${badge}">${txt}</span></div>`;
    }).join("");
  } catch (e) { /* sin datos aún */ }
}

// A4: estado del panel (ventana en días y orden de la tabla de proveedores).
let dashDays = 7;
let dashSortKey = "seen_count";
let dashSortDir = -1;
let dashProvShown = 12;

function providersTableHtml(items) {
  if (!items.length) return `<div class="hint">Sin proveedores en la ventana.</div>`;
  const max = Math.max(1, ...items.map(i => i.seen_count || 0));
  const kindLabel = { api: "API", web: "web", cdn: "CDN" };
  const sorted = [...items].sort((a, b) => {
    const av = a[dashSortKey], bv = b[dashSortKey];
    const cmp = typeof av === "string"
      ? String(av).localeCompare(String(bv)) : (av - bv);
    return cmp * dashSortDir;
  });
  const th = (key, label) =>
    `<th class="sortable${dashSortKey === key ? " active" : ""}" data-sort="${key}">${label}</th>`;
  const shown = sorted.slice(0, dashProvShown);
  const rest = sorted.length - shown.length;
  const rows = shown.map(i => `<tr>
    <td class="mono">${esc(i.name)}</td>
    <td>${kindLabel[i.kind] || esc(i.kind || "")}</td>
    <td>${aiLayerHtml(i.layer)}</td>
    ${numCell(i.seen_count, i.seen_count / max)}
  </tr>`).join("");
  const pager = rest > 0
    ? `<div class="pager"><button class="linkbtn" id="btn-prov-more">Ver los ${rest} restantes (${sorted.length} proveedores)</button></div>`
    : "";
  return `<table class="dash-providers">
    <thead><tr>${th("name", "Proveedor")}<th>Tipo</th><th>Capa</th>${th("seen_count", "Presencias")}</tr></thead>
    <tbody>${rows}</tbody>
  </table>${pager}`;
}

function renderDashboard(d) {
  const wrap = document.getElementById("dashboard-wrap");
  if (!wrap) return;
  // v2.6(6): densidad. Antes: una .row por item (12 px de margen cada una).
  // Ahora: chips inline y una sola tabla de proveedores paginada.
  const topList = (items, label) => items.length
    ? `<p class="hint">${label}</p><div class="chips">` + items.map(i =>
      `<span class="chip"><span class="mono">${esc(i.name)}</span>` +
      (i.sdk ? ` <span class="hint">[${esc(i.sdk)}]</span>` : "") +
      `<span class="num">${i.seen_count}</span></span>`).join("") + `</div>`
    : "";
  const layers = d.layers.length
    ? d.layers.map(l => `${l.layer}: ${l.seen_count}`).join(" / ")
    : "sin datos";
  const llm = d.llm_calls
    ? `${d.llm_calls.calls} llamadas · ${(d.llm_calls.prompt_tokens || 0) + (d.llm_calls.completion_tokens || 0)} tokens · ${fmtBytes((d.llm_calls.request_bytes || 0) + (d.llm_calls.response_bytes || 0))}`
    : "inspector sin datos";
  const daily = d.daily.map(x => `${x.date.slice(5)}: ${x.events} ev / ${x.triages} tri`).join(" · ");
  // v2.3: cloud_bytes disponible -> total + desglose por proveedor con
  // label api/web/cdn y hostname resuelto cuando el provider es 'desconocido'.
  const cb = d.cloud_bytes || {};
  const kindLabel = { api: "API", web: "web", cdn: "CDN" };
  const provAll = cb.by_provider || [];
  const provShown = provAll.slice(0, 8);
  const provRest = provAll.length - provShown.length;
  const provRows = provShown.map(p =>
    `<span class="chip"><span class="mono">${esc(p.provider)}</span>` +
    (p.host && p.host !== p.provider ? ` <span class="hint">(${esc(p.host)})</span>` : "") +
    (kindLabel[p.kind] ? ` <span class="hint">[${kindLabel[p.kind]}]</span>` : "") +
    ` <span class="num">${fmtBytes(p.bytes)}</span></span>`).join("");
  const restLine = provRest > 0
    ? `<span class="hint">+${provRest} proveedor(es) más</span>` : "";
  const cloudLine = cb.available
    ? `<div class="row"><b>Bytes cloud (TLS remoto)</b>: <span class="mono">${fmtBytes(cb.total_bytes || 0)}</span>${cb.spawn_method ? ` <span class="hint">(${esc(cb.spawn_method)})</span>` : ""}</div><div class="chips">${provRows}${restLine}</div>`
    : `<div class="row"><span class="hint">Bytes cloud: no disponible para TLS remoto (${esc(cb.reason || "")}).</span></div>`;
  // A4: resumen agregado de la ventana (totales y cardinalidades).
  const s = d.summary || {};
  const sumLine = s.events != null
    ? `<div class="chips"><span class="chip"><span class="hint">Resumen (${d.days} días)</span><b class="num">${s.events} eventos</b><span class="num">${s.seen_total} presencias</span><span class="num">${s.processes} procesos</span><span class="num">${s.providers} proveedores</span></span></div>`
    : "";
  const empty = !d.top_providers.length && !d.daily.length
    ? `<div class="empty">Sin datos en la ventana. Si el monitoreo está pausado (kill switch), reanúdalo con el botón de la cabecera; los eventos aparecen en cuanto hay conexiones IA.</div>`
    : "";
  wrap.innerHTML = `
    ${empty}
    <div class="chips">
      <span class="chip"><span class="hint">Capas</span><span class="num">${layers}</span></span>
      <span class="chip"><a href="#shadow-card">Shadow AI</a><span class="num">${d.shadow_count}</span></span>
      <span class="chip"><span class="hint">LLM Inspector</span><span class="num">${llm}</span></span>
    </div>
    ${sumLine}
    <div class="row"><span class="hint">Actividad (${d.days} días): ${daily || "sin datos"}</span></div>
    ${providersTableHtml(d.top_providers)}
    ${topList(d.top_processes, "Top procesos")}
    <div id="dash-sdk-block"></div>
    ${cloudLine}`;
  // A4: orden por cabecera (sin re-fetch; solo re-render con el dato cacheado).
  wrap.querySelectorAll("th.sortable").forEach(thEl => {
    thEl.onclick = () => {
      const k = thEl.dataset.sort;
      if (dashSortKey === k) dashSortDir *= -1;
      else { dashSortKey = k; dashSortDir = k === "name" ? 1 : -1; }
      renderDashboard(d);
    };
  });
  const pm = document.getElementById("btn-prov-more");
  if (pm) pm.onclick = () => { dashProvShown += 12; renderDashboard(d); };
}

async function refreshDashboard() {
  try {
    const d = await api(`/api/dashboard?days=${dashDays}`);
    renderDashboard(d);
    // v2.3: ficha de proceso por fingerprint de SDK IA (display).
    let sdkBlock = "";
    try {
      const sp = await api("/api/processes");
      if ((sp.processes || []).length) {
        sdkBlock = `<p class="hint">Procesos con SDK IA instalado</p>` + sp.processes.map(p =>
          `<div class="row"><span class="mono" title="${esc(p.image)}">${esc(p.image)}</span> <span class="hint">${esc(p.label)}</span></div>`).join("");
      }
    } catch (e) { /* sin monitor */ }
    const slot = document.getElementById("dash-sdk-block");
    if (slot) slot.innerHTML = sdkBlock;
  } catch (e) { /* sin datos aún */ }
}

function renderMonitorState(enabled) {
  const btn = document.getElementById("btn-monitor");
  if (!btn) return;
  btn.textContent = enabled ? "Monitoreo: ACTIVO" : "Monitoreo: PAUSADO";
  btn.classList.toggle("paused", !enabled);
  btn.setAttribute("aria-pressed", String(!enabled));
}

async function loadConfig() {
  try {
    const c = await api("/api/config");
    LLM_ENABLED = !!c.llm_enabled;
    renderMonitorState(c.monitoring_enabled !== false);
    const jevKey = document.getElementById("jev-key");
    // El servidor nunca devuelve la key: solo el flag. No se rellena el
    // input con la mascara (bug U-01: guardar sin escribir borraba la key).
    jevKey.value = "";
    jevKey.placeholder = c.jev_api_key_set ? "key ya guardada (oculta)" : "API key";
    const jevState = document.getElementById("jev-key-state");
    if (jevState) jevState.textContent = c.jev_api_key_set ? "Key guardada (DPAPI). Escribir una nueva la sustituye." : "Sin key guardada.";
    document.getElementById("llm-url").value = c.llm_base_url || "";
    document.getElementById("llm-model").value = c.llm_model || "";
    document.getElementById("llm-proxy-port").value = c.llm_proxy_port || 8098;
    document.getElementById("llm-proxy-target").value = c.llm_proxy_target || "127.0.0.1:8099";
    const layaUrl = document.getElementById("laya-url");
    if (layaUrl) {
      layaUrl.value = c.laya_base_url || "";
      document.getElementById("laya-model").value = c.laya_model || "";
      document.getElementById("laya-toggle").checked = !!c.laya_enabled;
    }
    const pt = document.getElementById("llm-proxy-toggle");
    pt.checked = !!c.llm_proxy_enabled;
    document.getElementById("alerts-toggle").checked = !!c.alerts_enabled;
    document.getElementById("alert-webhook").value = c.alert_webhook_url || "";
    document.getElementById("retention-days").value = c.retention_days || 90;
    document.getElementById("retention-llm-days").value = c.retention_days_llm || 30;
    document.getElementById("llm-content-store").checked = !!c.llm_store_content;
    const jevMin = document.getElementById("jev-minimal");
    if (jevMin) jevMin.checked = !!c.jev_minimal;
    approvedProviders = c.approved_providers || [];
    SUPPRESSED = new Set(c.suppressed_findings || []);
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
    const wrap = document.getElementById("triage-results");
    wrap.innerHTML = triageHtml(t.payload);
    paintBars(wrap);
    wrap.querySelectorAll("button[data-more]").forEach((b) => {
      b.onclick = () => {
        wrap.querySelectorAll(`tr.extra-${b.dataset.more}`).forEach((r) => { r.hidden = false; });
        paintBars(wrap);
        b.remove();
      };
    });
    wireInvestigate(wrap); // A2: mismo boton Investigar que en la tabla de eventos.
  } catch (e) { /* sin triajes aún */ }
}

// B: revision LLM local por lote (asesoria display-only, sin auto).
const REVIEW_EVAL_BADGE = {
  confirm: "badge-ok", refuta: "badge-bad", insuficiente: "badge-warn",
};

function reviewRowHtml(r) {
  const badge = r.evaluacion != null
    ? `<span class="${REVIEW_EVAL_BADGE[r.evaluacion] || "badge-warn"}">${esc(r.evaluacion)}</span>`
    : `<span class="hint">no disponible${r.reason ? ` (${esc(r.reason)})` : ""}</span>`;
  const acc = r.accion
    ? `<span class="${r.accion === "sacar" ? "badge-ok" : "badge-bad"}">${esc(r.accion)}</span>`
    : "";
  return `<div class="row"><b>#${r.event_id}</b> ${badge} ${acc}` +
    (r.porque ? `<div class="small hint">${esc(r.porque)}</div>` : "") +
    (r.evidencia_faltante ? `<div class="small hint">Falta: ${esc(r.evidencia_faltante)}</div>` : "") +
    `</div>`;
}

function renderReviewResults(data) {
  const wrap = document.getElementById("review-results");
  if (!wrap) return;
  if (data.status === "unavailable") {
    wrap.innerHTML = `<div class="hint">LLM no disponible (${esc(data.reason || "")}): sin revision.</div>`;
    return;
  }
  const rows = (data.reviews || []).map(reviewRowHtml).join("");
  wrap.innerHTML =
    `<p class="hint">Scope: ${esc(data.scope)} · revisados ${data.reviews.length}/${data.requested} (tope ${data.cap})</p>` + rows;
}

async function runReview(body) {
  const status = document.getElementById("review-status");
  if (status) status.textContent = "revisando...";
  try {
    const data = await api("/api/review", { method: "POST", body: JSON.stringify(body) });
    renderReviewResults(data);
    if (status) status.textContent = "";
    loadReviewHistory();
  } catch (e) {
    if (status) status.textContent = `error: ${e.message || e}`;
  }
}

async function loadReviewHistory() {
  const wrap = document.getElementById("review-history");
  if (!wrap) return;
  try {
    const d = await api("/api/reviews?limit=10");
    const rows = d.reviews || [];
    wrap.innerHTML = rows.length
      ? `<p class="hint">${rows.map(r =>
        `#${r.event_id} · ${esc(r.evaluacion || "no disponible")}${r.accion ? ` (${esc(r.accion)})` : ""} (${esc((r.ts || "").slice(0, 16))})`).join(" · ")}</p>`
      : `<div class="hint">Sin revisiones todavía.</div>`;
  } catch (e) { /* sin historial */ }
}

function bind() {
  const $ = (id) => document.getElementById(id);

  $("btn-theme").addEventListener("click", themeToggle);
  // A1: la guia es ya una pestana; el boton del header lleva a ella.
  $("btn-guide").addEventListener("click", () => showTab("guia"));
  // Kill switch global: pausa/reanuda el monitoreo sin reiniciar el server.
  $("btn-monitor").addEventListener("click", async () => {
    const btn = $("btn-monitor");
    const next = btn.classList.contains("paused");
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
    window.location.href = "/api/export/json";
  });
  $("btn-exp-csv").addEventListener("click", () => {
    window.location.href = "/api/export/csv";
  });
  $("btn-exp-pdf").addEventListener("click", () => {
    window.location.href = "/api/export/pdf";
  });
  // Evidencia (v2.3): days sale del select de opciones fijas (1/7/30/90).
  const evDays = () => {
    const v = parseInt($("ev-days").value, 10);
    return [1, 7, 30, 90].includes(v) ? v : 7;
  };
  $("btn-ev-chain").addEventListener("click", () => {
    window.location.href = `/api/evidence/chain?days=${evDays()}`;
  });
  $("btn-ev-stix").addEventListener("click", () => {
    window.location.href = `/api/evidence/stix?days=${evDays()}`;
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
      const wrap = document.getElementById("triage-results");
      wrap.innerHTML = triageHtml(data);
      wireInvestigate(wrap); // A2: boton Investigar en la tabla de triaje.
      $("triage-status").textContent = "Completado.";
      toast("Triaje guardado.", "ok");
    } catch (e) {
      $("triage-status").textContent = "";
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
    }
  });

  const evRefresh = () => refreshEvents();
  ["ev-group", "ev-layer", "ev-verdict", "ev-shadow", "ev-hide-cdn"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", evRefresh);
  });
  ["ev-process", "ev-dest"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", evRefresh);
  });
  $("btn-ev-clear").addEventListener("click", () => {
    $("ev-group").checked = true;
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

  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => showTab(t.dataset.tab)));

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
