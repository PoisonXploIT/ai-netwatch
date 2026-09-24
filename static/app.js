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

function groupedEventsTableHtml(events) {
  if (!events.length) return `<div class="hint">Sin eventos con los filtros actuales.</div>`;
  const rows = events.map((e) => `<tr>
    <td>${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}</td>
    <td class="mono">${esc(e.provider || "-")}${kindBadge(e.kind)}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 0}${beaconBadge(e)}</td>
    <td class="num">${e.seen_count ?? 0}</td>
    <td class="num" title="IPs distintas para este proceso y proveedor (CDN rotatorio).">${e.ip_count ?? 0}</td>
    <td class="mono small">${esc(e.first_seen || "")}</td>
    <td class="mono small">${esc(e.last_seen || "")}</td>
  </tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Proveedor</th><th>IA (capa)</th><th>Autonomía</th><th class="num" title="Sesiones = transiciones ausente→presente.">Sesiones</th><th class="num" title="Polls = muestras de presencia.">Polls</th><th class="num">#IPs</th><th>Primera vez</th><th>Última vez</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function eventsTableHtml(events, grouped) {
  if (grouped) return groupedEventsTableHtml(events);
  if (!events.length) return `<div class="hint">Sin eventos todavía (monitor activo).</div>`;
  const rows = events.map((e) => `<tr>
    <td><label class="check small" title="Seleccionar para Revisar (batch)"><input type="checkbox" class="ev-check" data-evid="${e.id}"></label> ${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}${LLM_ENABLED ? `<div class="small"><button class="small" data-investigate="${e.id}">Investigar con LLM local</button></div>` : ""}</td>
    <td class="mono">${esc(e.dest_host || e.dest_ip)}:${e.dest_port}</td>
    <td>${esc(e.protocol || "tcp")}</td>
    <td class="mono">${esc(e.sni_domain || "")}</td>
    <td>${esc(e.catalog_domain || "")}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 1}${beaconBadge(e)}</td>
    <td class="num">${e.seen_count}</td>
    <td class="mono small">${esc(e.first_seen)}</td>
    <td class="mono small">${esc(e.last_seen)}</td>
  </tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Destino</th><th>Proto</th><th>Dominio (SNI)</th><th>Catálogo</th><th title="Sesiones = transiciones ausente→presente (F1); Polls = muestras de presencia.">IA (capa)</th><th>Autonomía</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Primera vez</th><th>Última vez</th></tr></thead>
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
    const evs = data.events || [];
    let triaged = 0;
    const rows = evs.map((e, i) => {
      const v = (jev.verdicts || {})[String(i)] || {};
      if (v.verdict != null) triaged++;
      // Sin veredicto: 'no triado' explicito (no un vacio que parezca fallo).
      const cls = v.verdict != null ? verdictBadge(v.verdict)
        : `<span class="hint">no triado</span>`;
      const inv = LLM_ENABLED
        ? `<div class="small"><button class="small" data-investigate="${e.id}">Investigar</button></div>`
        : "";
      return `<tr>
        <td>${esc(e.process)}${inv}</td>
        <td class="mono">${esc(e.dest)}</td>
        <td>${cls}</td>
        ${numCell(v.confidence, v.confidence)}
        ${numCell(v.prob_false_positive == null ? null : Math.round(v.prob_false_positive * 100) + "%", v.prob_false_positive)}
        ${sevCell(v.severity_score)}
        ${numCell(v.immediate_action, v.immediate_action)}
      </tr>`;
    }).join("");
    const countNote = triaged < evs.length
      ? ` <span class="hint">(triados ${triaged} de ${evs.length})</span>` : "";
    parts.push(`<h3>Veredictos Jev${countNote}</h3><table>
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

async function refreshEvents() {
  try {
    const d = await api("/api/events?" + eventsQuery());
    const wrap = document.getElementById("events-wrap");
    wrap.innerHTML = eventsTableHtml(d.events, d.grouped);
    wireInvestigate(wrap);
  } catch (e) { /* server caído */ }
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
  if (!calls.length) return `<div class="hint">Sin llamadas registradas. Con el inspector activo, apunta el cliente al puerto del proxy.</div>`;
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

async function refreshLlmCalls() {
  try {
    const d = await api("/api/llm/calls?limit=100");
    document.getElementById("llm-calls-wrap").innerHTML = llmCallsHtml(d.calls);
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

async function refreshAutonomy() {
  const wrap = document.getElementById("autonomy-wrap");
  if (!wrap) return;
  try {
    const a = await api("/api/autonomy?" + autQuery());
    const sig = a.signals || {};
    const lockedTxt = sig.locked == null ? "?" : (sig.locked ? "bloqueada" : "activa");
    const idleTxt = sig.idle_seconds != null ? `${sig.idle_seconds} s` : "?";
    let html = `<p class="hint">Sesión: <b>${esc(lockedTxt)}</b> · usuario inactivo: <b>${esc(idleTxt)}</b> · foreground PID: <b>${sig.foreground_pid != null ? esc(String(sig.foreground_pid)) : "?"}</b></p>`;
    // A3: contadores de veredicto sobre TODOS los eventos vivos (sin filtros).
    const c = a.counts || {};
    const counters = document.getElementById("autonomy-counters");
    if (counters) {
      counters.textContent = `Veredictos (eventos vivos): autónomo ${c.autonomous ?? 0} · programado ${c.scheduled ?? 0} · usuario ${c.user_driven ?? 0} · desconocido ${c.unknown ?? 0}`;
    }
    if (!a.events.length) {
      html += '<p class="hint">Sin eventos con los filtros actuales.</p>';
    } else {
      html += a.events.map(e => {
        // Las filas agrupadas no llevan dest (son (proceso, proveedor));
        // la rama se decide por `grouped`, no por presencia de dest_port.
        const left = a.grouped
          ? `${esc(e.process)} → ${esc(e.provider || "-")}${kindBadge(e.kind)}`
          : `${esc(e.process)} → ${esc(e.dest_host || e.dest_ip)}:${e.dest_port}`;
        const vb = autonomyBadge(e.autonomy_verdict, e.autonomy_score)
          || '<span class="hint">desconocido</span>';
        const extra = a.grouped
          ? ` · ${e.seen_count ?? 0} polls · ${e.sessions ?? 0} sesiones`
          : ` · score ${e.autonomy_score ?? "?"}`;
        return `<div class="row">
        <span class="mono">${left}</span>
        <span class="hint">${vb} · flags ${esc(e.autonomy_flags || "")}${extra} · último ${esc(e.last_seen)}</span>
      </div>`;
      }).join("");
    }
    wrap.innerHTML = html;
  } catch (e) { /* sin datos aún */ }
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
  const rows = sorted.map(i => `<tr>
    <td class="mono">${esc(i.name)}</td>
    <td>${kindLabel[i.kind] || esc(i.kind || "")}</td>
    <td>${aiLayerHtml(i.layer)}</td>
    ${numCell(i.seen_count, i.seen_count / max)}
  </tr>`).join("");
  return `<table class="dash-providers">
    <thead><tr>${th("name", "Proveedor")}<th>Tipo</th><th>Capa</th>${th("seen_count", "Presencias")}</tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderDashboard(d) {
  const wrap = document.getElementById("dashboard-wrap");
  if (!wrap) return;
  const topList = (items, label) => items.length
    ? `<p class="hint">${label}</p>` + items.map(i =>
      `<div class="row"><span class="mono">${esc(i.name)}</span>` +
      (i.sdk ? ` <span class="hint">[${esc(i.sdk)}]</span>` : "") +
      `<span class="hint">${i.seen_count} presencias</span></div>`).join("")
    : "";
  const layers = d.layers.length
    ? d.layers.map(l => `${l.layer}: ${l.seen_count}`).join(" · ")
    : "sin datos";
  const llm = d.llm_calls
    ? `llamadas: ${d.llm_calls.calls} · tokens: ${(d.llm_calls.prompt_tokens || 0) + (d.llm_calls.completion_tokens || 0)} · bytes locales: ${fmtBytes((d.llm_calls.request_bytes || 0) + (d.llm_calls.response_bytes || 0))}`
    : "inspector sin datos";
  const daily = d.daily.map(x => `${x.date}: ${x.events} ev / ${x.triages} tri`).join(" · ");
  // v2.3: cloud_bytes disponible -> total + desglose por proveedor con
  // label api/web/cdn y hostname resuelto cuando el provider es 'desconocido'.
  const cb = d.cloud_bytes || {};
  const kindLabel = { api: "API", web: "web", cdn: "CDN" };
  const provRows = (cb.by_provider || []).map(p =>
    `<div class="row"><span class="mono">${esc(p.provider)}</span>` +
    (p.host && p.host !== p.provider ? ` <span class="hint">(${esc(p.host)})</span>` : "") +
    (kindLabel[p.kind] ? ` <span class="hint">[${kindLabel[p.kind]}]</span>` : "") +
    ` <span class="mono">${fmtBytes(p.bytes)}</span></div>`).join("");
  const cloudLine = cb.available
    ? `<div class="row"><b>Bytes cloud (TLS remoto)</b>: <span class="mono">${fmtBytes(cb.total_bytes || 0)}</span>${cb.spawn_method ? ` <span class="hint">(${esc(cb.spawn_method)})</span>` : ""}</div>${provRows}`
    : `<div class="row"><span class="hint">Bytes cloud: no disponible para TLS remoto (${esc(cb.reason || "")}).</span></div>`;
  // A4: resumen agregado de la ventana (totales y cardinalidades).
  const s = d.summary || {};
  const sumLine = s.events != null
    ? `<div class="row"><span class="hint">Resumen (${d.days} días): ${s.events} eventos · ${s.seen_total} presencias · ${s.processes} procesos · ${s.providers} proveedores</span></div>`
    : "";
  wrap.innerHTML = `
    <div class="row"><span class="hint">Actividad (${d.days} días): ${daily || "sin datos"}</span></div>
    ${sumLine}
    <p class="hint">Top proveedores por presencia (clic en cabecera para ordenar)</p>
    ${providersTableHtml(d.top_providers)}
    ${topList(d.top_processes, "Top procesos")}
    <div id="dash-sdk-block"></div>
    <div class="row"><span class="hint">Capas: ${layers}</span></div>
    <div class="row"><a href="#shadow-card" class="hint">Shadow AI: ${d.shadow_count} proveedor(es) no aprobado(s)</a></div>
    <div class="row"><span class="hint">LLM Inspector (local): ${llm}</span></div>
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

async function loadConfig() {
  try {
    const c = await api("/api/config");
    LLM_ENABLED = !!c.llm_enabled;
    document.getElementById("jev-key").value = c.jev_api_key || "";
    document.getElementById("llm-url").value = c.llm_base_url || "";
    document.getElementById("llm-model").value = c.llm_model || "";
    document.getElementById("llm-proxy-port").value = c.llm_proxy_port || 8098;
    document.getElementById("llm-proxy-target").value = c.llm_proxy_target || "127.0.0.1:8099";
    const pt = document.getElementById("llm-proxy-toggle");
    pt.checked = !!c.llm_proxy_enabled;
    document.getElementById("alerts-toggle").checked = !!c.alerts_enabled;
    document.getElementById("alert-webhook").value = c.alert_webhook_url || "";
    document.getElementById("retention-days").value = c.retention_days || 90;
    document.getElementById("retention-llm-days").value = c.retention_days_llm || 30;
    document.getElementById("llm-content-store").checked = !!c.llm_store_content;
    approvedProviders = c.approved_providers || [];
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
  return `<div class="row"><b>#${r.event_id}</b> ${badge}` +
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
        `#${r.event_id} · ${esc(r.evaluacion || "no disponible")} (${esc((r.ts || "").slice(0, 16))})`).join(" · ")}</p>`
      : `<div class="hint">Sin revisiones todavía.</div>`;
  } catch (e) { /* sin historial */ }
}

function bind() {
  const $ = (id) => document.getElementById(id);

  $("btn-theme").addEventListener("click", themeToggle);
  // A1: la guía nace oculta; el botón la muestra/oculta (ya no hace scroll).
  $("btn-guide").addEventListener("click", () => {
    const g = document.getElementById("guide-card");
    if (!g) return;
    const hidden = g.classList.toggle("guide-hidden");
    $("btn-guide").setAttribute("aria-expanded", String(!hidden));
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
    if (el) el.addEventListener("input", () => {
      clearTimeout(el._t);
      el._t = setTimeout(evRefresh, 300);
    });
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
  // A3: filtros de la tarjeta Autonomía (veredicto/proceso/proveedor/grupo).
  ["aut-verdict", "aut-group"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", refreshAutonomy);
  });
  ["aut-process", "aut-provider"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("input", () => {
      clearTimeout(el._t);
      el._t = setTimeout(refreshAutonomy, 300);
    });
  });
  $("btn-aut-clear").addEventListener("click", () => {
    $("aut-verdict").value = "";
    $("aut-process").value = "";
    $("aut-provider").value = "";
    $("aut-group").checked = false;
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
   ["btn-rev-untriaged", "untriaged"]].forEach(([id, scope]) => {
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

  loadConfig();
  loadLatestTriage();
  loadReviewHistory();
  refreshEvents();
  refreshStats();
  refreshLlmCalls();
  refreshShadow();
  refreshAutonomy();
  refreshRules();
  refreshDashboard();
  setInterval(refreshEvents, 5000);
  setInterval(refreshStats, 60000);
  setInterval(refreshLlmCalls, 10000);
  setInterval(refreshAlerts, 10000);
  setInterval(refreshShadow, 15000);
  setInterval(refreshAutonomy, 15000);
  setInterval(refreshRules, 60000);
  setInterval(refreshDashboard, 60000);
}

document.addEventListener("DOMContentLoaded", bind);
