// 03-events.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
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
    ["protocolo", e.protocol], ["SNI", e.sni_domain], ["catálogo", e.catalog_domain],
    ["capa IA", e.ai_layer], ["veredicto", e.autonomy_verdict], ["score", e.autonomy_score],
    ["sesiones", e.sessions], ["polls", e.seen_count],
    ["primera vez", e.first_seen], ["última vez", e.last_seen],
    ["anomalía", e.pre_score], ["flags", flags], ["MITRE", mitre],
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
    ? `<p class="hint">... y ${(g.member_total || 0) - (g.members || []).length} registros más (limitado a 10 por grupo).</p>`
    : "";
  const head = detailDl([
    ["proceso", g.process], ["imagen", g.image], ["proveedor", g.provider],
    ["destinos", (g.hosts || []).join(", ")], ["PID", (g.pids || []).join(", ")],
    ["capa IA", g.ai_layer], ["veredicto", g.autonomy_verdict], ["score", g.autonomy_score],
    ["sesiones", g.sessions], ["polls", g.seen_count], ["#IPs", g.ip_count],
    ["primera vez", g.first_seen], ["última vez", g.last_seen],
    ["anomalía", g.pre_score], ["MITRE", mitre],
  ]);
  const table = members
    ? `<table class="subtable"><thead><tr><th>IP:puerto</th><th>SNI</th><th>Catálogo</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Primera vez</th><th>Última vez</th></tr></thead><tbody>${members}</tbody></table>${more}`
    : "";
  return head + table;
}

// E-03: une filas del mismo proceso y la misma organización (display-only).
// api.x.com y www.x.com van a x.com; los procesos sin nombre (pid:NNN) van juntos.
const ORG_SLD = ["co", "com", "org", "net", "ac", "gov", "edu"];

function orgOf(host) {
  const h = String(host || "").toLowerCase();
  if (!h || /^[\d.:]+$/.test(h)) return h;
  const p = h.split(".");
  if (p.length <= 2) return h;
  const two = p[p.length - 1].length === 2 && ORG_SLD.includes(p[p.length - 2]);
  return p.slice(two ? -3 : -2).join(".");
}

const LAYER_RANK = { catalog: 0, heuristic: 1, llm: 2, unlisted: 3 };

function mergeRows(events) {
  const byKey = new Map();
  for (const e of events) {
    const pid = /^pid:\d+$/.test(e.process || "");
    const proc = pid ? "sin nombre" : e.process;
    const org = orgOf(e.provider);
    const k = proc + "|" + org;
    const g = byKey.get(k);
    if (!g) {
      byKey.set(k, { ...e, process: proc, provider: org, hosts: [e.provider], pids: pid ? [e.process] : [] });
      continue;
    }
    if (!g.hosts.includes(e.provider)) g.hosts.push(e.provider);
    if (pid && !g.pids.includes(e.process)) g.pids.push(e.process);
    for (const f of ["sessions", "seen_count", "ip_count", "member_total"]) g[f] = (g[f] || 0) + (e[f] || 0);
    g.members = (g.members || []).concat(e.members || []);
    if ((e.last_seen || "") > (g.last_seen || "")) g.last_seen = e.last_seen;
    if (e.first_seen && (!g.first_seen || e.first_seen < g.first_seen)) g.first_seen = e.first_seen;
    if ((LAYER_RANK[e.ai_layer] ?? 9) < (LAYER_RANK[g.ai_layer] ?? 9)) g.ai_layer = e.ai_layer;
    if (e.autonomy_verdict === "autonomous") {
      g.autonomy_verdict = e.autonomy_verdict;
      g.autonomy_score = Math.max(g.autonomy_score || 0, e.autonomy_score || 0);
    }
    if (g.image !== e.image) g.image = "";
  }
  return [...byKey.values()];
}

// U-03: filas pintadas en la tabla de eventos; el detalle se genera al abrirlo.
let EVENT_ROWS = [];

function groupedEventsTableHtml(events) {
  if (!events.length) return `<div class="hint">Sin eventos con los filtros actuales.</div>`;
  const rows = events.map((e, i) => `<tr>
    <td>${esc(e.process)}${e.pids && e.pids.length > 1 ? ` <span class="hint">· ${e.pids.length} PID</span>` : ""}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}</td>
    <td class="mono">${esc(e.provider || "-")}${kindBadge(e.kind)}${e.hosts && e.hosts.length > 1 ? ` <span class="hint">· ${e.hosts.length} destinos</span>` : ""}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 0}${beaconBadge(e)}</td>
    <td class="num" title="IPs distintas para este proceso y proveedor (CDN rotatorio).">${e.ip_count ?? 0}</td>
    <td class="small">${whenCell(e.last_seen)}</td>
    <td><button class="linklike" data-detail="ev-d-g${i}" aria-expanded="false">detalle</button></td>
  </tr>
  <tr class="ev-detail" id="ev-d-g${i}" data-idx="${i}" data-kind="g" hidden><td colspan="8"></td></tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Proveedor</th><th>IA (capa)</th><th>Autonomía</th><th class="num" title="Sesiones = transiciones ausente→presente.">Sesiones</th><th class="num">#IPs</th><th>Última vez</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function eventsTableHtml(events, grouped) {
  EVENT_ROWS = events;
  if (grouped) return groupedEventsTableHtml(events);
  if (!events.length) return `<div class="hint">Sin eventos todavía (monitor activo).</div>`;
  const rows = events.map((e, i) => `<tr>
    <td><label class="check small" title="Seleccionar para Revisar (batch)"><input type="checkbox" class="ev-check" data-evid="${e.id}"></label> ${esc(e.process)}${e.image ? `<div class="small mono" title="${esc(e.image)}">${esc(e.image)}</div>` : ""}${LLM_ENABLED ? `<div class="small"><button class="small" data-investigate="${e.id}">Investigar con LLM local</button></div>` : ""}</td>
    <td class="mono">${esc(e.dest_host || e.dest_ip)}:${e.dest_port}</td>
    <td class="mono">${esc(e.sni_domain || "")}</td>
    <td>${aiLayerHtml(e.ai_layer)}</td>
    <td>${autonomyBadge(e.autonomy_verdict, e.autonomy_score)}</td>
    <td class="num">${e.sessions ?? 1}${beaconBadge(e)}</td>
    <td class="small">${whenCell(e.last_seen)}</td>
    <td><button class="linklike" data-detail="ev-d-${i}" aria-expanded="false">detalle</button></td>
  </tr>
  <tr class="ev-detail" id="ev-d-${i}" data-idx="${i}" data-kind="e" hidden><td colspan="8"></td></tr>`).join("");
  return `<table>
    <thead><tr><th>Proceso</th><th>Destino</th><th>Dominio (SNI)</th><th title="Capa de detección: catálogo, heurística o LLM local.">IA (capa)</th><th>Autonomía</th><th class="num" title="Sesiones = transiciones ausente→presente (F1). Polls y primera vez estan en el detalle.">Sesiones</th><th>Última vez</th><th></th></tr></thead>
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
  const q = $("ev-search") && $("ev-search").value.trim();
  if (q && !dest) p.set("dest", q);
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
  const orgBox = document.getElementById("ev-org");
  const all = EVENTS.grouped && orgBox && orgBox.checked ? mergeRows(EVENTS.events) : EVENTS.events;
  const list = all.slice(0, eventsShown);
  const more = all.length > list.length
    ? `<div class="row"><button class="linkbtn" id="btn-events-more">Mostrar ${all.length - list.length} más (${all.length} en total)</button></div>`
    : "";
  wrap.innerHTML = eventsTableHtml(list, EVENTS.grouped) + more;
  setTabCount("eventos", all.length);
  wireInvestigate(wrap);
  wireEventDetail(wrap);
  const mb = document.getElementById("btn-events-more");
  if (mb) mb.onclick = () => { eventsShown += 60; renderEvents(); };
}

async function loadFacets() {
  try {
    const d = await api("/api/facets");
    const opt = (v) => `<option value="${esc(v)}">${esc(v)}</option>`;
    const isPid = (v) => /^pid:\d+$/.test(v);
    const procOptions = (items) => {
      const named = (items || []).filter((v) => !isPid(v));
      const pids = (items || []).filter(isPid);
      return named.map(opt).join("") + (pids.length
        ? `<optgroup label="Sin nombre (${pids.length} PID)">${pids.map(opt).join("")}</optgroup>`
        : "");
    };
    const fill = (id, items, allLabel, render) => {
      const sel = document.getElementById(id);
      if (!sel) return;
      const cur = sel.value;
      sel.innerHTML = `<option value="">${allLabel}</option>` +
        (render ? render(items) : (items || []).map(opt).join(""));
      if (cur) sel.value = cur;
    };
    fill("ev-process", d.processes, "Todos los procesos", procOptions);
    fill("ev-dest", d.destinations, "Todos los destinos");
    fill("aut-process", d.processes, "Todos los procesos", procOptions);
    fill("aut-provider", d.providers, "Todos los proveedores");
  } catch (e) { /* sin facets */ }
}

function wireEventDetail(wrap) {
  // #11: expandir/cerrar el registro completo de cada fila.
  wrap.querySelectorAll("button[data-detail]").forEach((b) => {
    b.onclick = () => {
      const row = document.getElementById(b.dataset.detail);
      if (!row) return;
      const cell = row.firstElementChild;
      if (cell && !cell.innerHTML && row.dataset.idx != null) {
        const ev = EVENT_ROWS[Number(row.dataset.idx)];
        if (ev) {
          cell.innerHTML = row.dataset.kind === "g" ? groupDetailHtml(ev) : eventDetailHtml(ev);
          paintBars(cell);
        }
      }
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
          const COINCIDE = { coincide: "badge-ok", discrepa: "badge-bad", dudoso: "badge-warn" };
          const tr = b.closest("tr");
          if (tr) {
            const row = document.createElement("tr");
            row.innerHTML = `<td colspan="11"><details open>
              <summary>Juicio del LLM local (${esc(r.model || "llm")}) — ${badge}` +
                (r.coincide ? ` · <span class="${COINCIDE[r.coincide] || "badge-warn"}">${esc(r.coincide)}</span>` : "") +
                `</summary>
              <p class="juicio">${esc(r.juicio || "")}</p>
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

