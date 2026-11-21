// 06-charts.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
function paintBars(root) {
  // Aplica los anchos de las barras sin style inline (bloqueado por la CSP).
  if (!root) return;
  root.querySelectorAll(".bar > div[data-pct]").forEach((el) => {
    el.style.width = el.dataset.pct + "%";
  });

}

/* ---------------------------------------------------------------------------
   Graficas del Panel (v2.6.7). Todo en SVG: la geometria va en atributos
   (x, y, r, stroke-dasharray) y el color en CSS. La CSP es style-src 'self',
   asi que no se puede style="..."; los atributos de presentacion SVG no son
   'style', por eso esto funciona sin relajar la politica.
   --------------------------------------------------------------------------- */
const CW = 600;          // ancho del viewBox de las graficas de barras
const LEFT = 48;         // reserva para el eje Y
const RIGHT = 580;
const BASE_Y = 118;      // linea de base
const TOP_Y = 18;        // techo util
const SPAN = BASE_Y - TOP_Y;

const LAYER_COLOR = {
  catalog: "s-catalog", heuristic: "s-heuristic", llm: "s-llm", none: "s-none", "?": "s-none",
};
const LAYER_LABEL = {
  catalog: "catálogo", heuristic: "heurística", llm: "LLM local", none: "sin capa",
};
const VERDICT_COLOR = {
  expected_ai_use: "s-catalog", background_exfil_suspect: "s-bad",
  telemetry_noise: "s-heuristic", unrelated: "s-none",
};

function gridAndAxis(max) {
  const half = BASE_Y - SPAN / 2;
  const mid = max / 2;
  const showMid = Number.isInteger(mid) && mid > 0;
  return `<line class="grid" x1="${LEFT}" y1="${BASE_Y}" x2="${RIGHT}" y2="${BASE_Y}"/>` +
    (showMid ? `<line class="grid" x1="${LEFT}" y1="${half}" x2="${RIGHT}" y2="${half}"/>` : "") +
    `<line class="grid" x1="${LEFT}" y1="${TOP_Y}" x2="${RIGHT}" y2="${TOP_Y}"/>` +
    `<text class="axis-y" x="${LEFT - 6}" y="${BASE_Y + 3}">0</text>` +
    (showMid ? `<text class="axis-y" x="${LEFT - 6}" y="${half + 3}">${mid}</text>` : "") +
    `<text class="axis-y" x="${LEFT - 6}" y="${TOP_Y + 3}">${max}</text>`;
}

// Serie de barras con eje, rejilla, etiquetas y tooltip nativo.
function barSeries(values, labels, clsFor, fmtTitle, showVal) {
  const n = values.length;
  if (!n) return "";
  const max = Math.max(1, ...values);
  const slot = (RIGHT - LEFT) / n;
  const bw = Math.max(6, Math.min(40, slot - 8));
  let out = gridAndAxis(max);
  values.forEach((v, i) => {
    const cx = LEFT + slot * i + slot / 2;
    const h = v > 0 ? Math.max(4, Math.round((v / max) * SPAN)) : 3;
    const y = BASE_Y - h;
    out += `<rect class="col ${clsFor ? clsFor(i, v) : ""}" x="${(cx - bw / 2).toFixed(1)}" y="${y}" width="${bw.toFixed(1)}" height="${h}" rx="3"><title>${esc(fmtTitle(i, v))}</title></rect>`;
    if (showVal && v > 0 && bw >= 14) {
      out += `<text class="col-val" x="${cx.toFixed(1)}" y="${y - 4}">${v}</text>`;
    }
    if (labels && labels[i]) {
      out += `<text class="axis" x="${cx.toFixed(1)}" y="${BASE_Y + 13}">${esc(labels[i])}</text>`;
    }
  });
  return out;
}

function activityChart(daily) {
  const days = daily || [];
  const every = days.length <= 12 ? 1 : 5;
  const body = barSeries(
    days.map(d => d.events || 0),
    days.map((d, i) => (i % every === 0 ? d.date.slice(8) : "")),
    (i, v) => (v ? "" : "zero"),
    (i, v) => `${days[i].date}: ${v} eventos, ${days[i].triages || 0} triajes`,
    true,
  );
  if (!body) return `<div class="empty">Sin actividad en la ventana.</div>`;
  return `<svg class="chart-svg" viewBox="0 0 ${CW} 140" role="img" aria-label="Eventos por dia"><title>Eventos por dia</title>${body}</svg>`;
}

// Histograma de sesiones por hora UTC: muestra CUANDO sale el trafico a IA.
function hourChart(hourly) {
  const vals = (hourly || []).slice(0, 24);
  if (!vals.length || !vals.some(v => v > 0)) {
    return `<div class="empty">Sin sesiones registradas en la ventana (el histograma por hora necesita el colector activo).</div>`;
  }
  const body = barSeries(
    vals,
    vals.map((_, i) => (i % 4 === 0 ? String(i) : "")),
    (i, v) => (i < 6 ? "night" : (v ? "" : "zero")),
    (i, v) => `${String(i).padStart(2, "0")}:00 UTC: ${v} sesiones`,
    false,
  );
  return `<svg class="chart-svg" viewBox="0 0 ${CW} 140" role="img" aria-label="Sesiones por hora UTC"><title>Sesiones por hora (UTC)</title>${body}</svg>`;
}

// Donut: segmentos por stroke-dasharray (atributo, no style).
function donut(items, centerValue, centerLabel) {
  const total = (items || []).reduce((s, i) => s + (i.value || 0), 0);
  if (!total) return `<div class="empty">Sin datos para este grafico.</div>`;
  const R = 42, C = 2 * Math.PI * R;
  let off = 0, segs = "";
  (items || []).forEach(it => {
    const frac = (it.value || 0) / total;
    if (frac <= 0) return;
    const len = frac * C;
    segs += `<circle class="donut-seg ${it.cls || "s-none"}" cx="60" cy="60" r="${R}" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"><title>${esc(it.label)}: ${it.value} (${Math.round(frac * 100)}%)</title></circle>`;
    off += len;
  });
  const legend = (items || []).filter(i => (i.value || 0) > 0).map(i =>
    `<span class="chip"><span class="dot ${i.cls || "s-none"}"></span>${esc(i.label)} <b class="num">${i.value}</b> <span class="num">${Math.round((i.value / total) * 100)}%</span></span>`).join("");
  return `<div class="donut-wrap"><svg class="donut-svg" viewBox="0 0 120 120" role="img" aria-label="${esc(centerLabel)}: ${centerValue}">` +
    `<circle class="donut-track" cx="60" cy="60" r="${R}"/>` +
    `<g transform="rotate(-90 60 60)">${segs}</g>` +
    `<text class="donut-val" x="60" y="60" dominant-baseline="central">${esc(String(centerValue))}</text></svg>` +
    `<div class="donut-side"><div class="donut-cap">${esc(centerLabel)}</div>` +
    `<div class="chips">${legend}</div></div></div>`;
}

// Barras horizontales por proveedor (rect con width en unidades del viewBox).
function providerBars(items) {
  if (!(items || []).length) return `<div class="empty">Sin proveedores en la ventana.</div>`;
  const max = Math.max(1, ...items.map(i => i.seen_count || 0));
  const kindLabel = { api: "API", web: "web", cdn: "CDN" };
  return `<div class="prov-bars">` + items.map(i => {
    const w = Math.max(2, Math.round(((i.seen_count || 0) / max) * 100));
    return `<div class="prov-row" title="${esc(i.name)}: ${i.seen_count} presencias, capa ${esc(i.layer || "none")}">` +
      `<span class="prov-name mono">${esc(i.name)} <span class="prov-kind hint">${kindLabel[i.kind] || esc(i.kind || "")}</span></span>` +
      `<svg class="hbar" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">` +
      `<rect class="hbar-track" x="0" y="0" width="100" height="10"/>` +
      `<rect class="hbar-fill ${LAYER_COLOR[i.layer] || "s-none"}" x="0" y="0" width="${w}" height="10"/></svg>` +
      `<span class="prov-val num">${i.seen_count}</span></div>`;
  }).join("") + `</div>`;
}

// Lectura en texto llano: que hay que entender del grafico sin leer numeros.
function panelTakeaway(d) {
  const s = d.summary || {};
  if (!s.events) {
    return "Sin conexiones IA en la ventana. Si el monitoreo está pausado (kill switch), reanúdalo desde la cabecera; si no, amplía la ventana o revisa el catálogo.";
  }
  const parts = [];
  const top = (d.top_providers || [])[0];
  if (top && s.seen_total) {
    parts.push(`${top.name} concentra el ${Math.round((top.seen_count / s.seen_total) * 100)}% de las presencias`);
  }
  parts.push(`${plural(s.processes, "proceso", "procesos")} hacia ${plural(s.providers, "proveedor", "proveedores")}`);
  const hourly = (d.hourly || []).slice(0, 24);
  if (hourly.some(v => v > 0)) {
    let peak = 0;
    hourly.forEach((v, i) => { if (v > hourly[peak]) peak = i; });
    const night = hourly.slice(0, 6).reduce((a, b) => a + b, 0);
    parts.push(`pico de sesiones a las ${String(peak).padStart(2, "0")}:00 UTC`);
    if (night) parts.push(`${plural(night, "sesión", "sesiones")} de madrugada (00-06 UTC)`);
  }
  if (d.shadow_count) parts.push(`${plural(d.shadow_count, "proveedor no aprobado", "proveedores no aprobados")}: Shadow AI`);
  return parts.join(" · ") + ".";
}

function kpiHtml(d) {
  const s = d.summary || {};
  const cb = d.cloud_bytes || {};
  const llm = d.llm_calls || {};
  const tiles = [
    { label: "Eventos", value: s.events ?? 0, note: `${d.days} días` },
    { label: "Presencias", value: s.seen_total ?? 0, note: plural(d.sessions ?? 0, "sesión", "sesiones") },
    { label: "Procesos", value: s.processes ?? 0, note: "que salen a IA" },
    { label: "Proveedores", value: s.providers ?? 0, note: `${d.shadow_count || 0} no aprobados` },
    { label: "LLM local", value: llm.calls ?? 0, note: `${fmtBytes((llm.request_bytes || 0) + (llm.response_bytes || 0))}` },
    { label: "Bytes cloud", value: cb.available ? fmtBytes(cb.total_bytes || 0) : "no disp.", note: cb.available ? (cb.spawn_method || "colector") : (cb.reason || "sin colector elevado") },
  ];
  return `<div class="kpis">` + tiles.map(t =>
    `<div class="kpi${t.label === "Bytes cloud" && !cb.available ? " kpi-na" : ""}${(t.label === "Proveedores" && d.shadow_count) ? " kpi-bad" : ""}">` +
    `<span class="kpi-val">${esc(String(t.value))}</span>` +
    `<span class="kpi-lbl">${esc(t.label)}</span>` +
    `<span class="kpi-note">${esc(String(t.note || ""))}</span></div>`).join("") + `</div>`;
}

