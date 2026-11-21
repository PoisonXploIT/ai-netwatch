// 10-dashboard.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
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
  // v2.6(7): el Panel pasa de lista de texto a graficas SVG. La lectura va
  // primero (una frase), luego los KPIs y depois las graficas.
  const topList = (items, label) => items.length
    ? `<p class="hint">${label}</p><div class="chips">` + items.map(i =>
      `<span class="chip"><span class="mono">${esc(i.name)}</span>` +
      (i.sdk ? ` <span class="hint">[${esc(i.sdk)}]</span>` : "") +
      `<span class="num">${i.seen_count}</span></span>`).join("") + `</div>`
    : "";
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
    ? `<span class="hint">+${plural(provRest, "proveedor", "proveedores")} más</span>` : "";
  const cloudLine = cb.available
    ? `<div class="row"><b>Bytes cloud (TLS remoto)</b>: <span class="mono">${fmtBytes(cb.total_bytes || 0)}</span>${cb.spawn_method ? ` <span class="hint">(${esc(cb.spawn_method)})</span>` : ""}</div><div class="chips">${provRows}${restLine}</div>`
    : `<div class="row"><span class="hint">Bytes cloud: no disponible para TLS remoto (${esc(cb.reason || "")}).</span></div>`;
  const layerItems = (d.layers || []).map(l => ({
    label: LAYER_LABEL[l.layer] || l.layer, value: l.seen_count || 0,
    cls: LAYER_COLOR[l.layer] || "s-none",
  }));
  const approved = Math.max(0, (d.summary && d.summary.providers ? d.summary.providers : 0) - (d.shadow_count || 0));
  const govItems = [
    { label: "aprobados", value: approved, cls: "s-catalog" },
    { label: "shadow (no aprobados)", value: d.shadow_count || 0, cls: "s-bad" },
  ];
  const verdictItems = Object.entries(d.verdicts || {}).map(([k, v]) => ({
    label: VERDICT_META[k] ? VERDICT_META[k].label : k, value: v,
    cls: VERDICT_COLOR[k] || "s-none",
  }));
  wrap.innerHTML = `
    <p class="takeaway">${esc(panelTakeaway(d))}</p>
    ${kpiHtml(d)}
    <div class="charts">
      <div class="chart chart-wide">
        <h3>Actividad diaria (eventos)</h3>
        ${activityChart(d.daily)}
        <p class="chart-note">Una barra = eventos IA vistos ese día. Pasa el ratón por la barra para ver el detalle.</p>
      </div>
      <div class="chart">
        <h3>Capas de detección</h3>
        ${donut(layerItems, (d.summary && d.summary.seen_total) || 0, "presencias")}
        <p class="chart-note">Cómo se identificó cada destino: catálogo (evidencia), heurística (señal a revisar) o LLM local.</p>
      </div>
      <div class="chart">
        <h3>Gobernanza (Shadow AI)</h3>
        ${donut(govItems, d.shadow_count || 0, "no aprobados")}
        <p class="chart-note">Proveedores IA observados: aprobados por el catálogo o por ti frente a los que no.</p>
      </div>
      <div class="chart chart-wide">
        <h3>Sesiones por hora (UTC)</h3>
        ${hourChart(d.hourly)}
        <p class="chart-note">Cuándo sale el tráfico a IA. Las barras de madrugada (00-06 UTC) se colorean aparte: son las que suelen indicar autonomía.</p>
      </div>
      <div class="chart">
        <h3>Top proveedores</h3>
        ${providerBars(d.top_providers.slice(0, 8))}
        <p class="chart-note">El color de la barra es la capa que detectó el dominio.</p>
      </div>
      <div class="chart">
        <h3>Veredictos de Jev</h3>
        ${verdictItems.length ? donut(verdictItems, verdictItems.reduce((s, i) => s + i.value, 0), "eventos triados") : `<div class="empty">Sin triaje en la ventana: pulsa "Triar eventos con Jev" en la pestana IA.</div>`}
        <p class="chart-note">Último triaje aplicado a los eventos vivos.</p>
      </div>
    </div>
    <details>
      <summary>Tabla de proveedores (ordenable, ${d.top_providers.length})</summary>
      ${providersTableHtml(d.top_providers)}
    </details>
    ${topList(d.top_processes, "Procesos que salen a IA")}
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
  paintBars(wrap);
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

