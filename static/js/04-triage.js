// 04-triage.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
function ttabShow(which) {
  const j = document.getElementById("ttab-jev");
  const l = document.getElementById("ttab-laya");
  const d = document.getElementById("ttab-disc");
  if (j) j.hidden = which !== "jev";
  if (l) l.hidden = which !== "laya";
  if (d) d.hidden = which !== "disc";
  document.querySelectorAll(".ttab").forEach((b) => b.classList.toggle("active", b.dataset.tt === which));
}

const TRIAGE_ROWS = 10;  // Filas visibles por tabla de triaje; el resto, desplegable.

function vsCell(aVerdict, bVerdict) {
  if (aVerdict == null || bVerdict == null) return `<td class="vs">sin dato</td>`;
  return aVerdict === bVerdict
    ? `<td class="vs vs-ok">coincide</td>`
    : `<td class="vs vs-bad">difiere</td>`;
}

function triageHtml(data) {
  if (!data) return "";
  const parts = [];
  let jevHtml = "";
  let layaHtml = "";
  const jev = data.jev || {};
  const layaRaw = data.laya || {};
  const LAYA_V = layaRaw.verdicts || {};
  // Comparacion Jev vs LAYA por evento (una sola vez, la usan los tres paneles).
  const CMP = (data.events || []).map((e, i) => {
    const jv = (jev.verdicts || {})[String(i)] || {};
    const lv = LAYA_V[String(i)] || {};
    return { e, jv, lv,
      both: jv.verdict != null && lv.verdict != null,
      agree: jv.verdict != null && lv.verdict != null && jv.verdict === lv.verdict };
  }).filter((r) => !SUPPRESSED.has(`${r.e.process}|${providerFromDest(r.e.dest)}`));
  const CMP_N = CMP.filter((r) => r.both).length;
  const CMP_OK = CMP.filter((r) => r.agree).length;
  const DISC = CMP.filter((r) => r.both && !r.agree);
  const CMP_PCT = CMP_N ? Math.round((CMP_OK / CMP_N) * 100) : 0;
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
        ${vsCell(v.verdict, (LAYA_V[String(i)] || {}).verdict)}
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
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificación</th><th>vs LAYA</th><th class="num">Confianza</th><th class="num">Prob. falso positivo</th><th class="num">Criticidad</th><th class="num">Acción inmediata</th></tr></thead>
      <tbody>${rows}</tbody></table>${moreJev}`;
  } else if (jev.status === "skipped") {
    jevHtml = `<div class="hint">Jev no disponible (${esc(jev.reason || "")}). Vista clásica intacta.</div>`;
  } else if (jev.status === "error") {
    jevHtml = `<div class="hint error">Error Jev: ${esc(jev.reason || "")}</div>`;
  }
  const laya = layaRaw;
  if (laya.status === "ok") {
    const lrowList = CMP.map((r) => {
      const v = r.lv;
      const cls = v.verdict != null ? verdictBadge(v.verdict, v.confidence) : `<span class="hint">no triado</span>`;
      const cmp = r.both
        ? (r.agree ? `<span class="cmp-ok">coincide</span>`
                   : `<span class="cmp-bad">difiere</span> <span class="hint">(Jev: ${esc(r.jv.verdict)})</span>`)
        : `<span class="hint">-</span>`;
      return { sev: Number(v.severity_score || 0),
        html: `<tr><td>${esc(r.e.process)}</td><td class="mono">${esc(r.e.dest)}</td><td>${cls}</td><td>${cmp}</td>${numCell(v.confidence, v.confidence)}${sevCell(v.severity_score)}${numCell(v.immediate_action, v.immediate_action)}</tr>` };
    });
    lrowList.sort((a, b) => b.sev - a.sev);
    const lrows = lrowList.map((r, i) => i < TRIAGE_ROWS ? r.html : r.html.replace("<tr", "<tr class=\"extra extra-laya\" hidden")).join("");
    const moreLaya = lrowList.length > TRIAGE_ROWS
      ? `<div class="row"><button class="linkbtn" data-more="laya">Mostrar los ${lrowList.length - TRIAGE_ROWS} restantes</button></div>`
      : "";
    layaHtml = `<h3>Veredictos LAY\u00c1 (local) <span class="hint">${esc(laya.model || "")} \u00b7 acuerdo con Jev: ${CMP_OK}/${CMP_N} (${CMP_PCT}%)</span></h3><table>
      <thead><tr><th>Proceso</th><th>Destino</th><th>Clasificaci\u00f3n</th><th>vs Jev</th><th class="num">Confianza</th><th class="num">Criticidad</th><th class="num">Acci\u00f3n inmediata</th></tr></thead>
      <tbody>${lrows}</tbody></table>${moreLaya}`;
  } else if (laya.status === "error") {
    layaHtml = `<div class="hint error">LAY\u00c1 local: ${esc(laya.reason || "")}</div>`;
  }
  const discHtml = DISC.length
    ? `<h3>Discrepancias Jev vs LAY\u00c1 <span class="hint">${DISC.length} de ${CMP_N} comparables</span></h3>
       <table><thead><tr><th>Proceso</th><th>Destino</th><th>Jev</th><th>LAYA</th><th class="num">Conf. Jev</th><th class="num">Conf. LAYA</th><th class="num">Criticidad</th></tr></thead>
       <tbody>${DISC.map((r) => `<tr><td>${esc(r.e.process)}</td><td class="mono">${esc(r.e.dest)}</td><td>${verdictBadge(r.jv.verdict, r.jv.confidence)}</td><td>${verdictBadge(r.lv.verdict, r.lv.confidence)}</td>${numCell(r.jv.confidence, r.jv.confidence)}${numCell(r.lv.confidence, r.lv.confidence)}${sevCell(r.lv.severity_score != null ? r.lv.severity_score : r.jv.severity_score)}</tr>`).join("")}</tbody></table>
       <p class="hint">Jev es el juez: la discrepancia no cambia nada, solo se registra. Si el veredicto de LAYA es de mayor criticidad, revisa el evento antes de sacar de cuarentena.</p>`
    : "";
  if (jevHtml || layaHtml) {
    const VCOUNT = {};
    CMP.forEach((r) => { if (r.jv.verdict) VCOUNT[r.jv.verdict] = (VCOUNT[r.jv.verdict] || 0) + 1; });
    const VCLASS = { expected_ai_use: "s-catalog", telemetry_noise: "s-heuristic",
      background_exfil_suspect: "s-bad", unrelated: "s-none" };
    const verdictItems = Object.entries(VCOUNT).sort((a, b) => b[1] - a[1]).map(([v, n]) => ({
      label: (VERDICT_META[v] || { label: v }).label, value: n, cls: VCLASS[v] || "s-none" }));
    const agreeItems = CMP_N
      ? [{ label: "coinciden", value: CMP_OK, cls: "s-catalog" },
         { label: "discrepancias", value: CMP_N - CMP_OK, cls: "s-bad" }]
      : [];
    parts.push(`<div class="triage-charts">
      ${verdictItems.length ? donut(verdictItems, verdictItems.reduce((s, i) => s + i.value, 0), "veredictos Jev") : ""}
      ${agreeItems.length ? donut(agreeItems, CMP_PCT + "%", "acuerdo Jev/LAYA") : ""}
    </div>
    <div class="ttabs">
      <button class="btn ttab active" data-tt="jev">Jev (juez)</button>
      <button class="btn ttab" data-tt="laya">LAY\u00c1 (local)</button>
      ${DISC.length ? `<button class="btn ttab" data-tt="disc">Discrepancias (${DISC.length})</button>` : ""}
    </div>
    <div id="ttab-jev">${jevHtml}</div>
    <div id="ttab-laya" hidden>${layaHtml}</div>
    ${DISC.length ? `<div id="ttab-disc" hidden>${discHtml}</div>` : ""}`);
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

