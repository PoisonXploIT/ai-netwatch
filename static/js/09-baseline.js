// 09-baseline.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
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
    ? `<div class="row"><button class="linkbtn" id="btn-baseline-more">Mostrar ${rest} grupos más (${groupsAll.length} en total)</button></div>`
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

