// 01-base.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
function esc(v) {
  return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function plural(n, uno, varios) {
  return `${n} ${Number(n) === 1 ? uno : varios}`;
}

function ago(ts) {
  if (!ts) return "nunca";
  const t = Date.parse(String(ts).replace(" ", "T"));
  if (Number.isNaN(t)) return String(ts);
  const m = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (m < 60) return `hace ${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `hace ${h} h`;
  return `hace ${Math.round(h / 24)} días`;
}

function whenCell(ts) {
  return `<span title="${esc(ts || "")} (UTC)">${esc(ago(ts))}</span>`;
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

