// 07-llm.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
function llmSummary(calls) {
  const lat = calls.map((c) => c.latency_ms).filter((v) => v != null).sort((a, b) => a - b);
  const avg = lat.length ? Math.round(lat.reduce((s, v) => s + v, 0) / lat.length) : 0;
  const med = lat.length ? lat[Math.floor(lat.length / 2)] : 0;
  const p95 = lat.length ? lat[Math.floor(lat.length * 0.95)] : 0;
  const tokIn = calls.reduce((s, c) => s + (c.prompt_tokens || 0), 0);
  const tokOut = calls.reduce((s, c) => s + (c.completion_tokens || 0), 0);
  const models = [...new Set(calls.map((c) => c.model || "—"))];
  const fails = calls.filter((c) => c.status === 0 || c.status == null).length;
  const totReq = calls.reduce((s, c) => s + (c.request_bytes || 0), 0);
  const totResp = calls.reduce((s, c) => s + (c.response_bytes || 0), 0);
  const maxLat = Math.max(1, ...lat, 1);
  const bars = lat.slice(0, 40).map((v, i) => {
    const h = Math.max(2, Math.round((v / maxLat) * 22));
    return `<rect class="latbar" x="${i * 6}" y="${22 - h}" width="5" height="${h}"></rect>`;
  }).join("");
  return `<div class="llmsum">
    <div class="kpis">
      <div class="kpi"><span class="kpi-val">${calls.length}</span><span class="kpi-lbl">llamadas registradas</span><span class="kpi-note">modelos: ${esc(models.join(", "))}</span></div>
      <div class="kpi"><span class="kpi-val">${avg} ms</span><span class="kpi-lbl">latencia media</span><span class="kpi-note">mediana ${med} ms · p95 ${p95} ms</span></div>
      <div class="kpi"><span class="kpi-val">${tokIn + tokOut}</span><span class="kpi-lbl">tokens</span><span class="kpi-note">${tokIn} prompt / ${tokOut} respuesta</span></div>
      <div class="kpi ${fails ? "kpi-bad" : ""}"><span class="kpi-val">${fails}</span><span class="kpi-lbl">llamadas fallidas</span><span class="kpi-note">sin respuesta o error</span></div>
    </div>
    <div class="latviz"><svg class="latspark" viewBox="0 0 240 24" width="240" height="24" role="img" aria-label="latencia de cada llamada">${bars}</svg><span class="hint">cada barra es una llamada; la altura es la latencia (max ${maxLat} ms)</span></div>
    <div class="small mono">Egress medido total: ${fmtBytes(totReq)} hacia el LLM · ${fmtBytes(totResp)} de vuelta</div>
  </div>`;
}

function llmCallsHtml(calls) {
  if (!calls.length) return `<div class="empty">Sin llamadas registradas. Con el inspector activo, apunta el cliente al puerto del proxy.</div>`;
  return llmSummary(calls) + calls.map((c) => {
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
let llmCallsShown = 10;

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
        <span class="hint">capa ${g.layers.join("/")} · ${plural(g.processes.length, "proceso", "procesos")} · ${g.seen_count} veces · último ${esc(g.last_seen)}</span>
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

