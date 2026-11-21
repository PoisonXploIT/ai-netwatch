// 11-config.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
function renderMonitorState(enabled) {
  const btn = document.getElementById("btn-monitor");
  if (!btn) return;
  btn.textContent = enabled ? "Monitoreo activo · pausar" : "Monitoreo en pausa · reanudar";
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
    jevKey.placeholder = c.jev_api_key_set ? "sustituir la key (la actual no se ve)" : "API key de Jev";
    const jevState = document.getElementById("jev-key-state");
    const jevDot = document.getElementById("jev-key-dot");
    if (jevState) {
      jevState.textContent = c.jev_api_key_set
        ? `activa · fingerprint ${c.jev_key_fingerprint || "????????"}`
        : "sin key · el triaje con Jev no funciona";
      jevState.title = c.jev_api_key_set
        ? "Key cifrada con DPAPI. Escribir una nueva la sustituye al pulsar Guardar."
        : "No hay key guardada: pega una y pulsa Guardar.";
    }
    if (jevDot) jevDot.className = "dot " + (c.jev_api_key_set ? "ok" : "bad");
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
    const nb = document.getElementById("netbytes-toggle");
    if (nb) {
      nb.checked = !!c.net_bytes_enabled;
      const nbState = document.getElementById("netbytes-state");
      if (nbState) {
        nbState.textContent = c.net_bytes_enabled
          ? (c.net_bytes_available ? "colector elevado disponible" : "activado, pero sin tarea elevada: no hay datos (ejecuta setup_netbytes_task.ps1 una vez)")
          : "apagado (no se lanzan procesos elevados)";
      }
    }
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
  const COINCIDE = { coincide: "badge-ok", discrepa: "badge-bad", dudoso: "badge-warn" };
  const coin = r.coincide
    ? `<span class="${COINCIDE[r.coincide] || "badge-warn"}">${esc(r.coincide)}</span>`
    : "";
  return `<div class="row"><b>#${r.event_id}</b> ${badge} ${acc} ${coin}` +
    (r.juicio ? `<p class="juicio">${esc(r.juicio)}</p>` : "") +
    (r.porque ? `<div class="small hint">Porque: ${esc(r.porque)}</div>` : "") +
    (r.evidencia_faltante ? `<div class="small hint">Falta: ${esc(r.evidencia_faltante)}</div>` : "") +
    `</div>`;
}

function renderReviewResults(data) {
  const wrap = document.getElementById("review-results");
  if (!wrap) return;
  if (data.status === "unavailable") {
    wrap.innerHTML = `<div class="hint">LLM no disponible (${esc(data.reason || "")}): sin revisión.</div>`;
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
    const d = await api("/api/reviews?limit=15");
    const rows = d.reviews || [];
    if (!rows.length) { wrap.innerHTML = `<div class="hint">Sin revisiones todavía.</div>`; return; }
    const COINCIDE = { coincide: "badge-ok", discrepa: "badge-bad", dudoso: "badge-warn" };
    wrap.innerHTML = rows.map((r, i) => {
      const badge = r.evaluacion
        ? `<span class="${REVIEW_EVAL_BADGE[r.evaluacion] || "badge-warn"}">${esc(r.evaluacion)}</span>`
        : `<span class="hint">no disponible</span>`;
      const acc = r.accion ? `<span class="${r.accion === "sacar" ? "badge-ok" : "badge-bad"}">${esc(r.accion)}</span>` : "";
      const coin = r.coincide ? `<span class="${COINCIDE[r.coincide] || "badge-warn"}">${esc(r.coincide)}</span>` : "";
      const dest = r.ev_sni || r.ev_catalog || r.ev_dest_ip || "?";
      const seen = r.ev_sessions != null ? ` · ${plural(r.ev_sessions, "sesión", "sesiones")}, ${r.ev_seen || 0} vistas` : "";
      return `<div class="revrow"><details${i < 3 ? " open" : ""}>
        <summary>#${r.event_id} ${esc(r.ev_process || "")} -> ${esc(dest)} ${badge} ${acc} ${coin} <span class="hint">${esc((r.ts || "").slice(0, 16))}</span></summary>
        ${r.juicio ? `<p class="juicio">${esc(r.juicio)}</p>` : ""}
        ${r.porque ? `<p class="small hint">Porque: ${esc(r.porque)}</p>` : ""}
        ${r.evidencia_faltante ? `<p class="small hint">Falta: ${esc(r.evidencia_faltante)}</p>` : ""}
        ${seen ? `<p class="small hint">Patrón:${seen}</p>` : ""}
      </details></div>`;
    }).join("");
  } catch (e) { /* sin historial */ }
}

