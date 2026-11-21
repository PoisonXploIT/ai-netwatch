// 05-findings.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
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
  if (!rev) return `<span class="hint">sin revisión</span>`;
  const ev = typeof rev === "string" ? rev : rev.evaluacion;
  if (!ev) return `<span class="hint">sin revisión</span>`;
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
        ? `<span class="badge-warn">${autonomyBadge(f.autonomy_verdict, f.autonomy_score)}</span>` : "",
    ].filter(Boolean).join(" ");
    const jev = f.jev_verdict ? verdictBadge(f.jev_verdict) : `<span class="hint">sin Jev</span>`;
    return `<tr class="finding-row" data-fi="${i}" tabindex="0" role="button" aria-expanded="false">
      <td><span class="score-badge ${scoreClass(f.score)}" title="Score ${f.score} de 100">${f.score}</span> <span class="small">${scoreLabel(f.score)}</span></td>
      <td>${esc(f.process)}</td>
      <td class="mono">${esc(f.provider || "-")}${kindBadge(f.kind)}</td>
      <td>${jev} ${badges}</td>
      <td class="num">${f.sessions ?? 0}</td>
      <td class="num">${f.seen_count ?? 0}</td>
      <td class="small">${whenCell(f.last_seen)}</td>
      <td>
        <button class="small blacklist-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Lista negra (cuarentena): aislar hasta revisión LLM">Aislar</button>
        <button class="small suppress-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Ocultar fila: los eventos se mantienen en la base de datos">Ocultar</button>
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
      return `<tr class="finding-row" data-qi="${i}" tabindex="0" role="button" aria-expanded="false">
        <td><span class="score-badge ${scoreClass(f.score)}" title="Score ${f.score} de 100">${f.score}</span> <span class="small">${scoreLabel(f.score)}</span></td>
        <td>${esc(f.process)}</td>
        <td class="mono">${esc(f.provider || "-")}${kindBadge(f.kind)}</td>
        <td>${jev} ${reviewBadge(f.review)}</td>
        <td class="num">${f.sessions ?? 0}</td>
        <td class="num">${f.seen_count ?? 0}</td>
        <td class="small">${whenCell(f.last_seen)}</td>
        <td>
          <button class="small unblacklist-finding" data-process="${esc(f.process)}" data-provider="${esc(f.provider || "")}" title="Sacar de cuarentena">sacar</button>
          <button class="small review-finding" data-eids="${(f.event_ids || []).join(",")}" title="Revisar estos eventos con el LLM local">revisar</button>
        </td>
      </tr>
      <tr class="finding-detail" data-qd="${i}" hidden><td colspan="8">${findingDetail(f)}</td></tr>`;
    }).join("");
    quarantineSection = `<details><summary>Cuarentena (${blacklisted.length})</summary>
      <p class="hint">En lista negra: aislados a la espera de revisión LLM. Los eventos siguen en la base de datos.</p>
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
    ? `<div class="row"><button class="linkbtn" id="btn-findings-more">Mostrar ${list.length - shown.length} más (${list.length} de ${total})</button></div>`
    : `<p class="hint">${list.length} hallazgos mostrados de ${total} (filtrados).</p>`;
  wrap.innerHTML = findingsHtml(shown, FINDINGS.suppressed, FINDINGS.blacklisted) + more;
  setTabCount("hallazgos", list.length);
  wireFindings(wrap);
  const mb = document.getElementById("btn-findings-more");
  if (mb) mb.onclick = () => { findingsShown += 25; renderFindings(); };
}

function wireFindings(wrap) {
    wrap.querySelectorAll("tr.finding-row").forEach((r) => {
      const toggle = () => {
        const sel = r.dataset.fi != null
          ? `tr.finding-detail[data-fd="${r.dataset.fi}"]`
          : `tr.finding-detail[data-qd="${r.dataset.qi}"]`;
        const det = wrap.querySelector(sel);
        if (!det) return;
        det.hidden = !det.hidden;
        r.setAttribute("aria-expanded", String(!det.hidden));
      };
      r.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) return;
        toggle();
      });
      r.addEventListener("keydown", (ev) => {
        if (ev.target !== r) return;  // no interceptar los botones de la fila
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
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

