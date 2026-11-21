// 08-autonomy.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
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

let autShown = 25;

async function refreshAutonomy() {
  const wrap = document.getElementById("autonomy-wrap");
  if (!wrap) return;
  try {
    const a = await api("/api/autonomy?" + autQuery());
    const sig = a.signals || {};
    const lockedTxt = sig.locked == null ? "?" : (sig.locked ? "bloqueada" : "activa");
    // v2.6(3): etiquetar el estado de la senal (no un '?' mudo ni un
    // numero sin contexto).
    const idleNotes = {
      counter_frozen: "sin señal: contador congelado (sesión sin entrada)",
      api_error: "sin señal: API no disponible",
      idle_gt_uptime: "sin señal: valor imposible (idle > uptime)",
      no_win: "sin señal: solo Windows",
      no_input_since_boot: "sin entrada desde el arranque (sesión sin HID)",
    };
    const note = sig.idle_note && idleNotes[sig.idle_note]
      ? ` (${idleNotes[sig.idle_note]})` : "";
    const idleTxt = sig.idle_seconds != null
      ? `${sig.idle_seconds} s${note}` : `?${note || ""}`;
    let html = `<p class="hint">Sesión: <b>${esc(lockedTxt)}</b> · usuario inactivo: <b>${esc(idleTxt)}</b> · foreground PID: <b>${sig.foreground_pid != null ? esc(String(sig.foreground_pid)) : "?"}</b></p>`;
    // A3: contadores de veredicto sobre TODOS los eventos vivos (sin filtros).
    const c = a.counts || {};
    const counters = document.getElementById("autonomy-counters");
    if (counters) {
      counters.textContent = `Veredictos (eventos vivos): autónomo ${c.autonomous ?? 0} · programado ${c.scheduled ?? 0} · usuario ${c.user_driven ?? 0} · desconocido ${c.unknown ?? 0}`;
    }
    if (!a.events.length) {
      html += '<div class="empty">Sin eventos con los filtros actuales. Si el monitoreo está pausado (kill switch), reanúdalo desde la cabecera.</div>';
    } else if (a.grouped) {
      // v2.6(4): colapsar por proveedor — un proveedor recibe de varios
      // procesos (y de muchos pid:XXXX sin resolver); una fila por
      // proveedor con el peor veredicto y la lista de procesos.
      const byProv = new Map();
      for (const e of a.events) {
        const p = e.provider || "-";
        let b = byProv.get(p);
        if (!b) {
          b = {provider: p, kind: e.kind, procs: new Set(),
               verdict: "unknown", sessions: 0, polls: 0, last: ""};
          byProv.set(p, b);
        }
        b.procs.add(e.process);
        const v = e.autonomy_verdict || "unknown";
        if (v === "autonomous" || v === "scheduled") b.verdict = v;
        b.sessions += e.sessions || 0;
        b.polls += e.seen_count || 0;
        if ((e.last_seen || "") > b.last) b.last = e.last_seen || "";
      }
      const ordered = [...byProv.values()].sort(
        (x, y) => (x.verdict === "unknown") - (y.verdict === "unknown"));
      const shown = ordered.slice(0, autShown);
      const rest = ordered.length - shown.length;
      html += `<table class="aut-table">
        <thead><tr><th>Proveedor</th><th>Veredicto</th><th>Procesos</th><th class="num">Sesiones</th><th class="num">Polls</th><th>Último</th></tr></thead>
        <tbody>${shown.map((b) => {
          const vb = autonomyBadge(b.verdict, null)
            || '<span class="hint">desconocido</span>';
          const procs = [...b.procs];
          const shownProcs = procs.slice(0, 4).join(", ");
          const more = procs.length - Math.min(4, procs.length);
          return `<tr>
            <td class="mono">${esc(b.provider)}${kindBadge(b.kind)}</td>
            <td>${vb}</td>
            <td class="small">${esc(shownProcs)}${more > 0 ? ` (+${more})` : ""}</td>
            <td class="num">${b.sessions}</td>
            <td class="num">${b.polls}</td>
            <td class="mono small">${esc(b.last)}</td>
          </tr>`;
        }).join("")}</tbody></table>` +
        (rest > 0 ? `<div class="pager"><button class="linkbtn" id="btn-aut-more">Mostrar ${rest} más (${ordered.length} proveedores)</button></div>` : "");
    } else {
      html += a.events.slice(0, autShown).map(e => {
        const left = `${esc(e.process)} → ${esc(e.dest_host || e.dest_ip)}:${e.dest_port}`;
        const vb = autonomyBadge(e.autonomy_verdict, e.autonomy_score)
          || '<span class="hint">desconocido</span>';
        return `<div class="row">
        <span class="mono">${left}</span>
        <span class="hint">${vb} · flags ${esc(e.autonomy_flags || "")} · score ${e.autonomy_score ?? "?"} · último ${esc(e.last_seen)}</span>
      </div>`;
      }).join("") + (a.events.length > autShown
        ? `<div class="pager"><button class="linkbtn" id="btn-aut-more">Mostrar ${a.events.length - autShown} más</button></div>`
        : "");
    }
    wrap.innerHTML = html;
    const mb = document.getElementById("btn-aut-more");
    if (mb) mb.onclick = () => { autShown += 25; refreshAutonomy(); };
  } catch (e) { /* sin datos aún */ }
}

// v2.6(4): colapsar eventos vivos que comparten (puerto, protocolo,
// pre_score, flags) en una sola fila con recuento. Los proveedores
// rotan IP anycast (p. ej. Cloudflare IPv6), asi que 100+ IPs distintas
// del mismo proveedor darian 100+ filas identicas; la fila colapsada
// muestra el recuento, una muestra de IPs y los flags una sola vez.
function collapseCurrent(cur) {
  const bySig = new Map();
  for (const c of cur) {
    const fsig = (c.pre_flags || []).map(f => f.flag).join(",");
    const key = `${c.dest_port}|${c.protocol}|${c.pre_score}|${fsig}`;
    let b = bySig.get(key);
    if (!b) {
      b = {count: 0, ips: [], pre_score: c.pre_score,
           dest_port: c.dest_port, protocol: c.protocol,
           pre_flags: c.pre_flags};
      bySig.set(key, b);
    }
    b.count += 1;
    b.ips.push(c.dest_ip);
  }
  return [...bySig.values()];
}

