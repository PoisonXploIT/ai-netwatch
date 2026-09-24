"""v2.5(3) D1/D2 — Baseline aprendido por (proceso, proveedor) y anomalia
determinista (sin IA).

D1 — "lo normal" de cada par (proceso, proveedor), derivado de lo que ya
existe en disco (no hay nuevo estado):
- primera aparicion: min(first_seen) de los eventos vivos del par.
- horario tipico: histograma por hora UTC de los inicios de sesion
  (sessions_log, transiciones ausente->presente de F1); horas tipicas =
  top TOP_HOURS por numero de sesiones (solo con >= MIN_SESSIONS_HOURS
  sesiones; sin eso no hay baseline de horario y se deja vacio).
- ratio: sesiones / horas de abanico (de la primera aparicion a la ultima
  observacion; abanico con piso de 1 h para no inflar el ratio).

Solo cuenta lo atribuible: una sesion (process, dest_ip) se asigna al
proveedor solo si esa IP tiene mapeo a proveedor en los eventos vivos.
Sin mapeo, no se cuenta (honestidad: sin dato, no valor inventado).

D2 — anomalia determinista por evento (sin IA, explicable): cada flag
lleva su "porque" y un peso; pre_score = suma de pesos de flags activos
(tope 100). No es caja negra ni re-puntua nada: es display + enriquece el
state que se pasa a Jev (que sigue siendo el juez) + alimenta la regla
`anomaly_pre_score`. Si una senal no esta disponible, su flag no sale;
nunca se fabrica.

Constantes (todas visibles y documentadas):
- FIRST_SEEN_HOURS: "nuevo" = primera aparicion dentro de las ultimas 24 h.
- MIN_SESSIONS_HOURS: minimo de sesiones para que el horario tipico sea
  fiable (y, por tanto, para que off_hours pueda dispararse).
- TOP_HOURS: cuantas horas tipicas se muestran (top por sesiones).
- RECENT_WINDOW_H / HIGH_FACTOR / HIGH_MIN_RECENT: high_sessions =
  >=HIGH_MIN_RECENT sesiones en las ultimas RECENT_WINDOW_H h y a la vez
  >HIGH_FACTOR veces lo que su propio ratio predice para esa ventana.
"""
from __future__ import annotations

import datetime as dt

FIRST_SEEN_HOURS = 24
MIN_SESSIONS_HOURS = 5
TOP_HOURS = 6
RECENT_WINDOW_H = 24
HIGH_FACTOR = 3.0
HIGH_MIN_RECENT = 5

WEIGHTS: dict[str, int] = {
    "first_time_dest": 25,  # (proceso, proveedor) nunca visto antes
    "new_process": 25,      # primera vez que el proceso habla con IA
    "off_hours": 20,        # fuera de sus horas habituales (baseline >=5 ses)
    "high_sessions": 25,    # rafaga de sesiones vs su ratio baseline
    "udp_non443": 15,       # UDP a puerto que no es 443
}


def _parse(ts: str) -> dt.datetime | None:
    """'YYYY-MM-DD HH:MM:SSZ' (UTC naive en el store) -> datetime. None si no."""
    try:
        return dt.datetime.fromisoformat(str(ts).replace("Z", "").strip())
    except ValueError:
        return None


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def compute_baseline(
        events: list[dict],
        sessions: list[tuple[str, str, str]],
        ip_provider: dict[str, str],
        now: dt.datetime | None = None) -> dict:
    """Baseline por (proceso, proveedor) sobre eventos vivos + sesiones.

    events: dicts con (process, provider, first_seen, last_seen); el
    servidor añade 'provider' con la misma logica que el resto del panel.
    sessions: filas (ts, process, dest_ip) de sessions_log.
    ip_provider: dest_ip -> proveedor (mas reciente gana; lo construye el
    servidor a partir de los eventos vivos).

    Devuelve {"groups": [...], "process_first_seen": {process: ts}} donde
    cada grupo es {process, provider, first_seen, last_seen,
    sessions_total, span_hours, sessions_per_hour (None sin sesiones),
    days_active, hour_hist {hora: n}, typical_hours [h], recent_sessions}
    ordenado por sesiones_total desc. Determinista; sin I/O.
    """
    now = now or _utcnow()
    groups: dict[tuple[str, str], dict] = {}
    proc_first: dict[str, str] = {}

    for e in events:
        p, prov = str(e.get("process") or ""), str(e.get("provider") or "")
        if not p or not prov:
            continue
        fs = str(e.get("first_seen") or "")
        ls = str(e.get("last_seen") or "")
        if fs and (p not in proc_first or fs < proc_first[p]):
            proc_first[p] = fs
        g = groups.setdefault((p, prov), {
            "process": p, "provider": prov,
            "first_seen": fs, "last_seen": ls, "_sess_ts": []})
        if fs and (not g["first_seen"] or fs < g["first_seen"]):
            g["first_seen"] = fs
        if ls and (not g["last_seen"] or ls > g["last_seen"]):
            g["last_seen"] = ls

    for ts, process, dest_ip in sessions:
        mapped = ip_provider.get(str(dest_ip or ""))
        if not mapped:
            continue  # IP sin mapeo a proveedor: no atribuible, no se cuenta
        key = (str(process or ""), mapped)
        gg = groups.get(key)
        if gg is None:
            continue  # el par ya no esta vivo: no hay baseline que alimentar
        gg["_sess_ts"].append(str(ts))

    out: list[dict] = []
    for g in groups.values():
        parsed = [_parse(t) for t in g.pop("_sess_ts")]
        sess: list[dt.datetime] = [t for t in parsed if t is not None]
        hist: dict[int, int] = {}
        for t in sess:
            hist[t.hour] = hist.get(t.hour, 0) + 1
        hour_hist = {str(h): n for h, n in sorted(hist.items())}
        typical: list[int] = []
        if len(sess) >= MIN_SESSIONS_HOURS:
            # top por (count desc, hora asc): ties -> hora menor primero.
            typical = [h for h, _ in sorted(
                hist.items(), key=lambda kv: (-kv[1], kv[0]))
                [:TOP_HOURS]]
        span_h = 0.0
        fs_p, ls_p = _parse(g["first_seen"]), _parse(g["last_seen"])
        if fs_p and ls_p:
            span_h = max((ls_p - fs_p).total_seconds() / 3600.0, 1.0)
        rate = (len(sess) / span_h) if (sess and span_h > 0) else None
        recent = sum(1 for t in sess
                     if (now - t).total_seconds() <= RECENT_WINDOW_H * 3600)
        days = {t.date() for t in sess}
        if fs_p:
            days.add(fs_p.date())
        out.append({
            "process": g["process"], "provider": g["provider"],
            "first_seen": g["first_seen"], "last_seen": g["last_seen"],
            "sessions_total": len(sess),
            "span_hours": round(span_h, 2),
            "sessions_per_hour": (round(rate, 4) if rate is not None
                                  else None),
            "days_active": len(days),
            "hour_hist": hour_hist,
            "typical_hours": typical,
            "recent_sessions": recent,
        })
    out.sort(key=lambda g: (-g["sessions_total"], g["process"],
                            g["provider"]))
    return {"groups": out, "process_first_seen": proc_first}


def score_event(event: dict, group: dict | None,
                proc_first: str | None,
                now: dt.datetime | None = None) -> dict:
    """Anomalia determinista de un evento vivo contra su baseline.

    event: dict con (process, first_seen, protocol, dest_port).
    group: grupo del compute_baseline para este (proceso, proveedor),
    o None (no se evaluan los flags que lo necesitan).
    proc_first: primera aparicion global del proceso (cualquier proveedor).

    Devuelve {"pre_score": 0..100, "pre_flags": [{"flag","porque"}]}
    en orden de peso desc. Determinista; sin I/O.
    """
    now = now or _utcnow()
    flags: list[dict] = []

    def _add(flag: str, porque: str) -> None:
        flags.append({"flag": flag, "porque": porque})

    p = str(event.get("process") or "")
    prov = str(group.get("provider") if group else
               event.get("provider") or "")

    # first_time_dest: el par (proceso, proveedor) nunca visto antes.
    fs = str((group or {}).get("first_seen")
             or event.get("first_seen") or "")
    fs_p = _parse(fs) if fs else None
    if fs_p and (now - fs_p).total_seconds() <= FIRST_SEEN_HOURS * 3600:
        age_h = max((now - fs_p).total_seconds() / 3600.0, 0.0)
        _add("first_time_dest",
             f"primera aparicion de {p} -> {prov} hace {age_h:.1f} h"
             f" (<{FIRST_SEEN_HOURS} h)")

    # new_process: primera vez que este proceso habla con IA.
    pf_p = _parse(proc_first) if proc_first else None
    if pf_p and (now - pf_p).total_seconds() <= FIRST_SEEN_HOURS * 3600:
        age_h = max((now - pf_p).total_seconds() / 3600.0, 0.0)
        _add("new_process",
             f"primera vez que {p} habla con IA (hace {age_h:.1f} h)")

    # off_hours: hora actual fuera de las tipicas (solo con baseline >=5).
    if (group and group.get("typical_hours")
            and now.hour not in group["typical_hours"]):
        typ = ", ".join(str(h) for h in group["typical_hours"])
        _add("off_hours",
             f"hora {now.hour} UTC fuera de sus horas habituales ({typ})")

    # high_sessions: rafaga reciente vs su propio ratio baseline.
    if group:
        recent = int(group.get("recent_sessions") or 0)
        rate = group.get("sessions_per_hour")
        if (recent >= HIGH_MIN_RECENT and rate is not None
                and recent > HIGH_FACTOR * max(float(rate) * RECENT_WINDOW_H,
                                               1e-9)):
            expected = float(rate) * RECENT_WINDOW_H
            _add("high_sessions",
                 f"{recent} sesiones en {RECENT_WINDOW_H} h vs ~{expected:.1f}"
                 f" esperadas por su ratio ({rate:.2f}/h)")

    # udp_non443: UDP a puerto que no es 443 (QUIC/IA va por 443).
    if str(event.get("protocol") or "") == "udp" \
            and int(event.get("dest_port") or 0) != 443:
        _add("udp_non443",
             f"UDP a puerto {event.get('dest_port')} (lo esperado hacia IA"
             " es TCP/QUIC 443)")

    total = min(100, sum(WEIGHTS[f["flag"]] for f in flags))
    flags.sort(key=lambda f: -WEIGHTS[f["flag"]])
    return {"pre_score": total, "pre_flags": flags}
