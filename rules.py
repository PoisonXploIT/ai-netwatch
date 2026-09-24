"""v2.2 — Motor de reglas: reglas por umbral sobre señales existentes.

Funcion pura (sin I/O): el servidor pasa eventos con 'provider' y
'unapproved' ya calculados (unica fuente de verdad: la logica shadow)
y decide las alertas por transicion no-firing -> firing.

Reglas:
- service_ai_call: veredicto autonomous/scheduled llamando a IA no
  aprobada (R2 + shadow).
- beacon_unapproved: beaconing (N>=5, CV<=0.3) a proveedor no aprobado
  (D3 + shadow).
- egress_volume_unapproved: >X MB a IA no aprobada (bytes remotos del
  colector elevado; acumulado desde inicio del colector). Sin datos de
  colector => available=False. Honestidad: sin dato, no regla.
- anomaly_pre_score: anomalia determinista (v2.5(3) D2): algun evento con
  pre_score >= umbral (flags explicables: primera aparicion, proceso
  nuevo, fuera de horas tipicas, rafaga de sesiones, UDP no 443).
  Detecion sin IA; la regla solo avisa, Jev sigue siendo el juez.
"""
from __future__ import annotations

_BEACON_CV_MAX = 0.3
_BEACON_MIN_N = 5
_ANOMALY_MIN_SCORE = 50


def _top(items: list[str], n: int = 5) -> str:
    seen: list[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return ", ".join(seen[:n]) + (" ..." if len(seen) > n else "")


def evaluate(events: list[dict], *, egress_mb_per_day: float,
             egress: list[dict] | None = None) -> list[dict]:
    """Evalua las reglas contra eventos ya enriquecidos.

    events: dicts con (process, provider, autonomy_verdict, sessions,
    iat_cv, unapproved, pre_score). egress: bytes remotos por proveedor
    [{provider, bytes, unapproved}] o None si el colector elevado no ha
    volcado datos (la regla egress queda disponible=False).
    Devuelve uno por regla: {id, available, reason, fired, detail}.
    """
    svc = [f"{e.get('process')} -> {e.get('provider')}" for e in events
           if (e.get("autonomy_verdict") in ("autonomous", "scheduled")
               and e.get("unapproved"))]
    bcn: list[str] = []
    for e in events:
        cv = e.get("iat_cv")
        n = int(e.get("sessions") or 0)
        if (cv is not None and float(cv) <= _BEACON_CV_MAX
                and n >= _BEACON_MIN_N and e.get("unapproved")):
            bcn.append(f"{e.get('process')} -> {e.get('provider')}"
                       f" (CV {float(cv):.3f}, {n} sesiones)")
    if egress is None:
        egress_rule = {
            "id": "egress_volume_unapproved",
            "available": False,
            "reason": (f"> {egress_mb_per_day:g} MB a IA no aprobada: "
                       "sin datos del colector elevado (ETW Kernel-Network"
                       ", requiere admin)"),
            "fired": False,
            "detail": None,
        }
    else:
        limit_b = float(egress_mb_per_day) * 1024.0 * 1024.0
        over = [f"{r['provider']} ({int(r['bytes']) / (1024.0 * 1024.0):.1f}"
                f" MB)" for r in egress
                if r.get("unapproved") and int(r["bytes"]) > limit_b]
        egress_rule = {
            "id": "egress_volume_unapproved",
            "available": True,
            "reason": None,
            "fired": bool(over),
            "detail": (f"egress a IA no aprobada > {egress_mb_per_day:g} MB:"
                       f" {_top(over)}" if over else None),
        }
    anom = [f"{e.get('process')} -> {e.get('provider')}"
            f" (pre_score {e.get('pre_score')})"
            for e in events
            if int(e.get("pre_score") or 0) >= _ANOMALY_MIN_SCORE]
    return [
        egress_rule,
        {"id": "service_ai_call",
         "available": True,
         "reason": None,
         "fired": bool(svc),
         "detail": (f"llamadas IA autonomas/programadas a no aprobados:"
                    f" {_top(svc)}" if svc else None)},
        {"id": "beacon_unapproved",
         "available": True,
         "reason": None,
         "fired": bool(bcn),
         "detail": (f"beaconing a proveedores no aprobados: {_top(bcn)}"
                    if bcn else None)},
        {"id": "anomaly_pre_score",
         "available": True,
         "reason": None,
         "fired": bool(anom),
         "detail": (f"anomalia determinista pre_score >= {_ANOMALY_MIN_SCORE}:"
                    f" {_top(anom)}" if anom else None)},
    ]
