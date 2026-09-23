"""v2.2 — Motor de reglas: reglas por umbral sobre señales existentes.

Funcion pura (sin I/O): el servidor pasa eventos con 'provider' y
'unapproved' ya calculados (unica fuente de verdad: la logica shadow)
y decide las alertas por transicion no-firing -> firing.

Reglas:
- service_ai_call: veredicto autonomous/scheduled llamando a IA no
  aprobada (R2 + shadow).
- beacon_unapproved: beaconing (N>=5, CV<=0.3) a proveedor no aprobado
  (D3 + shadow).
- egress_volume_unapproved: >X MB/dia a IA no aprobada — PENDIENTE de
  bytes remotos (v2.2: ETW Kernel-Network, requiere admin): available
  False hasta entonces. Honestidad: sin dato, no regla.
"""
from __future__ import annotations

_BEACON_CV_MAX = 0.3
_BEACON_MIN_N = 5


def _top(items: list[str], n: int = 5) -> str:
    seen: list[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return ", ".join(seen[:n]) + (" ..." if len(seen) > n else "")


def evaluate(events: list[dict], *, egress_mb_per_day: float) -> list[dict]:
    """Evalua las reglas contra eventos ya enriquecidos.

    events: dicts con (process, provider, autonomy_verdict, sessions,
    iat_cv, unapproved). Devuelve uno por regla: {id, available, reason,
    fired, detail}.
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
    return [
        {"id": "egress_volume_unapproved",
         "available": False,
         "reason": (f"> {egress_mb_per_day:g} MB/dia a IA no aprobada: "
                    "pendiente de bytes remotos (v2.2: ETW Kernel-Network,"
                    " requiere admin)"),
         "fired": False,
         "detail": None},
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
    ]
