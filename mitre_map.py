"""D6: mapa MITRE ATT&CK por evento (v2.6(1)).

Mapeo DETERMINISTA y display-only de las senales observadas a tecnicas
MITRE ATT&CK: no cambia deteccion, veredictos ni aprobaciones; es lectura
de informe sobre lo que ya se mide. Cada regla lleva su porque para que
el mapa sea explicable en el panel y en los exports.

Reglas (un evento puede mapear a varias tecnicas):
- R1  conexion IA (tcp/udp 443)          -> T1071.001 Web Service
- R2  autonomia autonomous/scheduled     -> T1567 Cloud Service
- R3  beaconing (iat_cv <= 0.3, n >= 5) -> T1041 Exfiltration Over C2 Channel
- R4  flag new_process/first_time_dest   -> T1109 Ingress Tool Transfer
- R5  flag udp_non443                   -> T1095 Non-Application Layer Protocol

Solo senales observadas: si no hay senal, no hay tecnica (honestidad).
"""
from __future__ import annotations

_BEACON_CV_MAX = 0.3
_BEACON_MIN_N = 5


def _t(id: str, name: str, tactic: str, porque: str) -> dict:
    return {"id": id, "name": name, "tactic": tactic, "porque": porque}


def map_event(event: dict, pre_flags: list[dict] | None = None) -> list[dict]:
    """Tecnicas ATT&CK que aplican a un evento IA.

    event: dict de eventos (autonomy_verdict, iat_cv, sessions, ...).
    pre_flags: flags del baseline (D1/D2); None o vacio si no hay grupo.
    Devuelve [{id, name, tactic, porque}] sin duplicados, en orden de
    regla. Todo evento que llega aqui es una conexion a destino IA
    (la tabla solo guarda esas), asi R1 siempre aplica.
    """
    out: list[dict] = []

    def _add(t: dict) -> None:
        if not any(x["id"] == t["id"] for x in out):
            out.append(t)

    # R1: el canal en si (TLS/QUIC sobre 443 a proveedor IA).
    _add(_t("T1071.001", "Application Layer Protocol: Web Service",
            "Command and Control",
            "conexion TLS/QUIC a proveedor IA"))

    # R2: salida a nube iniciada por la maquina (sin usuario delante).
    verdict = str(event.get("autonomy_verdict") or "")
    if verdict in ("autonomous", "scheduled"):
        _add(_t("T1567", "Cloud Service", "Exfiltration",
                f"salida a nube iniciada por la maquina ({verdict}): "
                "canal de exfiltracion plausible"))

    # R3: periodicidad regular sobre el mismo canal (beacon).
    cv = event.get("iat_cv")
    sessions = int(event.get("sessions") or 0)
    if cv is not None and sessions >= _BEACON_MIN_N \
            and float(cv) <= _BEACON_CV_MAX:
        _add(_t("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                f"periodicidad regular (CV {cv:g}, n={sessions}) "
                "sobre el mismo canal"))

    flags = {f.get("flag") for f in (pre_flags or [])}
    # R4: proceso/destino nuevo contactando IA.
    if {"new_process", "first_time_dest"} & flags:
        _add(_t("T1109", "Ingress Tool Transfer", "Initial Access",
                "proceso/destino nuevo contactando proveedor IA"))

    # R5: UDP en puerto no estandar hacia destino IA.
    if "udp_non443" in flags:
        _add(_t("T1095", "Non-Application Layer Protocol",
                "Command and Control",
                "UDP en puerto no estandar hacia destino IA"))

    return out


def union_mitre(per_member: list[list[dict]]) -> list[dict]:
    """Union de tecnicas de varios eventos (fila agrupada/hallazgo),
    sin duplicados y conservando el orden de primera aparicion."""
    out: list[dict] = []
    for lst in per_member:
        for t in lst:
            if not any(x["id"] == t["id"] for x in out):
                out.append(t)
    return out
