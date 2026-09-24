"""I1: firma determinista de evento para dedup de triaje (v2.6(2)).

La firma resume el estado del evento que afecta al veredicto de Jev.
Si la firma no cambio desde el ultimo triaje OK, el veredicto se
reutiliza sin llamar a Jev (ahorro de coste y ruido; display-only:
Jev sigue siendo el juez cuando algo cambia).

EXCLUIDOS a proposito (volatiles entre triajes): seen_count, sessions,
pre_score exacto, last_seen, first_seen. Si solo cambian esos, el
contexto que vio Jev no cambio y re-triar seria ruido, no senal.
INCLUIDOS: identidad (proceso, destino, catalogo, capa, protocolo),
autonomia (veredicto) y flags del baseline (conjunto discreto).
"""
from __future__ import annotations

import hashlib
import json


def event_signature(e: dict) -> str:
    """Firma corta (16 hex) del estado triable de un evento.

    Determinista: mismo estado -> misma firma. No es una clave unica
    del evento: dos eventos distintos pueden coincidir, y eso no
    importa porque la reutilizacion se hace por (event_id, firma).
    """
    flags = sorted(str(f.get("flag")) for f in (e.get("pre_flags") or []))
    core = {
        "process": e.get("process"),
        "dest_ip": e.get("dest_ip"),
        "dest_port": e.get("dest_port"),
        "catalog_domain": e.get("catalog_domain"),
        "ai_layer": e.get("ai_layer"),
        "protocol": e.get("protocol"),
        "autonomy_verdict": e.get("autonomy_verdict"),
        "pre_flags": flags,
    }
    blob = json.dumps(core, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
