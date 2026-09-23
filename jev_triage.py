"""Jev (TypeSafe) como juez de criticidad de eventos cloud AI.

Mismo contrato que sec-dashboard: POST {base_url} con
{model, state[], questions{}} -> {answers}. Modelo pin jev-1.13.0.
Una sola llamada por triaje (batch). Fail-safe: nunca lanza hacia fuera;
devuelve status ok/skipped/error y el caller degrada a vista clasica.

Preguntas EXACTAS (las parametrisan los eventos, no la prosa):
  fN_class -> Choice: expected_ai_use / background_exfil_suspect /
                     telemetry_noise / unrelated
  fN_sev   -> Score 0-3 de criticidad de exfiltracion
  fN_act   -> Noul: requiere accion inmediata ahora?
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

PINNED_MODEL = "jev-1.13.0"
DEFAULT_BASE_URL = "https://api.typesafe.ai/v1/systemone"
TRIAGE_CAP = 50

# Criterias en ingles a proposito (doc TypeSafe: english = mejor precision).
_CLASS_CRITERIA = {
    "expected_ai_use": {
        "what": (
            "User-triggered call to a known/authorized cloud AI endpoint:"
            " interactive use, or an explicit triage/triaction the user started"
        ),
        "not_for": (
            "Outbound connections with no user action, off-hours sending, or"
            " periodic heartbeat-like repeats"
        ),
    },
    "background_exfil_suspect": {
        "what": (
            "Data leaving to a cloud/AI endpoint without user action, at unusual"
            " hours, or with telemetry-like periodicity"
        ),
        "not_for": ("Small low-sensitivity metadata pings (that is telemetry_noise)"),
    },
    "telemetry_noise": {
        "what": (
            "Small periodic metadata/telemetry from an AI tool, low sensitivity"
        ),
        "not_for": ("Anything carrying plausible user data or large payloads"),
    },
    "unrelated": {
        "what": (
            "Not actually cloud-AI related (catalog false positive, e.g. shared"
            " IP of a CDN)"
        ),
        "not_for": ("Real traffic to an AI provider endpoint"),
    },
}

_SEVERITY_LEVELS = [
    "Expected use or no sensitive data involved",
    "Probable low-sensitivity telemetry",
    "Background sending to an unknown/ambiguous destination with moderate sensitivity",
    "Probable active exfiltration (repeated/periodic, off-hours, unknown host,"
    " or sustained connection churn)",
]


def _http_post_json(url: str, body: dict, api_key: str, timeout: int = 30):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # El cuerpo del 4xx/5xx de TypeSafe lleva el detalle exacto; no tirarlo.
        detail = ""
        try:
            detail = e.read().decode()[:300]
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code}: {detail}".strip()) from None


def _questions_for(global_i: int, local_i: int | None = None) -> dict[str, dict]:
    """Las 3 preguntas de un evento. ID por indice GLOBAL; la instruccion
    referencia state[local] (en llamada completa local == global)."""
    li = global_i if local_i is None else local_i
    base = f"About event {global_i} (state[{li}]): "
    return {
        f"f{global_i}_class": {
            "type": "choice",
            "instructions": (
                base + "which classification applies to this cloud-AI "
                          "network event observed on a Windows host?"
            ),
            "criteria": _CLASS_CRITERIA,
        },
        f"f{global_i}_sev": {
            "type": "score",
            "instructions": (
                base + "how critical is the exfiltration risk if this pattern"
                " continues?"
            ),
            "criteria": _SEVERITY_LEVELS,
        },
        f"f{global_i}_act": {
            "type": "noul",
            "instructions": base + "does this event require IMMEDIATE action right now?",
        },
    }


def _state_for(event: dict) -> dict:
    # sni_domain = dominio real declarado en el handshake TLS (tshark):
    # mas fiable que dest_host (cache DNS, puede ser nombre de CDN).
    sni = str(event.get("sni_domain") or "")[:120]
    host = sni or str(event.get("dest_host") or "")[:120]
    return {
        "title": f"{event.get('process')} -> {host or event.get('dest_ip')}:{event.get('dest_port')}",
        "process": str(event.get("process") or "")[:80],
        "dest_ip": str(event.get("dest_ip") or ""),
        "dest_port": int(event.get("dest_port") or 0),
        "dest_host": str(event.get("dest_host") or "")[:120],
        "sni_domain": sni,
        "catalog_domain": str(event.get("catalog_domain") or ""),
        "seen_count": int(event.get("seen_count") or 1),
        "first_seen": str(event.get("first_seen") or ""),
        "last_seen": str(event.get("last_seen") or ""),
        # R2: veredicto de autonomia persistido por evento (user_driven |
        # autonomous | scheduled); unknown si no hay senal.
        "user_active": str(event.get("autonomy_verdict") or "unknown"),
        # F1/D3: sesiones (no polls) y beaconing (CV de inter-arrival).
        "sessions": int(event.get("sessions") or 1),
        "iat_cv": event.get("iat_cv"),
        "beaconing": bool(
            event.get("iat_cv") is not None
            and float(event["iat_cv"]) <= 0.3
            and int(event.get("sessions") or 0) >= 5),
    }


def _prob_false_positive(verdict, confidence):
    if not verdict or confidence is None:
        return None
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return None
    if verdict == "expected_ai_use":
        return round(1.0 - conf, 4)
    return round(conf, 4)


_CHUNK = 10  # tamano del reintent por trozos si la llamada completa falla


def _ask(states: list[dict], idxs: list[int], api_key: str, base_url: str,
         model: str, timeout: int) -> dict | None:
    """Una llamada TypeSafe para los eventos idxs (state local 0..n-1)."""
    questions: dict[str, dict] = {}
    for pos, gi in enumerate(idxs):
        questions.update(_questions_for(gi, pos))
    data = _http_post_json(base_url, {
        "model": model, "state": states, "questions": questions,
    }, api_key, timeout)
    return data.get("answers") if isinstance(data, dict) else None


def triage_events(events: list[dict], api_key: str, base_url: str = DEFAULT_BASE_URL,
                   model: str = PINNED_MODEL, timeout: int = 30) -> dict:
    """Triaje batch. Devuelve {status, model, count, verdicts{idx: {...}}}."""
    if not events:
        return {"status": "skipped", "reason": "no_events"}
    if not api_key:
        return {"status": "skipped", "reason": "no_api_key"}
    events = events[:TRIAGE_CAP]
    state = [_state_for(e) for e in events]
    answers: dict | None = None
    try:
        answers = _ask(state, list(range(len(state))), api_key, base_url,
                       model, timeout)
    except Exception as e:
        # Fallback por trozos de 10: tolera limites/errores transitorios del API.
        answers = {}
        errors: list[str] = []
        for start in range(0, len(state), _CHUNK):
            idxs = list(range(start, min(start + _CHUNK, len(state))))
            try:
                a = _ask([state[i] for i in idxs], idxs, api_key, base_url,
                         model, timeout)
                if isinstance(a, dict):
                    answers.update(a)
            except Exception as e2:
                errors.append(f"chunk {idxs[0]}-{idxs[-1]}: {e2}")
        if not answers:
            return {"status": "error",
                    "reason": "; ".join(errors) or f"{type(e).__name__}: {e}"}
    if not isinstance(answers, dict):
        return {"status": "error", "reason": "bad_response_shape"}
    verdicts: dict[str, dict] = {}
    for i in range(len(events)):
        cls = answers.get(f"f{i}_class") or {}
        sev = answers.get(f"f{i}_sev") or {}
        act = answers.get(f"f{i}_act") or {}
        choice = cls.get("choice") if isinstance(cls, dict) else None
        conf = cls.get("confidence") if isinstance(cls, dict) else None
        score = sev.get("score") if isinstance(sev, dict) else None
        noul = act.get("noul") if isinstance(act, dict) else None
        verdicts[str(i)] = {
            "verdict": choice,
            "confidence": conf,
            "severity_score": score,
            "immediate_action": noul,
            "prob_false_positive": _prob_false_positive(choice, conf),
        }
    missing = [i for i in range(len(events)) if f"f{i}_class" not in answers]
    return {"status": "ok", "model": model, "count": len(events),
            "partial": bool(missing), "verdicts": verdicts}
