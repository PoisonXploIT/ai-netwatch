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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _state_for(event: dict) -> dict:
    return {
        "title": f"{event.get('process')} -> {event.get('dest_host') or event.get('dest_ip')}:{event.get('dest_port')}",
        "process": str(event.get("process") or "")[:80],
        "dest_ip": str(event.get("dest_ip") or ""),
        "dest_port": int(event.get("dest_port") or 0),
        "dest_host": str(event.get("dest_host") or "")[:120],
        "catalog_domain": str(event.get("catalog_domain") or ""),
        "seen_count": int(event.get("seen_count") or 1),
        "first_seen": str(event.get("first_seen") or ""),
        "last_seen": str(event.get("last_seen") or ""),
        "user_active": "unknown",
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


def triage_events(events: list[dict], api_key: str, base_url: str = DEFAULT_BASE_URL,
                   model: str = PINNED_MODEL, timeout: int = 30) -> dict:
    """Triaje batch. Devuelve {status, model, count, verdicts{idx: {...}}}."""
    if not events:
        return {"status": "skipped", "reason": "no_events"}
    if not api_key:
        return {"status": "skipped", "reason": "no_api_key"}
    events = events[:TRIAGE_CAP]
    state = [_state_for(e) for e in events]
    questions: dict[str, dict] = {}
    for i in range(len(events)):
        base = f"About event {i} (state[{i}]): "
        questions[f"f{i}_class"] = {
            "type": "choice",
            "instructions": (
                base + "which classification applies to this cloud-AI "
                          "network event observed on a Windows host?"
            ),
            "criteria": _CLASS_CRITERIA,
        }
        questions[f"f{i}_sev"] = {
            "type": "score",
            "instructions": (
                base + "how critical is the exfiltration risk if this pattern"
                " continues?"
            ),
            "criteria": _SEVERITY_LEVELS,
        }
        questions[f"f{i}_act"] = {
            "type": "noul",
            "instructions": base + "does this event require IMMEDIATE action right now?",
        }
    try:
        data = _http_post_json(base_url, {
            "model": model, "state": state, "questions": questions,
        }, api_key, timeout)
    except Exception as e:
        return {"status": "error", "reason": f"{type(e).__name__}: {e}"}
    answers = data.get("answers") if isinstance(data, dict) else None
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
    return {"status": "ok", "model": data.get("model") or model,
            "count": len(events), "verdicts": verdicts}
