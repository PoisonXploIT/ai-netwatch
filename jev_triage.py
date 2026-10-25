"""Jev (TypeSafe) como juez de criticidad de eventos cloud AI.

Mismo contrato que sec-dashboard: POST {base_url} con
{model, state[], questions{}} -> {answers}. Modelo pin jev-1.13.0.
Un lote de hasta TRIAGE_CAP eventos por llamada (batch); el triaje cubre
todos los eventos en lotes. Fail-safe: nunca lanza hacia fuera; devuelve
status ok/skipped/error y el caller degrada a vista clasica.

Preguntas EXACTAS (las parametrisan los eventos, no la prosa):
  fN_class -> Choice: expected_ai_use / background_exfil_suspect /
                     telemetry_noise / unrelated
  fN_sev   -> Score 0-3 de criticidad de exfiltracion
  fN_act   -> Noul: requiere accion inmediata ahora?
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

PINNED_MODEL = "jev-1.13.0"
DEFAULT_BASE_URL = "https://api.typesafe.ai/v1/systemone"
# Backend local: laya-serve (proceso aparte, CPU, sin VRAM). Key desde env
# LAYA_API_KEY; nunca en claro en data/config.json.
LOCAL_BASE_URL = "http://127.0.0.1:8787/v1/systemone"
LOCAL_MODEL = "english"
_BACKENDS = {
    "cloud": {"base_url": DEFAULT_BASE_URL, "model": PINNED_MODEL},
    "local": {"base_url": LOCAL_BASE_URL, "model": LOCAL_MODEL},
}
# Eventos por llamada TypeSafe (tamano de lote). El triaje cubre TODOS
# los eventos en lotes de este tamano; no es un techo global.
TRIAGE_CAP = 50

# Criterias en ingles a proposito (doc TypeSafe: english = mejor precision).
_CLASS_CRITERIA = {
    "expected_ai_use": {
        "what": (
            "Call to a known/authorized cloud AI endpoint: user-triggered"
            " interactive use, OR autonomous traffic from an installed AI tool"
            " (SDK calls, model/dataset downloads, provider APIs) at the host"
            " that is the known endpoint for that tool"
        ),
        "not_for": (
            "The same data leaving to an UNKNOWN or non-AI destination (that is"
            " background_exfil_suspect); small periodic metadata pings (that is"
            " telemetry_noise)"
        ),
    },
    "background_exfil_suspect": {
        "what": (
            "Data leaving WITHOUT user action to a destination that is NOT the"
            " known/authorized AI endpoint for that tool (unknown host, catalog"
            " false positive, unexpected provider), at unusual hours, or with"
            " sustained outbound churn / telemetry-like periodicity"
        ),
        "not_for": (
            "Small low-sensitivity metadata pings (that is telemetry_noise);"
            " autonomous traffic to the tool's own known AI endpoint (that is"
            " expected_ai_use)"
        ),
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


def _local_questions() -> dict[str, dict]:
    """Plantilla SIN indice para backend=local (laya-serve).

    A3 REAL (data/laya_a3_gate.txt): /v1/systemone trata state=[] como UN
    documento y ignora el indice f{i}; por eso el adaptador local usa
    /v1/systemone/batch con states[] y UNA plantilla unica (ids class/sev/
    act) aplicada a cada estado, mapeando results[i] al evento i.
    noul con criteria true/false (C1): sin criteria el checkpoint english
    clava 'no' casi siempre; labels NO se mandan (la doc avisa de que el
    checkpoint sigue sus propios labels y un relabel sesga).
    """
    return {
        "class": {
            "type": "choice",
            "instructions": (
                "which classification applies to this cloud-AI network "
                "event observed on a Windows host?"
            ),
            "criteria": _CLASS_CRITERIA,
        },
        "sev": {
            "type": "score",
            "instructions": (
                "how critical is the exfiltration risk if this pattern "
                "continues?"
            ),
            "criteria": _SEVERITY_LEVELS,
        },
        "act": {
            "type": "noul",
            "instructions": "does this event require IMMEDIATE action right now?",
            "criteria": {
                "false": "no immediate action needed",
                "true": "yes, requires immediate action now",
            },
        },
    }


def _local_verdict(answers: dict) -> dict:
    """Parseo de answers de laya al contrato de salida (C2/C3).

    - choice:  verdict = answers['class']['choice']
    - score:   severity_score = float tal cual (se redondea solo al presentar)
    - noul:    'act' devuelve P(true) en [0,1], NO etiqueta:
               immediate_action = 'yes' if noul >= 0.5 else 'no'
    - C2:      prob_false_positive = 1 - answer_confidence (la masa sobre
               el label reportado; la 'confidence' de laya es entropia
               normalizada y NO es intercambiable con la de Jev).
    """
    cls = answers.get("class") or {}
    sev = answers.get("sev") or {}
    act = answers.get("act") or {}
    choice = cls.get("choice") if isinstance(cls, dict) else None
    conf = cls.get("answer_confidence") if isinstance(cls, dict) else None
    score = sev.get("score") if isinstance(sev, dict) else None
    noul = act.get("noul") if isinstance(act, dict) else None
    try:
        immediate = "yes" if float(noul or 0) >= 0.5 else "no"
    except (TypeError, ValueError):
        immediate = None
    return {
        "verdict": choice,
        "confidence": conf,
        "severity_score": score,
        "immediate_action": immediate,
        "prob_false_positive": _prob_false_positive(choice, conf),
    }


def _state_for(event: dict, minimal: bool = False) -> dict:
    # sni_domain = dominio real declarado en el handshake TLS (tshark):
    # mas fiable que dest_host (cache DNS, puede ser nombre de CDN).
    sni = str(event.get("sni_domain") or "")[:120]
    host = sni or str(event.get("dest_host") or "")[:120]
    state = {
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
    if minimal:
        # S-07 modo "solo dominios": no salen proceso, IP, puerto ni nombre de
        # host. El modelo solo ve el dominio observado y su patron temporal.
        state = {
            "title": host or "(sin dominio)",
            "sni_domain": sni,
            "dest_host": host,
            "catalog_domain": str(event.get("catalog_domain") or ""),
            "seen_count": state["seen_count"],
            "first_seen": state["first_seen"],
            "last_seen": state["last_seen"],
            "sessions": state["sessions"],
            "iat_cv": state["iat_cv"],
            "beaconing": state["beaconing"],
        }
    return state


def _prob_false_positive(verdict, confidence):
    """Probabilidad de falso positivo = complemento de la confianza en el
    veredicto elegido. Jev reporta confianza 0..1 sobre SU veredicto
    (expected_ai_use o sospechoso); la prob. de que ese veredicto sea un
    falso positivo es 1 - conf en ambos casos."""
    if not verdict or confidence is None:
        return None
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return None
    return round(1.0 - conf, 4)


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


def _ask_local(states: list[dict], api_key: str, base_url: str,
               model: str, timeout: int) -> list[dict] | None:
    """POST /v1/systemone/batch (laya 0.3.22+): states[] + UNA plantilla sin
    indice; results[i].answers corresponde al estado i (orden de entrada).
    Max 64 states por llamada (TRIAGE_CAP=50 < 64). Devuelve la lista de
    answers o None si la respuesta no tiene forma esperable."""
    data = _http_post_json(base_url + "/batch", {
        "model": model, "states": states,
        "questions": _local_questions(),
    }, api_key, timeout)
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return None
    out: list[dict] = []
    for r in results:
        a = r.get("answers") if isinstance(r, dict) else None
        out.append(a if isinstance(a, dict) else {})
    return out


def _triage_local(states_all: list[dict], api_key: str, base_url: str,
                  model: str, timeout: int) -> tuple[dict[str, dict], list[str],
                                                     dict[str, dict]]:
    """Camino local (laya-serve). Devuelve (verdicts por indice global,
    errores, answers crudas por indice global). Fail-safe igual que
    cloud: nunca lanza hacia fuera."""
    n = len(states_all)
    verdicts: dict[str, dict] = {}
    raw: dict[str, dict] = {}
    errors: list[str] = []

    # CPU: ~1.7 s/estado medido (2026-09-30). Un batch de 50 tarda ~90 s,
    # asi que el timeout local escala con el tamano del lote; el default
    # de 30 s de cloud no sirve aqui.
    def one(i: int) -> dict | None:
        # Fallback 1 llamada por evento a /v1/systemone (tambien cubre la
        # hipotesis de version sin /batch): state unico, misma plantilla.
        data = _http_post_json(base_url, {
            "model": model, "state": states_all[i],
            "questions": _local_questions(),
        }, api_key, max(timeout, 60))
        a = data.get("answers") if isinstance(data, dict) else None
        return a if isinstance(a, dict) else None

    for start in range(0, n, TRIAGE_CAP):
        idxs = list(range(start, min(start + TRIAGE_CAP, n)))
        try:
            res = _ask_local([states_all[i] for i in idxs], api_key,
                             base_url, model, max(timeout, 60 + 5 * len(idxs)))
            if res is not None and len(res) == len(idxs):
                for gi, a in zip(idxs, res):
                    verdicts[str(gi)] = _local_verdict(a)
                    raw[str(gi)] = a
                continue
            errors.append(f"lote {idxs[0]}-{idxs[-1]}: bad_batch_shape")
        except Exception as e:
            errors.append(f"lote {idxs[0]}-{idxs[-1]}: {e}")
        # Fallback por evento (tamien tolera /batch ausente o 404).
        for i in idxs:
            if str(i) in verdicts:
                continue
            try:
                single = one(i)
                if single is not None:
                    verdicts[str(i)] = _local_verdict(single)
                    raw[str(i)] = single
                else:
                    errors.append(f"evento {i}: bad_response_shape")
            except Exception as e2:
                errors.append(f"evento {i}: {e2}")
    # Contrato: una entrada por evento (None si no hay respuesta), igual
    # que el camino cloud.
    full = {str(i): verdicts.get(str(i)) or _local_verdict({})
           for i in range(n)}
    return full, errors, raw


def triage_events(events: list[dict], api_key: str,
                  base_url: str | None = None, model: str | None = None,
                  timeout: int = 30, backend: str = "cloud",
                  minimal: bool = False) -> dict:
    """Triaje batch de TODOS los eventos. Devuelve
    {status, model, count, verdicts{idx: {...}}}, mas el campo ADITIVO
    raw{idx: answers crudas} (dataset Fase F; no cambia el contrato).

    Procesa en lotes de TRIAGE_CAP (50) y fusiona veredictos por indice
    global: cubre todos los eventos sin exceder el limite probado por
    llamada. Si un lote falla, reintenta por sub-trozos de _CHUNK (10).

    backend (Fase B): "cloud" (default; comportamiento actual, Jev) o
    "local" (laya-serve en 127.0.0.1:8787, proceso aparte, sin VRAM). Con
    local la key se toma de env LAYA_API_KEY (si no esta definida usa
    api_key); el estado nunca sale de la maquina.
    """
    if backend not in _BACKENDS:
        raise ValueError(f"backend desconocido: {backend!r}")
    if base_url is None:
        base_url = _BACKENDS[backend]["base_url"]
    if model is None:
        model = _BACKENDS[backend]["model"]
    if not events:
        return {"status": "skipped", "reason": "no_events"}
    if not api_key:
        return {"status": "skipped", "reason": "no_api_key"}
    n = len(events)
    states_all = [_state_for(e, minimal=minimal) for e in events]

    if backend == "local":
        key = os.environ.get("LAYA_API_KEY") or api_key
        verdicts, errors, raw = _triage_local(states_all, key, base_url,
                                              model, timeout)
        missing = [i for i in range(n) if verdicts[str(i)]["verdict"] is None]
        if all(v["verdict"] is None for v in verdicts.values()):
            return {"status": "error",
                    "reason": "; ".join(errors)[:500] or "no_answers"}
        return {"status": "ok", "model": model, "count": n,
                "partial": bool(missing), "verdicts": verdicts,
                "raw": raw}

    answers: dict = {}
    errors = []
    for start in range(0, n, TRIAGE_CAP):
        idxs = list(range(start, min(start + TRIAGE_CAP, n)))
        try:
            a = _ask([states_all[i] for i in idxs], idxs, api_key, base_url,
                     model, timeout)
            if isinstance(a, dict):
                answers.update(a)
            else:
                errors.append(f"lote {idxs[0]}-{idxs[-1]}: bad_response_shape")
        except Exception:
            # Fallback por sub-trozos de _CHUNK (10): tolera limites/
            # errores transitorios del API.
            for s2 in range(0, len(idxs), _CHUNK):
                sub = idxs[s2:s2 + _CHUNK]
                try:
                    a2 = _ask([states_all[i] for i in sub], sub, api_key,
                              base_url, model, timeout)
                    if isinstance(a2, dict):
                        answers.update(a2)
                except Exception as e2:
                    errors.append(f"chunk {sub[0]}-{sub[-1]}: {e2}")
    if not answers:
        return {"status": "error",
                "reason": "; ".join(errors)[:500] or "no_answers"}
    verdicts = {}
    for i in range(n):
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
    # Campo ADITIVO (dataset Fase F): las answers crudas de Jev por indice
    # global, con claves f{gi}_class/_sev/_act tal cual el API. No cambia
    # ninguna clave existente del contrato.
    raw = {str(i): {k: v for k, v in answers.items()
                    if k.startswith(f"f{i}_")}
           for i in range(n)}
    missing = [i for i in range(n) if f"f{i}_class" not in answers]
    return {"status": "ok", "model": model, "count": n,
            "partial": bool(missing), "verdicts": verdicts, "raw": raw}
