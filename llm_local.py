"""LLM local (OpenAI-compatible, SOLO loopback) para explicaciones tecnicas
en espanol de los eventos marcados por Jev. Sin API key. Fail-safe.
"""
from __future__ import annotations

import json
import socket
from urllib import parse, request as urlrequest

MAX_EXPLAIN = 10


def is_loopback_url(url: str) -> bool:
    try:
        host = parse.urlparse(url).hostname or ""
    except Exception:
        return False
    if host in ("localhost", "::1"):
        return True
    if host == "127.0.0.1":
        return True
    try:
        return socket.gethostbyname(host) == "127.0.0.1"
    except Exception:
        return False


def _chat(base_url: str, model: str, system: str, user: str, timeout: int = 120) -> str:
    url = base_url.rstrip("/") + "/v1/chat/completions"
    body = {
        "model": model,
        "temperature": 0,
        "max_tokens": 2048,
        "reasoning_effort": "low",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    req = urlrequest.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return (data.get("choices") or [{}])[0].get("message", {}).get("content", "")


def _parse_json(content: str) -> dict | None:
    txt = (content or "").strip()
    if txt.startswith("```"):
        txt = txt.strip("`")
        txt = txt[txt.find("\n") + 1:] if "\n" in txt else txt
        txt = txt[: txt.rfind("```")] if "```" in txt else txt
    try:
        d = json.loads(txt)
        return d if isinstance(d, dict) else None
    except json.JSONDecodeError:
        return None


def explain_events(base_url: str, model: str, events: list[dict],
                   verdicts: dict | None = None) -> list[dict]:
    """Explicaciones tecnicas (espanol) de hasta MAX_EXPLAIN eventos.

    Orden: primero los con severity_score mayor o sin veredicto Jev.
    """
    if not base_url or not model or not events:
        return []
    if not is_loopback_url(base_url):
        return [{"status": "unavailable", "reason": "not_loopback"}]

    def _sev(i: int) -> float:
        s = ((verdicts or {}).get(str(i)) or {}).get("severity_score")
        return float(s) if isinstance(s, (int, float)) else -1.0

    ranked = sorted(range(len(events)), key=_sev, reverse=True)[:MAX_EXPLAIN]
    out: list[dict] = []
    for i in ranked:
        e = events[i]
        v = (verdicts or {}).get(str(i)) or {}
        try:
            content = _chat(
                base_url, model,
                "Eres un tecnico senior de ciberseguridad. Explica en espanol,"
                " de forma breve y precisa, el evento de red a nube AI que se"
                " describe. Responde SOLO con JSON estricto {resumen, porque,"
                " sugerencia} (max 60 palabras por campo).",
                json.dumps({
                    "evento": {
                        "proceso": e.get("process"),
                        "destino": f"{e.get('dest_host') or e.get('dest_ip')}:{e.get('dest_port')}",
                        "catalogo": e.get("catalog_domain"),
                        "veces_vistas": e.get("seen_count"),
                        "primera_vez": e.get("first_seen"),
                        "ultima_vez": e.get("last_seen"),
                    },
                    "jev": {
                        "veredicto": v.get("verdict"),
                        "confianza": v.get("confidence"),
                        "criticidad": v.get("severity_score"),
                        "accion_inmediata": v.get("immediate_action"),
                    },
                }, ensure_ascii=False),
            )
        except Exception as ex:
            out.append({"process": e.get("process"), "dest": str(e.get("dest_ip")),
                        "status": "unavailable", "reason": str(ex)[:120]})
            continue
        d = _parse_json(content)
        if not d or not all(k in d for k in ("resumen", "porque", "sugerencia")):
            out.append({"process": e.get("process"), "dest": str(e.get("dest_ip")),
                        "status": "unavailable", "reason": "bad_json"})
            continue
        out.append({
            "process": e.get("process"),
            "dest": f"{e.get('dest_host') or e.get('dest_ip')}:{e.get('dest_port')}",
            "status": "ok",
            "resumen": str(d["resumen"])[:400],
            "porque": str(d["porque"])[:400],
            "sugerencia": str(d["sugerencia"])[:400],
        })
    return out
