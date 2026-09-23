"""Clasificador automatico (v2.0): el LLM local rellena las incognitas 0.5.

NO corre en el hilo del monitor (una llamada LLM lenta no bloquearia el
poll de 5 s): job periodico en el server con rate-limit, cache persistente
por dominio (tabla domain_classifications) y fail-safe total.

Capas: el catalogo (1.0) siempre gana; aqui solo se tocan dominios
heuristic (0.5). Sin LLM local configurado es no-op: los dominios quedan
en 0.5, visibles, nunca ocultos.
"""
from __future__ import annotations

import json
import re
import time

from llm_local import _chat

CATEGORIES = ("chat", "embeddings", "images", "audio", "other")

SYSTEM_PROMPT = (
    "Clasificas dominios de red para un monitor de egress IA. Responde SOLO"
    " con un objeto JSON valido, sin markdown ni texto adicional:\n"
    '{"is_ai": true|false, "provider": "nombre o null", '
    '"category": "chat"|"embeddings"|"images"|"audio"|"other",'
    ' "confidence": 0.0-1.0}\n\n'
    "Criterios contrastivos:\n"
    "- is_ai=true si el dominio sirve (o es muy probable que sirva)"
    " inferencia o generacion de IA: APIs de chat/completions, gateways de"
    " inferencia, endpoints de embeddings, servicios de imagen/voz con IA.\n"
    "- is_ai=false si no hay evidencia de IA aunque el nombre suene tech:"
    " CDNs genericos, hosting, analytics sin IA, SaaS corporativo normal.\n"
    '- "provider": el proveedor mas probable ("openai", "mistral", ...)'
    ' o null.\n'
    '- "category": chat (completions/chat), embeddings, images, audio,'
    ' other (IA pero otro uso).\n'
    "- confidence: tu confianza 0.0-1.0; si solo adivinas por el nombre,"
    " maximo 0.6.\n\n"
    "Ejemplos:\n"
    '- api.openai.com -> {"is_ai": true, "provider": "openai",'
    ' "category": "chat", "confidence": 1.0}\n'
    '- embed.cohere.ai -> {"is_ai": true, "provider": "cohere",'
    ' "category": "embeddings", "confidence": 0.9}\n'
    '- cdn.example-corp.com -> {"is_ai": false, "provider": null,'
    ' "category": "other", "confidence": 0.8}'
)


def parse_verdict(text: str | None) -> dict | None:
    """Extrae el veredicto JSON estricto; None si no se interpreta.

    Leniente con markdown (vuelve a intentarlo sin fences), estricto con el
    contenido: sin "is_ai" no hay veredicto.
    """
    if not text:
        return None
    t = re.sub(r"```[a-zA-Z]*", "", text)  # fences de markdown
    m = re.search(r"\{.*\}", t, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "is_ai" not in data:
        return None
    cat = str(data.get("category") or "other").lower()
    if cat not in CATEGORIES:
        cat = "other"
    try:
        conf = float(data.get("confidence", 0.8))
    except (TypeError, ValueError):
        conf = 0.8
    provider = str(data.get("provider") or "").strip().lower() or None
    return {
        "is_ai": bool(data["is_ai"]),
        "provider": provider,
        "category": cat,
        "confidence": round(max(0.0, min(1.0, conf)), 2),
    }


def classify_domain_llm(base_url: str, model: str, domain: str,
                        context: str = "") -> dict | None:
    """Pregunta al LLM local por un dominio. Lanza si el LLM no responde;
    devuelve None si responde pero no se interpreta."""
    ctx = f"Proceso que lo consulto: {context}\n" if context else ""
    user = f"{ctx}Dominio a clasificar: {domain}"
    raw = _chat(base_url, model, SYSTEM_PROMPT, user, timeout=60)
    return parse_verdict(raw)


def run_cycle(store, base_url: str, model: str, limit: int = 5,
              min_interval_s: float = 10.0, ttl_days: int = 30) -> list[dict]:
    """Clasifica hasta `limit` dominios heuristic pendientes (FIFO por
    recencia). Rate-limit entre dominios; backoff simple: si el LLM falla,
    corta el ciclo y el siguiente reintenta. Fail-safe: nunca lanza."""
    out: list[dict] = []
    for dom in store.pending_heuristic_domains(limit=limit, ttl_days=ttl_days):
        try:
            v = classify_domain_llm(
                base_url, model, dom, context=store.process_for_domain(dom) or "")
        except Exception:
            break  # LLM caido/tiempo agotado: no seguir golpeando
        if v is None:
            continue  # respuesta ininterpretable: no se asume nada
        store.upsert_classification(
            dom, v["is_ai"], v["provider"], v["category"],
            v["confidence"], "llm")
        # El catalogo nunca se pisa; solo 'heuristic' -> 'llm'.
        store.apply_classification_layer(dom, "llm")
        out.append({"domain": dom, **v})
        if min_interval_s:
            time.sleep(min_interval_s)  # rate-limit entre dominios
    return out
