"""Clasificador de destinos IA en 3 capas (R1 - cobertura universal).

Solo stdlib. Filosofia: clasificar por evidencia, no por heuristica sola.

Capa 1 (catalogo): evidencia directa. El dominio esta en el catalogo ->
    proveedor conocido, confianza 1.0. Es la capa que "afirma".
Capa 2 (heuristica): senal de revision, NO evidencia. Token IA/TLD .ai en
    el dominio. Confianza 0.5. Sirve para que un proveedor/SDK no listado se
    vea ("sin clasificar" nunca se oculta), pero no se afirma como verdad.
Capa 3 (LLM local): opcional, inyectado (`llm_fn(dom)->bool|None`), con cache
    por dominio y fail-safe (un fallo del clasificador nunca rompe el monitor).
    Confianza 0.8. No corre en el bucle caliente; se usa bajo demanda.

Un dominio que no cae en ninguna capa queda "sin clasificar" (is_ai=False,
layer="unlisted"): visible para el usuario, nunca descartado en silencio.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ai_catalog import match_domain


@dataclass(frozen=True)
class Classification:
    domain: str
    is_ai: bool
    layer: str            # "catalog" | "heuristic" | "llm" | "unlisted"
    provider: str | None  # dominio del catalogo si capa 1; None en resto
    confidence: float     # 0.0..1.0
    reason: str


# Capa 2: tokens de dominio claramente IA (senal, no evidencia).
_AI_TOKENS: tuple[str, ...] = (
    "openai", "anthropic", "llm", "gpt", "genai", "inference", "copilot",
    "mistral", "groq", "cohere", "huggingface", "deepseek", "together",
    "replicate", "perplexity", "stability", "cerebras", "fireworks",
    "sambacloud", "openrouter", "ollama", "lmstudio",
)
# TLD que por si solo es senal fuerte de IA.
_AI_TLDS: tuple[str, ...] = (".ai",)


def _heuristic(domain: str) -> tuple[bool, str]:
    d = domain.lower()
    for tok in _AI_TOKENS:
        if tok in d:
            return True, f"token IA '{tok}' en el dominio"
    for tld in _AI_TLDS:
        if d.endswith(tld):
            return True, "TLD .ai"
    return False, ""


def classify_domain(domain, llm_fn=None, cache=None) -> Classification:
    """Clasifica un dominio en 3 capas (catalogo -> heuristica -> LLM).

    `llm_fn(dom)->bool|None` es opcional; si se da y las capas 1-2 no decidieron,
    se consulta al LLM local (cache por dominio, fail-safe a False).
    """
    d = (domain or "").strip().lower().split(":", 1)[0]
    if not d:
        return Classification("", False, "unlisted", None, 0.0,
                              "dominio vacio")

    # Capa 1: catalogo (evidencia directa).
    cat = match_domain(d)
    if cat:
        return Classification(d, True, "catalog", cat, 1.0,
                              f"en el catalogo ({cat})")

    # Capa 2: heuristica (senal de revision).
    hit, why = _heuristic(d)
    if hit:
        return Classification(d, True, "heuristic", None, 0.5,
                              f"heuristica: {why}")

    # Capa 3: LLM local opcional (con cache por dominio, fail-safe).
    if llm_fn is not None:
        verdict = cache.get(d) if cache is not None else None
        if verdict is None:
            try:
                verdict = bool(llm_fn(d))
            except Exception:
                verdict = False  # el clasificador nunca rompe al monitor
            if cache is not None:
                cache[d] = verdict
        if verdict:
            return Classification(d, True, "llm", None, 0.8,
                                  "clasificado por LLM local")

    return Classification(d, False, "unlisted", None, 0.0, "sin clasificar")


def is_ai(domain, llm_fn=None, cache=None) -> bool:
    """Atajo booleano de `classify_domain`."""
    return classify_domain(domain, llm_fn=llm_fn, cache=cache).is_ai


# v2.3: marcadores de hostname para el label API/web/CDN (heuristica de
# display; no afecta deteccion ni aprobaciones).
_CDN_MARKERS: tuple[str, ...] = (
    "cloudfront.net", "akamai", "fastly.net", "cloudflare",
    "edgekey.net", "cdn.",
)


def destination_kind(host: str) -> str:
    """v2.3 label de display por hostname: 'api' | 'web' | 'cdn' | ''.

    Heuristica documentada (NO evidencia, no toca deteccion/aprobaciones):
    - 'cdn': hostname de CDN (cloudfront/akamai/fastly/cloudflare/edgekey/cdn).
    - 'api': subdominio 'api.*' o TLD .ai.
    - 'web': cualquier otro hostname resuelto (apex, sitio web, descargas).
    - '': IP cruda, vacio o no clasificable. Degrada a vacio, nunca inventa.
    """
    h = str(host or "").strip().lower()
    if not h or ":" in h:
        return ""
    try:
        ipaddress.ip_address(h)  # IP pura (v4/v6): sin etiqueta.
        return ""
    except ValueError:
        pass
    if any(mk in h for mk in _CDN_MARKERS):
        return "cdn"
    labels = [l for l in h.split(".") if l]
    if "api" in labels:
        return "api"
    if len(labels) >= 2 and labels[-1] == "ai":
        return "api"
    return "web"
