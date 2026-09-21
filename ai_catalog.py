"""Catálogo de destinos cloud AI y heurística de procesos.

Solo stdlib. El catálogo es una lista plana de dominios (sin subdominios:
el match usa sufijo de dominio). Los hosts extra los añade el usuario en
config (solo memoria) para vigilar destinos propios.
"""
from __future__ import annotations

# Dominios cloud AI conocidos (v1). El match es por sufijo de dominio.
KNOWN_AI_DOMAINS: tuple[str, ...] = (
    # OpenAI / Microsoft
    "openai.com", "azure.ai", "azure-usgov.com", "cognitiveservices.azure.com",
    # Anthropic
    "anthropic.com",
    # Google
    "googleapis.com", "generativelanguage.googleapis.com",
    # TypeSafe (Jev)
    "typesafe.ai",
    # Otros proveedores LLM
    "groq.com", "openrouter.ai", "mistral.ai", "cohere.com", "huggingface.co",
    "deepseek.com", "x.ai", "together.ai", "replicate.com", "perplexity.ai",
    "stability.ai", "fireworks.ai", "cerebras.ai", "sambacloud.ai",
)

# Procesos que, aunque el destino no esté en el catálogo, son clientes IA
# evidentes (heurística secundaria; v1 solo la registra, no dispara sola).
AI_PROCESS_HINTS: tuple[str, ...] = (
    "ollama", "llama-server", "llama-cli", "lmstudio", "chatbox", "cherry-studio",
)


def match_domain(host: str) -> str | None:
    """Devuelve el dominio del catálogo que coincide con `host`, o None.

    Acepta hosts con puerto ("example.com:443") y con subdominios.
    """
    h = (host or "").strip().lower().split(":", 1)[0].lstrip("[").rstrip("]")
    if not h:
        return None
    for dom in KNOWN_AI_DOMAINS:
        if h == dom or h.endswith("." + dom):
            return dom
    return None


def process_hint(name: str) -> bool:
    n = (name or "").lower()
    return any(h in n for h in AI_PROCESS_HINTS)
