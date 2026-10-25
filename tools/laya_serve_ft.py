# -*- coding: utf-8 -*-
"""Arranca laya-serve sirviendo el checkpoint LAYA fine-tuned como 'multilingual'.

Motivo: el registro de modelos de laya (router.DEFAULT_MODELS) solo acepta los
nombres english / multilingual / typed-decisions; no se puede pasar una ruta
local por LAYA_MODELS. Pero Router acepta un mapa models={"multilingual": <ruta>}
y Agent soporta rutas locales. Este lanzador inyecta ese Router en
laya.serve.create_app (que reutiliza TODO el servidor: /health, /v1/systemone,
/v1/systemone/batch, auth bearer, limites).

Uso:
    C:\\Users\\Sammi\\laya-env\\Scripts\\python.exe tools\\laya_serve_ft.py
Env opcional:
    LAYA_FT_CHECKPOINT  ruta del checkpoint fine-tuned (por defecto la de Kaggle)
    LAYA_HOST / LAYA_PORT (default 127.0.0.1:8787)
La API key se toma de data/laya_serve.env (LAYA_API_KEY), igual que el cliente.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "data" / "laya_serve.env"
CKPT = os.environ.get(
    "LAYA_FT_CHECKPOINT",
    r"C:\Users\Sammi\AI\laya-checkpoints\ft-multilingual-2026-10-04\laya_finetuned_typed_decisions",
)

# Cargar data/laya_serve.env (LAYA_API_KEY, LAYA_HOST, LAYA_PORT, LAYA_DEVICE...).
if ENV.exists():
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

os.environ.setdefault("LAYA_DEVICE", "cpu")

from laya.router import Router  # noqa: E402
from laya.serve import create_app  # noqa: E402


def build():
    if not os.path.isdir(CKPT):
        raise SystemExit("checkpoint no encontrado: %s" % CKPT)
    router = Router(
        models={"multilingual": CKPT},
        device=os.environ.get("LAYA_DEVICE", "cpu"),
        default="multilingual",
        preload=False,
        auto_task_detection=False,
    )
    # Precarga solo multilingual (el fine-tuned). No descarga los otros checkpoints.
    router.preload(["multilingual"])
    return create_app(router)


def main() -> None:
    import uvicorn

    app = build()
    host = os.environ.get("LAYA_HOST", "127.0.0.1")
    port = int(os.environ.get("LAYA_PORT", "8787"))
    print("laya-serve FT | checkpoint=%s | %s:%d" % (CKPT, host, port), flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
