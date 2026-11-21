"""Lectura de los ficheros estaticos para los tests de UI (v2.8, A-01).

El JavaScript de la consola se reparte en varios scripts clasicos. Los tests
los leen todos, unidos en el orden de carga de index.html, para que buscar un
texto no dependa del fichero en el que esta.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


def js_paths() -> list:
    """Scripts de la consola en orden de carga (sin theme.js, que va en el head)."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    srcs = re.findall(r'<script src="/static/([\w/.-]+\.js)\?v=\{\{ASSETV\}\}"></script>', html)
    return [STATIC / s for s in srcs if s != "theme.js"]


def read_js() -> str:
    """Todo el JavaScript de la consola, unido en orden de carga."""
    return "\n".join(p.read_text(encoding="utf-8") for p in js_paths())
