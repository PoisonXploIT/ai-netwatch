"""v2.3: Fingerprinting de SDK IA por proceso + artefactos (sin TLS).

Senal primaria: que runtime es el proceso (python/node) y que SDKs de IA
tiene instalados en su arbol (site-packages / node_modules). Identifica
el cliente IA SIN depender del dominio destino.

Label de display: alimenta la ficha del proceso; NO toca deteccion ni
aprobaciones. Degrada honestamente: sin artefacto verificable, None —
nunca inventa.

JA3/JA4 (huella de red) queda fuera a proposito: tshark captura el
ClientHello, pero la huella TLS se comparte con navegadores y runtimes;
solo seria confirmacion, no prueba, y exige parsear TLS que stdlib no da.
"""
from __future__ import annotations

import os
from pathlib import Path

# Nombres de proceso que son runtime IA (sin mayusculas).
RUNTIME_NAMES: frozenset[str] = frozenset(
    {"python.exe", "pythonw.exe", "node.exe"})

# Directorios top-level en site-packages que marcan un SDK IA (Python) ->
# etiqueta canonica. Solo nombres inequivocos; nada generico ("google").
_PY_SDK_DIRS: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "cohere": "cohere",
    "groq": "groq",
    "mistralai": "mistralai",
    "together": "together",
    "replicate": "replicate",
    "huggingface_hub": "huggingface-hub",
    "litellm": "litellm",
    "ollama": "ollama",
    "llama_index": "llama-index",
    "langchain_core": "langchain",
    "langchain": "langchain",
    "autogen": "autogen",
}

# Directorios top-level o scoped en node_modules que marcan un SDK IA.
_NODE_SDK_DIRS: dict[str, str] = {
    "openai": "openai",
    "@anthropic-ai": "@anthropic-ai/sdk",
    "@langchain": "@langchain/*",
    "@cohere-ai": "@cohere-ai/sdk",
    "@mistralai": "@mistralai/*",
    "groq-sdk": "groq-sdk",
    "ollama": "ollama",
}

_PY_RUNTIME_NAMES = {"python.exe", "pythonw.exe"}
_NODE_RUNTIME_NAMES = {"node.exe", "node"}


def _site_dirs(exe: Path) -> list[Path]:
    """Candidatos de site-packages para un python.exe en `exe`.

    Layout venv: <root>/Scripts/python.exe -> <root>/Lib/site-packages.
    Layout sistema: <install>/python.exe -> <install>/Lib/site-packages."""
    base = exe.parent
    if base.name.lower() in ("scripts", "bin"):
        base = base.parent
    return [base / "Lib" / "site-packages", base / "lib" / "site-packages"]


def _node_module_dirs(exe: Path) -> list[Path]:
    """Candidatos de node_modules para un node.exe en `exe` (local y
    global por usuario via %APPDATA%\\npm)."""
    out = [exe.parent / "node_modules"]
    appdata = os.environ.get("APPDATA") or ""
    if appdata:
        out.append(Path(appdata) / "npm" / "node_modules")
    return out


def _sdks_in(dirs: list[Path], table: dict[str, str]) -> list[str]:
    """SDKs del `table` presentes en alguno de los `dirs` (ordenados)."""
    found: list[str] = []
    for d in dirs:
        try:
            if not d.is_dir():
                continue
            names = {p.name for p in d.iterdir()}
        except OSError:
            continue
        for name, label in table.items():
            if name in names and label not in found:
                found.append(label)
    return sorted(found)


def _is_venv(exe: Path) -> bool:
    """Heuristica de ruta: alguna parte del path marca un virtualenv."""
    parts = [p.lower() for p in exe.parts]
    return any(p in (".venv", "venv", "virtualenv") or p.startswith(".venv-")
               for p in parts[:-1])


def _exe_from_cmdline(cmdline: str) -> str:
    """Primer token de una command line (con o sin comillas)."""
    c = str(cmdline or "").strip()
    if not c:
        return ""
    if c[0] in "\"'":
        q = c[0]
        end = c.find(q, 1)
        return c[1:end] if end > 0 else ""
    toks = c.split()
    return toks[0] if toks else ""


def _fp_python(exe: Path | None) -> dict | None:
    if exe is None:
        return None
    sdks = _sdks_in(_site_dirs(exe), _PY_SDK_DIRS)
    if not sdks:
        return None  # sin artefacto verificable: no se afirma nada
    return {"runtime": "python", "venv": _is_venv(exe), "sdks": sdks,
            "label": f"python-sdk({', '.join(sdks)})"}


def _fp_node(exe: Path | None) -> dict | None:
    if exe is None:
        return None
    sdks = _sdks_in(_node_module_dirs(exe), _NODE_SDK_DIRS)
    if not sdks:
        return None
    return {"runtime": "node", "venv": None, "sdks": sdks,
            "label": f"node-sdk({', '.join(sdks)})"}


def fingerprint_process(name: str, exe_path: str = "",
                        cmdline: str = "") -> dict | None:
    """Fingerprint de SDK IA para un proceso.

    name: nombre del proceso (python.exe / node.exe). exe_path: ruta
    completa de la imagen; si viene vacia se intenta extraer de cmdline.
    Devuelve {"runtime","venv","sdks","label"} o None si no hay artefacto
    verificable (display-only; nunca afecta deteccion ni aprobaciones).
    """
    n = str(name or "").strip().lower()
    raw_exe = str(exe_path or "").strip()
    exe: Path | None = Path(raw_exe) if raw_exe else None
    if exe is None and cmdline:
        cand = _exe_from_cmdline(str(cmdline))
        if cand.lower().endswith(("python.exe", "pythonw.exe",
                                  "node.exe")):
            exe = Path(cand)
    if n in _PY_RUNTIME_NAMES:
        return _fp_python(exe)
    if n in _NODE_RUNTIME_NAMES:
        return _fp_node(exe)
    return None
