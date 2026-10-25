#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""apply_corrections.py — aplica data/finetune/correcciones.jsonl al dataset.

correcciones.jsonl (52 propuestas de la curaduria) tiene el campo libre 'cambiar'
(p. ej. "gold f*_class: choice -> expected_ai_use ... nivel 1"). Este script lo
convierte en un mapeo estructurado event_id -> {class, sev} y lo aplica sobre
data/finetune/jev_raw.jsonl (override del veredicto raw de Jev), con backup, y
regenera cases.jsonl.

El cambio es de ETIQUETA (unificar el patron HF y los casos puntuales que Jev
etiqueto de forma inconsistente). Se usa one-hot en las probabilidades: la
correccion es una decision humana, no una probabilidad.

Uso
    .venv/Scripts/python.exe tools/apply_corrections.py --dry-run
    .venv/Scripts/python.exe tools/apply_corrections.py            # aplica + backup + regenera cases.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

FINETUNE = Path(__file__).resolve().parent.parent / "data" / "finetune"
CORRECCIONES = FINETUNE / "correcciones.jsonl"
JEV_RAW = FINETUNE / "jev_raw.jsonl"
CASES = FINETUNE / "cases.jsonl"

CLASS_LABELS = ("expected_ai_use", "background_exfil_suspect",
                "telemetry_noise", "unrelated")
SEV_LEVELS = ("0", "1", "2", "3")

_RE_CLASS = re.compile(r"->\s*(expected_ai_use|background_exfil_suspect|telemetry_noise|unrelated)")
_RE_SEV = re.compile(r"nivel\s*(\d+)")


def parse_corrections() -> dict[int, dict]:
    """Lee correcciones.jsonl y devuelve {event_id: {class?, sev?}}."""
    out: dict[int, dict] = {}
    for line in CORRECCIONES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        eid = int(d["event_id"])
        change = str(d.get("cambiar") or "")
        entry: dict = {}
        m = _RE_CLASS.search(change)
        if m:
            entry["class"] = m.group(1)
        m = _RE_SEV.search(change)
        if m:
            level = int(m.group(1))
            if 0 <= level <= 3:
                entry["sev"] = level
        if entry:
            out.setdefault(eid, {}).update(entry)
    return out


def find_key(obj: dict, suffix: str) -> str | None:
    for k in obj:
        if k.endswith(suffix):
            return k
    return None


def one_hot_class(target: str) -> dict:
    return {label: (1.0 if label == target else 0.0) for label in CLASS_LABELS}


def one_hot_sev(level: int) -> dict:
    return {str(i): (1.0 if i == level else 0.0) for i in range(4)}


def apply_to_line(line: dict, entry: dict) -> tuple[dict, list[str]]:
    """Aplica la correccion a una linea de jev_raw.jsonl. Devuelve (linea, cambios)."""
    raw = line.get("raw") or {}
    cambios: list[str] = []
    if "class" in entry:
        k = find_key(raw, "_class")
        if k and isinstance(raw.get(k), dict):
            raw[k]["choice"] = entry["class"]
            raw[k]["probabilities"] = one_hot_class(entry["class"])
            raw[k]["confidence"] = 1.0
            cambios.append(f"class -> {entry['class']}")
    if "sev" in entry:
        k = find_key(raw, "_sev")
        if k and isinstance(raw.get(k), dict):
            raw[k]["score"] = float(entry["sev"])
            raw[k]["probabilities"] = one_hot_sev(entry["sev"])
            raw[k]["confidence"] = 1.0
            cambios.append(f"sev -> {entry['sev']}")
    if cambios:
        line["raw"] = raw
    return line, cambios


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    corr = parse_corrections()
    print(f"correcciones parseadas: {len(corr)} eventos")

    lines = [json.loads(x) for x in JEV_RAW.read_text(encoding="utf-8").splitlines()
             if x.strip()]
    changes: dict[int, list[str]] = {}
    for line in lines:
        eid = int(line.get("event_id"))
        if eid in corr:
            _, c = apply_to_line(line, corr[eid])
            if c:
                changes[eid] = c

    print(f"eventos a cambiar: {len(changes)} de {len(lines)}")
    for eid, c in sorted(changes.items()):
        print(f"  {eid}: {', '.join(c)}")

    if a.dry_run:
        print("dry-run: sin cambios en disco.")
        return

    # Backup con timestamp.
    bak = JEV_RAW.with_name(f"jev_raw.jsonl.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(JEV_RAW, bak)
    print(f"backup: {bak}")

    JEV_RAW.write_text(
        "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines),
        encoding="utf-8",
    )

    # Regenerar cases.jsonl con el script existente.
    print("regenerando cases.jsonl (tools/raw_to_cases.py) ...")
    r = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "raw_to_cases.py")],
                       capture_output=True, text=True, timeout=300)
    print(r.stdout[-800:] if r.stdout else "")
    if r.stderr:
        print("stderr:", r.stderr[-500:])
    print(f"cases.jsonl: {CASES.stat().st_size} bytes, "
          f"{sum(1 for _ in CASES.open(encoding='utf-8'))} lineas")


if __name__ == "__main__":
    main()
