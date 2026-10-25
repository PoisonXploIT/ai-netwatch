"""Convierte data/finetune/jev_raw.jsonl en data/finetune/cases.jsonl.

Formato del notebook de laya (una linea por caso):
    {"state": <dict _state_for>, "questions": {...}, "gold": {...}}

- questions: plantilla canonica de UN evento (claves f0_class/f0_sev/f0_act,
  via jev_triage._questions_for(0)): el state de cada caso es un documento
  unico, asi que el indice por lote del raw no aplica.
- gold: keyed por id de pregunta, con el objetivo SUAVE tal cual Jev, en el
  formato que consume el notebook/script de finetuning de laya
  (`gold[qid]["probabilities"]`):
    - f0_class -> {"probabilities": {label -> prob}} de la respuesta choice
    - f0_sev   -> {"probabilities": {"0".."3" -> prob}} de la respuesta score
    - f0_act   -> {"probabilities": {"false": 1-P(true), "true": P(true)}}
      (jev_triage: noul = P(true); immediate_action = yes si noul >= 0.5)

No llama a ningun backend: es una conversion local del crudo capturado.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import jev_triage  # noqa: E402

RAW_PATH = ROOT / "data" / "finetune" / "jev_raw.jsonl"
CASES_PATH = ROOT / "data" / "finetune" / "cases.jsonl"


def _pick(raw: dict, suffix: str) -> dict | None:
    """La answer cruda cuyo id termina en `suffix` (fN_class, f0_class...)."""
    for k, v in raw.items():
        if k.endswith(suffix) and isinstance(v, dict):
            return v
    return None


def to_case(rec: dict) -> dict | None:
    """Una linea de jev_raw.jsonl -> caso {state, questions, gold} o None."""
    state = rec.get("state")
    raw = rec.get("raw") or {}
    if not isinstance(state, dict) or not isinstance(raw, dict):
        return None
    cls = _pick(raw, "_class")
    sev = _pick(raw, "_sev")
    act = _pick(raw, "_act")
    probs_cls = (cls or {}).get("probabilities")
    probs_sev = (sev or {}).get("probabilities")
    noul = (act or {}).get("noul")
    if not isinstance(probs_cls, dict) or not isinstance(noul, (int, float)):
        return None
    gold: dict = {
        "f0_class": {"probabilities": probs_cls},
        "f0_act": {"probabilities": {"false": 1.0 - float(noul),
                                     "true": float(noul)}},
    }
    if isinstance(probs_sev, dict):
        gold["f0_sev"] = {"probabilities": probs_sev}
    return {"state": state, "questions": jev_triage._questions_for(0),
            "gold": gold}


def main() -> int:
    if not RAW_PATH.exists():
        print(f"falta {RAW_PATH}; primero ejecuta build_finetune_dataset.py")
        return 1
    n = ok = bad = 0
    lines: list[str] = []
    for line in RAW_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            rec = json.loads(line)
        except Exception:
            bad += 1
            continue
        case = to_case(rec)
        if case is None:
            bad += 1
            continue
        lines.append(json.dumps(case, ensure_ascii=False))
        ok += 1
    CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
    CASES_PATH.write_text("\n".join(lines) + ("\n" if lines else ""),
                          encoding="utf-8")
    print(f"[ok] {CASES_PATH} ({ok} casos; {bad} descartados de {n} lineas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
