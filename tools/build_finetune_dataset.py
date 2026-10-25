"""Construye el dataset de finetuning (Fase F) RE-PREGUNTANDO a Jev.

Uso:  py -3.12 tools/build_finetune_dataset.py [--limit 200] [--force]

- Carga hasta --limit eventos de data/events.db con la misma muestra
  determinista que compare_backends (_load_events): con --limit 50 son
  exactamente los mismos 50 del compare. Acotado a 200 por seguridad de
  coste (llamadas NUEVAS a Jev <= 200 eventos).
- Construye el state con jev_triage._state_for y las preguntas con
  jev_triage._questions_for, llama a Jev en lotes de TRIAGE_CAP (50)
  con fallback por trozos de _CHUNK (10), igual que el triaje.
- Guarda la respuesta CRUDA COMPLETA por evento en data/finetune/jev_raw.jsonl:
  una linea JSON {event_id, ts, state, questions, raw} donde `raw` son las
  answers crudas de Jev (f{gi}_class/_sev/_act) con probabilities y noul.
- Dedup por event_id: no re-gasta Jev en eventos ya capturados (re-ejecutar
  el script es barato; --force para reconstruir desde cero).
- La API key sale de data/config.json (jev_api_key, prefijo dpapi:) via
  secret_store.unprotect; NUNCA se imprime ni persiste en claro.

Coste: solo eventos nuevos (dedup); cada llamada batch cubre 50 eventos.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import jev_triage  # noqa: E402
from compare_backends import _jev_api_key, _load_events  # noqa: E402

RAW_PATH = ROOT / "data" / "finetune" / "jev_raw.jsonl"
MAX_EVENTS = 200  # acote de llamadas NUEVAS a Jev (coste)


def _existing_ids(path: Path) -> set[int]:
    if not path.exists():
        return set()
    out: set[int] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.add(int(json.loads(line)["event_id"]))
        except Exception:
            continue
    return out


def _ask_batches(states: list[dict], key: str, base_url: str,
                 model: str) -> dict:
    """Mismo batching que triage_events (lotes de TRIAGE_CAP, fallback
    por trozos de _CHUNK), pero devuelve las answers crudas tal cual."""
    answers: dict = {}
    n = len(states)
    for start in range(0, n, jev_triage.TRIAGE_CAP):
        idxs = list(range(start, min(start + jev_triage.TRIAGE_CAP, n)))
        try:
            a = jev_triage._ask([states[i] for i in idxs], idxs, key,
                                base_url, model, 30)
            if isinstance(a, dict):
                answers.update(a)
                continue
        except Exception as e:
            print(f"[aviso] lote {idxs[0]}-{idxs[-1]}: {e}")
        for s2 in range(0, len(idxs), jev_triage._CHUNK):
            sub = idxs[s2:s2 + jev_triage._CHUNK]
            try:
                a2 = jev_triage._ask([states[i] for i in sub], sub, key,
                                     base_url, model, 30)
                if isinstance(a2, dict):
                    answers.update(a2)
            except Exception as e2:
                print(f"[aviso] chunk {sub[0]}-{sub[-1]}: {e2}")
    return answers


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=200,
                    help="eventos de la muestra (acotado a 200)")
    ap.add_argument("--force", action="store_true",
                    help="re-pregunta a Jev incluso los eventos ya capturados")
    args = ap.parse_args()
    limit = min(max(args.limit, 1), MAX_EVENTS)

    key = _jev_api_key()
    if not key:
        print("sin key Jev en data/config.json; aborta (no gasto nada).")
        return 1

    events = _load_events(limit)
    states = [jev_triage._state_for(e) for e in events]
    existing = set() if args.force else _existing_ids(RAW_PATH)
    todo = [(i, e) for i, e in enumerate(events) if int(e["id"]) not in existing]
    skipped = len(events) - len(todo)
    if not todo:
        print(f"[dedup] {limit} eventos ya capturados; nada que hacer "
              "(usa --force).")
        return 0

    print(f"[info] {len(todo)} eventos nuevos (skipped existentes: "
          f"{skipped}); llamando a Jev en lotes de {jev_triage.TRIAGE_CAP}...")
    # La lista preguntada se numera 0..M-1 (como el triaje live): las claves
    # f{pos}_* de `raw` y `questions` usan ese indice; el event_id real va
    # en su campo propio.
    answers = _ask_batches([states[i] for i, _ in todo], key,
                           jev_triage._BACKENDS["cloud"]["base_url"],
                           jev_triage._BACKENDS["cloud"]["model"])

    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with RAW_PATH.open("a", encoding="utf-8") as f:
        for pos, (i, e) in enumerate(todo):
            raw_ev = {k: v for k, v in answers.items()
                      if k.startswith(f"f{pos}_")}
            rec = {"event_id": int(e["id"]), "ts": e.get("ts"),
                   "state": states[i],
                   "questions": jev_triage._questions_for(pos),
                   "raw": raw_ev}
            if not raw_ev:
                print(f"[aviso] evento {e['id']}: sin respuesta cruda; omitido")
                continue
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1
    print(f"[ok] {RAW_PATH} (+{written} lineas nuevas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
