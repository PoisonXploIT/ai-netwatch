"""Harness A/B: Jeff (clasificador local :11434) vs gold de Jev.

Lee data/finetune/jev_raw.jsonl (217 eventos con las respuestas crudas de
Jev como gold) y, para cada evento, construye las 3 llamadas equivalentes a
Jeff POST /classify:

  fN_class -> choice: opciones = keys de criteria Jev (con su descripcion
                    'what'), pregunta = instrucciones Jev + state JSON.
  fN_sev   -> score : opciones = los 4 niveles 0-3 con sus descripciones;
                    el argmax de Jeff da el nivel entero, MAE contra el
                    score float de Jev (0-3).
  fN_act   -> noul  : opciones ["no accion inmediata", "accion inmediata"];
                    P(true) = probabilidad de la opcion 1, umbral 0.5, igual
                    que el gold noul de Jev.

Metricas contra el gold (Jev): acuerdo de verdict (argmax class), acuerdo de
accion (noul >= 0.5), MAE de severidad y distribuciones/confusion por opcion.

Uso:
  py -3.12 tools/jeff_ab.py --dry-run            # sin red: valida payloads
  py -3.12 tools/jeff_ab.py                     # contra Jeff en :11434
  py -3.12 tools/jeff_ab.py --limit 10          # solo los primeros 10
  py -3.12 tools/jeff_ab.py --jev               # (opcional) re-query Jev live

Salida: data/finetune/jeff_ab_results.json + resumen legible en stdout.
Privacidad: sin --jev no hay ninguna salida de red mas que a 127.0.0.1.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLD_PATH = ROOT / "data" / "finetune" / "jev_raw.jsonl"
OUT_PATH = ROOT / "data" / "finetune" / "jeff_ab_results.json"

DEFAULT_URL = "http://127.0.0.1:11434/classify"
MIN_OPTIONS, MAX_OPTIONS = 2, 26
ACTION_NO = "no accion inmediata"
ACTION_YES = "accion inmediata"


def _load_gold(limit: int | None) -> list[dict]:
    events = []
    with GOLD_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
            if limit is not None and len(events) >= limit:
                break
    return events


def _state_text(state: dict) -> str:
    return json.dumps(state, ensure_ascii=False)


def _question(instructions: str, state: dict) -> str:
    # Jev recibia el state como estructura aparte; Jeff solo tiene 'question',
    # asi que se inlina: instrucciones Jev + state JSON.
    return f"{instructions}\n\nState:\n{_state_text(state)}"


def _pick(ev: dict) -> tuple[dict, dict, dict]:
    """Encuentra fN_class/fN_sev/fN_act (el prefijo fN varia por batch)."""
    q = ev["questions"]
    class_q = next(v for k, v in q.items() if k.endswith("_class"))
    sev_q = next(v for k, v in q.items() if k.endswith("_sev"))
    act_q = next(v for k, v in q.items() if k.endswith("_act"))
    return class_q, sev_q, act_q


def _pick_raw(ev: dict) -> tuple[dict, dict, dict]:
    """Mismo para las respuestas crudas (gold) de Jev."""
    raw = ev["raw"]
    g_class = next(v for k, v in raw.items() if k.endswith("_class"))
    g_sev = next(v for k, v in raw.items() if k.endswith("_sev"))
    g_act = next(v for k, v in raw.items() if k.endswith("_act"))
    return g_class, g_sev, g_act


def _build_payloads(ev: dict) -> dict[str, dict]:
    """Los 3 payloads /classify por evento, con las mismas opciones que Jev."""
    state = ev["state"]
    out: dict[str, dict] = {}

    class_q, sev_q, act_q = _pick(ev)
    crit = class_q["criteria"]
    opts = []
    for key, val in crit.items():
        what = (val or {}).get("what") if isinstance(val, dict) else None
        opts.append(f"{key}: {what}" if what else str(key))
    out["class"] = {"question": _question(class_q["instructions"], state),
                    "options": opts}

    levels = list(sev_q["criteria"])
    out["sev"] = {"question": _question(sev_q["instructions"], state),
                 "options": [f"{i}: {desc}" for i, desc in enumerate(levels)]}

    out["act"] = {"question": _question(act_q["instructions"], state),
                 "options": [ACTION_NO, ACTION_YES]}
    return out


def _validate_payloads(payloads: dict[str, dict]) -> None:
    for name, p in payloads.items():
        opts = p["options"]
        if not (MIN_OPTIONS <= len(opts) <= MAX_OPTIONS):
            raise ValueError(f"{name}: {len(opts)} opciones fuera de "
                             f"rango {MIN_OPTIONS}..{MAX_OPTIONS}")
        if len(set(opts)) != len(opts):
            raise ValueError(f"{name}: opciones duplicadas")


def _post(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _norm_action(v) -> str | None:
    if isinstance(v, str):
        return v.strip().lower()
    try:
        return "yes" if float(v) >= 0.5 else "no"
    except (TypeError, ValueError):
        return None


def _run_jeff(payloads: dict[str, dict], url: str, timeout: int) -> dict:
    results = {}
    for name, p in payloads.items():
        t0 = time.monotonic()
        res = _post(url, p, timeout)
        dt_ms = (time.monotonic() - t0) * 1000.0
        results[name] = {"choice_index": int(res["choice_index"]),
                         "probabilities": [float(x) for x in res["probabilities"]],
                         "ms": round(dt_ms, 1)}
    return results


def _metrics(events: list[dict], jeff: dict[int, dict[str, dict]]) -> dict:
    """Metricas Jeff vs gold Jev por primitiva."""
    verdict_pairs: list[tuple[str | None, str | None]] = []   # (gold, jeff) keys class
    action_pairs: list[tuple[str | None, str | None]] = []   # (gold, jeff) yes/no
    sev_diffs: list[float] = []
    act_prob_diffs: list[float] = []
    confusion: dict[str, dict[str, int]] = {}
    per_event: list[dict] = []

    for ev in events:
        eid = ev.get("event_id")
        g_class, g_sev, g_act = _pick_raw(ev)
        class_q, _, _ = _pick(ev)
        crit_keys = list(class_q["criteria"].keys())
        j = jeff.get(eid) if eid is not None else None
        row = {"event_id": eid}
        if not j:
            row["error"] = "missing"
            per_event.append(row)
            continue

        # class: argmax -> key (mismo orden que criteria Jev)
        jc = j["class"]
        jeff_key = crit_keys[jc["choice_index"]]
        gold_key = g_class["choice"]
        verdict_pairs.append((gold_key, jeff_key))
        confusion.setdefault(gold_key, {}).setdefault(jeff_key, 0)
        confusion[gold_key][jeff_key] += 1
        row["class"] = {"gold": gold_key, "jeff": jeff_key}

        # sev: argmax level vs score float de Jev (0-3)
        js = j["sev"]
        gold_score = float(g_sev["score"])
        jeff_level = int(js["choice_index"])
        sev_diffs.append(abs(jeff_level - gold_score))
        row["sev"] = {"gold": round(gold_score, 3), "jeff": jeff_level}

        # act: P(true) umbral 0.5 en ambos lados
        ja = j["act"]
        p_true = float(ja["probabilities"][1])
        gold_noul = float(g_act["noul"])
        action_pairs.append((_norm_action(gold_noul), _norm_action(p_true)))
        act_prob_diffs.append(abs(p_true - gold_noul))
        row["act"] = {"gold": round(gold_noul, 3), "jeff_p_true": round(p_true, 4)}

        ms = [j[k].get("ms", 0.0) for k in ("class", "sev", "act")]
        row["ms_total"] = round(sum(ms), 1)
        per_event.append(row)

    def _agree(pairs: list[tuple[str | None, str | None]]) -> tuple[int, float | None]:
        ok = pairs and all(a is not None and b is not None for a, b in pairs)
        n_ok = sum(1 for a, b in pairs if a == b)
        pct = round(n_ok / len(pairs) * 100, 2) if pairs else None
        return n_ok, pct

    v_ok, v_pct = _agree(verdict_pairs)
    a_ok, a_pct = _agree(action_pairs)
    mae_sev = round(sum(sev_diffs) / len(sev_diffs), 4) if sev_diffs else None
    mae_act = round(sum(act_prob_diffs) / len(act_prob_diffs), 4) \
        if act_prob_diffs else None

    all_ms = [row["ms_total"] for row in per_event if "ms_total" in row]
    return {
        "n_events": len(events),
        "verdict_agreement_pct": v_pct,
        "verdict_agree_n": v_ok,
        "action_agreement_pct": a_pct,
        "action_agree_n": a_ok,
        "severity_mae_0_3": mae_sev,
        "noul_prob_mae_0_1": mae_act,
        "latency_ms_total_median": round(statistics.median(all_ms), 1) if all_ms else None,
        "confusion_class": confusion,
        "per_event": per_event,
    }


def _jev_live(events: list[dict], timeout: int = 60) -> dict[int, dict]:
    """(Solo con --jev) Re-query Jev live para comparar deriva. Gasta API."""
    sys.path.insert(0, str(ROOT))
    import jev_triage  # noqa: E402

    cfg = json.loads((ROOT / "data" / "config.json").read_text(encoding="utf-8"))
    raw_key = str(cfg.get("jev_api_key") or "")
    if raw_key.startswith("dpapi:"):
        import secret_store
        key = secret_store.unprotect(raw_key) or ""
    else:
        key = raw_key
    res = jev_triage.triage_events(events, key, backend="cloud", timeout=timeout)
    if res.get("status") != "ok":
        raise RuntimeError(f"Jev live no disponible: {res}")
    out: dict[int, dict] = {}
    for idx_s, v in res.get("verdicts", {}).items():
        out[int(idx_s)] = {"class": v.get("verdict"),
                           "sev": v.get("severity_score"),
                           "act": _norm_action(v.get("immediate_action"))}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="solo construir y validar payloads; sin red")
    ap.add_argument("--limit", type=int, default=None,
                    help="solo los primeros N eventos (por defecto todos)")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"URL /classify de Jeff (default {DEFAULT_URL})")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--jev", action="store_true",
                    help="re-query Jev live (gasta API; solo si se pide)")
    args = ap.parse_args(argv)

    events = _load_gold(args.limit)
    payloads: dict[int, dict[str, dict]] = {}
    for ev in events:
        p = _build_payloads(ev)
        _validate_payloads(p)
        payloads[ev["event_id"]] = p

    if args.dry_run:
        report = {
            "dry_run": True,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "n_events": len(events),
            "n_payloads": sum(len(p) for p in payloads.values()),
            "options_per_question": {
                k: sorted(set(n_opts_by(k, payloads)))
                for k in ("class", "sev", "act")},
            "max_options_seen": max(max(len(p[k]["options"]) for p in payloads.values())
                                    for k in ("class", "sev", "act")),
            "network_calls": 0,
        }
        print(json.dumps({k: v for k, v in report.items() if k != "options_per_question"},
                         indent=2, ensure_ascii=False))
        print(f"dry-run OK: {report['n_events']} eventos, "
              f"{report['n_payloads']} payloads, sin red.")
        return 0

    jeff: dict[int, dict[str, dict]] = {}
    errors: list[dict] = []
    for ev in events:
        eid = ev["event_id"]
        try:
            jeff[eid] = _run_jeff(payloads[eid], args.url, args.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                OSError, ValueError, KeyError) as exc:
            errors.append({"event_id": eid, "error": str(exc)[:300]})
            print(f"  [fail] event {eid}: {str(exc)[:120]}", file=sys.stderr)

    metrics = _metrics(events, jeff)
    if errors:
        metrics["errors"] = errors

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "gold": str(GOLD_PATH),
        "n_events": len(events),
        "limit": args.limit,
        "jeff_url": args.url,
        "metrics": metrics,
    }

    if args.jev:
        try:
            live = _jev_live(events, timeout=args.timeout)
            result["jev_live"] = {str(k): v for k, v in live.items()}
        except Exception as exc:  # no bloquear el A/B por Jev live
            result["jev_live_error"] = str(exc)[:300]

    OUT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    m = metrics
    print(f"A/B Jeff vs gold Jev: {m['n_events']} eventos -> {OUT_PATH}")
    print(f"  acuerdo verdict (class) : {m['verdict_agreement_pct']}% "
          f"({m['verdict_agree_n']}/{m['n_events']})")
    print(f"  acuerdo accion (noul>=.5): {m['action_agreement_pct']}% "
          f"({m['action_agree_n']}/{m['n_events']})")
    print(f"  MAE severidad (0-3)     : {m['severity_mae_0_3']}")
    print(f"  MAE P(accion) (0-1)     : {m['noul_prob_mae_0_1']}")
    print(f"  latencia total mediana  : {m['latency_ms_total_median']} ms/evento")
    return 0


def n_opts_by(kind: str, payloads: dict[int, dict[str, dict]]) -> list[int]:
    return [len(p[kind]["options"]) for p in payloads.values()]


if __name__ == "__main__":
    raise SystemExit(main())
