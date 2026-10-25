"""Arnes de comparacion dual cloud (Jev) vs local (laya-serve). Fase D.

Uso:  py -3.12 tools/compare_backends.py [--n 50] [--force]

- Carga hasta N eventos representativos de data/events.db (estratificados
  por dominio catalogo, ordenados por seen_count; determinista).
- Llama triage_events(events, key, backend="cloud") y backend="local".
- Escribe data/compare_<YYYYMMDD>.json con veredictos lado a lado y
  metricas: acuerdo verdict (%), acuerdo immediate_action, MAE de
  severity_score, matriz de confusion (filas=cloud, columnas=local).

Coste: N<=50 por default (1 llamada batch a Jev ~$0.001-0.002). Si ya
existe compare_<hoy>.json NO se vuelve a llamar a Jev (dedup por fecha;
--force para forzar). laya-serve debe estar corriendo en 127.0.0.1:8787.
Privacidad: backend=local solo habla con 127.0.0.1 (ninguna salida a
api.typesafe.ai); el arnes registra las URLs base usadas como evidencia.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import jev_triage  # noqa: E402


def _load_events(n: int) -> list[dict]:
    """Hasta n eventos representativos de data/events.db.

    Estratificacion determinista: grupos por (catalog_domain o IP),
    dentro de cada grupo el mas visto primero; se intercalan grupos para
    que la muestra cubra varios destinos."""
    con = sqlite3.connect(str(ROOT / "data" / "events.db"))
    con.row_factory = sqlite3.Row
    cols = ["id", "ts", "process", "dest_ip", "dest_port", "dest_host",
            "sni_domain", "catalog_domain", "seen_count", "first_seen",
            "last_seen", "protocol", "ai_layer", "autonomy_verdict",
            "sessions", "iat_cv"]
    rows = [dict(r) for r in con.execute(
        f"select {', '.join(cols)} from events order by id")]
    con.close()
    groups: dict[str, list[dict]] = {}
    for e in rows:
        key = str(e.get("catalog_domain") or e.get("dest_ip") or "?")
        groups.setdefault(key, []).append(e)
    for g in groups.values():
        g.sort(key=lambda e: -int(e.get("seen_count") or 1))
    # Intercalar por grupos (round-robin) para diversidad.
    out: list[dict] = []
    queues = [groups[k] for k in sorted(groups)]
    while len(out) < n and any(queues):
        for q in list(queues):
            if not q:
                continue
            out.append(q.pop(0))
            if len(out) >= n:
                break
    return out


def _jev_api_key() -> str:
    """Key Jev desde data/config.json (DPAPI), mismo patron que server.py."""
    cfg = json.loads((ROOT / "data" / "config.json").read_text())
    raw = str(cfg.get("jev_api_key") or "")
    if raw.startswith("dpapi:"):
        import secret_store
        return secret_store.unprotect(raw) or ""
    return raw


def _norm_action(v):
    """Normaliza immediate_action a 'yes'/'no' para comparar backends.

    Jev (cloud) puede devolver la etiqueta o un float; laya (local) ya
    llega normalizado por el umbral 0.5 en _local_verdict."""
    if isinstance(v, str):
        return v.strip().lower()
    try:
        return "yes" if float(v) >= 0.5 else "no"
    except (TypeError, ValueError):
        return None


def _mae(a: list[float | None], b: list[float | None]) -> float | None:
    pairs = [(x, y) for x, y in zip(a, b)
             if isinstance(x, (int, float)) and isinstance(y, (int, float))]
    if not pairs:
        return None
    return round(sum(abs(x - y) for x, y in pairs) / len(pairs), 4)


def _ab_metrics(cloud_verdicts: list[dict],
                local_verdicts: list[dict]) -> tuple[dict, dict]:
    """Metricas de un checkpoint local contra el tramo cloud cacheado.

    Misma semantica que la comparacion principal: acuerdo verdict (%),
    acuerdo immediate_action, MAE severity_score y matriz de confusion
    (filas=cloud, columnas=local)."""
    cv = [c.get("verdict") for c in cloud_verdicts]
    lv = [l.get("verdict") for l in local_verdicts]
    both = [(c, l) for c, l in zip(cv, lv) if c and l]
    agree_v = (sum(1 for c, l in both if c == l) / len(both) * 100) \
        if both else None
    acts = [(_norm_action(c.get("immediate_action")),
             _norm_action(l.get("immediate_action")))
            for c, l in zip(cloud_verdicts, local_verdicts)]
    acts_ok = [(c, l) for c, l in acts if c and l]
    agree_a = (sum(1 for c, l in acts_ok if c == l) / len(acts_ok) * 100) \
        if acts_ok else None
    mae_s = _mae([c.get("severity_score") for c in cloud_verdicts],
                [l.get("severity_score") for l in local_verdicts])
    labels = sorted({v for v in cv + lv if v})
    confusion = {c: {l: sum(1 for cc, ll in both if cc == c and ll == l)
                    for l in labels} for c in labels}
    return {
        "verdict_agreement_pct": round(agree_v, 2) if agree_v is not None else None,
        "immediate_action_agreement_pct": round(agree_a, 2) if agree_a is not None else None,
        "severity_score_mae": mae_s,
        "compared_pairs": len(both),
    }, confusion


def _ab_recommendation(results: dict[str, dict]) -> str:
    """Umbral Fase E: >=~85% viable; <70% insuficiente; lo demas intermedio."""
    parts = []
    for name in sorted(results):
        m = results[name]["metrics"]
        pct = m.get("verdict_agreement_pct")
        if pct is None:
            zone = "sin datos suficientes"
        elif pct >= 85.0:
            zone = "viable (>= umbral Fase E ~85%)"
        elif pct < 70.0:
            zone = "insuficiente (<70%)"
        else:
            zone = "zona intermedia (entre 70% y 85%): no alcanza el umbral"
        parts.append(f"{name}: acuerdo verdict {pct}% -> {zone}")
    eng = results.get("english", {}).get("metrics", {})
    typ = results.get("typed-decisions", {}).get("metrics", {})
    if None not in (eng.get("verdict_agreement_pct"),
                    typ.get("verdict_agreement_pct")):
        delta = round(typ["verdict_agreement_pct"] -
                      eng["verdict_agreement_pct"], 2)
        parts.append(
            f"delta typed-decisions vs english: {delta:+.2f} puntos de acuerdo")
    if typ.get("verdict_agreement_pct") is not None and \
            typ["verdict_agreement_pct"] >= 85.0:
        parts.append(
            "conclusion: typed-decisions es viable SIN entrenar (via sin "
            "finetuning); no hace falta gastar en etiquetado")
    elif typ.get("verdict_agreement_pct") is not None and \
            typ["verdict_agreement_pct"] >= 70.0:
        parts.append(
            "conclusion: typed-decisions sigue por debajo del umbral de "
            "viabilidad; el checkpoint sin entrenar no basta y hace falta "
            "finetuning (o validar la zona intermedia con mas eventos)")
    else:
        parts.append(
            "conclusion: typed-decisions es insuficiente (<70%); confirma "
            "que hace falta finetuning antes de sustituir a Jev")
    return "; ".join(parts)


def run_ab(ref_path: Path, models: list[str]) -> int:
    """A/B de checkpoints locales SIN llamar a Jev (Fase E).

    Reutiliza los veredictos cloud cacheados en ref_path (mismos N eventos,
    _load_events es determinista) y corre solo backend=local con cada
    modelo pedido. Coste Jev adicional = 0."""
    ref = json.loads(ref_path.read_text())
    ref_events = ref.get("events") or []
    n = len(ref_events)
    if n == 0:
        print(f"[ab] {ref_path.name} no tiene eventos; aborta.")
        return 1
    cloud_ref = (ref.get("cloud") or {}).get("status")
    if cloud_ref != "ok":
        print(f"[ab] el tramo cloud de {ref_path.name} no es ok; aborta.")
        return 1
    events = _load_events(n)
    # Sanidad: la muestra determinista debe coincidir con la cacheada.
    mismatch = sum(
        1 for i, (e, p) in enumerate(zip(events, ref_events))
        if e.get("process") != p.get("process") or
        f"{e.get('catalog_domain') or e.get('dest_ip')}:{e.get('dest_port')}"
        != p.get("dest"))
    if mismatch:
        print(f"[ab] AVISO: {mismatch}/{n} eventos no coinciden con la "
              f"cache {ref_path.name}; el indice sigue siendo valido pero "
              "verificar antes de decidir.")
    env_path = ROOT / "data" / "laya_serve.env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("LAYA_API_KEY="):
                os.environ["LAYA_API_KEY"] = line.split("=", 1)[1].strip()
                break
    cloud_verdicts = [p.get("cloud") or {} for p in ref_events]
    results: dict[str, dict] = {}
    per_event = [{"idx": p["idx"], "process": p.get("process"),
                  "dest": p.get("dest"), "cloud": p.get("cloud")}
                 for p in ref_events]
    for model in models:
        print(f"[ab] local model={model} sobre {n} eventos (sin Jev)...")
        local = jev_triage.triage_events(
            events, os.environ.get("LAYA_API_KEY") or "",
            base_url=jev_triage.LOCAL_BASE_URL, model=model,
            backend="local")
        lv = [local.get("verdicts", {}).get(str(i)) or {}
              for i in range(n)]
        metrics, confusion = _ab_metrics(cloud_verdicts, lv)
        results[model] = {"status": local.get("status"),
                          "model": model,
                          "base_url": jev_triage.LOCAL_BASE_URL,
                          "metrics": metrics,
                          "confusion_cloud_vs_local": confusion}
        for i in range(n):
            per_event[i][model] = lv[i]
        print(f"[ab] {model}: "
              f"{json.dumps(metrics, ensure_ascii=False)}")
    result = {
        "date": str(date.today()),
        "mode": "ab_no_jev",
        "reference": str(ref_path.relative_to(ROOT)),
        "n_events": n,
        "cloud": {"status": "ok", "model": ref["cloud"].get("model"),
                 "base_url": ref["cloud"].get("base_url"),
                 "note": "veredictos cloud cacheados; 0 llamadas Jev nuevas"},
        "checkpoints": results,
        "events": per_event,
        "recommendation": _ab_recommendation(results),
    }
    out_path = ROOT / "data" / f"compare_typed_{date.today():%Y%m%d}.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[ok] {out_path}")
    print("[ab] recomendacion:", result["recommendation"])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50, help="eventos (max 50)")
    ap.add_argument("--force", action="store_true",
                    help="re-triar cloud y local desde cero (gasta Jev)")
    ap.add_argument("--local-only", action="store_true",
                    help="reutiliza el tramo cloud guardado y repite solo "
                         "local (gratis)")
    ap.add_argument("--ab", action="store_true",
                    help="A/B de checkpoints locales SIN Jev: reutiliza los "
                         "veredictos cloud cacheados en --ref")
    ap.add_argument("--models", default="english,typed-decisions",
                    help="checkpoints locales a comparar (coma), modo --ab")
    ap.add_argument("--ref", default=None,
                    help="fichero compare_<fecha>.json con el tramo cloud "
                         "cacheado (default: data/compare_20260930.json)")
    args = ap.parse_args()
    if args.ab:
        ref_path = Path(args.ref) if args.ref else \
            ROOT / "data" / "compare_20260930.json"
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        return run_ab(ref_path, models)
    # 2026-10-07: cap subido de 50 a 200 para refrescar el reference cloud con muestra mayor.
    n = min(max(args.n, 1), 200)

    out_path = ROOT / "data" / f"compare_{date.today():%Y%m%d}.json"
    prev: dict | None = None
    if out_path.exists() and not args.force:
        # Dedup por fecha: reutilizo el tramo cloud ya pagado; solo se
        # vuelve a llamar (local, gratis) si falta o fallo.
        prev = json.loads(out_path.read_text())
        if not args.local_only and \
                (prev.get("local") or {}).get("status") == "ok":
            print(f"[dedup] {out_path.name} ya esta completo; no llamo a "
                  "ningun backend (usa --force para forzar).")
            return 0
        if len(prev.get("events") or []) != n:
            print(f"[dedup] --n {n} no coincide con la muestra guardada "
                  f"({len(prev['events'])}); usa --force para re-triar todo.")
            return 1
        print(f"[dedup] {out_path.name} existe con local="
              f"{prev['local']['status']}; reutilizo cloud y repito solo local.")

    events = _load_events(n)
    key = _jev_api_key()
    if not key:
        print("sin key Jev en data/config.json; aborta (no gasto nada).")
        return 1
    # B4: token local desde env LAYA_API_KEY; aqui se carga de
    # data/laya_serve.env (el fichero con el que arranca laya-serve).
    env_path = ROOT / "data" / "laya_serve.env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("LAYA_API_KEY="):
                os.environ["LAYA_API_KEY"] = line.split("=", 1)[1].strip()
                break

    if prev and (prev.get("cloud") or {}).get("status") == "ok":
        # Se reconstruye el tramo cloud evento a evento desde la salida
        # previa (mismo orden de eventos: _load_events es determinista).
        cloud = {"status": "ok", "model": prev["cloud"].get("model"),
                 "verdicts": {str(p["idx"]): p.get("cloud") or {}
                              for p in (prev.get("events") or [])}}
    else:
        cloud = jev_triage.triage_events(events, key, backend="cloud")
    local = jev_triage.triage_events(
        events, key, base_url=jev_triage.LOCAL_BASE_URL,
        model=jev_triage.LOCAL_MODEL, backend="local")

    per_event = []
    cloud_verdicts: list[str | None] = []
    local_verdicts: list[str | None] = []
    acts: list[tuple[str | None, str | None]] = []
    scores: list[tuple[float | None, float | None]] = []
    for i, e in enumerate(events):
        cv = (cloud.get("verdicts") or {}).get(str(i)) or {}
        lv = (local.get("verdicts") or {}).get(str(i)) or {}
        per_event.append({
            "idx": i,
            "process": str(e.get("process"))[:60],
            "dest": f"{e.get('catalog_domain') or e.get('dest_ip')}:"
                    f"{e.get('dest_port')}",
            "cloud": cv,
            "local": lv,
        })
        cloud_verdicts.append(cv.get("verdict"))
        local_verdicts.append(lv.get("verdict"))
        acts.append((_norm_action(cv.get("immediate_action")),
                    _norm_action(lv.get("immediate_action"))))
        scores.append((cv.get("severity_score"), lv.get("severity_score")))

    both = [(c, l) for c, l in zip(cloud_verdicts, local_verdicts)
            if c and l]
    agree_v = (sum(1 for c, l in both if c == l) / len(both) * 100) if both else None
    acts_ok = [(c, l) for c, l in acts if c and l]
    agree_a = (sum(1 for c, l in acts_ok if c == l) / len(acts_ok) * 100) \
        if acts_ok else None
    mae_s = _mae([c for c, _ in scores], [l for _, l in scores])

    labels = sorted({v for v in cloud_verdicts + local_verdicts if v})
    confusion = {c: {l: sum(1 for cc, ll in both if cc == c and ll == l)
                    for l in labels} for c in labels}

    result = {
        "date": str(date.today()),
        "n_events": len(events),
        "cloud": {"status": cloud.get("status"),
                  "model": cloud.get("model"),
                  "base_url": jev_triage._BACKENDS["cloud"]["base_url"]},
        "local": {"status": local.get("status"),
                  "model": local.get("model"),
                  "base_url": jev_triage._BACKENDS["local"]["base_url"],
                  "note": "solo 127.0.0.1; ninguna salida a api.typesafe.ai"},
        "metrics": {
            "verdict_agreement_pct": round(agree_v, 2) if agree_v is not None else None,
            "immediate_action_agreement_pct": round(agree_a, 2) if agree_a is not None else None,
            "severity_score_mae": mae_s,
            "compared_pairs": len(both),
        },
        "confusion_cloud_vs_local": confusion,
        "events": per_event,
    }
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[ok] {out_path}")
    print(json.dumps(result["metrics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
