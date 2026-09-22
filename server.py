"""AI NetWatch — monitor de salidas de red a proveedores cloud IA.

Solo loopback (127.0.0.1). FastAPI + stdlib. El monitor corre en un hilo;
Jev (TypeSafe) es juez de criticidad a demanda; LLM local (solo loopback)
da explicaciones tecnicas en espanol. Fail-safe: sin IA, la vista clasica
funciona igual.

Arranque:  python -m uvicorn server:app --host 127.0.0.1 --port 8790
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from jev_triage import DEFAULT_BASE_URL, PINNED_MODEL, triage_events
from llm_local import explain_events, is_loopback_url
from monitor import NetMonitor
from store import Store
from sysmon_source import poll_sysmon_events, sysmon_available

DATA_DIR = Path(__file__).resolve().parent / "data"
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="AI NetWatch")

_cfg: dict = {
    "jev_enabled": True,
    "jev_api_key": "",
    "jev_model": PINNED_MODEL,
    "jev_base_url": DEFAULT_BASE_URL,
    "llm_enabled": False,
    "llm_base_url": "",
    "llm_model": "",
    "extra_hosts": [],
    "sysmon_enabled": True,
}

store: Store | None = None
monitor: NetMonitor | None = None


@app.on_event("startup")
def _start() -> None:
    global store, monitor
    store = Store(DATA_DIR / "events.db")
    sm = poll_sysmon_events if (_cfg["sysmon_enabled"] and sysmon_available()) else None
    monitor = NetMonitor(store, extra_hosts=list(_cfg["extra_hosts"]),
                         sysmon_fn=sm)
    monitor.start()


@app.on_event("shutdown")
def _stop() -> None:
    if monitor:
        monitor.stop()
        monitor.join(timeout=3)
    if store:
        store.close()


def _mask(cfg: dict) -> dict:
    out = dict(cfg)
    if out.get("jev_api_key"):
        out["jev_api_key"] = "***"
    return out


class ConfigRequest(BaseModel):
    jev_enabled: bool | None = None
    jev_api_key: str | None = None
    llm_enabled: bool | None = None
    llm_base_url: str | None = None
    llm_model: str | None = None
    extra_hosts: list[str] | None = None
    sysmon_enabled: bool | None = None


class TriageRequest(BaseModel):
    event_ids: list[int] | None = None


class TestRequest(BaseModel):
    target: str  # jev | llm


class ResetRequest(BaseModel):
    confirm: bool = False


@app.get("/api/config")
def get_config():
    return _mask(_cfg)


@app.post("/api/config")
def set_config(req: ConfigRequest):
    if req.jev_enabled is not None:
        _cfg["jev_enabled"] = req.jev_enabled
    if req.jev_api_key is not None:
        _cfg["jev_api_key"] = (req.jev_api_key or "").strip()
    if req.llm_enabled is not None:
        _cfg["llm_enabled"] = req.llm_enabled
    if req.llm_base_url is not None:
        url = (req.llm_base_url or "").strip()
        if url and not is_loopback_url(url):
            raise HTTPException(400, "LLM base_url debe ser loopback")
        _cfg["llm_base_url"] = url
    if req.llm_model is not None:
        _cfg["llm_model"] = (req.llm_model or "").strip()
    if req.extra_hosts is not None:
        hosts = [h.strip().lower() for h in req.extra_hosts if h and h.strip()]
        _cfg["extra_hosts"] = hosts
        if monitor:
            monitor.extra_hosts = hosts
    if req.sysmon_enabled is not None:
        _cfg["sysmon_enabled"] = req.sysmon_enabled
        if monitor:  # toggle en vivo, sin reiniciar
            monitor._sysmon = (poll_sysmon_events
                              if req.sysmon_enabled and sysmon_available()
                              else None)
    return _mask(_cfg)


@app.post("/api/test")
def test_ai(req: TestRequest):
    if req.target == "jev":
        if not _cfg.get("jev_api_key"):
            return {"ok": False, "error": "sin api key"}
        # Mismo shape que el triaje real (dicts con type/instructions/criteria);
        # una pregunta string -> 422 de TypeSafe.
        from jev_triage import _http_post_json, _questions_for
        try:
            data = _http_post_json(
                _cfg["jev_base_url"],
                {"model": _cfg["jev_model"],
                 "state": [{"title": "selftest", "process": "netwatch-selftest"}],
                 "questions": _questions_for(0)},
                _cfg["jev_api_key"], 30,
            )
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        answers = data.get("answers") or {}
        cls = answers.get("f0_class") or {}
        return {"ok": True, "model": data.get("model"),
                "answer": cls.get("choice") if isinstance(cls, dict) else None}
    if req.target == "llm":
        from llm_local import _chat, is_loopback_url
        base = (_cfg.get("llm_base_url") or "").strip()
        model = (_cfg.get("llm_model") or "").strip()
        if not base or not model:
            return {"status": "error",
                    "reason": "configura URL y modelo del LLM local primero"}
        if not is_loopback_url(base):
            return {"status": "error", "reason": "solo se permite loopback"}
        try:
            content = _chat(base, model, "Responde solo 'ok'.", "di ok", 60)
            return {"status": "ok", "model": model,
                    "reply": content[:80]}
        except Exception as e:
            return {"status": "error", "reason": f"{type(e).__name__}: {e}"}
    raise HTTPException(400, "target debe ser jev o llm")


@app.get("/api/events")
def list_events(limit: int = 200, process: str | None = None,
                dest: str | None = None):
    limit = max(1, min(int(limit), 1000))
    return {"events": store.list_events(limit=limit, process=process, dest=dest)}


@app.post("/api/triage")
def triage(req: TriageRequest):
    events = (store.list_events(limit=1000) if req.event_ids is None
              else [e for i in req.event_ids if (e := store.get_event(i))] )
    if not events:
        raise HTTPException(404, "no hay eventos que triar")
    result = {"status": "skipped", "reason": "ai_disabled"}
    if _cfg.get("jev_enabled") and _cfg.get("jev_api_key"):
        result = triage_events(events, _cfg["jev_api_key"],
                               _cfg["jev_base_url"], _cfg["jev_model"])
    explanations: list[dict] | None = None
    if (result.get("status") == "ok" and _cfg.get("llm_enabled")
            and _cfg.get("llm_base_url") and _cfg.get("llm_model")):
        flagged = [e for i, e in enumerate(events)
                   if ((result.get("verdicts") or {}).get(str(i), {})
                       .get("severity_score") is not None
                       and (result["verdicts"][str(i)]["severity_score"] >= 2
                            or result["verdicts"][str(i)]["verdict"] != "expected_ai_use"))]
        if flagged:
            explanations = explain_events(
                _cfg["llm_base_url"], _cfg["llm_model"], events, result.get("verdicts"))
    payload = {"events": [
        {"id": e["id"], "process": e["process"],
         "dest": f"{e['dest_host'] or e['dest_ip']}:{e['dest_port']}",
         "catalog": e["catalog_domain"], "seen_count": e["seen_count"]}
        for e in events],
        "jev": result, "llm_explanations": explanations}
    store.save_triage(result.get("status", "error"), result.get("model"), payload)
    return payload


@app.get("/api/triages/latest")
def latest_triage():
    t = store.latest_triage()
    if not t:
        raise HTTPException(404, "sin triajes")
    return t


@app.get("/api/stats")
def stats(days: int = 7):
    days = max(1, min(int(days), 365))
    live = store.list_events(limit=1000)
    return {
        "daily": store.stats(days=days),
        "live": {
            "events": len(live),
            "processes": len({e["process"] for e in live}),
            "destinations": len({f"{e['dest_ip']}:{e['dest_port']}" for e in live}),
        },
    }


@app.post("/api/reset")
def reset(req: ResetRequest):
    if not req.confirm:
        raise HTTPException(400, "se requiere {\"confirm\": true}")
    out = store.reset()
    return {**out, "daily_stats_kept": True}


@app.get("/api/export/json")
def export_json():
    events = store.list_events(limit=1000)
    triage = store.latest_triage()
    return JSONResponse({
        "tool": "ai_net_monitor", "events": events,
        "latest_triage": triage["payload"] if triage else None,
    })


@app.get("/api/export/csv")
def export_csv():
    events = store.list_events(limit=1000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "process", "image", "protocol", "dest_ip", "dest_port",
                "dest_host", "catalog_domain", "seen_count",
                "first_seen", "last_seen"])
    for e in events:
        w.writerow([e["ts"], e["process"], e.get("image") or "",
                    e.get("protocol", "tcp"), e["dest_ip"], e["dest_port"],
                    e["dest_host"] or "", e["catalog_domain"] or "",
                    e["seen_count"], e["first_seen"], e["last_seen"]])
    return Response(buf.getvalue(), media_type="text/csv")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
