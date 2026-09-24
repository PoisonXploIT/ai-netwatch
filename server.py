"""AI NetWatch — monitor de salidas de red a proveedores cloud IA.

Solo loopback (127.0.0.1). FastAPI + stdlib. El monitor corre en un hilo;
Jev (TypeSafe) es juez de criticidad a demanda; LLM local (solo loopback)
da explicaciones tecnicas en espanol. Fail-safe: sin IA, la vista clasica
funciona igual.

Arranque:  python -m uvicorn server:app --host 127.0.0.1 --port 8790
"""
from __future__ import annotations

import csv
import ipaddress
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ai_catalog import KNOWN_AI_DOMAINS
from ai_classifier import classify_domain, destination_kind
from alerts import AlertLog
import auto_classify
import evidence
import rules
import secret_store
from jev_triage import DEFAULT_BASE_URL, PINNED_MODEL, triage_events
from llm_local import (explain_events, investigate_event,
                       is_loopback_url)
from llm_proxy import LlmProxy
from pdf_export import build_report_pdf
from monitor import NetMonitor
from store import LlmCallStore, Store
from sysmon_source import (poll_sysmon_dns, poll_sysmon_events,
                           poll_sysmon_process_creation, sysmon_available)
import autonomy
from tshark_source import (SniCapture, find_active_interface, sni_available,
                          tshark_path)

DATA_DIR = Path(__file__).resolve().parent / "data"
STATIC_DIR = Path(__file__).resolve().parent / "static"
CONFIG_PATH = DATA_DIR / "config.json"
VERSION = "2.0-alpha"

app = FastAPI(title="AI NetWatch")

_cfg: dict = {
    "jev_enabled": True,
    "jev_api_key": "",
    "jev_model": PINNED_MODEL,
    "jev_base_url": DEFAULT_BASE_URL,
    "llm_enabled": False,
    "llm_base_url": "",
    "llm_model": "",
    # B: tope de eventos por lote en POST /api/review (una llamada LLM
    # por evento; el resto queda pendiente para el proximo lote).
    "llm_review_max": 10,
    "llm_proxy_enabled": False,
    "llm_proxy_port": 8098,
    "llm_proxy_target": "127.0.0.1:8099",
    "extra_hosts": [],
    "sysmon_enabled": True,
    "tshark_enabled": True,
    "retention_days": 90,
    # llm_calls guarda prompts/respuestas en claro (el dato mas sensible):
    # retencion mas corta que la de eventos (metadatos).
    "retention_days_llm": 30,
    "llm_store_content": True,
    "alerts_enabled": True,
    "alert_webhook_url": "",
    # v2.2: motor de reglas (umbral de egress para la regla pendiente de
    # bytes remotos).
    "rules_enabled": True,
    "rule_egress_mb_per_day": 500.0,
    # v2.2: colector elevado de bytes remotos (opt-in; UAC en cada ciclo).
    "net_bytes_enabled": False,
    "net_bytes_duration_s": 30,
    "net_bytes_cycle_s": 600,
}


def _effective_llm_base() -> str:
    """URL real para llamar al LLM.

    Auto-observacion: si el inspector esta activo y la config apunta al mismo
    upstream que el target del proxy, las llamadas propias (explicador, test)
    se enrutan por el proxy. La config NO se reescribe; el proxy sigue
    apuntando al LLM real, no a si mismo (sin bucle).
    """
    url = _cfg.get("llm_base_url", "") or ""
    if not llm_proxy or not url:
        return url
    m = re.match(r"https?://([^:/]+):(\d+)", url)
    if not m:
        return url
    host, port = m.group(1).lower(), m.group(2)
    thost, tport = llm_proxy.target[0].lower(), str(llm_proxy.target[1])
    if host == thost and port == tport:
        return f"http://{llm_proxy.bind_host}:{llm_proxy.bound_port}"
    return url


def _valid_proxy_target(target: str) -> bool:
    """Target del proxy inspector: host:port cuyo host resuelve a loopback.
    Mismo criterio SSRF que llm_base_url: el proxy es un punto HTTP saliente
    a destino elegido por el usuario."""
    host_port = (target or "").strip()
    if ":" not in host_port:
        return False
    host, _, port_s = host_port.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return False
    if not (1 <= port <= 65535):
        return False
    return is_loopback_url(f"http://{host}:{port}")


_KEY_NEEDS_MIGRATION = False


def _load_config() -> None:
    """Config persistente (data/config.json). Si el LLM URL persistido no es
    loopback absoluto, se descarta (SSRF): la seguridad no la hereda un
    archivo editado a mano."""
    global _KEY_NEEDS_MIGRATION
    _KEY_NEEDS_MIGRATION = False
    if not CONFIG_PATH.exists():
        return
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    for k in ("jev_enabled", "jev_api_key", "llm_enabled", "llm_base_url",
              "llm_model", "llm_proxy_enabled", "llm_proxy_port",
              "llm_proxy_target", "extra_hosts", "sysmon_enabled",
              "tshark_enabled", "retention_days", "retention_days_llm",
              "llm_store_content", "alerts_enabled",
              "alert_webhook_url", "catalog_approved",
              "approved_providers",
              # v2.1/v2.2: sin estas, un restart revertia reglas y bytes
              # remotos a los defaults (persistencia silenciosamente rota).
              "rules_enabled", "rule_egress_mb_per_day",
              "net_bytes_enabled", "net_bytes_duration_s",
              "net_bytes_cycle_s", "llm_review_max"):  # noqa: E128
        if k in data:
            _cfg[k] = data[k]
    for key, default in (("retention_days", 90),
                         ("retention_days_llm", 30)):
        rd = _cfg.get(key)
        if not isinstance(rd, int) or isinstance(rd, bool) \
                or not (1 <= rd <= 3650):
            _cfg[key] = default
    if not isinstance(_cfg.get("llm_store_content"), bool):
        _cfg["llm_store_content"] = True
    if not isinstance(_cfg.get("alerts_enabled"), bool):
        _cfg["alerts_enabled"] = True
    if not isinstance(_cfg.get("catalog_approved"), bool):
        _cfg["catalog_approved"] = True
    if not isinstance(_cfg.get("rules_enabled"), bool):
        _cfg["rules_enabled"] = True
    egress = _cfg.get("rule_egress_mb_per_day")
    if not isinstance(egress, (int, float)) or isinstance(egress, bool) \
            or not (0 < egress <= 1e9):
        _cfg["rule_egress_mb_per_day"] = 500.0
    if not isinstance(_cfg.get("net_bytes_enabled"), bool):
        _cfg["net_bytes_enabled"] = False
    dur = _cfg.get("net_bytes_duration_s")
    if not isinstance(dur, int) or isinstance(dur, bool) \
            or not (5 <= dur <= 3600):
        _cfg["net_bytes_duration_s"] = 30
    cyc = _cfg.get("net_bytes_cycle_s")
    if not isinstance(cyc, int) or isinstance(cyc, bool) \
            or not (30 <= cyc <= 86400):
        _cfg["net_bytes_cycle_s"] = 600
    rm = _cfg.get("llm_review_max")
    if not isinstance(rm, int) or isinstance(rm, bool) \
            or not (1 <= rm <= 100):
        _cfg["llm_review_max"] = 10
    ap = _cfg.get("approved_providers")
    if not isinstance(ap, list):
        ap = []
    _cfg["approved_providers"] = [str(p).strip().lower() for p in ap
                                  if str(p).strip()]
    # Webhook: solo loopback; un archivo editado a mano no lo apunta fuera.
    wh = str(_cfg.get("alert_webhook_url") or "")
    if wh and not is_loopback_url(wh):
        _cfg["alert_webhook_url"] = ""
    url = str(_cfg.get("llm_base_url") or "")
    if url and not is_loopback_url(url):
        _cfg["llm_base_url"] = ""
    # Revalidar proxy: un archivo editado a mano no apunta el proxy fuera.
    port = _cfg.get("llm_proxy_port")
    if not isinstance(port, int) or isinstance(port, bool) \
            or not (1 <= port <= 65535):
        _cfg["llm_proxy_port"] = 8098
    if not _valid_proxy_target(str(_cfg.get("llm_proxy_target") or "")):
        _cfg["llm_proxy_target"] = "127.0.0.1:8099"
    # Secreto: la key Jev se persiste cifrada (DPAPI). Un blob 'dpapi:' se
    # descifra a memoria; si no descifra, queda vacia. Un valor en claro de un
    # config antiguo se mantiene en memoria y se migra al proximo guardado.
    stored_key = str(data.get("jev_api_key") or "")
    if secret_store.is_protected(stored_key):
        _cfg["jev_api_key"] = secret_store.unprotect(stored_key) or ""
    elif stored_key:
        _KEY_NEEDS_MIGRATION = True


def _save_config() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # La key Jev nunca se escribe en claro: se cifra con DPAPI; si el cifrado
    # no esta disponible, no se persiste (se re-introduce en la UI).
    out = dict(_cfg)
    key = str(out.get("jev_api_key") or "")
    if key:
        enc = secret_store.protect(key)
        out["jev_api_key"] = enc if enc else ""
    CONFIG_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")


_load_config()
if _KEY_NEEDS_MIGRATION and _cfg.get("jev_api_key"):
    try:  # migracion silenciosa: config antiguo en claro -> blob DPAPI
        _save_config()
        _KEY_NEEDS_MIGRATION = False
    except OSError:
        pass

store: Store | None = None
llm_calls: LlmCallStore | None = None
monitor: NetMonitor | None = None
sni_capture: SniCapture | None = None
llm_proxy: LlmProxy | None = None
alerts: AlertLog | None = None
_auto_stop = threading.Event()


def _req_store() -> Store:
    """Store inicializado. Los endpoints solo corren tras el startup; si no,
    es un 503 limpio en vez de un AttributeError sobre None."""
    if store is None:
        raise HTTPException(503, "store no inicializado")
    return store


def _set_sni_capture(enabled: bool) -> None:
    """Arranque/paro en vivo de la captura SNI (tshark). Fail-safe: sin
    tshark o sin interfaz activa, queda inerte."""
    global sni_capture
    if not enabled:
        if sni_capture:
            sni_capture.stop()
            sni_capture = None
        if monitor:
            monitor._sni_poll = None
        return
    path = tshark_path()
    if not path or sni_capture is not None:
        return
    iface = find_active_interface(path)
    if iface is None:
        return
    sni_capture = SniCapture(path, iface)
    sni_capture.start()
    if monitor:
        monitor._sni_poll = sni_capture.poll_records


def _set_llm_proxy(enabled: bool) -> bool:
    """Arranque/paro en vivo del proxy inspector (R3). Devuelve True si queda
    activo. Fail-safe: puerto ocupado o target invalido lo deja inerte."""
    global llm_proxy
    if not enabled:
        if llm_proxy:
            llm_proxy.stop()
            llm_proxy = None
        return False
    if llm_proxy is not None:
        return True
    host, _, port_s = str(_cfg["llm_proxy_target"]).rpartition(":")
    proxy = LlmProxy(bind_host="127.0.0.1",
                     bind_port=int(_cfg["llm_proxy_port"]),
                     target=(host or "127.0.0.1", int(port_s or 8099)),
                     on_call=_record_llm_call if llm_calls else None)
    try:
        proxy.bind()
    except OSError:
        return False
    proxy.start()
    llm_proxy = proxy
    return True


def _auto_classify_cycle() -> None:
    """Clasificador automatico (v2.0): LLM local rellena incognitas 0.5.
    No-op sin LLM local configurado (fail-safe); nunca lanza."""
    if not (_cfg.get("llm_enabled") and _cfg.get("llm_base_url")
            and _cfg.get("llm_model") and store is not None):
        return
    try:
        auto_classify.run_cycle(
            store, _effective_llm_base(), str(_cfg["llm_model"]))
    except Exception:
        pass


def _ip_host_map() -> dict[str, str]:
    """v2.3: dest_ip -> mejor hostname conocido (cualquier dominio, IA o no):
    eventos (SNI > catalogo > cache DNS; el mas reciente gana) + resoluciones
    EID 22 persistidas. Sirve para etiquetar y mostrar el destino aunque el
    proveedor quede 'desconocido'."""
    ev: dict[str, str] = {}
    if store is None:
        return ev
    for ip, sni, cat, host in store.ip_resolution_rows():
        ip = str(ip or "")
        if not ip:
            continue
        prov = _provider_of({"sni_domain": sni, "catalog_domain": cat,
                             "dest_host": host, "dest_ip": ip})
        if prov and prov != ip.lower():
            ev.setdefault(ip, prov)  # mas reciente gana
    out: dict[str, str] = {}
    for ip, dom in store.dns_resolution_map().items():
        out[ip] = dom
    out.update(ev)  # eventos definitivos: ganan sobre DNS persistido
    return out


def _ip_provider_map() -> dict[str, str]:
    """v2.3: dest_ip -> proveedor (dominio IA), cruzando TODA la senal:
    eventos (SNI > catalogo > cache DNS; el mas reciente gana) + EID 22 en
    memoria del monitor + resoluciones EID 22 persistidas (sobreviven el
    restart). Solo dominios IA. Las IPs sin dominio resuelto quedan fuera
    => 'desconocido' en by_provider."""
    ev_map: dict[str, str] = {}
    if store is not None:
        for ip, sni, cat, host in store.ip_resolution_rows():
            ip = str(ip or "")
            if not ip:
                continue
            prov = _provider_of({"sni_domain": sni, "catalog_domain": cat,
                                 "dest_host": host, "dest_ip": ip})
            if prov and prov != ip.lower():
                ev_map.setdefault(ip, prov)  # mas reciente gana
    out: dict[str, str] = {}
    if monitor is not None:
        out.update(monitor.eid22_provider_map())
    if store is not None:
        for ip, dom in store.dns_resolution_map().items():
            if classify_domain(dom).is_ai:
                out.setdefault(ip, dom)
    out.update(ev_map)  # los eventos son definitivos: ganan sobre EID 22
    return out


def _egress_rows() -> list[dict]:
    """v2.2: bytes remotos por proveedor (net_bytes + mapeo IP->proveedor).
    Vacio si el colector elevado nunca ha volcado datos. v2.3: cada fila
    lleva 'host' (mejor hostname conocido) y 'kind' (label api/web/cdn)."""
    if store is None:
        return []
    ip_prov = _ip_provider_map()
    ip_host = _ip_host_map()
    out: list[dict] = []
    for r in store.net_bytes_sum():
        ip = str(r["dest_ip"])
        prov = ip_prov.get(ip, "desconocido")
        host = ip_host.get(ip, "")
        # label sobre el proveedor si hay; si no, sobre el hostname resuelto.
        kind = destination_kind(ip_prov.get(ip) or host)
        out.append({"provider": prov, "host": host, "kind": kind,
                    "bytes": int(r["bytes"]),
                    "unapproved": not _is_approved_provider(prov)})
    return out


def _rules_events() -> list[dict]:
    """Eventos enriquecidos para el motor de reglas (provider y
    unapproved con la misma logica que shadow). Vacio sin store."""
    out: list[dict] = []
    if store is None:
        return out
    for ev in store.list_events(limit=500):
        provider = _provider_of(ev)
        out.append({
            "process": ev.get("process"),
            "provider": provider,
            "autonomy_verdict": ev.get("autonomy_verdict"),
            "sessions": ev.get("sessions"),
            "iat_cv": ev.get("iat_cv"),
            "unapproved": not _is_approved_provider(provider),
        })
    return out


def _rules_cycle() -> None:
    """v2.2: motor de reglas sobre el estado existente (ciclo de 60 s).
    Fail-safe; alerta solo en transicion no-firing -> firing."""
    if not _cfg.get("rules_enabled", True):
        return
    if alerts is None or not _cfg.get("alerts_enabled"):
        return
    try:
        egress = _egress_rows() or None
        results = rules.evaluate(
            _rules_events(),
            egress_mb_per_day=float(_cfg.get("rule_egress_mb_per_day", 500)),
            egress=egress)
        for r in results:
            if r["fired"] and r["id"] not in _rules_alerted:
                _rules_alerted.add(r["id"])
                alerts.push(
                    "rule_fired",
                    f"Regla {r['id']}: {r['detail']}",
                    details={"rule": r["id"], "detail": r["detail"]},
                )
    except Exception:
        pass


def _auto_classify_loop() -> None:
    """Hilo daemon del clasificador y reglas: 60 s entre ciclos.
    Deliberadamente NO en el hilo del monitor (una llamada LLM lenta no
    bloquea el poll de 5 s)."""
    while not _auto_stop.is_set():
        _auto_classify_cycle()
        _rules_cycle()
        _auto_stop.wait(60)


_net_stop = threading.Event()
_net_last_meta: dict | None = None  # diagnostico del ultimo colector
_netbytes_spawn_method: str | None = None  # 'task' | 'uac' | None
NETBYTES_TASK_NAME = "AI-NETWATCH-NetBytes"


def _netbytes_cmd_file() -> Path:
    return DATA_DIR / "netcollector_cmd.json"


def _write_netbytes_cmd(duration_s: int, out_path: Path) -> None:
    """Parametros para la tarea programada (wrapper): rutas absolutas,
    sin suposiciones de cwd ni usuario."""
    cmd = {
        "python": sys.executable,
        "script": str(Path(__file__).resolve().parent / "netcollector.py"),
        "duration_s": int(duration_s),
        "out_path": str(out_path),
    }
    _netbytes_cmd_file().write_text(
        json.dumps(cmd, ensure_ascii=False), encoding="utf-8")


def _netbytes_task_exists(name: str = NETBYTES_TASK_NAME) -> bool:
    """Existe la tarea programada (creada una vez con
    setup_netbytes_task.ps1 elevado)?"""
    try:
        r = subprocess.run(["schtasks", "/query", "/TN", name],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _spawn_netcollector(duration_s: int, out_path: Path) -> str:
    """Lanza el colector elevado. Devuelve el metodo usado: 'task' o
    'uac'. El hijo ELEVADO escribe el JSONL; este proceso (no elevado)
    solo espera a leerlo.

    - Tarea programada AI-NETWATCH-NetBytes (creada una vez, highest
      privileges): `schtasks /run` — sin prompt, funciona aunque el
      servidor corra desde un proceso de fondo oculto.
    - Si no existe: fallback UAC (Start-Process -Verb RunAs); solo
      funciona desde consola interactiva. Sin admin => no hay fichero:
      degradacion honesta, sin numeros."""
    if _netbytes_task_exists():
        _write_netbytes_cmd(duration_s, out_path)
        subprocess.run(["schtasks", "/run", "/TN", NETBYTES_TASK_NAME],
                       capture_output=True, timeout=60)
        return "task"
    py = sys.executable
    script = Path(__file__).resolve().parent / "netcollector.py"
    ps = (f"Start-Process -FilePath '{py}'"
          f" -ArgumentList '{script}', {int(duration_s)}, '{out_path}'"
          " -Verb RunAs")
    subprocess.Popen(["powershell", "-NoProfile", "-Command", ps],
                     creationflags=0x0800)  # CREATE_NO_WINDOW
    return "uac"


def _netbytes_log(msg: str) -> None:
    """Diagnostico append-only en data/netbytes.log: distingue 'el bucle
    corre' de 'config false en memoria', y que camino de spawn se tomo.
    Sin esto, un fallo del camino elevado es invisible desde fuera."""
    try:
        with open(DATA_DIR / "netbytes.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + " "
                    + msg + "\n")
    except OSError:
        pass


def _read_netjsonl(out_path: Path) -> tuple[list[dict], dict | None]:
    """Lee el JSONL del colector: filas de bytes + linea meta (diagnostico,
    no bytes). Devuelve (rows, meta)."""
    rows: list[dict] = []
    meta: dict | None = None
    with open(out_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "meta" in obj:
                meta = dict(obj["meta"])
                continue
            rows.append(obj)
    return rows, meta


def _netbytes_cycle() -> None:
    """v2.2: un ciclo del colector elevado (opt-in). Fail-safe total."""
    if store is None:
        return
    duration_s = int(_cfg.get("net_bytes_duration_s", 30))
    out_path = DATA_DIR / f"netprobe_{int(time.time())}.jsonl"
    _netbytes_log(f"ciclo inicio dur={duration_s}s "
                 f"tarea={'si' if _netbytes_task_exists() else 'no'}")
    global _netbytes_spawn_method
    try:
        method = _spawn_netcollector(duration_s, out_path)
        _netbytes_spawn_method = method
        _netbytes_log(f"spawn {method}")
    except (OSError, subprocess.SubprocessError) as e:
        _netbytes_log(f"spawn fallo: {e}")
        return
    deadline = time.monotonic() + duration_s + 90
    while not out_path.exists() and time.monotonic() < deadline:
        _net_stop.wait(5)
    if not out_path.exists():
        _netbytes_log("sin JSONL (fallo elevado o timeout)")
        return  # sin admin / UAC denegado / fallo: no hay datos
    global _net_last_meta
    try:
        rows, meta = _read_netjsonl(out_path)
        if meta is not None:
            _net_last_meta = meta
        store.ingest_net_bytes(rows, time.strftime("%Y-%m-%dT%H:%M:%S"))
        _netbytes_log(f"ingesta rows={len(rows)} meta={meta}")
    except (OSError, ValueError) as e:
        _netbytes_log(f"lectura/ingesta fallo: {e}")
        return
    try:
        out_path.unlink()
    except OSError:
        pass


def _netbytes_loop() -> None:
    """Hilo daemon del colector elevado: cada net_bytes_cycle_s, si esta
    activado. Desactivado => solo duerme (opt-in por diseño). Log de
    arranque y transiciones en data/netbytes.log."""
    _netbytes_log("hilo netbytes iniciado")
    enabled_prev: bool | None = None
    while not _net_stop.is_set():
        enabled = bool(_cfg.get("net_bytes_enabled"))
        if enabled != enabled_prev:
            # El config se carga en memoria al arrancar: una edicion del
            # fichero con el servidor vivo NO se ve hasta restart.
            _netbytes_log(
                f"net_bytes_enabled -> {str(enabled).lower()}")
            enabled_prev = enabled
        if enabled:
            try:
                _netbytes_cycle()
            except Exception as e:
                _netbytes_log(f"ciclo fallo inesperado: {e}")
        cycle = int(_cfg.get("net_bytes_cycle_s", 600))
        _net_stop.wait(max(30, min(cycle, 86400)))


_shadow_alerted: set[str] = set()
_autonomy_alerted: set[str] = set()  # R2: una alerta por proceso+proveedor
_beacon_alerted: set[str] = set()    # D3: una alerta de beaconing por clave
_rules_alerted: set[str] = set()     # v2.2: una alerta por regla
_new_dest_alerted: set[str] = set()  # v2.3: una alerta por proceso+proveedor


def _provider_of(ev: dict) -> str:
    """Proveedor de un evento: sni > catalogo > cache DNS > IP (mismo
    orden que el mensaje de alertas). 'extra:' se quita (hosts extra)."""
    host = (str(ev.get("sni_domain") or ev.get("catalog_domain")
                or ev.get("dest_host") or ev.get("dest_ip") or "")
            .strip().lower())
    if host.startswith("extra:"):
        host = host[len("extra:"):]
    return host


def _is_approved_provider(provider: str) -> bool:
    """Shadow AI: aprobado = catalogo (si catalog_approved) union
    approved_providers. Match por sufijo de dominio; IPs, exacto."""
    provider = (provider or "").strip().lower()
    if not provider:
        return False
    approved: list[str] = []
    if _cfg.get("catalog_approved", True):
        approved.extend(d.lower() for d in KNOWN_AI_DOMAINS)
    approved.extend(str(p).strip().lower()
                    for p in _cfg.get("approved_providers") or [])
    try:
        ipaddress.ip_address(provider)
        return provider in set(approved)
    except ValueError:
        pass
    return any(provider == a or provider.endswith("." + a)
               for a in approved if a)


def _on_beacon(key: tuple, stats: dict) -> None:
    """D3: una clave IA acaba de pasar a beaconing (CV bajo, N>=5).
    Corriendo en el hilo del monitor; fail-safe total."""
    if not _cfg.get("alerts_enabled") or alerts is None:
        return
    try:
        proc, ip, port = key
        ev = store.get_event_by_key(proc, ip, port) if store else None
        if ev is None:
            return
        if not (ev.get("catalog_domain") or ev.get("ai_layer")):
            return  # solo IA: el beaconing de trafico no-IA no es alerta aqui
        host = _provider_of(ev)
        k = f"{proc}:{host}"
        if k in _beacon_alerted:
            return
        _beacon_alerted.add(k)
        alerts.push(
            "beaconing_ai_call",
            (f"Beaconing IA: {proc} -> {host}:{port} "
             f"({stats['sessions']} sesiones, CV "
             f"{stats['iat_cv']:.3f})"),
            details={"process": proc, "provider": host,
                     "dest_ip": ip, "dest_port": port,
                     "sessions": stats["sessions"],
                     "iat_cv": stats["iat_cv"],
                     "beacon_score": stats["beacon_score"]},
        )
    except Exception:
        pass


def _on_new_ai_event(ev: dict) -> None:
    """Alerta (O3): aparece un destino IA nuevo (proceso->destino antes no
    visto). El motor de reglas por umbral llega en v2.1; esto es la base."""
    if not _cfg.get("alerts_enabled") or alerts is None:
        return
    # SNI y catalogo son definitivos; la IP cruda es el ultimo refugio.
    host = _provider_of(ev)
    dest = f"{host}:{ev.get('dest_port')}"
    layer = ev.get("ai_layer") or "?"
    # Dedup por (proceso, proveedor): una IP nueva del mismo proveedor (CDN
    # con IPv6 rotatoria) no vuelve a alertar. Antes disparaba por evento.
    key = f"{ev.get('process')}|{host}"
    if key not in _new_dest_alerted:
        _new_dest_alerted.add(key)
        alerts.push(
            "new_ai_destination",
            f"Nuevo destino IA: {ev.get('process')} -> {dest} (capa {layer})",
            details={"event_id": ev.get("id"), "process": ev.get("process"),
                     "dest_ip": ev.get("dest_ip"),
                     "dest_port": ev.get("dest_port"),
                     "catalog_domain": ev.get("catalog_domain"),
                     "ai_layer": layer},
        )
    # Shadow AI: IA detectada que no esta aprobada. Una alerta por
    # proveedor; se reevalua al cambiar la aprobacion (set_config).
    if host and not _is_approved_provider(host) \
            and host not in _shadow_alerted:
        _shadow_alerted.add(host)
        alerts.push(
            "shadow_ai",
            (f"Shadow AI: {ev.get('process')} -> {dest} "
             f"(capa {layer}, proveedor no aprobado)"),
            details={"event_id": ev.get("id"), "process": ev.get("process"),
                     "provider": host, "dest_ip": ev.get("dest_ip"),
                     "dest_port": ev.get("dest_port"), "ai_layer": layer},
        )
    # R2: salida a IA con veredicto autonomous/scheduled. Una alerta por
    # (proceso, proveedor); el reset limpia el dedup y re-alerta.
    verdict = str(ev.get("autonomy_verdict") or "")
    if verdict in ("autonomous", "scheduled") and host:
        key = f"{ev.get('process')}:{host}"
        if key not in _autonomy_alerted:
            _autonomy_alerted.add(key)
            alerts.push(
                "autonomous_ai_call",
                (f"Autonomía: {ev.get('process')} -> {dest} "
                 f"(veredicto {verdict}, score "
                 f"{ev.get('autonomy_score')})"),
                details={"event_id": ev.get("id"),
                         "process": ev.get("process"), "provider": host,
                         "verdict": verdict,
                         "score": ev.get("autonomy_score"),
                         "flags": str(ev.get("autonomy_flags") or "")},
            )


def _prune_retention() -> None:
    """Retencion (F7): eventos/triajes > retention_days; llm_calls >
    retention_days_llm (contenido en claro: vida mas corta). Fail-safe: un
    fallo de prune nunca rompe el arranque ni el ciclo del monitor."""
    try:
        days = int(_cfg.get("retention_days") or 90)
        if store is not None:
            store.prune(days)
        if llm_calls is not None:
            llm_calls.prune(int(_cfg.get("retention_days_llm") or 30))
    except Exception:
        pass


def _record_llm_call(call: dict) -> None:
    """Guarda la llamada del proxy. Con `llm_store_content` apagado solo se
    persisten metadatos y bytes; prompt/respuesta (claro) no."""
    if llm_calls is None:
        return
    if not _cfg.get("llm_store_content", True):
        call = dict(call)
        call["prompt"] = ""
        call["response"] = ""
    llm_calls.record(call)


@app.on_event("startup")
def _start() -> None:
    global store, monitor, sni_capture, llm_calls, alerts
    store = Store(DATA_DIR / "events.db")
    llm_calls = LlmCallStore(DATA_DIR / "llm_calls.db")
    alerts = AlertLog(DATA_DIR / "alerts.log",
                      webhook_url=str(_cfg.get("alert_webhook_url") or ""))
    _prune_retention()
    if _cfg["llm_proxy_enabled"]:
        _set_llm_proxy(True)
    sm = poll_sysmon_events if (_cfg["sysmon_enabled"] and sysmon_available()) else None
    eid22 = poll_sysmon_dns if sm else None  # mismo canal Sysmon que EID 3
    eid1 = poll_sysmon_process_creation if sm else None  # R2: linaje
    sni_fn = None
    if _cfg["tshark_enabled"]:
        path = tshark_path()
        if path is not None:
            iface = find_active_interface(path)
            if iface is not None:
                sni_capture = SniCapture(path, iface)
                sni_capture.start()
                sni_fn = sni_capture.poll_records
    monitor = NetMonitor(store, extra_hosts=list(_cfg["extra_hosts"]),
                         sysmon_fn=sm, eid22_fn=eid22, eid1_fn=eid1,
                         sni_fn=sni_fn, prune_fn=_prune_retention,
                         on_new_event=_on_new_ai_event,
                         on_beacon=_on_beacon)
    monitor.start()
    _auto_stop.clear()
    threading.Thread(target=_auto_classify_loop, daemon=True,
                     name="ai-netwatch-auto-classify").start()
    _net_stop.clear()
    threading.Thread(target=_netbytes_loop, daemon=True,
                     name="ai-netwatch-netbytes").start()


@app.on_event("shutdown")
def _stop() -> None:
    _auto_stop.set()
    _net_stop.set()
    if llm_proxy:
        llm_proxy.stop()
    if sni_capture:
        sni_capture.stop()
    if monitor:
        monitor.stop()
        monitor.join(timeout=3)
    if store:
        store.close()
    if llm_calls:
        llm_calls.close()


def _mask(cfg: dict) -> dict:
    out = dict(cfg)
    if out.get("jev_api_key"):
        out["jev_api_key"] = "***"
    return out


class ConfigRequest(BaseModel):
    alerts_enabled: bool | None = None
    alert_webhook_url: str | None = None
    jev_enabled: bool | None = None
    jev_api_key: str | None = None
    llm_enabled: bool | None = None
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_proxy_enabled: bool | None = None
    llm_proxy_port: int | None = None
    llm_proxy_target: str | None = None
    extra_hosts: list[str] | None = None
    sysmon_enabled: bool | None = None
    tshark_enabled: bool | None = None
    retention_days: int | None = None
    retention_days_llm: int | None = None
    llm_store_content: bool | None = None
    catalog_approved: bool | None = None
    approved_providers: list[str] | None = None
    rules_enabled: bool | None = None
    rule_egress_mb_per_day: float | None = None
    net_bytes_enabled: bool | None = None
    net_bytes_duration_s: int | None = None
    net_bytes_cycle_s: int | None = None
    llm_review_max: int | None = None


class TriageRequest(BaseModel):
    event_ids: list[int] | None = None


class InvestigateRequest(BaseModel):
    event_id: int


class ReviewRequest(BaseModel):
    """B: scope de la revision batch O ids explicitos (no ambos)."""
    scope: str | None = None
    event_ids: list[int] | None = None


class TestRequest(BaseModel):
    target: str  # jev | llm


class ResetRequest(BaseModel):
    confirm: bool = False


@app.get("/api/config")
def get_config():
    out = _mask(_cfg)
    out["tshark_available"] = sni_available()
    out["llm_proxy_running"] = llm_proxy is not None
    return out


@app.post("/api/config")
def set_config(req: ConfigRequest):
    if req.alerts_enabled is not None:
        _cfg["alerts_enabled"] = bool(req.alerts_enabled)
    if req.alert_webhook_url is not None:
        url = (req.alert_webhook_url or "").strip()
        if url and not is_loopback_url(url):
            raise HTTPException(
                400, "alert_webhook_url: solo http(s) loopback"
                    " (p. ej. http://127.0.0.1:9000/alert)")
        _cfg["alert_webhook_url"] = url
        if alerts is not None:
            alerts.webhook_url = url
    if req.jev_enabled is not None:
        _cfg["jev_enabled"] = req.jev_enabled
    if req.jev_api_key is not None:
        _cfg["jev_api_key"] = (req.jev_api_key or "").strip()
    if req.llm_enabled is not None:
        _cfg["llm_enabled"] = req.llm_enabled
    if req.llm_base_url is not None:
        # SSRF: solo http(s) absoluto cuyo host resuelva a loopback.
        from urllib import parse as urlparse
        url = (req.llm_base_url or "").strip()
        parsed = urlparse.urlparse(url)
        if url and (
            parsed.scheme not in ("http", "https") or not parsed.netloc
            or not is_loopback_url(url)
        ):
            raise HTTPException(
                400, "LLM base_url: solo http(s) loopback (p. ej. http://127.0.0.1:8099)"
            )
        _cfg["llm_base_url"] = url
    if req.llm_model is not None:
        _cfg["llm_model"] = (req.llm_model or "").strip()
    if req.llm_proxy_port is not None:
        if not (1 <= int(req.llm_proxy_port) <= 65535):
            raise HTTPException(400, "llm_proxy_port: entre 1 y 65535")
        _cfg["llm_proxy_port"] = int(req.llm_proxy_port)
    if req.llm_proxy_target is not None:
        target = (req.llm_proxy_target or "").strip()
        if not _valid_proxy_target(target):
            raise HTTPException(
                400,
                "llm_proxy_target: solo host:port loopback"
                " (p. ej. 127.0.0.1:8099)")
        _cfg["llm_proxy_target"] = target
    if req.llm_proxy_enabled is not None:
        _cfg["llm_proxy_enabled"] = req.llm_proxy_enabled
        if llm_calls is not None:
            if req.llm_proxy_enabled:
                if not _set_llm_proxy(True):
                    raise HTTPException(
                        409, "proxy LLM no arrancado (¿puerto en uso?)")
            else:
                _set_llm_proxy(False)
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
    if req.tshark_enabled is not None:
        _cfg["tshark_enabled"] = req.tshark_enabled
        _set_sni_capture(req.tshark_enabled)
    for key in ("retention_days", "retention_days_llm"):
        val = getattr(req, key)
        if val is not None:
            v = int(val)
            if not (1 <= v <= 3650):
                raise HTTPException(400, f"{key}: entre 1 y 3650")
            _cfg[key] = v
    if req.llm_store_content is not None:
        _cfg["llm_store_content"] = bool(req.llm_store_content)
    if req.llm_review_max is not None:
        v = int(req.llm_review_max)
        if not (1 <= v <= 100):
            raise HTTPException(400, "llm_review_max: entre 1 y 100")
        _cfg["llm_review_max"] = v
    if (req.net_bytes_enabled is not None
            or req.net_bytes_duration_s is not None
            or req.net_bytes_cycle_s is not None):
        if req.net_bytes_enabled is not None:
            _cfg["net_bytes_enabled"] = bool(req.net_bytes_enabled)
        if req.net_bytes_duration_s is not None:
            v = int(req.net_bytes_duration_s)
            if not (5 <= v <= 600):
                raise HTTPException(
                    400, "net_bytes_duration_s: entre 5 y 600 s")
            _cfg["net_bytes_duration_s"] = v
        if req.net_bytes_cycle_s is not None:
            v = int(req.net_bytes_cycle_s)
            if not (60 <= v <= 86400):
                raise HTTPException(
                    400, "net_bytes_cycle_s: entre 60 y 86400 s")
            _cfg["net_bytes_cycle_s"] = v
    if req.rules_enabled is not None or req.rule_egress_mb_per_day is not None:
        # Cambian las reglas: reevaluar desde cero (re-alerta si sigue
        # firmando).
        _rules_alerted.clear()
        if req.rules_enabled is not None:
            _cfg["rules_enabled"] = bool(req.rules_enabled)
        if req.rule_egress_mb_per_day is not None:
            mb = float(req.rule_egress_mb_per_day)
            if not (0.1 <= mb <= 1_000_000):
                raise HTTPException(
                    400, "rule_egress_mb_per_day: entre 0.1 y 1000000 MB")
            _cfg["rule_egress_mb_per_day"] = mb
    if req.catalog_approved is not None or req.approved_providers is not None:
        # Cambia la aprobacion: reevaluar alertas shadow (los que queden
        # sin aprobar vuelven a alertar al reaparecer).
        _shadow_alerted.clear()
        # La aprobacion tambien cambia 'unapproved' en las reglas.
        _rules_alerted.clear()
        if req.catalog_approved is not None:
            _cfg["catalog_approved"] = bool(req.catalog_approved)
        if req.approved_providers is not None:
            _cfg["approved_providers"] = [
                p.strip().lower() for p in req.approved_providers
                if p and p.strip()
            ]
    _save_config()
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
        base = _effective_llm_base().strip()
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


def _group_by_provider(rows: list[dict]) -> list[dict]:
    """v2.3: colapsa eventos por (proceso, proveedor) para quitar el ruido de
    las IPs rotatorias de CDN. Suma sesiones/polls, cuenta IPs y conserva el
    primer/ultimo avistamiento. Solo agregacion de vista: no toca deteccion."""
    groups: dict[tuple[str, str], dict] = {}
    for e in rows:
        key = (str(e.get("process") or ""), str(e.get("provider") or ""))
        g = groups.get(key)
        if g is None:
            g = {
                "process": e.get("process"), "image": e.get("image"),
                "provider": e.get("provider"), "kind": e.get("kind"),
                "ai_layer": e.get("ai_layer"),
                "autonomy_verdict": e.get("autonomy_verdict"),
                "autonomy_score": e.get("autonomy_score"),
                "iat_cv": e.get("iat_cv"), "dest_port": e.get("dest_port"),
                "sessions": 0, "seen_count": 0, "_ips": set(),
                "first_seen": e.get("first_seen"),
                "last_seen": e.get("last_seen"),
            }
            groups[key] = g
        g["sessions"] += int(e.get("sessions") or 0)
        g["seen_count"] += int(e.get("seen_count") or 0)
        g["_ips"].add(str(e.get("dest_ip")))
        fs, ls = e.get("first_seen"), e.get("last_seen")
        if fs and (not g["first_seen"] or fs < g["first_seen"]):
            g["first_seen"] = fs
        if ls and (not g["last_seen"] or ls > g["last_seen"]):
            g["last_seen"] = ls
    out: list[dict] = []
    for g in groups.values():
        g["ip_count"] = len(g.pop("_ips"))
        out.append(g)
    out.sort(key=lambda g: g.get("last_seen") or "", reverse=True)
    return out


@app.get("/api/events")
def list_events(limit: int = 200, process: str | None = None,
                dest: str | None = None, layer: str | None = None,
                verdict: str | None = None, shadow: bool = False,
                hide_cdn: bool = False, group: str = "provider"):
    """Eventos con filtros de vista (v2.3): proceso/destino/capa/veredicto,
    solo-no-aprobados (shadow), ocultar CDN, y agrupacion por proveedor
    (colapsa el ruido de IPs rotatorias). Nada de esto cambia la deteccion."""
    limit = max(1, min(int(limit), 1000))
    fetch = 1000 if group == "provider" else limit
    rows = _req_store().list_events(limit=fetch, process=process, dest=dest,
                                    layer=layer, verdict=verdict)
    for e in rows:
        e["provider"] = _provider_of(e)
        e["kind"] = destination_kind(e.get("provider") or "")
    if shadow:
        rows = [e for e in rows if e["provider"]
                and not _is_approved_provider(e["provider"])]
    if hide_cdn:
        rows = [e for e in rows if e["kind"] != "cdn"]
    grouped = group == "provider"
    if grouped:
        rows = _group_by_provider(rows)[:limit]
    return {"events": rows, "grouped": grouped}


@app.post("/api/triage")
def triage(req: TriageRequest):
    st = _req_store()
    events = (st.list_events(limit=1000) if req.event_ids is None
              else [e for i in req.event_ids if (e := st.get_event(i))] )
    if not events:
        raise HTTPException(404, "no hay eventos que triar")
    result: dict = {"status": "skipped", "reason": "ai_disabled"}
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
                _effective_llm_base(), _cfg["llm_model"], events, result.get("verdicts"))
    # Destino con identidad IA (sni > catalogo > cache DNS > IP), mismo
    # orden que _provider_of: sin esto la tabla mostraba IPs crudas y
    # CDN, y el trafico a IA no se reconocia como tal.
    payload = {"events": [
        {"id": e["id"], "process": e["process"],
         "dest": f"{_provider_of(e)}:{e['dest_port']}",
         "catalog": e["catalog_domain"], "seen_count": e["seen_count"]}
        for e in events],
        "jev": result, "llm_explanations": explanations}
    st.save_triage(result.get("status", "error"), result.get("model"), payload)
    return payload


@app.get("/api/triages/latest")
def latest_triage():
    t = _req_store().latest_triage()
    if not t:
        raise HTTPException(404, "sin triajes")
    return t


def _jev_verdict_for_event(event_id: int) -> dict | None:
    """Veredicto Jev del ultimo triaje para ese evento (None si no hay).
    El payload guarda el indice i de cada evento en la lista triada; los
    veredictos van por str(i)."""
    t = _req_store().latest_triage()
    if not t:
        return None
    payload = t.get("payload") or {}
    evs = payload.get("events") or []
    verdicts = (payload.get("jev") or {}).get("verdicts") or {}
    for i, e in enumerate(evs):
        if int(e.get("id") or -1) == int(event_id):
            v = verdicts.get(str(i))
            return v if isinstance(v, dict) else None
    return None


def _investigate_context(e: dict) -> dict:
    """v2.4: contexto (truncado, sin secretos) para la asesoria LLM local.
    Display-only: no se guarda nada; Jev sigue siendo el juez."""
    provider = _provider_of(e)
    sdk_map = monitor.sdk_fingerprint_map() if monitor is not None else {}
    fp = sdk_map.get(str(e.get("image") or ""))
    proc = str(e.get("process") or "")
    bytes_local: int | None = None
    calls = llm_calls.list_calls(limit=100) if llm_calls else []
    for c in calls:
        if str(c.get("client_process") or "") == proc:
            b = int(c.get("request_bytes") or 0) + \
                int(c.get("response_bytes") or 0)
            bytes_local = (bytes_local or 0) + b
    iat_cv = e.get("iat_cv")
    return {
        "evento": {
            "process": str(proc)[:80],
            "image": str(e.get("image") or "")[:200],
            "dest_ip": str(e.get("dest_ip") or ""),
            "dest_port": int(e.get("dest_port") or 0),
            "dest_host": str(e.get("dest_host") or "")[:120],
            "sni_domain": str(e.get("sni_domain") or "")[:120],
            "catalog_domain": str(e.get("catalog_domain") or ""),
            "ai_layer": e.get("ai_layer"),
            "seen_count": int(e.get("seen_count") or 1),
            "first_seen": str(e.get("first_seen") or ""),
            "last_seen": str(e.get("last_seen") or ""),
        },
        # Veredicto Jev como DATO (el LLM opina sobre el; nunca lo cambia).
        "jev": _jev_verdict_for_event(int(e["id"])),
        "sesiones": int(e.get("sessions") or 1),
        "iat_cv": iat_cv,
        "beaconing": bool(iat_cv is not None and float(iat_cv) <= 0.3
                          and int(e.get("sessions") or 0) >= 5),
        "autonomia": {
            "verdict": e.get("autonomy_verdict"),
            "score": e.get("autonomy_score"),
            "flags": str(e.get("autonomy_flags") or "")[:200],
        },
        "destino": {"provider": provider,
                    "kind": destination_kind(provider)},
        # None si no hay artefacto verificable (degradacion honesta).
        "sdk_proceso": fp,
        # Bytes egress hacia el LLM local de este proceso (si aplica).
        "bytes_llm_local_proceso": bytes_local,
    }


_REVIEW_SCOPES = ("autonomous", "unapproved", "flagged", "untriaged")


def _review_scope_events(st, scope: str) -> list[dict]:
    """B: resuelve un scope a eventos vivos (mas recientes primero).

    - autonomous: veredicto de autonomia autonomous/scheduled.
    - unapproved: proveedor fuera del catalogo/aprobados (shadow).
    - flagged: marcados en el ultimo triage (severity>=2 o no expected;
      mismo criterio que las explicaciones LLM). Sin triage ok -> [].
    - untriaged: vivos que NO aparecen en el ultimo triage.
    """
    if scope not in _REVIEW_SCOPES:
        raise HTTPException(
            400, f"scope invalido; usa uno de {list(_REVIEW_SCOPES)}")
    rows = st.list_events(limit=1000)
    for e in rows:
        e["provider"] = _provider_of(e)
    if scope == "autonomous":
        return [e for e in rows
                if str(e.get("autonomy_verdict") or "").strip().lower()
                in ("autonomous", "scheduled")]
    if scope == "unapproved":
        return [e for e in rows
                if e["provider"]
                and not _is_approved_provider(e["provider"])]
    t = st.latest_triage()
    if not t:
        return []
    payload = t.get("payload") or {}
    evs = payload.get("events") or []
    verdicts = (payload.get("jev") or {}).get("verdicts") or {}
    ids: set[int] = set()
    if scope == "flagged":
        # Sin triage ok no hay marcas fiables: degradar a vacio, no inventar.
        if (payload.get("jev") or {}).get("status") != "ok":
            return []
        for i, e in enumerate(evs):
            v = verdicts.get(str(i)) or {}
            sev = v.get("severity_score")
            if (sev is not None and float(sev) >= 2
                    or v.get("verdict") != "expected_ai_use"):
                ids.add(int(e.get("id") or -1))
    else:  # untriaged
        for e in evs:
            ids.add(int(e.get("id") or -1))
        return [e for e in rows if int(e["id"]) not in ids]
    return [e for e in rows if int(e["id"]) in ids]


@app.post("/api/review")
def review(req: ReviewRequest):
    """B: revision LLM local por lote (asesoria display-only, sin auto).

    Un scope ('autonomous' | 'unapproved' | 'flagged' | 'untriaged') o
    event_ids explicitos; una llamada LLM por evento con tope llm_review_max.
    Nunca re-puntua ni ejecuta: Jev sigue siendo el juez. Persiste en
    llm_reviews (historial display). Sin LLM -> 'no disponible' sin llamar."""
    st = _req_store()
    if req.event_ids is not None:
        evs = [e for i in dict.fromkeys(req.event_ids)
               if (e := st.get_event(i))]
    else:
        evs = _review_scope_events(st, str(req.scope or "").strip().lower())
    scope = ("event_ids" if req.event_ids is not None
             else str(req.scope or "").strip().lower())
    cap = max(1, int(_cfg.get("llm_review_max", 10)))
    if not (_cfg.get("llm_enabled") and _cfg.get("llm_base_url")
            and _cfg.get("llm_model")):
        return {"status": "unavailable", "reason": "llm_no_configurado",
                "scope": scope, "reviews": []}
    base = _effective_llm_base().strip()
    if not is_loopback_url(base):
        return {"status": "unavailable", "reason": "not_loopback",
                "scope": scope, "reviews": []}
    model = str(_cfg["llm_model"])
    reviews: list[dict] = []
    for e in evs[:cap]:
        r = investigate_event(base, model, _investigate_context(e))
        pq = str(r.get("porque") or "")
        ef = str(r.get("evidencia_faltante") or "")
        row = {"event_id": int(e["id"]),
               "evaluacion": r.get("evaluacion"),
               "porque": pq,
               "evidencia_faltante": ef}
        if r.get("status") == "ok":
            # investigate_event valida evaluacion en ok; str() por si acaso.
            st.save_review(int(e["id"]),
                           str(r.get("evaluacion") or ""), pq, ef)
        else:
            # Fail-safe por evento: no persistir transitorios, pero si
            # devolver la fila con evaluacion None (no fabricar).
            row["reason"] = str(r.get("reason") or "unavailable")
        reviews.append(row)
    return {"status": "ok", "scope": scope, "cap": cap,
            "requested": len(evs), "reviews": reviews}


@app.get("/api/reviews")
def list_reviews(limit: int = 50):
    """B: historial de revisiones LLM (display-only)."""
    st = _req_store()
    limit = max(1, min(int(limit), 200))
    return {"reviews": st.list_reviews(limit=limit)}


@app.post("/api/investigate")
def investigate(req: InvestigateRequest):
    """v2.4: asesoria LLM local por evento (display-only, NO re-puntuacion).

    Jev sigue siendo el juez: esto no altera veredictos ni aprobaciones;
    solo opina sobre el contexto del evento. Sin LLM configurado degrada
    a 'no disponible' (fail-safe). SSRF ya cubierto por llm_base_url."""
    st = _req_store()
    e = st.get_event(req.event_id)
    if not e:
        raise HTTPException(404, "evento no existe")
    if not (_cfg.get("llm_enabled") and _cfg.get("llm_base_url")
            and _cfg.get("llm_model")):
        return {"status": "unavailable", "reason": "llm_no_configurado"}
    base = _effective_llm_base().strip()
    if not is_loopback_url(base):
        return {"status": "unavailable", "reason": "not_loopback"}
    return investigate_event(
        base, str(_cfg["llm_model"]), _investigate_context(e))


def _pid_by_local_ports(ports: set[int]) -> dict[int, int]:
    """Mapa puerto local (IPv4) -> PID propietario via iphlpapi (stdlib
    ctypes). Solo Windows; si falla, devuelve lo que haya logrado."""
    out: dict[int, int] = {}
    if not ports or os.name != "nt":
        return out
    try:
        import ctypes

        class MIB_TCPROW_EX(ctypes.Structure):
            _fields_ = [
                ("dwState", ctypes.c_uint32),
                ("dwLocalAddr", ctypes.c_uint32),
                ("dwLocalPort", ctypes.c_uint32),
                ("dwRemoteAddr", ctypes.c_uint32),
                ("dwRemotePort", ctypes.c_uint32),
                ("dwOwningPid", ctypes.c_uint32),
            ]

        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        size = ctypes.c_uint32()
        proto, table_class = 2, 1  # AF_INET, TABLE_OWNER_PID
        err = iphlpapi.GetExtendedTcpTable(
            None, ctypes.byref(size), False, proto, table_class, 0)
        if err not in (0, 120):  # 120 = ERROR_INSUFFICIENT_BUFFER
            return out
        buf = ctypes.create_string_buffer(size.value)
        err = iphlpapi.GetExtendedTcpTable(
            buf, ctypes.byref(size), False, proto, table_class, 0)
        if err != 0:
            return out
        n = int(ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0])
        rows = (MIB_TCPROW_EX * n).from_buffer_copy(buf, 4)
        for r in rows:
            port = ((r.dwLocalPort >> 8) & 0xFF) * 256 + (r.dwLocalPort & 0xFF)
            if port in ports and r.dwOwningPid:
                out[port] = r.dwOwningPid
    except Exception:
        pass
    return out


def _port_of(addr: str | None) -> int | None:
    if not addr or ":" not in addr:
        return None
    try:
        return int(addr.rsplit(":", 1)[1])
    except ValueError:
        return None


def _link_calls(out: list[dict], events: list[dict], target_host: str,
                target_port: int, pidmap: dict[int, str]) -> None:
    """Enlace local (in-place): llamada -> eventos de red con mismo destino,
    proceso y ventana temporal (120 s). Vacio es legitimo: el destino solo
    genera evento si esta siendo vigilado (catalogo/extra hosts)."""

    def _ts(s):
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%SZ")
        except (ValueError, TypeError):
            return None

    cands = []
    for e in events:
        if (e.get("dest_ip") == target_host
                and e.get("dest_port") == target_port):
            t = _ts(e.get("last_seen", ""))
            if t:
                cands.append((e.get("process"), t, e["id"]))
    for c in out:
        proc = pidmap.get(c.get("client_pid") or 0)
        rel = []
        t = _ts(c.get("ts", ""))
        if t and proc:
            rel = [eid for (p, et, eid) in cands
                   if p == proc and abs((et - t).total_seconds()) <= 120]
        c["client_process"] = proc or ""
        c["related_event_ids"] = sorted(set(rel))[:5]


def _calls_payload(calls: list[dict]) -> list[dict]:
    pids = _pid_by_local_ports({p for p in (_port_of(c.get("client_addr"))
                                            for c in calls) if p})
    out = []
    for c in calls:
        c = dict(c)
        port = _port_of(c.get("client_addr"))
        c["client_pid"] = pids.get(port) if port else None
        out.append(c)
    target_host, target_port = (llm_proxy.target if llm_proxy else ("", 0))
    pidmap = getattr(monitor, "_pidmap_cache", {}) or {}
    events = (store.list_events(limit=2000)
              if (target_host and store) else [])
    _link_calls(out, events, target_host, target_port, pidmap)
    return out


@app.get("/api/llm/calls")
def list_llm_calls(limit: int = 100):
    limit = max(1, min(int(limit), 1000))
    calls = llm_calls.list_calls(limit=limit) if llm_calls else []
    return {"calls": _calls_payload(calls)}


@app.get("/api/llm/calls/{call_id}")
def get_llm_call(call_id: int):
    c = llm_calls.get_call(call_id) if llm_calls else None
    if not c:
        raise HTTPException(404, "llamada no encontrada")
    return _calls_payload([c])[0]


@app.post("/api/llm/calls/reset")
def reset_llm_calls(req: ResetRequest):
    if not req.confirm:
        raise HTTPException(400, 'se requiere {"confirm": true}')
    n = llm_calls.clear() if llm_calls else 0
    return {"calls_removed": n}


@app.get("/api/shadow")
def shadow_providers() -> dict:
    """Shadow AI: IA detectada que no esta aprobada, agrupado por
    proveedor. Aprobado = catalogo (si catalog_approved) + approved."""
    st = _req_store()
    groups: dict[str, dict] = {}
    for r in st.ai_events():
        prov = _provider_of(r)
        if not prov or _is_approved_provider(prov):
            continue
        g = groups.get(prov)
        if g is None:
            g = groups[prov] = {
                "provider": prov, "processes": [], "layers": [],
                "seen_count": 0, "first_seen": r["first_seen"],
                "last_seen": r["last_seen"], "event_ids": [],
            }
        if r["process"] not in g["processes"]:
            g["processes"].append(r["process"])
        layer = str(r.get("ai_layer") or "?")
        if layer not in g["layers"]:
            g["layers"].append(layer)
        g["seen_count"] += int(r.get("seen_count") or 1)
        g["first_seen"] = min(g["first_seen"], r["first_seen"])
        g["last_seen"] = max(g["last_seen"], r["last_seen"])
        if len(g["event_ids"]) < 100:
            g["event_ids"].append(r["id"])
    for g in groups.values():
        g["processes"].sort()
        g["layers"].sort()
    items = sorted(groups.values(), key=lambda g: -g["seen_count"])
    return {"shadow": items, "count": len(items)}


@app.get("/api/autonomy")
def autonomy_state(verdict: str | None = None, process: str | None = None,
                   provider: str | None = None, group: str = "none",
                   limit: int = 100) -> dict:
    """R2: senales globales de autonomia + eventos con veredicto. Las
    senales son del momento (no historico). Filtros de vista (A3):
    veredicto (autonomous/scheduled/user_driven/unknown), proceso y
    proveedor por substring, y agrupacion por proveedor como en la tarjeta
    de eventos. `counts` = reparticion de veredictos sobre TODOS los
    eventos vivos (sin filtros): para los contadores de la UI."""
    st = _req_store()
    sig = {"idle_seconds": autonomy.get_idle_seconds(),
           "locked": autonomy.is_session_locked(),
           "foreground_pid": autonomy.get_foreground_pid()}
    limit = max(1, min(int(limit), 1000))
    rows = st.list_events(limit=1000)
    for e in rows:
        e["provider"] = _provider_of(e)
        e["kind"] = destination_kind(e.get("provider") or "")
    counts: dict[str, int] = {"autonomous": 0, "scheduled": 0,
                              "user_driven": 0, "unknown": 0}
    for e in rows:
        v = str(e.get("autonomy_verdict") or "").strip().lower()
        counts[v if v in ("autonomous", "scheduled", "user_driven")
               else "unknown"] += 1
    if verdict:
        if verdict == "unknown":
            rows = [e for e in rows
                    if str(e.get("autonomy_verdict") or "").strip().lower()
                    not in ("autonomous", "scheduled", "user_driven")]
        else:
            rows = [e for e in rows
                    if str(e.get("autonomy_verdict") or "").strip().lower()
                    == verdict]
    if process:
        p = str(process).strip().lower()
        rows = [e for e in rows if p in str(e.get("process") or "").lower()]
    if provider:
        p = str(provider).strip().lower()
        rows = [e for e in rows if p in str(e.get("provider") or "").lower()]
    grouped = group == "provider"
    if grouped:
        rows = _group_by_provider(rows)[:limit]
    else:
        rows = rows[:limit]
    return {"signals": sig, "counts": counts,
            "events": rows, "grouped": grouped}


@app.get("/api/processes")
def processes_fichas() -> dict:
    """v2.3: ficha de proceso por fingerprint de SDK IA (display; no toca
    deteccion ni aprobaciones). Vacia si no hay monitor."""
    out: list[dict] = []
    if monitor is not None:
        m = monitor.sdk_fingerprint_map()
        out = [{"image": img, **fp} for img, fp in sorted(m.items())]
    return {"processes": out}


@app.get("/api/dashboard")
def dashboard(days: int = 7) -> dict:
    """Panel (v2.0): agrega lo que ya existe — actividad diaria, top
    proveedores/procesos por presencia, reparto por capa, shadow y LLM
    local. Bytes cloud: reales si el colector elevado ha volcado datos;
    si no, 'no disponible' con motivo (nunca un cero que engane)."""
    days = max(1, min(int(days), 365))
    st = _req_store()
    evs = st.events_since(days)
    providers: dict[str, int] = {}
    processes: dict[str, int] = {}
    layers: dict[str, int] = {}
    # A4: capa dominante por proveedor (para el label API/web/CDN + capa
    # junto al nombre en el panel).
    prov_layers: dict[str, dict[str, int]] = {}
    for e in evs:
        seen = int(e.get("seen_count") or 1)
        prov = _provider_of(e)
        if prov:
            providers[prov] = providers.get(prov, 0) + seen
            pl = prov_layers.setdefault(prov, {})
            layer = str(e.get("ai_layer") or "none")
            pl[layer] = pl.get(layer, 0) + seen
        proc = str(e.get("process") or "?")
        processes[proc] = processes.get(proc, 0) + seen
        layer = str(e.get("ai_layer") or "none")
        layers[layer] = layers.get(layer, 0) + seen

    def _top_providers() -> list[dict]:
        out: list[dict] = []
        for k, v in sorted(providers.items(), key=lambda kv: -kv[1])[:10]:
            pl = prov_layers.get(k) or {}
            dom_layer = ("none" if not pl else
                         sorted(pl.items(),
                                key=lambda kv: (-kv[1], kv[0]))[0][0])
            out.append({"name": k, "seen_count": v,
                        "kind": destination_kind(k),
                        "layer": dom_layer})
        return out

    def _top(d: dict[str, int]) -> list[dict]:
        return [{"name": k, "seen_count": v}
                for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:10]]

    # A4: resumen agregado de la ventana (totales + cardinalidades).
    summary = {"days": days,
               "events": len(evs),
               "seen_total": sum(int(e.get("seen_count") or 1) for e in evs),
               "processes": len({str(e.get("process") or "?") for e in evs}),
               "providers": len(providers)}

    # v2.3: label de SDK IA por nombre de proceso (display; la ficha
    # completa esta en /api/processes).
    sdk_map: dict[str, dict] = (monitor.sdk_fingerprint_map()
                                if monitor is not None else {})
    proc_sdk: dict[str, str] = {}
    for img in sorted(sdk_map):
        base = img.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        proc_sdk.setdefault(base, sdk_map[img]["label"])
    top_procs = _top(processes)
    for row in top_procs:
        row["sdk"] = proc_sdk.get(str(row["name"]).lower(), "")
    return {
        "days": days,
        "summary": summary,
        "daily": st.stats(days=days),
        "top_providers": _top_providers(),
        "top_processes": top_procs,
        "layers": [{"layer": k, "seen_count": v}
                   for k, v in sorted(layers.items(),
                                      key=lambda kv: -kv[1])],
        "shadow_count": shadow_providers()["count"],
        "llm_calls": (llm_calls.summary(days=days)
                      if llm_calls is not None else None),
        "cloud_bytes": _cloud_bytes(),
    }


def _cloud_bytes() -> dict:
    """v2.2: bytes remotos reales si el colector elevado ha volcado datos;
    si no, 'no disponible' con motivo (nunca un cero que engane)."""
    egress = _egress_rows()
    if not egress:
        return {"available": False,
                "reason": ("bytes remotos: colector elevado sin datos "
                           "(ETW Kernel-Network requiere admin; activar en "
                           "config net_bytes_enabled)"),
                "last_meta": _net_last_meta,
                "spawn_method": _netbytes_spawn_method}
    total = sum(r["bytes"] for r in egress)
    return {"available": True,
            "total_bytes": total,
            "last_meta": _net_last_meta,
            "spawn_method": _netbytes_spawn_method,
            "window": ("acumulado desde inicio del colector elevado"
                       " (ventanas sin solapes)"),
            # v2.3: host/kind pasan al API (label api/web/cdn y hostname
            # resuelto aunque el provider quede 'desconocido').
            "by_provider": [{"provider": r["provider"],
                             "host": r.get("host", ""),
                             "kind": r.get("kind", ""),
                             "bytes": r["bytes"]}
                            for r in sorted(egress,
                                            key=lambda x: -x["bytes"])[:10]]}


@app.get("/api/rules")
def list_rules():
    """v2.2: estado actual de las reglas (evalua ahora, sin cache)."""
    results = rules.evaluate(
        _rules_events(),
        egress_mb_per_day=float(_cfg.get("rule_egress_mb_per_day", 500)),
        egress=_egress_rows() or None)
    return {"rules": results}


@app.get("/api/alerts")
def list_alerts(since_id: int = 0):
    return {"alerts": alerts.list(since_id) if alerts else [],
            "enabled": bool(_cfg.get("alerts_enabled"))}


@app.get("/api/stats")
def stats(days: int = 7):
    days = max(1, min(int(days), 365))
    st = _req_store()
    live = st.list_events(limit=1000)
    return {
        "daily": st.stats(days=days),
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
    out = _req_store().reset()
    # Sin eventos no hay dedup que conserve: re-alerta desde cero.
    _shadow_alerted.clear()
    _autonomy_alerted.clear()
    _beacon_alerted.clear()
    _rules_alerted.clear()
    _new_dest_alerted.clear()
    return {**out, "daily_stats_kept": True}


@app.get("/api/export/json")
def export_json():
    st = _req_store()
    events = st.list_events(limit=1000)
    triage = st.latest_triage()
    return JSONResponse(
        {"tool": "ai_net_monitor", "version": VERSION, "events": events,
         "latest_triage": triage["payload"] if triage else None},
        headers={"Content-Disposition":
                 'attachment; filename="ai-netwatch.json"'})


@app.get("/api/export/pdf")
def export_pdf():
    # Solo datos del store; nunca config/keys (ver tests de seguridad).
    st = _req_store()
    events = st.list_events(limit=1000)
    triage = st.latest_triage()
    daily = st.stats(days=7)
    pdf = build_report_pdf(VERSION, events,
                           triage["payload"] if triage else None, daily)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition":
                             'attachment; filename="ai-netwatch.pdf"'})


@app.get("/api/export/csv")
def export_csv():
    events = _req_store().list_events(limit=1000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "process", "image", "protocol", "dest_ip", "dest_port",
                "dest_host", "sni_domain", "catalog_domain", "seen_count",
                "first_seen", "last_seen"])
    for e in events:
        w.writerow([e["ts"], e["process"], e.get("image") or "",
                    e.get("protocol", "tcp"), e["dest_ip"], e["dest_port"],
                    e["dest_host"] or "", e.get("sni_domain") or "",
                    e["catalog_domain"] or "",
                    e["seen_count"], e["first_seen"], e["last_seen"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             'attachment; filename="ai-netwatch.csv"'})


def _evidence_events(days: int) -> list[dict]:
    """Eventos de la ventana ordenados (first_seen, id): orden estable para
    cadena de hashes y bundle STIX reproducible."""
    st = _req_store()
    return sorted(st.events_since(days),
                  key=lambda e: (str(e.get("first_seen")),
                                 int(e.get("id") or 0)))


@app.get("/api/evidence/chain")
def evidence_chain(days: int = 7):
    """v2.3: cadena de hashes sobre los eventos (JSONL). Cada fila liga
    indice + hash anterior + evento; alterar cualquier fila rompe el resto
    y es verificable offline (evidence.verify_chain)."""
    days = max(1, min(int(days), 365))
    evs = _evidence_events(days)
    if not evs:
        raise HTTPException(404, "no events in window")
    rows = evidence.hash_chain(evs)
    body = "\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True)
                    for r in rows) + "\n"
    stamp = datetime.now().strftime("%Y%m%d")
    return Response(body.encode("utf-8"),
                    media_type="application/x-ndjson",
                    headers={"Content-Disposition":
                             f'attachment; filename="ai-netwatch-chain-{stamp}.jsonl"'})


@app.get("/api/evidence/stix")
def evidence_stix(days: int = 7):
    """v2.3: bundle STIX 2.1 sobre los eventos (JSON). IDs deterministas:
    misma ventana -> mismo bundle, reproducible para evidencia."""
    days = max(1, min(int(days), 365))
    evs = _evidence_events(days)
    if not evs:
        raise HTTPException(404, "no events in window")
    first = str(evs[0].get("first_seen") or "")
    last = str(evs[-1].get("last_seen") or "")
    bundle = evidence.stix_bundle(
        evs,
        title=f"AI-NETWATCH evidencia {first} .. {last}",
        description=(f"{len(evs)} conexiones a destinos IA (ventana de "
                     f"{days} dias). Generado por ai-netwatch v{VERSION}."))
    stamp = datetime.now().strftime("%Y%m%d")
    return Response(json.dumps(bundle, ensure_ascii=False, indent=2),
                    media_type="application/stix+json;version=2.1",
                    headers={"Content-Disposition":
                             f'attachment; filename="ai-netwatch-stix-{stamp}.json"'})


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
