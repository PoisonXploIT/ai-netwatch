"""Monitor de red (solo stdlib): polling de conexiones establecidas y
observacion de las que van a destinos cloud AI del catalogo o extra.

Fuente: `Get-NetTCPConnection` via PowerShell (sin dependencias). v1 no ve
bytes ni dominios fiables: ve proceso + destino IP/puerto + periodicidad.
v2 (futuro): Sysmon EventID 3 para bytes y dominio real.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import autonomy
from ai_catalog import KNOWN_AI_DOMAINS, match_domain
from ai_classifier import classify_domain
from store import Store

_POLL_S = 5.0
_PIDMAP_REFRESH_S = 30.0
_DNS_REFRESH_S = 60.0


def _run_ps(script: str, timeout: int = 20) -> str:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.stdout


def _parse_conns(out: str, protocol: str) -> list[dict]:
    rows = json.loads(out or "[]")
    if isinstance(rows, dict):
        rows = [rows]
    conns = []
    for r in rows:
        ip = str(r.get("RemoteAddress") or "").strip()
        port = int(r.get("RemotePort") or 0)
        pid = int(r.get("OwningProcess") or 0)
        if ip and port:
            conns.append({"remote_ip": ip, "remote_port": port,
                          "pid": pid, "protocol": protocol})
    return conns


def poll_connections() -> list[dict]:
    """Conexiones TCP establecidas: [{remote_ip, remote_port, pid, protocol}]."""
    out = _run_ps(
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue"
        " | Select-Object -Property RemoteAddress,RemotePort,OwningProcess"
        " | ConvertTo-Json -Compress"
    )
    return _parse_conns(out, "tcp")


def poll_udp_endpoints() -> list[dict]:
    """Endpoints UDP con remoto (Get-NetUDPEndpoint): mismo shape, protocol=udp.

    Menos relevante para nube IA (casi todo es TCP/TLS 443) pero barato de
    mirar y descarta trafico oculto por UDP."""
    out = _run_ps(
        "Get-NetUDPEndpoint -ErrorAction SilentlyContinue |"
        " Where-Object { $_.RemoteAddress } |"
        " Select-Object -Property RemoteAddress,RemotePort,OwningProcess |"
        " ConvertTo-Json -Compress"
    )
    return _parse_conns(out, "udp")


def poll_pid_map() -> dict[int, str]:
    """PID -> nombre de proceso (ej. 'chrome.exe')."""
    out = _run_ps(
        "Get-CimInstance Win32_Process"
        " | Select-Object -Property ProcessId,Name"
        " | ConvertTo-Json -Compress"
    )
    rows = json.loads(out or "[]")
    if isinstance(rows, dict):
        rows = [rows]
    m: dict[int, str] = {}
    for r in rows:
        try:
            pid = int(r.get("ProcessId"))
        except (TypeError, ValueError):
            continue
        name = str(r.get("Name") or "").strip()
        if pid and name:
            m[pid] = name
    return m


# Formato Win7/XP: "Name is : x" / "Address: y"
# Formato Win10/11: "DNS Address . . . . : x" / "Addresses: y"
_DNS_IP_PATTERNS = [
    # Win en-US: "Addresses: 1.2.3.4" / "Address        : 9.9.9.9"
    re.compile(r"(?i)^\s*Address(?:es)?\s*:?.*?([0-9a-fA-F.:]{7,})\s*$"),
    # Win en-es: "Un registro (host). . : 3.173.21.63"
    re.compile(r"(?i)^\s*Un registro \(host\)[.\s]*:?\s*([0-9a-fA-F.:]+)\s*$"),
]
_DNS_NAME_PATTERNS = [
    # Win7/XP:  "Name is        : api.groq.com"
    re.compile(r"(?i)^\s*Name\s+is\s*:?\s*(\S+)"),
    # ipconfig antiguo: "Host Name . . . . : x"
    re.compile(r"(?i)^\s*Host Name(?:\s*\.\s*)*:?:?\s*(\S+)"),
    # Win10/11 en-US: "DNS Address . . . . . . . : api.openai.com"
    re.compile(r"(?i)^\s*DNS Address(?:\s*\.\s*)*:?:?\s*(\S+)"),
    # Win10/11 en-es: "Nombre de registro  . : api.deepseek.com"
    re.compile(r"(?i)^\s*Nombre de registro[.\s]*:?\s*(\S+)"),
]


def poll_dns_cache() -> dict[str, str]:
    """Caché DNS del sistema: IP -> nombre (best effort, para enriquecer)."""
    out = _run_ps("ipconfig /displaydns", timeout=25)
    result: dict[str, str] = {}
    current_name: str | None = None
    for raw in out.splitlines():
        line = raw.strip()
        m = next((p.match(line) for p in _DNS_NAME_PATTERNS if p.match(line)), None)
        if m:
            current_name = m.group(1).lower().rstrip(".")
            continue
        m = next((p.match(line) for p in _DNS_IP_PATTERNS if p.match(line)), None)
        if m and current_name:
            ip = m.group(1)
            if ":" not in ip:  # solo IPv4 en v1
                result.setdefault(ip, current_name)
            current_name = None
    return result


_CATALOG_IP_REFRESH_S = 300.0


def poll_catalog_ips(extra_hosts: list[str] | None = None) -> dict[str, str]:
    """Resuelve activamente dominios del catalogo + extra -> IP -> dominio.

    Indispensable: muchos proveedores saltan por CNAME (DeepSeek ->
    cloudfront.net) y la caché DNS solo guarda el nombre final, asi que el
    match por nombre nunca llega al dominio real. Parallelizado (stdlib).
    """
    from concurrent.futures import ThreadPoolExecutor
    domains = list(KNOWN_AI_DOMAINS)
    for h in (extra_hosts or []):
        if "." in h and not re.match(r"^[0-9.]+$", h):
            domains.append(h.lower())
    out: dict[str, str] = {}

    def _resolve(d: str) -> tuple[str, str | None]:
        try:
            return d, socket.gethostbyname(d)
        except Exception:
            return d, None

    with ThreadPoolExecutor(max_workers=12) as ex:
        for dom, ip in ex.map(_resolve, domains):
            if ip:
                out.setdefault(ip, dom.lower())
    return out


class NetMonitor(threading.Thread):
    """Hilo daemon que observa conexiones y las guarda en el Store.

    `extra_hosts`: lista de IPs o dominios extra del usuario (solo memoria).
    """

    def __init__(self, store: Store, poll_fn=poll_connections,
                 pidmap_fn=poll_pid_map, dns_fn=poll_dns_cache,
                 udp_fn=poll_udp_endpoints, catalog_fn=poll_catalog_ips,
                 sysmon_fn=None, sni_fn=None, eid22_fn=None, eid1_fn=None,
                 prune_fn=None, on_new_event=None,
                 interval: float = _POLL_S, extra_hosts: list[str] | None = None):
        super().__init__(daemon=True, name="ai-netwatch-monitor")
        self.store = store
        self._poll = poll_fn
        self._pidmap = pidmap_fn
        self._dns = dns_fn
        self._udp = udp_fn
        self._catalog_ips = catalog_fn
        self._sysmon = sysmon_fn
        self._sni_poll = sni_fn
        self._eid22 = eid22_fn
        self._eid1 = eid1_fn
        # R2: linaje proceso -> padre (Sysmon EID 1) y senales de autonomia
        # con cache corta (las llamadas Win32 son baratas pero no gratis).
        self._lineage: dict[str, dict] = {}
        self._aut_cache: tuple[float, dict] | None = None
        self._prune = prune_fn
        self._on_new_event = on_new_event
        self._eid22_cache: dict[str, str] = {}
        self._sm_last_recid = 0
        self._catalog_ip_cache: dict[str, str] = {}
        self.interval = interval
        self.extra_hosts: list[str] = [h.lower() for h in (extra_hosts or [])]
        self._stop = threading.Event()
        self.errors: list[str] = []

    def stop(self) -> None:
        self._stop.set()

    def _match_extra(self, ip: str, host: str | None) -> str | None:
        for h in self.extra_hosts:
            if h == ip or (host and (host.lower().endswith(h) or host.lower() == h)):
                return f"extra:{h}"
        return None

    def _process_conn(self, ip: str, port: int, pid: int,
                      protocol: str, image: str | None) -> None:
        pidmap = getattr(self, "_pidmap_cache", {})
        dns = getattr(self, "_dns_cache", {})
        host = dns.get(ip)
        # Match por orden: nombre (caché DNS), IP activa del catalogo
        # (cubre CNAME/CDN), y hosts extra.
        dom = (match_domain(host or ip) or self._catalog_ip_cache.get(ip)
               or self._match_extra(ip, host))
        # 4) EID 22 (DnsQuery): dominio resuelto por el proceso aunque no este
        #    en catalogo ni caché DNS. Solo si se clasifica como IA, para no
        #    inundar con trafico no-IA de internet. Cobertura universal (R1).
        if not dom:
            cand = self._eid22_cache.get(ip)
            if cand and classify_domain(cand).is_ai:
                dom = cand
        if not dom:
            return
        name = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] if image else None
        proc = name or pidmap.get(pid, f"pid:{pid}")
        cls = classify_domain(dom[6:] if dom.startswith("extra:") else dom)
        is_new = not self.store.has_event(proc, ip, port)
        aut = self._autonomy_for(name, pid)
        ev = self.store.observe_connection(
            process=proc, dest_ip=ip, dest_port=port,
            catalog_domain=dom, dest_host=dns.get(ip),
            protocol=protocol, image=image, ai_layer=cls.layer,
            autonomy_score=aut["score"],
            autonomy_flags=",".join(aut["flags"]) or None,
            autonomy_verdict=aut["verdict"],
        )
        if is_new and self._on_new_event is not None:
            self._on_new_event(ev)

    def _cycle(self, conns: list[dict] | None = None) -> None:
        if conns is None:
            conns = self._poll()
        for c in conns:
            self._process_conn(c["remote_ip"], c["remote_port"], c["pid"],
                               c.get("protocol", "tcp"), None)

    def _sysmon_cycle(self) -> None:
        """Eventos EventID 3 de Sysmon desde el ultimo RecordId visto.

        Primera llamada: fija el watermark SIN backfill (no inunda con
        historico). A partir de ahi, cada evento nuevo pasa por el mismo
        pipeline que el polling (match catalogo + store).
        """
        if self._sysmon is None:
            return
        events = self._sysmon()
        if not events:
            return
        if self._sm_last_recid == 0:
            self._sm_last_recid = max(e["record_id"] for e in events)
            return
        new = [e for e in events if e["record_id"] > self._sm_last_recid]
        if not new:
            return
        self._sm_last_recid = max(e["record_id"] for e in new)
        for e in new:
            self._process_conn(e["dest_ip"], e["dest_port"], e["pid"],
                               e.get("protocol", "tcp"), e.get("image") or None)

    def _autonomy_for(self, name: str | None, pid: int) -> dict:
        """Veredicto de autonomia (R2) para un proceso. Fail-safe: si las
        senales no estan, queda unknown sin romper el pipeline."""
        sig = self._autonomy_signals()
        lin = self._lineage.get((name or "").lower())
        try:
            return autonomy.evaluate(
                name or "", pid,
                idle_seconds=sig["idle_seconds"],
                locked=sig["locked"],
                foreground_pid=sig["foreground_pid"],
                parent_image=(lin or {}).get("parent_image"),
                parent_process=(lin or {}).get("parent_process"),
                parent_cmdline=(lin or {}).get("parent_cmdline"),
            )
        except Exception:
            return {"score": 0, "flags": [], "verdict": autonomy.UNKNOWN}

    def _autonomy_signals(self) -> dict:
        now = time.monotonic()
        if self._aut_cache and now - self._aut_cache[0] < 5.0:
            return self._aut_cache[1]
        st = {"idle_seconds": autonomy.get_idle_seconds(),
              "locked": autonomy.is_session_locked(),
              "foreground_pid": autonomy.get_foreground_pid()}
        self._aut_cache = (now, st)
        return st

    def _eid1_cycle(self) -> None:
        """Linaje proceso -> padre desde Sysmon EID 1 (R2).

        Sin watermark: toma los 300 mas recientes y el ultimo gana por
        proceso (idempotente, como el cache de EID 22)."""
        if self._eid1 is None:
            return
        evs = self._eid1()
        if not evs:
            return
        for e in evs:  # de antiguo a reciente: el ultimo gana
            proc = str(e.get("process") or "").strip().lower()
            if proc:
                self._lineage[proc] = {
                    "parent_image": e.get("parent_image"),
                    "parent_process": e.get("parent_process"),
                    "parent_cmdline": e.get("parent_cmdline"),
                }

    def _eid22_cycle(self) -> None:
        """Refresca IP -> dominio desde Sysmon EID 22 (DnsQuery).

        Usa QueryResults (los IPs resueltos): el join es proceso->dominio->IP
        real, no heuristico. Persiste entre ciclos (una resolucion sigue
        valiendo hasta que llegue una mas reciente). Sin datos -> conserva.
        """
        if self._eid22 is None:
            return
        evs = self._eid22()
        if not evs:
            return
        m: dict[str, str] = {}
        for e in evs:  # de antiguo a reciente: el ultimo gana
            dom = e.get("query_name")
            if not dom:
                continue
            for ip in e.get("ips", []):
                if ip:
                    m[ip] = dom
        if m:
            self._eid22_cache = m

    def _sni_cycle(self) -> None:
        """Drena los SNI capturados y los asocia a eventos por (ip, puerto).

        El SNI es definitivo sobre la caché DNS: rellena sni_domain siempre;
catalog_domain solo si estaba vacio.
        """
        if self._sni_poll is None:
            return
        for rec in self._sni_poll():
            self.store.attach_sni(
                rec["dst_ip"], rec["dst_port"], rec["sni"],
                catalog=match_domain(rec["sni"]))

    def run(self) -> None:
        last_pidmap = 0.0
        last_dns = 0.0
        last_catip = 0.0
        # Retencion (F7): el primer prune lo hace el server en _start; aqui
        # solo el refresco periodico (24 h).
        last_prune = time.monotonic()
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now - last_pidmap >= _PIDMAP_REFRESH_S:
                    self._pidmap_cache = self._pidmap()
                    last_pidmap = now
                if now - last_dns >= _DNS_REFRESH_S:
                    self._dns_cache = self._dns()
                    last_dns = now
                if now - last_catip >= _CATALOG_IP_REFRESH_S:
                    self._catalog_ip_cache = self._catalog_ips(self.extra_hosts)
                    last_catip = now
                if self._prune is not None and now - last_prune >= 86400.0:
                    self._prune()
                    last_prune = now
                conns = self._poll() + self._udp()
                self._eid22_cycle()
                self._cycle(conns)
                self._sysmon_cycle()
                self._eid1_cycle()
                self._sni_cycle()
            except Exception as e:  # fail-safe: el monitor nunca rompe el server
                self.errors.append(f"{time.strftime('%H:%M:%S')} {type(e).__name__}: {e}")
                self.errors = self.errors[-10:]
            self._stop.wait(self.interval)
