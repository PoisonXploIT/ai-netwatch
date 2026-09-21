"""Monitor de red (solo stdlib): polling de conexiones establecidas y
observacion de las que van a destinos cloud AI del catalogo o extra.

Fuente: `Get-NetTCPConnection` via PowerShell (sin dependencias). v1 no ve
bytes ni dominios fiables: ve proceso + destino IP/puerto + periodicidad.
v2 (futuro): Sysmon EventID 3 para bytes y dominio real.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from pathlib import Path

from ai_catalog import match_domain
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


def poll_connections() -> list[dict]:
    """Conexiones establecidas: [{remote_ip, remote_port, pid}]."""
    out = _run_ps(
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue"
        " | Select-Object -Property RemoteAddress,RemotePort,OwningProcess"
        " | ConvertTo-Json -Compress"
    )
    rows = json.loads(out or "[]")
    if isinstance(rows, dict):
        rows = [rows]
    conns = []
    for r in rows:
        ip = str(r.get("RemoteAddress") or "").strip()
        port = int(r.get("RemotePort") or 0)
        pid = int(r.get("OwningProcess") or 0)
        if ip and port:
            conns.append({"remote_ip": ip, "remote_port": port, "pid": pid})
    return conns


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
_DNS_IP_RE = re.compile(r"(?i)^\s*Address(?:es)?\s*:?.*?([0-9a-fA-F.:]{7,})\s*$")
_DNS_NAME_PATTERNS = [
    # Win7/XP:  "Name is        : api.groq.com"
    re.compile(r"(?i)^\s*Name\s+is\s*:?\s*(\S+)"),
    # ipconfig antiguo: "Host Name . . . . : x"
    re.compile(r"(?i)^\s*Host Name(?:\s*\.\s*)*:?\s*(\S+)"),
    # Win10/11: "DNS Address . . . . . . . : api.openai.com"
    re.compile(r"(?i)^\s*DNS Address(?:\s*\.\s*)*:?\s*(\S+)"),
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
        m = _DNS_IP_RE.match(line)
        if m and current_name:
            ip = m.group(1)
            if ":" not in ip:  # solo IPv4 en v1
                result.setdefault(ip, current_name)
            current_name = None
    return result


class NetMonitor(threading.Thread):
    """Hilo daemon que observa conexiones y las guarda en el Store.

    `extra_hosts`: lista de IPs o dominios extra del usuario (solo memoria).
    """

    def __init__(self, store: Store, poll_fn=poll_connections,
                 pidmap_fn=poll_pid_map, dns_fn=poll_dns_cache,
                 interval: float = _POLL_S, extra_hosts: list[str] | None = None):
        super().__init__(daemon=True, name="ai-netwatch-monitor")
        self.store = store
        self._poll = poll_fn
        self._pidmap = pidmap_fn
        self._dns = dns_fn
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

    def _cycle(self) -> None:
        pidmap = getattr(self, "_pidmap_cache", {})
        dns = getattr(self, "_dns_cache", {})
        for c in self._poll():
            ip = c["remote_ip"]
            host = dns.get(ip)
            # El catalogo son dominios; Get-NetTCPConnection da IPs -> el match
            # real va por la caché DNS (best effort) o por hosts extra.
            dom = match_domain(host or ip) or self._match_extra(ip, host)
            if not dom:
                continue
            proc = pidmap.get(c["pid"], f"pid:{c['pid']}")
            self.store.observe_connection(
                process=proc, dest_ip=ip, dest_port=c["remote_port"],
                catalog_domain=dom, dest_host=dns.get(ip),
            )

    def run(self) -> None:
        last_pidmap = 0.0
        last_dns = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now - last_pidmap >= _PIDMAP_REFRESH_S:
                    self._pidmap_cache = self._pidmap()
                    last_pidmap = now
                if now - last_dns >= _DNS_REFRESH_S:
                    self._dns_cache = self._dns()
                    last_dns = now
                self._cycle()
            except Exception as e:  # fail-safe: el monitor nunca rompe el server
                self.errors.append(f"{time.strftime('%H:%M:%S')} {type(e).__name__}: {e}")
                self.errors = self.errors[-10:]
            self._stop.wait(self.interval)
