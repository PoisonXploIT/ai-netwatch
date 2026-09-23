"""Fuente de eventos Sysmon v15 (EventID 3) para AI NetWatch.

Canal: Microsoft-Windows-Sysmon/Operational (v15; en v14 era
Microsoft-Windows-Sysmon-Operational). Servicio: Sysmon64.

Esquema v15 (cambiado respecto a v14):
  DestinationIp (antes DestinationAddress), DestinationHostname,
  Protocol minúscula, UtcTime, Image ruta completa, ProcessId, RecordId.

Ventaja sobre el polling de Get-NetTCPConnection: es EVENTO, no foto ->
las conexiones breves (<5 s) tambien quedan registradas, y llega la ruta
completa del proceso (detecta masquerading: svchost.exe fuera de System32).
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from monitor import _run_ps

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

_PS_CMD = (
    "$ev = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'"
    " -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 3 };"
    " $ev | ForEach-Object { @{ RecordId = [string]$_.RecordId; Xml = $_.ToXml() } }"
    " | ConvertTo-Json -Compress"
)


def sysmon_available() -> bool:
    """True si el servicio Sysmon64 existe (no requiere que este corriendo)."""
    out = _run_ps(
        "(Get-Service Sysmon64 -ErrorAction SilentlyContinue | Measure-Object).Count",
        timeout=15,
    ).strip()
    lines = [l for l in out.splitlines() if l.strip()]
    return bool(lines) and lines[-1].strip() == "1"


def poll_sysmon_events(max_events: int = 300) -> list[dict]:
    """Eventos EventID 3 mas recientes (de mas antiguo a mas reciente).

    Cada evento: {record_id, ts, image, protocol, dest_ip, dest_port, pid}.
    Fallo de Sysmon/PS -> [] (fail-safe; el polling classico sigue vivo).
    """
    out = _run_ps(_PS_CMD, timeout=45)
    text = (out or "").strip()
    if not text:
        return []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):  # PS 5.1: un solo objeto, no array
        rows = [rows]
    events: list[dict] = []
    for r in rows:
        fields = _xml_fields(r.get("Xml") or "")
        try:
            rec = int(r.get("RecordId") or 0)
            ip = str(fields.get("DestinationIp") or "").strip()
            port = int(fields.get("DestinationPort") or 0)
            proto = str(fields.get("Protocol") or "tcp").lower()
            image = str(fields.get("Image") or "")
            pid = int(fields.get("ProcessId") or 0)
            ts = str(fields.get("UtcTime") or "")
        except (TypeError, ValueError):
            continue
        if rec and ip and port:
            events.append({
                "record_id": rec, "ts": ts, "image": image,
                "protocol": proto, "dest_ip": ip, "dest_port": port,
                "pid": pid,
            })
    return sorted(events, key=lambda e: e["record_id"])


_PS_CMD_DNS = (
    "$ev = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'"
    " -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 22 };"
    " $ev | ForEach-Object { @{ RecordId = [string]$_.RecordId; Xml = $_.ToXml() } }"
    " | ConvertTo-Json -Compress"
)


def _parse_query_results(raw: str) -> list[str]:
    """QueryResults de EID 22 ('a.b.c.d;::ffff:a.b.c.d;...') -> IPs limpias.

    Convierte los v4 embebidos '::ffff:x.x.x.x' a su forma v4. Deduplica
    preservando el orden (un mismo dominio puede dar varios A/AAAA).
    """
    out: list[str] = []
    for tok in (raw or "").split(";"):
        ip = tok.strip()
        if not ip:
            continue
        if ip.startswith("::ffff:"):
            ip = ip[len("::ffff:"):]
        if ip and ip not in out:
            out.append(ip)
    return out


def poll_sysmon_dns(max_events: int = 300) -> list[dict]:
    """Eventos EventID 22 (DnsQuery) mas recientes, de antiguo a reciente.

    Cada evento: {record_id, ts, image, pid, query_name, ips}.
    `ips` son las direcciones resueltas en QueryResults (v4/v6). Fallo de
    Sysmon/PS -> [] (fail-safe; el resto del monitor sigue vivo).
    """
    out = _run_ps(_PS_CMD_DNS, timeout=45)
    text = (out or "").strip()
    if not text:
        return []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):  # PS 5.1: un solo objeto, no array
        rows = [rows]
    events: list[dict] = []
    for r in rows:
        fields = _xml_fields(r.get("Xml") or "")
        try:
            rec = int(r.get("RecordId") or 0)
            qname = str(fields.get("QueryName") or "").strip().lower()
            pid = int(fields.get("ProcessId") or 0)
        except (TypeError, ValueError):
            continue
        if not (rec and qname):
            continue
        events.append({
            "record_id": rec,
            "ts": str(fields.get("UtcTime") or ""),
            "image": str(fields.get("Image") or ""),
            "pid": pid,
            "query_name": qname,
            "ips": _parse_query_results(str(fields.get("QueryResults") or "")),
        })
    return sorted(events, key=lambda e: e["record_id"])


_PS_CMD_EID1 = (
    "$ev = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'"
    " -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1 };"
    " $ev | ForEach-Object { @{ RecordId = [string]$_.RecordId; Xml = $_.ToXml() } }"
    " | ConvertTo-Json -Compress"
)


def poll_sysmon_process_creation(max_events: int = 300) -> list[dict]:
    """Eventos EventID 1 (ProcessCreate): linaje proceso -> padre (R2).

    Cada evento: {record_id, ts, image, process, pid, parent_image,
    parent_process, parent_cmdline}. Fallo de Sysmon/PS -> [] (fail-safe;
    el resto del monitor sigue vivo).
    """
    out = _run_ps(_PS_CMD_EID1, timeout=45)
    text = (out or "").strip()
    if not text:
        return []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):  # PS 5.1: un solo objeto, no array
        rows = [rows]
    events: list[dict] = []
    for r in rows:
        fields = _xml_fields(r.get("Xml") or "")
        try:
            rec = int(r.get("RecordId") or 0)
            image = str(fields.get("Image") or "")
            proc = str(fields.get("ProcessName") or "")
            pid = int(fields.get("ProcessId") or 0)
            parent_image = str(fields.get("ParentImage") or "")
        except (TypeError, ValueError):
            continue
        if not (rec and image and proc):
            continue
        events.append({
            "record_id": rec,
            "ts": str(fields.get("UtcTime") or ""),
            "image": image,
            "process": proc,
            "pid": pid,
            "cmdline": str(fields.get("CommandLine") or ""),
            "parent_image": parent_image,
            "parent_process": parent_image.rsplit("\\", 1)[-1]
            .rsplit("/", 1)[-1],
            "parent_cmdline": str(fields.get("ParentCommandLine") or ""),
        })
    return sorted(events, key=lambda e: e["record_id"])


def _xml_fields(xml: str) -> dict[str, str]:
    """Data Name=... de un evento Sysmon -> {name: value} (tolerante)."""
    if not xml:
        return {}
    try:
        root = ET.fromstring(xml)
        out: dict[str, str] = {}
        for data in root.iter():
            if data.tag.endswith("}Data") or data.tag == "Data":
                name = data.get("Name")
                if name:
                    out[name] = data.text or ""
        return out
    except ET.ParseError:
        return {}
