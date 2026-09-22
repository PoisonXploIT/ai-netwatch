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
