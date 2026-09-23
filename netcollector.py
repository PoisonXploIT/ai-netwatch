"""v2.2 — Colector elevado de bytes remotos (ETW Kernel-Network).

Proceso separado ELEVADO (UAC) que el servidor lanza: logman start -> N s
-> stop -> tracerpt -of XML -> parseo POR NOMBRE (<Data Name="PID">...) ->
agregar por destino (daddr, dport), excluyendo loopback y DNS (dport 53)
-> JSONL en una ruta fija. El servidor (no elevado) solo lee el JSONL y lo
ingesta; nunca interpreta ETLs.

Mapa EventID verificado en maquina real (task 10 = TCPIP, 11 = UDPIP):
- 10, 18, 26, 27, 34 = copia de datos TCP -> size = bytes.
- 11 = datos UDP.
- El resto (handshake, connect/accept, DNS) se ignora.

Honestidad: cualquier fallo (sin admin, logman/tracerpt ausentes, sin
eventos) => sin fichero o vacio; el servidor degrada a "no disponible"
con motivo. Nunca numeros inventados.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

_TCP_DATA_IDS = frozenset({10, 18, 26, 27, 34})
_UDP_DATA_IDS = frozenset({11})


def _data_map(ev: ET.Element) -> dict[str, str]:
    """Todos los <Data Name="X">valor</Data> del evento (robusto al
    anidamiento): {name: texto}. Sin valor => omitido."""
    out: dict[str, str] = {}
    for d in ev.iter():
        if d.tag == "Data":
            name = d.get("Name")
            if name is not None:
                out[name] = (d.text or "").strip()
    return out


def parse_xml(path: Path) -> list[dict]:
    """Eventos de copia de datos con size>0 y sin loopback.

    Devuelve [{pid, dest_ip, dest_port, bytes}]. IPv4 e IPv6. Fallos de
    parseo o fichero ausente => lista vacia (degradacion honesta).
    """
    out: list[dict] = []
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError):
        return out
    for ev in root.iter("TraceEvent"):
        header = ev.find("Header")
        if header is None:
            continue
        task_el = header.find("Task")
        eid_el = header.find("EventID")
        if task_el is None or eid_el is None:
            continue
        try:
            task = int((task_el.text or "").strip())
            eid = int((eid_el.text or "").strip())
        except ValueError:
            continue
        if not ((task == 10 and eid in _TCP_DATA_IDS)
                or (task == 11 and eid in _UDP_DATA_IDS)):
            continue
        data = _data_map(ev)
        try:
            size = int(data.get("size", ""))
        except ValueError:
            continue
        if size <= 0:
            continue
        daddr = data.get("daddr", "")
        dport_s = data.get("dport", "")
        try:
            dest_ip_obj = ipaddress.ip_address(daddr)
            dport = int(dport_s)
        except ValueError:
            continue
        if dest_ip_obj.is_loopback:
            continue  # loopback no es egress
        if dport == 53:
            continue  # DNS: metadato, no volumen de IA
        try:
            pid = int(data.get("PID", ""))
        except ValueError:
            continue
        out.append({"pid": pid, "dest_ip": str(dest_ip_obj),
                    "dest_port": dport, "bytes": size})
    return out


def aggregate(rows: list[dict]) -> dict[tuple[str, int], int]:
    """Suma bytes por (dest_ip, dest_port)."""
    out: dict[tuple[str, int], int] = {}
    for r in rows:
        key = (str(r["dest_ip"]), int(r["dest_port"]))
        out[key] = out.get(key, 0) + int(r["bytes"])
    return out


def run_trace(base_name: str, duration_s: int, workdir: Path) -> Path | None:
    """logman start -> N s -> stop -> tracerpt -of XML.

    Gotcha verificado: logman escribe {base}_000001.etl (sufijo), no el
    nombre tal cual; se resuelve con glob. Devuelve la ruta del XML o
    None (sin admin / fallo). Los ETLs intermedios se limpian.
    """
    base = workdir / f"{base_name}.etl"
    xml_path = workdir / f"{base_name}.xml"
    cmd_start = ["logman", "create", "trace", base_name,
                 "-p", "Microsoft-Windows-Kernel-Network",
                 "0x8000000000000000", "-o", str(base), "-ets"]
    try:
        subprocess.run(cmd_start, capture_output=True, timeout=30,
                       check=False)
        # Sin admin/UAC denegada el ETL nunca aparece: no esperar la
        # duracion entera (degradacion rapida y honesta).
        t0 = time.monotonic()
        etl = None
        while time.monotonic() - t0 < 15:
            etls = sorted(workdir.glob(f"{base_name}_*.etl"))
            if etls:
                etl = etls[0]
                break
            time.sleep(0.5)
        if etl is None:
            return None
        elapsed = time.monotonic() - t0
        remaining = max(0, int(duration_s) - int(elapsed))
        time.sleep(remaining)
        subprocess.run(["logman", "stop", base_name],
                       capture_output=True, timeout=30, check=False)
        conv = ["tracerpt", "-of", "XML", "-o", str(xml_path), str(etl)]
        subprocess.run(conv, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        for p in list(workdir.glob(f"{base_name}*.etl")):
            try:
                p.unlink()
            except OSError:
                pass
    return xml_path if xml_path.exists() else None


def main(argv: list[str]) -> int:
    """Uso elevado: netcollector.py <duracion_s> <ruta_jsonl_salida>."""
    import autonomy
    try:
        duration_s = int(argv[0]) if argv else 30
    except ValueError:
        duration_s = 30
    out_path = Path(argv[1]) if len(argv) > 1 else Path("netprobe.jsonl")
    base_name = f"netprobe_{int(time.time())}"
    workdir = out_path.parent
    xml_path = run_trace(base_name, duration_s, workdir)
    rows: list[dict] = []
    if xml_path is not None:
        rows = parse_xml(xml_path)
        try:
            xml_path.unlink()
        except OSError:
            pass
    pids = autonomy.pid_name_map()
    agg = aggregate(rows)
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(out_path, "w", encoding="utf-8") as f:
        for (dest_ip, dest_port), total in sorted(agg.items()):
            pset = {r["pid"] for r in rows
                    if (str(r["dest_ip"]), int(r["dest_port"])) == (
                        dest_ip, dest_port)}
            procs = sorted({pids.get(p, f"pid:{p}") for p in pset})
            f.write(json.dumps({
                "ts": now, "dest_ip": dest_ip, "dest_port": dest_port,
                "bytes": total, "processes": procs,
            }, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
