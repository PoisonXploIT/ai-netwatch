"""Wrapper de la tarea programada AI-NETWATCH-NetBytes (elevada, sin consola).

Se lanza con `pythonw.exe` (interprete sin consola). El anterior wrapper era
PowerShell y, con `LogonType Interactive` + `RunLevel Highest`, Task Scheduler
le crea una consola: cada ciclo (10 min) aparecia una ventana de PowerShell
que robaba el foco y molestaba mientras se trabaja. `pythonw.exe` no abre
ventana: el colector corre en segundo plano de verdad.

El servidor (no elevado) escribe los parametros en data/netcollector_cmd.json;
aqui se leen y se ejecuta netcollector.main(). Fail-safe: cualquier fallo se
deja en data/netcollector_task_error.txt y sale con codigo 1.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

import netcollector  # noqa: E402


def _diag(message: str) -> None:
    try:
        (REPO / "data" / "netcollector_task_error.txt").write_text(
            message, encoding="utf-8")
    except OSError:
        pass


def run() -> int:
    cmd_path = REPO / "data" / "netcollector_cmd.json"
    try:
        cmd = json.loads(cmd_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _diag(f"no se pudo leer {cmd_path}: {exc}")
        return 1
    duration = cmd.get("duration_s", 30)
    out_path = cmd.get("out_path") or str(REPO / "data" / "netprobe.jsonl")
    try:
        return int(netcollector.main([str(duration), str(out_path)]))
    except Exception as exc:  # noqa: BLE001 - el task engine no ve la consola
        _diag(f"colector fallo: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(run())
