"""Audit log (S4): rastro de acciones con coste o efecto.

Cada entrada es una linea JSON: ts, action, method, path, status, origin,
client, y un detalle (que campos se tocaron, no sus valores: una key de API
no se escribe en el log).

Fail-safe: un fallo de escritura nunca rompe el endpoint que se esta
sirviendo. El fichero se rota cuando supera MAX_BYTES (se conservan las
ultimas ~2000 lineas).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 1_000_000
KEEP_LINES = 2000


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, method: str, path: str, status: int,
            origin: str | None = None, client: str | None = None,
            detail: dict | None = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "action": action,
            "method": method,
            "path": path,
            "status": int(status),
            "origin": origin or "",
            "client": client or "",
        }
        if detail:
            entry["detail"] = detail
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if self.path.stat().st_size > MAX_BYTES:
                self._rotate()
        except OSError:
            pass  # el log no puede tumbar la consola

    def _rotate(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            self.path.write_text("\n".join(lines[-KEEP_LINES:]) + "\n",
                                 encoding="utf-8")
        except OSError:
            pass

    def tail(self, limit: int = 50) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
