"""Alertas v2.0 (O3): cola en memoria + log de archivo + webhook opcional.

Solo stdlib. El push corre desde el hilo del monitor: el log de archivo es
apendido bloqueado y el webhook se despacha en un hilo daemon (nunca bloquea
el ciclo de monitor). Fail-safe total: una alerta nunca rompe al monitor.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib import request as urlrequest


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


class AlertLog:
    """Cola de alertas acotada + log plano (data/alerts.log) + webhook."""

    def __init__(self, path: Path | str | None = None, max_items: int = 200,
                 webhook_url: str = ""):
        self.path = Path(path) if path else None
        self.max_items = max(10, int(max_items))
        self.webhook_url = webhook_url or ""
        self._items: list[dict] = []
        self._lock = threading.Lock()
        self._next_id = 1

    def push(self, kind: str, message: str, details: dict | None = None) -> dict:
        with self._lock:
            item = {
                "id": self._next_id,
                "ts": _now(),
                "kind": kind,
                "message": message,
                "details": details or {},
            }
            self._next_id += 1
            self._items.append(item)
            del self._items[: len(self._items) - self.max_items]
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self._lock:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(
                            item, ensure_ascii=False, default=str) + "\n")
            except OSError:
                pass  # el log nunca rompe al monitor
        if self.webhook_url:
            threading.Thread(target=self._post_webhook, args=(item,),
                             daemon=True).start()
        return item

    def _post_webhook(self, item: dict) -> None:
        try:
            body = json.dumps(item, ensure_ascii=False).encode("utf-8")
            req = urlrequest.Request(
                self.webhook_url, data=body, method="POST",
                headers={"Content-Type": "application/json"})
            with urlrequest.urlopen(req, timeout=5) as resp:
                resp.read(4096)
        except Exception:
            pass  # webhook caido o lento no rompe nada

    def list(self, since_id: int = 0) -> list[dict]:
        with self._lock:
            return [i for i in self._items if i["id"] > max(0, int(since_id))]
