"""Almacenamiento SQLite (stdlib) de eventos y triajes de AI NetWatch."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    process TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    dest_host TEXT,
    catalog_domain TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS triages (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    status TEXT NOT NULL,
    model TEXT,
    payload TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self.conn.commit()

    def observe_connection(
        self, process: str, dest_ip: str, dest_port: int,
        catalog_domain: str | None, dest_host: str | None,
    ) -> dict:
        """Registra una conexion establecida a un destino AI.

        Si ya existe la misma (process, dest_ip, dest_port), incrementa
        seen_count y actualiza last_seen (senal de periodicidad).
        """
        ts = _now()
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM events WHERE process=? AND dest_ip=? AND dest_port=?",
                (process, dest_ip, dest_port),
            ).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE events SET seen_count=seen_count+1, last_seen=?, ts=? "
                    "WHERE id=?",
                    (ts, ts, row["id"]),
                )
                event_id = row["id"]
            else:
                cur = self.conn.execute(
                    "INSERT INTO events (ts, process, dest_ip, dest_port, dest_host,"
                    " catalog_domain, seen_count, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,1,?,?)",
                    (ts, process, dest_ip, dest_port, dest_host, catalog_domain, ts, ts),
                )
                event_id = cur.lastrowid
            self.conn.commit()
        return self.get_event(event_id) or {}

    def get_event(self, event_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM events WHERE id=?", (event_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_events(self, limit: int = 200, process: str | None = None,
                    dest: str | None = None) -> list[dict]:
        q = "SELECT * FROM events"
        args: list[object] = []
        if process:
            q += " WHERE process LIKE ?"
            args.append(f"%{process}%")
        if dest:
            cols = (" AND (dest_ip LIKE ? OR COALESCE(dest_host,'') LIKE ?"
                    " OR COALESCE(catalog_domain,'') LIKE ?)"
                    if process else
                    " WHERE dest_ip LIKE ? OR COALESCE(dest_host,'') LIKE ?"
                    " OR COALESCE(catalog_domain,'') LIKE ?")
            q += cols
            args.extend([f"%{dest}%", f"%{dest}%", f"%{dest}%"])
        q += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def save_triage(self, status: str, model: str | None, payload: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO triages (ts, status, model, payload) VALUES (?,?,?,?)",
                (_now(), status, model, json.dumps(payload, ensure_ascii=False)),
            )
            self.conn.commit()
            return cur.lastrowid

    def latest_triage(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM triages ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        out = dict(row)
        out["payload"] = json.loads(out["payload"])
        return out

    def close(self) -> None:
        with self._lock:
            self.conn.close()
