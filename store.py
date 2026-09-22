"""Almacenamiento SQLite (stdlib) de eventos, triajes y llamadas LLM de
AI NetWatch. Los LLM calls viven en su propia base (llm_calls.db) para no
mezclar retenciones con los eventos de red."""
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
    protocol TEXT NOT NULL DEFAULT 'tcp',
    image TEXT,
    sni_domain TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    events INTEGER NOT NULL DEFAULT 0,
    triages INTEGER NOT NULL DEFAULT 0,
    first_ts TEXT,
    last_ts TEXT
);
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


_LLM_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    method TEXT,
    path TEXT,
    status INTEGER,
    model TEXT,
    streaming INTEGER NOT NULL DEFAULT 0,
    prompt_chars INTEGER,
    response_chars INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    latency_ms REAL,
    client_addr TEXT,
    prompt TEXT,
    response TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_calls_ts ON llm_calls(ts);
"""


class LlmCallStore:
    """SQLite de llamadas LLM capturadas por el proxy inspector (R3)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(_LLM_SCHEMA)
            self.conn.commit()

    def record(self, call: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO llm_calls (ts, method, path, status, model,"
                " streaming, prompt_chars, response_chars, prompt_tokens,"
                " completion_tokens, latency_ms, client_addr, prompt, response)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (call["ts"], call.get("method"), call.get("path"),
                 call.get("status"), call.get("model"),
                 int(call.get("streaming") or 0),
                 call.get("prompt_chars"), call.get("response_chars"),
                 call.get("prompt_tokens"), call.get("completion_tokens"),
                 call.get("latency_ms"), call.get("client_addr"),
                 call.get("prompt"), call.get("response")),
            )
            self.conn.commit()
            return cur.lastrowid

    def list_calls(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        rows = self.conn.execute(
            "SELECT * FROM llm_calls ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_call(self, call_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM llm_calls WHERE id=?", (call_id,)
        ).fetchone()
        return dict(row) if row else None

    def clear(self) -> int:
        with self._lock:
            n = self.conn.execute("SELECT COUNT(*) FROM llm_calls").fetchone()[0]
            self.conn.execute("DELETE FROM llm_calls")
            self.conn.commit()
        return n

    def close(self) -> None:
        with self._lock:
            self.conn.close()


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(_SCHEMA)
            # Migracion: bases antiguas sin columna protocol.
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(events)")}
            if "protocol" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'"
                )
            if "image" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN image TEXT")
            if "sni_domain" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN sni_domain TEXT")
            self.conn.commit()

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _bump_daily(self, kind: str) -> None:
        day = self._today()
        ev, tr = (1, 0) if kind == "events" else (0, 1)
        self.conn.execute(
            "INSERT INTO daily_stats (date, events, triages, first_ts, last_ts)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(date) DO UPDATE SET"
            f" {kind}=daily_stats.{kind}+1, last_ts=excluded.last_ts",
            (day, ev, tr, _now(), _now()),
        )

    def observe_connection(
        self, process: str, dest_ip: str, dest_port: int,
        catalog_domain: str | None, dest_host: str | None,
        protocol: str = "tcp", image: str | None = None,
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
                    "UPDATE events SET seen_count=seen_count+1, last_seen=?, ts=?,"
                    " image=COALESCE(?, image) WHERE id=?",
                    (ts, ts, image, row["id"]),
                )
                event_id = row["id"]
            else:
                cur = self.conn.execute(
                    "INSERT INTO events (ts, process, dest_ip, dest_port, dest_host,"
                    " catalog_domain, protocol, image, seen_count, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,1,?,?)",
                    (ts, process, dest_ip, dest_port, dest_host, catalog_domain,
                     protocol, image, ts, ts),
                )
                event_id = cur.lastrowid
            self._bump_daily("events")
            self.conn.commit()
        return self.get_event(event_id) or {}

    def attach_sni(
        self, dst_ip: str, dst_port: int, sni: str,
        catalog: str | None = None,
    ) -> int:
        """Asocia el SNI capturado a los eventos con ese (dst_ip, dst_port).

        El SNI es definitivo sobre la caché DNS: se escribe siempre; el
catalog_domain solo se rellena si estaba vacio (no pisa un match previo).
        Devuelve el numero de filas actualizadas.
        """
        with self._lock:
            cur = self.conn.execute(
                "UPDATE events SET sni_domain=?,"
                " catalog_domain=CASE WHEN catalog_domain IS NULL OR"
                " catalog_domain='' THEN ? ELSE catalog_domain END"
                " WHERE dest_ip=? AND dest_port=?",
                (sni, catalog or "", dst_ip, dst_port),
            )
            self.conn.commit()
            return cur.rowcount

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
                    " OR COALESCE(catalog_domain,'') LIKE ?"
                    " OR COALESCE(sni_domain,'') LIKE ?)"
                    if process else
                    " WHERE dest_ip LIKE ? OR COALESCE(dest_host,'') LIKE ?"
                    " OR COALESCE(catalog_domain,'') LIKE ?"
                    " OR COALESCE(sni_domain,'') LIKE ?")
            q += cols
            args.extend([f"%{dest}%", f"%{dest}%", f"%{dest}%", f"%{dest}%"])
        q += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def save_triage(self, status: str, model: str | None, payload: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO triages (ts, status, model, payload) VALUES (?,?,?,?)",
                (_now(), status, model, json.dumps(payload, ensure_ascii=False)),
            )
            self._bump_daily("triages")
            self.conn.commit()
            return cur.lastrowid

    def stats(self, days: int = 7) -> list[dict]:
        """Rollup diario de los ultimos `days` dias (incluye dias sin actividad)."""
        from datetime import timedelta
        today = datetime.now(timezone.utc)
        want = [(today - timedelta(days=i)).strftime("%Y-%m-%d")
                for i in range(max(1, days) - 1, -1, -1)]
        have = {r["date"]: dict(r) for r in self.conn.execute(
            "SELECT * FROM daily_stats WHERE date >= ? ORDER BY date",
            ((today - timedelta(days=max(1, days) - 1)).strftime("%Y-%m-%d"),))}
        out = []
        for d in want:
            row = have.get(d)
            out.append({
                "date": d,
                "events": row["events"] if row else 0,
                "triages": row["triages"] if row else 0,
            })
        return out

    def reset(self) -> dict:
        """Borra eventos y triajes vivos; daily_stats NO se toca (historico)."""
        with self._lock:
            ev = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            tr = self.conn.execute("SELECT COUNT(*) FROM triages").fetchone()[0]
            self.conn.execute("DELETE FROM events")
            self.conn.execute("DELETE FROM triages")
            self.conn.commit()
        return {"events_removed": ev, "triages_removed": tr}

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
