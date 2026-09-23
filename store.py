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
    ai_layer TEXT,
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
CREATE TABLE IF NOT EXISTS domain_classifications (
    domain TEXT PRIMARY KEY,
    is_ai INTEGER NOT NULL,
    provider TEXT,
    category TEXT,
    confidence REAL,
    source TEXT,
    ts TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _cutoff_ts(days: int) -> str:
    """Corte de retencion (F7): mismo formato que ts, comparable lexicografico."""
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%d %H:%M:%SZ")


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
    request_bytes INTEGER,
    response_bytes INTEGER,
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
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(llm_calls)")}
            if "request_bytes" not in cols:
                self.conn.execute("ALTER TABLE llm_calls ADD COLUMN request_bytes INTEGER")
            if "response_bytes" not in cols:
                self.conn.execute("ALTER TABLE llm_calls ADD COLUMN response_bytes INTEGER")
            self.conn.commit()

    def record(self, call: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO llm_calls (ts, method, path, status, model,"
                " streaming, prompt_chars, response_chars, prompt_tokens,"
                " completion_tokens, request_bytes, response_bytes, latency_ms,"
                " client_addr, prompt, response)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (call["ts"], call.get("method"), call.get("path"),
                 call.get("status"), call.get("model"),
                 int(call.get("streaming") or 0),
                 call.get("prompt_chars"), call.get("response_chars"),
                 call.get("prompt_tokens"), call.get("completion_tokens"),
                 call.get("request_bytes"), call.get("response_bytes"),
                 call.get("latency_ms"), call.get("client_addr"),
                 call.get("prompt"), call.get("response")),
            )
            self.conn.commit()
            return int(cur.lastrowid or 0)

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

    def prune(self, days: int) -> int:
        """Retencion (F7): borra llamadas mas antiguas que N dias + VACUUM."""
        cut = _cutoff_ts(days)
        with self._lock:
            cur = self.conn.execute("DELETE FROM llm_calls WHERE ts < ?", (cut,))
            n = cur.rowcount
            # VACUUM no puede correr dentro de la transaccion del DELETE.
            self.conn.commit()
            self.conn.execute("VACUUM")
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
            if "ai_layer" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN ai_layer TEXT")
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
        ai_layer: str | None = None,
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
                    " image=COALESCE(?, image),"
                    " ai_layer=COALESCE(?, ai_layer) WHERE id=?",
                    (ts, ts, image, ai_layer, row["id"]),
                )
                event_id = row["id"]
            else:
                cur = self.conn.execute(
                    "INSERT INTO events (ts, process, dest_ip, dest_port, dest_host,"
                    " catalog_domain, protocol, image, ai_layer, seen_count, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
                    (ts, process, dest_ip, dest_port, dest_host, catalog_domain,
                     protocol, image, ai_layer, ts, ts),
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

    # --- Clasificador automatico (cache por dominio) -------------------

    def upsert_classification(
            self, domain: str, is_ai: bool, provider: str | None,
            category: str | None, confidence: float, source: str,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO domain_classifications"
                " (domain, is_ai, provider, category, confidence, source, ts)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(domain) DO UPDATE SET"
                " is_ai=excluded.is_ai, provider=excluded.provider,"
                " category=excluded.category, confidence=excluded.confidence,"
                " source=excluded.source, ts=excluded.ts",
                (domain.lower(), int(bool(is_ai)), provider, category,
                 float(confidence), source, _now()),
            )
            self.conn.commit()

    def get_classification(self, domain: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM domain_classifications WHERE domain=?",
            (domain.lower(),),
        ).fetchone()
        return dict(row) if row else None

    def pending_heuristic_domains(self, limit: int = 10,
                                  ttl_days: int = 30) -> list[str]:
        """Dominios en capa 0.5 sin clasificar (o con clase mas antigua que el
        TTL). Solo catalog_domain: es la clave canonica del dominio."""
        cut = _cutoff_ts(ttl_days)
        rows = self.conn.execute(
            "SELECT e.catalog_domain AS domain FROM events e"
            " LEFT JOIN domain_classifications dc ON dc.domain=e.catalog_domain"
            " WHERE e.ai_layer='heuristic' AND e.catalog_domain IS NOT NULL"
            " AND e.catalog_domain != ''"
            " AND (dc.domain IS NULL OR dc.ts < ?)"
            " GROUP BY e.catalog_domain ORDER BY MAX(e.last_seen) DESC LIMIT ?",
            (cut, limit),
        ).fetchall()
        return [r["domain"] for r in rows]

    def apply_classification_layer(self, domain: str, layer: str) -> int:
        """Pasa eventos de 'heuristic' a la capa nueva. El catalogo NUNCA se
        pisa (la capa 1.0 siempre gana). Devuelve filas actualizadas."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE events SET ai_layer=? WHERE catalog_domain=?"
                " AND ai_layer='heuristic'",
                (layer, domain.lower()),
            )
            self.conn.commit()
            return cur.rowcount

    def process_for_domain(self, domain: str) -> str | None:
        row = self.conn.execute(
            "SELECT process FROM events WHERE catalog_domain=?"
            " ORDER BY seen_count DESC LIMIT 1",
            (domain.lower(),),
        ).fetchone()
        return row["process"] if row else None

    def has_event(self, process: str, dest_ip: str,
                  dest_port: int) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM events WHERE process=? AND dest_ip=? AND dest_port=?",
            (process, dest_ip, dest_port),
        ).fetchone()
        return row is not None

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

    def ai_events(self) -> list[dict]:
        """Eventos clasificados como IA (ai_layer != none)."""
        q = ("SELECT * FROM events"
             " WHERE ai_layer IS NOT NULL AND ai_layer != 'none'"
             " ORDER BY last_seen DESC")
        return [dict(r) for r in self.conn.execute(q).fetchall()]

    def save_triage(self, status: str, model: str | None, payload: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO triages (ts, status, model, payload) VALUES (?,?,?,?)",
                (_now(), status, model, json.dumps(payload, ensure_ascii=False)),
            )
            self._bump_daily("triages")
            self.conn.commit()
            return int(cur.lastrowid or 0)

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

    def prune(self, days: int) -> dict:
        """Retencion (F7): borra eventos/triajes mas antiguos que N dias.

        Eventos por last_seen (un evento vivo no caduca aunque sea antiguo);
        daily_stats NO se toca (historico de rollup). VACUUM para recuperar
        espacio; pensado para correr meses sin crecer sin limite."""
        cut = _cutoff_ts(days)
        with self._lock:
            ev = self.conn.execute(
                "DELETE FROM events WHERE last_seen < ?", (cut,)).rowcount
            tr = self.conn.execute(
                "DELETE FROM triages WHERE ts < ?", (cut,)).rowcount
            # VACUUM no puede correr dentro de la transaccion del DELETE.
            self.conn.commit()
            self.conn.execute("VACUUM")
            self.conn.commit()
        return {"events_removed": ev, "triages_removed": tr}

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
