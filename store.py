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
CREATE TABLE IF NOT EXISTS sessions_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    process TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_key
    ON sessions_log(process, dest_ip, dest_port, ts);
CREATE TABLE IF NOT EXISTS net_bytes (
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    PRIMARY KEY (dest_ip, dest_port)
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
CREATE TABLE IF NOT EXISTS dns_resolutions (
    dest_ip TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# D3: umbral de beaconing. CV (coef. de variacion de inter-arrival)
# <= 0.3 con >=5 sesiones = periodicidad regular (beacon), no keep-alive.
_BEACON_CV_MAX = 0.3
_BEACON_MIN_N = 5


def _ts_to_epoch(ts: str) -> float | None:
    try:
        return datetime.strptime(
            str(ts), "%Y-%m-%d %H:%M:%SZ"
        ).replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _cv_from_ts(ts_list: list[str]) -> float | None:
    """CV (desv/ media) de los inter-arrival de timestamps de sesion
    (orden ascendente). None si no hay datos suficientes."""
    epochs = [e for e in (_ts_to_epoch(t) for t in ts_list)
              if e is not None]
    if len(epochs) < 2:
        return None
    iats = [b - a for a, b in zip(epochs, epochs[1:])]
    mean = sum(iats) / len(iats)
    if mean <= 0:
        return None
    var = sum((x - mean) ** 2 for x in iats) / len(iats)
    return (var ** 0.5) / mean


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

    def summary(self, days: int | None = None) -> dict:
        """Totales del inspector (locales): llamadas, tokens y bytes."""
        q = ("SELECT COUNT(*) AS calls,"
             " COALESCE(SUM(prompt_tokens),0) AS prompt_tokens,"
             " COALESCE(SUM(completion_tokens),0) AS completion_tokens,"
             " COALESCE(SUM(request_bytes),0) AS request_bytes,"
             " COALESCE(SUM(response_bytes),0) AS response_bytes"
             " FROM llm_calls")
        args: list[object] = []
        if days is not None:
            q += " WHERE ts >= ?"
            args.append(_cutoff_ts(days))
        r = self.conn.execute(q, tuple(args)).fetchone()
        return {k: int(v or 0) for k, v in dict(r).items()}

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
            # R2: autonomia por evento (score/flags/veredicto).
            if "autonomy_score" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN autonomy_score INTEGER")
            if "autonomy_flags" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN autonomy_flags TEXT")
            if "autonomy_verdict" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN autonomy_verdict TEXT")
            # F1/D3: sesiones (no polls) y beaconing por clave.
            if "sessions" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN sessions INTEGER NOT NULL DEFAULT 1")
            if "iat_cv" not in cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN iat_cv REAL")
            if "beacon_score" not in cols:
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN beacon_score INTEGER")
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
        autonomy_score: int | None = None,
        autonomy_flags: str | None = None,
        autonomy_verdict: str | None = None,
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
                # Autonomia se recalcula en cada observacion: overwrite.
                self.conn.execute(
                    "UPDATE events SET seen_count=seen_count+1, last_seen=?, ts=?,"
                    " image=COALESCE(?, image),"
                    " ai_layer=COALESCE(?, ai_layer),"
                    " autonomy_score=?, autonomy_flags=?, autonomy_verdict=?"
                    " WHERE id=?",
                    (ts, ts, image, ai_layer,
                     autonomy_score, autonomy_flags, autonomy_verdict,
                     row["id"]),
                )
                event_id = row["id"]
            else:
                cur = self.conn.execute(
                    "INSERT INTO events (ts, process, dest_ip, dest_port, dest_host,"
                    " catalog_domain, protocol, image, ai_layer, seen_count, first_seen, last_seen,"
                    " autonomy_score, autonomy_flags, autonomy_verdict, sessions)"
                    " VALUES (?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,0)",
                    (ts, process, dest_ip, dest_port, dest_host, catalog_domain,
                     protocol, image, ai_layer, ts, ts,
                     autonomy_score, autonomy_flags, autonomy_verdict),
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

    def ip_resolution_rows(
            self) -> list[tuple[str, str, str, str]]:
        """v2.3: (dest_ip, sni_domain, catalog_domain, dest_host) de TODOS
        los eventos, mas reciente primero. Sirve para mapear las IPs de
        net_bytes a proveedor aunque no salgan en la ventana reciente."""
        return self.conn.execute(
            "SELECT dest_ip, COALESCE(sni_domain,''),"
            " COALESCE(catalog_domain,''), COALESCE(dest_host,'')"
            " FROM events ORDER BY last_seen DESC").fetchall()

    def record_dns_resolution(self, ip: str, domain: str) -> None:
        """v2.3: persiste una resolucion EID 22 (ip->dominio); el mas
        reciente gana. Conocimiento que sobrevive el restart: cierra el
        hueco de net_bytes 'desconocido' cuya resolucion ya salio de la
        ventana en memoria de los ultimos 300 DnsQuery."""
        ip = str(ip or "").strip()
        domain = str(domain or "").strip().lower()
        if not ip or not domain:
            return
        with self._lock:
            self.conn.execute(
                "INSERT INTO dns_resolutions(dest_ip, domain, last_seen)"
                " VALUES(?,?,?)"
                " ON CONFLICT(dest_ip) DO UPDATE SET"
                " domain=excluded.domain, last_seen=excluded.last_seen",
                (ip, domain, _now()))
            self.conn.commit()

    def dns_resolution_map(self) -> dict[str, str]:
        """v2.3: dest_ip -> dominio desde las resoluciones EID 22
        persistidas (cualquier dominio; el filtro IA se hace en el uso)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT dest_ip, domain FROM dns_resolutions").fetchall()
        return {str(r["dest_ip"]): str(r["domain"]) for r in rows}

    def events_since(self, days: int) -> list[dict]:
        """Eventos vivos con last_seen dentro de `days` (panel)."""
        q = ("SELECT * FROM events WHERE last_seen >= ?"
             " ORDER BY last_seen DESC")
        return [dict(r) for r in
                self.conn.execute(q, (_cutoff_ts(days),)).fetchall()]

    def get_event_by_key(self, process: str, dest_ip: str,
                         dest_port: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM events WHERE process=? AND dest_ip=? AND dest_port=?",
            (process, dest_ip, dest_port)).fetchone()
        return dict(row) if row else None

    def record_session(self, process: str, dest_ip: str,
                       dest_port: int) -> dict:
        """F1/D3: inicio de sesion (transicion ausente->presente).

        Incrementa events.sessions, guarda el timestamp en sessions_log y
        recalcula beaconing con la ventana de los ultimos 20 timestamps:
        CV = desv/ media de inter-arrival; beaconing si N>=5 y CV<=0.3.
        Devuelve {sessions, iat_cv, beacon_score, beaconing,
        new_beaconing} (new_beaconing = transicion a beaconing ahora).
        """
        out: dict[str, object] = {
            "sessions": 0, "iat_cv": None, "beacon_score": None,
               "beaconing": False, "new_beaconing": False}
        with self._lock:
            # Reconciliacion: el conteo acumulado es max(eventos, log);
            # ambos avanzan juntos en produccion y esto cubre deriva o
            # filas legacy (pre-F1, donde sessions no existia).
            row = self.conn.execute(
                "SELECT sessions FROM events"
                " WHERE process=? AND dest_ip=? AND dest_port=?",
                (process, dest_ip, dest_port)).fetchone()
            log_n = self.conn.execute(
                "SELECT COUNT(*) FROM sessions_log"
                " WHERE process=? AND dest_ip=? AND dest_port=?",
                (process, dest_ip, dest_port)).fetchone()[0]
            n_prev = max(int(row["sessions"]) if row else 0, int(log_n))
            n_new = n_prev + 1
            prev = [r[0] for r in self.conn.execute(
                "SELECT ts FROM sessions_log"
                " WHERE process=? AND dest_ip=? AND dest_port=?"
                " ORDER BY ts DESC LIMIT 19",
                (process, dest_ip, dest_port))]
            # Estado ANTES de esta sesion: sin el +1 (la transicion se
            # detecta contra lo que ya habia, no contra lo nuevo).
            old_cv = _cv_from_ts(sorted(prev)) if len(prev) >= 4 else None
            old_n = len(prev)
            old_beacon = bool(
                old_cv is not None and old_cv <= _BEACON_CV_MAX
                and old_n >= _BEACON_MIN_N)
            self.conn.execute(
                "INSERT INTO sessions_log (ts, process, dest_ip, dest_port)"
                " VALUES (?,?,?,?)", (_now(), process, dest_ip, dest_port))
            # Techo por clave: la ventana de stats solo usa 20; no dejar
            # mas de 50 timestamps por (proceso, ip, puerto).
            self.conn.execute(
                "DELETE FROM sessions_log WHERE process=? AND dest_ip=?"
                " AND dest_port=? AND id NOT IN ("
                " SELECT id FROM sessions_log"
                " WHERE process=? AND dest_ip=? AND dest_port=?"
                " ORDER BY ts DESC, id DESC LIMIT 50)",
                (process, dest_ip, dest_port,
                 process, dest_ip, dest_port))
            win = [r[0] for r in self.conn.execute(
                "SELECT ts FROM sessions_log"
                " WHERE process=? AND dest_ip=? AND dest_port=?"
                " ORDER BY ts DESC LIMIT 20",
                (process, dest_ip, dest_port))]
            cv = _cv_from_ts(sorted(win)) if len(win) >= 4 else None
            beaconing = bool(
                cv is not None and cv <= _BEACON_CV_MAX
                and n_new >= _BEACON_MIN_N)
            score = int(round((1.0 - min(cv, 1.0)) * 100)) if cv is not None else None
            self.conn.execute(
                "UPDATE events SET sessions=?, iat_cv=?, beacon_score=?"
                " WHERE process=? AND dest_ip=? AND dest_port=?",
                (n_new, cv, score, process, dest_ip, dest_port))
            self.conn.commit()
        out.update({"sessions": n_new, "iat_cv": cv, "beacon_score": score,
                    "beaconing": beaconing,
                    "new_beaconing": beaconing and not old_beacon})
        return out

    def autonomy_events(self, limit: int = 100) -> list[dict]:
        """Eventos con veredicto de autonomia autonomous/scheduled (R2)."""
        q = ("SELECT * FROM events"
             " WHERE autonomy_verdict IN ('autonomous', 'scheduled')"
             " ORDER BY last_seen DESC LIMIT ?")
        return [dict(r) for r in
                self.conn.execute(q, (limit,)).fetchall()]

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

    def ingest_net_bytes(self, rows: list[dict], ts: str) -> int:
        """v2.2: bytes remotos del colector elevado por destino.

        rows: [{dest_ip, dest_port, bytes}]. Acumula (cada ciclo del
        colector es una ventana nueva; no hay solapes). Devuelve el
        numero de destinos actualizados."""
        n = 0
        for r in rows:
            try:
                b = int(r.get("bytes") or 0)
                dest_ip = str(r.get("dest_ip") or "")
                dest_port = int(r.get("dest_port") or 0)
            except (TypeError, ValueError):
                continue
            if b <= 0 or not dest_ip:
                continue
            self.conn.execute(
                "INSERT INTO net_bytes(dest_ip, dest_port, bytes,"
                " first_seen, last_seen) VALUES(?, ?, ?, ?, ?)"
                " ON CONFLICT(dest_ip, dest_port) DO UPDATE SET"
                " bytes = net_bytes.bytes + excluded.bytes,"
                " last_seen = max(net_bytes.last_seen, excluded.last_seen)"
                , (dest_ip, dest_port, b, ts, ts))
            n += 1
        self.conn.commit()
        return n

    def net_bytes_sum(self) -> list[dict]:
        """Bytes acumulados por destino, mayor primero."""
        rows = self.conn.execute(
            "SELECT dest_ip, dest_port, SUM(bytes) AS b FROM net_bytes"
            " GROUP BY dest_ip, dest_port ORDER BY b DESC"
        ).fetchall()
        return [{"dest_ip": r["dest_ip"], "dest_port": int(r["dest_port"]),
                 "bytes": int(r["b"])} for r in rows]

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
            sl = self.conn.execute(
                "DELETE FROM sessions_log WHERE ts < ?", (cut,)).rowcount
            nb = self.conn.execute(
                "DELETE FROM net_bytes WHERE last_seen < ?", (cut,)).rowcount
            dr = self.conn.execute(
                "DELETE FROM dns_resolutions WHERE last_seen < ?",
                (cut,)).rowcount
            # VACUUM no puede correr dentro de la transaccion del DELETE.
            self.conn.commit()
            self.conn.execute("VACUUM")
            self.conn.commit()
        return {"events_removed": ev, "triages_removed": tr,
                "sessions_removed": sl, "net_bytes_removed": nb,
                "dns_resolutions_removed": dr}

    def reset(self) -> dict:
        """Borra eventos y triajes vivos; daily_stats NO se toca (historico)."""
        with self._lock:
            ev = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            tr = self.conn.execute("SELECT COUNT(*) FROM triages").fetchone()[0]
            nb = self.conn.execute(
                "SELECT COUNT(*) FROM net_bytes").fetchone()[0]
            self.conn.execute("DELETE FROM events")
            self.conn.execute("DELETE FROM triages")
            self.conn.execute("DELETE FROM sessions_log")
            self.conn.execute("DELETE FROM net_bytes")
            dr = self.conn.execute(
                "SELECT COUNT(*) FROM dns_resolutions").fetchone()[0]
            self.conn.execute("DELETE FROM dns_resolutions")
            self.conn.commit()
        return {"events_removed": ev, "triages_removed": tr,
                "net_bytes_removed": nb, "dns_resolutions_removed": dr}

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
