"""v2.5(3) D1/D2 — Baseline aprendido por (proceso, proveedor) y anomalia
determinista (sin IA).

- compute_baseline: agrupacion, primera aparicion, histograma UTC de
  inicios de sesion, horas tipicas (top con minimo de sesiones), ratio
  con piso de abanico, solo lo atribuible a proveedor.
- score_event: cada flag con su porque y peso; pre_score = suma (tope
  100); sin senal no hay flag (nunca se fabrica).
- GET /api/baseline: grupos con kind y eventos vivos con pre_score.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import baseline  # noqa: E402
import rules  # noqa: E402
import server  # noqa: E402
from store import LlmCallStore, Store  # noqa: E402

NOW = dt.datetime(2026, 9, 24, 12, 0, 0)      # hora 12 UTC (off-hours)
NOW_TYPICAL = dt.datetime(2026, 9, 24, 9, 30, 0)  # dentro de typical [9]


def _ev(process, provider, first_seen, last_seen=None):
    return {"process": process, "provider": provider,
            "first_seen": first_seen,
            "last_seen": last_seen or first_seen}


class TestComputeBaseline(unittest.TestCase):
    def test_grouping_and_first_seen(self):
        events = [
            _ev("a.exe", "openai.com", "2026-09-24 10:00:00Z"),
            # mismo par, otra IP (rotacion CDN): se agrupa.
            _ev("a.exe", "openai.com", "2026-09-20 08:00:00Z",
                "2026-09-24 11:30:00Z"),
            _ev("b.exe", "huggingface.co", "2026-09-21 09:00:00Z"),
        ]
        sessions = [
            ("2026-09-24 10:05:00Z", "a.exe", "1.1.1.1"),
            ("2026-09-23 09:00:00Z", "a.exe", "2.2.2.2"),
            ("2026-09-21 09:00:00Z", "b.exe", "3.3.3.3"),
        ]
        ip_provider = {"1.1.1.1": "openai.com",
                       "2.2.2.2": "openai.com",
                       "3.3.3.3": "huggingface.co"}
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        groups = {(g["process"], g["provider"]): g for g in view["groups"]}
        g = groups[("a.exe", "openai.com")]
        self.assertEqual(g["first_seen"], "2026-09-20 08:00:00Z")
        self.assertEqual(g["last_seen"], "2026-09-24 11:30:00Z")
        self.assertEqual(g["sessions_total"], 2)
        self.assertEqual(groups[("b.exe", "huggingface.co")]
                         ["sessions_total"], 1)
        # Ordenado por sesiones_total desc.
        self.assertEqual(view["groups"][0]["process"], "a.exe")

    def test_hour_hist_and_typical_hours(self):
        events = [_ev("a.exe", "openai.com", "2026-09-01 00:00:00Z")]
        sessions = []
        # horas 9 (x3), 14 (x3), 15 (x2), 20 (x1): top 6 por (count, hora).
        for i, h in enumerate([9, 9, 9, 14, 14, 14, 15, 15, 20]):
            sessions.append((f"2026-09-{i + 1:02d} {h:02d}:00:00Z",
                             "a.exe", "1.1.1.1"))
        ip_provider = {"1.1.1.1": "openai.com"}
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        g = view["groups"][0]
        self.assertEqual(g["hour_hist"], {"9": 3, "14": 3, "15": 2, "20": 1})
        self.assertEqual(g["typical_hours"], [9, 14, 15, 20])

    def test_typical_hours_min_sessions_gate(self):
        events = [_ev("a.exe", "openai.com", "2026-09-01 00:00:00Z")]
        sessions = [(f"2026-09-{i + 1:02d} 09:00:00Z", "a.exe", "1.1.1.1")
                    for i in range(4)]
        ip_provider = {"1.1.1.1": "openai.com"}
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        self.assertEqual(view["groups"][0]["typical_hours"], [])
        # Con 5 sesiones si sale.
        sessions.append(("2026-09-05 09:00:00Z", "a.exe", "1.1.1.1"))
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        self.assertEqual(view["groups"][0]["typical_hours"], [9])

    def test_rate_and_span_floor(self):
        # Abanico 10 h con 2 sesiones -> 0.2/h.
        events = [_ev("a.exe", "openai.com", "2026-09-24 02:00:00Z",
                      "2026-09-24 12:00:00Z")]
        sessions = [("2026-09-24 03:00:00Z", "a.exe", "1.1.1.1"),
                    ("2026-09-24 11:00:00Z", "a.exe", "1.1.1.1")]
        ip_provider = {"1.1.1.1": "openai.com"}
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        g = view["groups"][0]
        self.assertEqual(g["sessions_total"], 2)
        self.assertAlmostEqual(g["sessions_per_hour"], 0.2, places=4)
        # Abanico con piso de 1 h: primera y ultima en el mismo segundo.
        events = [_ev("a.exe", "openai.com", "2026-09-24 11:59:00Z",
                      "2026-09-24 11:59:30Z")]
        sessions = [("2026-09-24 11:59:10Z", "a.exe", "1.1.1.1")]
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        self.assertAlmostEqual(view["groups"][0]["sessions_per_hour"], 1.0,
                               places=4)

    def test_unattributable_sessions_skipped(self):
        events = [_ev("a.exe", "openai.com", "2026-09-24 10:00:00Z")]
        # Sesion a una IP sin mapeo a proveedor: no se cuenta (honestidad).
        sessions = [("2026-09-24 10:05:00Z", "a.exe", "9.9.9.9")]
        view = baseline.compute_baseline(events, sessions, {}, now=NOW)
        g = view["groups"][0]
        self.assertEqual(g["sessions_total"], 0)
        self.assertIsNone(g["sessions_per_hour"])

    def test_process_first_seen_and_days(self):
        events = [
            _ev("a.exe", "openai.com", "2026-09-10 10:00:00Z"),
            _ev("a.exe", "huggingface.co", "2026-09-05 08:00:00Z"),
        ]
        sessions = [
            ("2026-09-12 10:05:00Z", "a.exe", "1.1.1.1"),
            ("2026-09-24 11:00:00Z", "a.exe", "1.1.1.1"),
        ]
        ip_provider = {"1.1.1.1": "openai.com"}
        view = baseline.compute_baseline(events, sessions, ip_provider,
                                         now=NOW)
        self.assertEqual(view["process_first_seen"]["a.exe"],
                         "2026-09-05 08:00:00Z")
        g = {g_["provider"]: g_ for g_ in view["groups"]}
        # dias_active incluye la fecha de primera aparicion.
        self.assertEqual(g["openai.com"]["days_active"], 3)
        # recent_sessions: solo las del ultimo dia (NOW - 24 h).
        self.assertEqual(g["openai.com"]["recent_sessions"], 1)


class TestScoreEvent(unittest.TestCase):
    def _group(self, **kw):
        base = {"process": "a.exe", "provider": "openai.com",
                "first_seen": "2026-09-01 09:00:00Z",
                "last_seen": "2026-09-24 11:00:00Z",
                "sessions_total": 10, "span_hours": 720.0,
                "sessions_per_hour": 0.0139, "days_active": 20,
                "hour_hist": {"9": 10}, "typical_hours": [9],
                "recent_sessions": 1}
        base.update(kw)
        return base

    def _ev(self, **kw):
        base = {"process": "a.exe", "provider": "openai.com",
                "first_seen": "2026-09-01 09:00:00Z",
                "protocol": "tcp", "dest_port": 443}
        base.update(kw)
        return base

    def test_no_flags_old_pair(self):
        # now en hora tipica (9h): sin flags para un par antiguo.
        s = baseline.score_event(self._ev(), self._group(),
                                 "2026-09-01 09:00:00Z", now=NOW_TYPICAL)
        self.assertEqual(s["pre_score"], 0)
        self.assertEqual(s["pre_flags"], [])

    def test_first_time_dest(self):
        ev = self._ev(first_seen="2026-09-24 11:00:00Z")
        g = self._group(first_seen="2026-09-24 11:00:00Z")
        s = baseline.score_event(ev, g, "2026-09-01 09:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual(s["pre_score"], 25)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["first_time_dest"])
        self.assertIn("primera aparicion", s["pre_flags"][0]["porque"])

    def test_new_process(self):
        ev = self._ev()
        g = self._group()
        s = baseline.score_event(ev, g, "2026-09-24 11:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["new_process"])
        self.assertEqual(s["pre_score"], 25)

    def test_off_hours_requires_typical(self):
        ev = self._ev()
        # typical vacio (baseline <5 sesiones): no se evalua.
        g = self._group(typical_hours=[])
        s = baseline.score_event(ev, g, "2026-09-01 09:00:00Z", now=NOW)
        self.assertEqual(s["pre_score"], 0)
        # typical [9] y ahora son las 12h: dispara.
        g = self._group(typical_hours=[9])
        s = baseline.score_event(ev, g, "2026-09-01 09:00:00Z", now=NOW)
        self.assertEqual([f["flag"] for f in s["pre_flags"]], ["off_hours"])
        self.assertEqual(s["pre_score"], 20)

    def test_high_sessions(self):
        ev = self._ev()
        # ratio 0.5/h -> esperado 12 en 24h; 40 recientes > 3*12 y >=5.
        g = self._group(sessions_per_hour=0.5, recent_sessions=40)
        s = baseline.score_event(ev, g, "2026-09-01 09:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["high_sessions"])
        # 15 recientes < 3*12 (36): no dispara.
        g = self._group(sessions_per_hour=0.5, recent_sessions=15)
        s = baseline.score_event(ev, g, "2026-09-01 09:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual(s["pre_score"], 0)

    def test_udp_non443(self):
        ev = self._ev(protocol="udp", dest_port=5353)
        s = baseline.score_event(ev, self._group(),
                                "2026-09-01 09:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["udp_non443"])
        # UDP 443 (QUIC esperado): no dispara.
        ev = self._ev(protocol="udp", dest_port=443)
        s = baseline.score_event(ev, self._group(),
                                "2026-09-01 09:00:00Z",
                                now=NOW_TYPICAL)
        self.assertEqual(s["pre_score"], 0)

    def test_score_cap_and_order(self):
        ev = self._ev(first_seen="2026-09-24 11:00:00Z",
                      protocol="udp", dest_port=5353)
        g = self._group(first_seen="2026-09-24 11:00:00Z",
                        typical_hours=[9],
                        sessions_per_hour=0.5, recent_sessions=40)
        s = baseline.score_event(ev, g, "2026-09-24 11:00:00Z", now=NOW)
        # 25+25+20+25+15 = 110 -> tope 100.
        self.assertEqual(s["pre_score"], 100)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["first_time_dest", "new_process",
                          "high_sessions", "off_hours", "udp_non443"])

    def test_no_group_only_udp(self):
        ev = self._ev(protocol="udp", dest_port=5353)
        s = baseline.score_event(ev, None, None, now=NOW)
        self.assertEqual([f["flag"] for f in s["pre_flags"]],
                         ["udp_non443"])


class BaselineEndpointBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.llm = LlmCallStore(Path(self.tmp.name) / "llm.db")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH", "llm_calls")}
        server.store = self.store
        server.llm_calls = self.llm
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True,
                       "approved_providers": []}

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.llm.close()
        self.tmp.cleanup()

    def _seed_session(self, ts, process, dest_ip):
        self.store.conn.execute(
            "INSERT INTO sessions_log (ts, process, dest_ip, dest_port)"
            " VALUES (?,?,?,443)", (ts, process, dest_ip))
        self.store.conn.commit()


class TestBaselineEndpoint(BaselineEndpointBase):
    def test_groups_kind_and_current_score(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        self._seed_session("2026-09-24 11:59:00Z", "a.exe", "1.1.1.1")
        out = server.baseline_api()
        self.assertEqual(len(out["groups"]), 1)
        g = out["groups"][0]
        self.assertEqual(g["provider"], "api.openai.com")
        self.assertEqual(g["kind"], "api")
        self.assertEqual(g["sessions_total"], 1)
        self.assertEqual(len(g["current"]), 1)
        # Evento nuevo: first_time_dest + new_process = 50.
        self.assertEqual(g["current"][0]["pre_score"], 50)
        flags = {f["flag"] for f in g["current"][0]["pre_flags"]}
        self.assertEqual(flags, {"first_time_dest", "new_process"})
        self.assertEqual(out["window"]["since"], g["first_seen"])

    def test_empty_store(self):
        out = server.baseline_api()
        self.assertEqual(out["groups"], [])
        self.assertIsNone(out["window"]["since"])


class TestEventsPreScore(BaselineEndpointBase):
    def test_rows_and_grouped(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        # Sin agrupar: pre_score y flags por fila.
        out = server.list_events(group="none")
        e0 = out["events"][0]
        self.assertEqual(e0["pre_score"], 50)
        self.assertEqual({f["flag"] for f in e0["pre_flags"]},
                         {"first_time_dest", "new_process"})
        # Agrupado: el max de miembros y sus flags.
        out = server.list_events()
        g0 = out["events"][0]
        self.assertTrue(out["grouped"])
        self.assertEqual(g0["pre_score"], 50)
        self.assertEqual({f["flag"] for f in g0["pre_flags"]},
                         {"first_time_dest", "new_process"})


class TestTriagePreScore(BaselineEndpointBase):
    def test_payload_has_pre_score(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        out = server.triage(server.TriageRequest())
        self.assertEqual(out["jev"]["status"], "skipped")
        ev0 = out["events"][0]
        self.assertEqual(ev0["pre_score"], 50)
        self.assertTrue(any(f["flag"] == "first_time_dest"
                            for f in ev0["pre_flags"]))


class TestRulesAnomaly(unittest.TestCase):
    def _ev(self, pre_score):
        return {"process": "a.exe", "provider": "openai.com",
                "autonomy_verdict": "unknown", "sessions": 1,
                "iat_cv": None, "unapproved": True,
                "pre_score": pre_score}

    def test_rule_fires_with_detail(self):
        res = {r["id"]: r for r in
               rules.evaluate([self._ev(60)], egress_mb_per_day=500)}
        self.assertTrue(res["anomaly_pre_score"]["fired"])
        self.assertIn("pre_score 60", res["anomaly_pre_score"]["detail"])

    def test_rule_not_fired_below_threshold(self):
        res = {r["id"]: r for r in
               rules.evaluate([self._ev(25)], egress_mb_per_day=500)}
        self.assertFalse(res["anomaly_pre_score"]["fired"])
        self.assertIsNone(res["anomaly_pre_score"]["detail"])


class TestRulesEventsPreScore(BaselineEndpointBase):
    def test_rules_events_includes_pre_score(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        evs = server._rules_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["pre_score"], 50)


if __name__ == "__main__":
    unittest.main()
