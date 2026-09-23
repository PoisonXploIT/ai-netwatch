"""Tests F1/D3 (v2.1): sesiones (no polls) y beaconing.

- F1: sesion = transicion ausente->presente por clave; un keep-alive largo
  sigue siendo 1 sesion; un reconnect suma.
- D3: CV de inter-arrival sobre la ventana de ultimos timestamps;
  beaconing si N>=5 y CV<=0.3 (regular). new_beaconing solo en la
  transicion (estado anterior, sin contar la nueva).
- Alerta beaconing_ai_call: una por clave IA; no-IA no alerta.
- Jev: sessions/iat_cv/beaconing en el payload.

Aceptacion: sintetica cada 60 s -> CV ~0 -> beaconing; keep-alive ->
sessions=1, sin beacon.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import jev_triage  # noqa: E402
import server  # noqa: E402
from monitor import NetMonitor  # noqa: E402
from store import Store  # noqa: E402

def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _ts(offset_s: int) -> str:
    """Timestamp a offset_s segundos de AHORA (negativo = pasado).

    record_session usa _now() real; los seeds tienen que ser relativos
    al momento para que el ultimo inter-arrival sea coherente."""
    return (_now_dt() + timedelta(seconds=offset_s)).strftime(
        "%Y-%m-%d %H:%M:%SZ")


class StoreBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.store.observe_connection("a.exe", "1.2.3.4", 443, None, None)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _seed(self, offsets):
        for off in offsets:
            self.store.conn.execute(
                "INSERT INTO sessions_log"
                " (ts, process, dest_ip, dest_port) VALUES (?,?,?,?)",
                (_ts(off), "a.exe", "1.2.3.4", 443))


class TestRecordSession(StoreBase):
    def test_first_session(self):
        s = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertEqual(s["sessions"], 1)
        self.assertIsNone(s["iat_cv"])
        self.assertFalse(s["beaconing"])

    def test_keepalive_single_session_no_beacon(self):
        # Aceptacion: keep-alive largo -> sessions=1, sin beacon.
        s = self.store.record_session("a.exe", "1.2.3.4", 443)
        row = self.store.get_event_by_key("a.exe", "1.2.3.4", 443)
        self.assertEqual(s["sessions"], 1)
        self.assertEqual(row["sessions"], 1)
        self.assertIsNone(row["iat_cv"])

    def test_regular_60s_is_beaconing(self):
        # Aceptacion: sintetica cada 60 s -> CV ~0 -> beaconing.
        self._seed([-240, -180, -120, -60])
        s = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertEqual(s["sessions"], 5)
        self.assertTrue(s["beaconing"])
        self.assertTrue(s["new_beaconing"])
        self.assertLess(s["iat_cv"], 0.3)
        row = self.store.get_event_by_key("a.exe", "1.2.3.4", 443)
        self.assertIsNotNone(row["beacon_score"])
        self.assertGreaterEqual(row["beacon_score"], 70)

    def test_irregular_is_not_beaconing(self):
        # IATs irregulares (10/15/35/180 s) -> CV >> 0.3: no beacon.
        self._seed([-240, -230, -215, -180])
        s = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertEqual(s["sessions"], 5)
        self.assertFalse(s["beaconing"])
        self.assertTrue(s["new_beaconing"] is False)

    def test_new_beaconing_only_on_transition(self):
        self._seed([-240, -180, -120, -60])
        first = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertTrue(first["beaconing"])
        self.assertTrue(first["new_beaconing"])
        # Un arribo fuera de ciclo (segundos despues) rompe el patron:
        # ventana estricta -> deja de ser beaconing. new_beaconing
        # nunca repite sin transicion.
        second = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertFalse(second["beaconing"])
        self.assertFalse(second["new_beaconing"])

    def test_window_capped_at_20(self):
        # 50 sesiones pasadas a 60 s (regulares).
        self._seed([-(i * 60) for i in range(1, 51)])
        s = self.store.record_session("a.exe", "1.2.3.4", 443)
        self.assertEqual(s["sessions"], 51)
        self.assertTrue(s["beaconing"])
        # Techo por clave: no mas de 50 timestamps persistidos.
        n = self.store.conn.execute(
            "SELECT COUNT(*) FROM sessions_log").fetchone()[0]
        self.assertLessEqual(n, 50)


class TestMonitorSessions(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.m = NetMonitor(self.store)
        self.key = ("a.exe", "1.2.3.4", 443)
        self.store.observe_connection(*self.key, None, None)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _cycle(self, keys):
        self.m._seen_iter = set(keys)
        self.m._session_cycle()

    def test_transition_counts_once(self):
        self._cycle([self.key])          # primera vez: sesion 1
        self._cycle([self.key])          # presente->presente: sigue 1
        self._cycle([])                  # ausente: nada
        self._cycle([self.key])          # ausente->presente: sesion 2
        row = self.store.get_event_by_key(*self.key)
        self.assertEqual(row["sessions"], 2)

    def test_beacon_callback_fires_once(self):
        fired = []
        self.m._on_beacon = lambda key, stats: fired.append((key, stats))
        for off in (-240, -180, -120, -60):
            self.store.conn.execute(
                "INSERT INTO sessions_log"
                " (ts, process, dest_ip, dest_port) VALUES (?,?,?,?)",
                (_ts(off), *self.key))
        self._cycle([self.key])
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0][0], self.key)
        self.assertTrue(fired[0][1]["new_beaconing"])
        # Ciclos siguientes sin transicion: no repite.
        self._cycle([self.key])
        self.assertEqual(len(fired), 1)


class BeaconAlertBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.log = alerts.AlertLog(Path(self.tmp.name) / "alerts.log")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH", "alerts")}
        server.store = self.store
        server.alerts = self.log
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True,
                       "approved_providers": [],
                       "alerts_enabled": True}
        server._beacon_alerted.clear()

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()


class TestBeaconAlert(BeaconAlertBase):
    STATS = {"sessions": 5, "iat_cv": 0.1, "beacon_score": 90,
             "beaconing": True, "new_beaconing": True}

    def _kinds(self):
        return [a["kind"] for a in self.log.list()]

    def test_ai_key_alerts_once(self):
        self.store.observe_connection(
            "svc.exe", "9.9.9.9", 443, "api.openai.com", None)
        server._on_beacon(("svc.exe", "9.9.9.9", 443), self.STATS)
        server._on_beacon(("svc.exe", "9.9.9.9", 443), self.STATS)
        self.assertEqual(
            self._kinds().count("beaconing_ai_call"), 1)

    def test_non_ai_key_does_not_alert(self):
        self.store.observe_connection("b.exe", "8.8.8.8", 80, None, None)
        server._on_beacon(("b.exe", "8.8.8.8", 80), self.STATS)
        self.assertNotIn("beaconing_ai_call", self._kinds())


class TestJevPayload(unittest.TestCase):
    def test_sessions_and_beacon_fields(self):
        ev = {"sessions": 7, "iat_cv": 0.1}
        p = jev_triage._state_for(ev)
        self.assertEqual(p["sessions"], 7)
        self.assertEqual(p["iat_cv"], 0.1)
        self.assertTrue(p["beaconing"])
        ev2 = {"sessions": 2, "iat_cv": 0.1}
        self.assertFalse(jev_triage._state_for(ev2)["beaconing"])


if __name__ == "__main__":
    unittest.main()
