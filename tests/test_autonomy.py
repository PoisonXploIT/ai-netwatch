"""Tests de Autonomia (R2, v2.1): quien hace la salida a IA.

- evaluate(): funcion pura de senales -> {score, flags, verdict}.
- Señales Win32: smoke (tipo correcto, nunca lanza).
- Store: autonomia_score/flags/verdict persistidos por evento (overwrite).
- Jev: user_active real desde el veredicto persistido.
- Alerta autonomous_ai_call: una por (proceso, proveedor).
- Monitor: linaje EID 1 -> _lineage; _autonomy_for con cache de señales.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import autonomy  # noqa: E402
import jev_triage  # noqa: E402
import server  # noqa: E402
from monitor import NetMonitor  # noqa: E402
from store import Store  # noqa: E402


class TestEvaluate(unittest.TestCase):
    def test_locked_session_is_autonomous(self):
        # Bloqueo es autonomia por regla directa (no por umbral de score).
        r = autonomy.evaluate("agent.exe", 1, locked=True)
        self.assertEqual(r["verdict"], "autonomous")
        self.assertIn("session_locked", r["flags"])
        self.assertEqual(r["score"], 50)

    def test_long_idle_is_autonomous(self):
        r = autonomy.evaluate("agent.exe", 1, idle_seconds=300)
        self.assertEqual(r["verdict"], "autonomous")

    def test_scheduled_task_lineage(self):
        r = autonomy.evaluate(
            "agent.exe", 1, idle_seconds=5, locked=False,
            parent_cmdline=r"C:\Windows\System32\schtasks.exe /run "
                          r"/tn NightlyReport")
        self.assertEqual(r["verdict"], "scheduled")
        self.assertIn("scheduled_task", r["flags"])

    def test_service_parent_alone_is_not_autonomous(self):
        # 25 puntos: sospecha, pero no basta para el veredicto.
        r = autonomy.evaluate(
            "svc.exe", 1, locked=False, idle_seconds=5,
            parent_image=r"C:\Windows\System32\svchost.exe")
        self.assertEqual(r["verdict"], "user_driven")
        self.assertIn("service_parent", r["flags"])

    def test_active_user_is_user_driven(self):
        r = autonomy.evaluate("chrome.exe", 1, locked=False, idle_seconds=3)
        self.assertEqual(r["verdict"], "user_driven")

    def test_no_signals_is_unknown(self):
        r = autonomy.evaluate("mystery.exe", 1)
        self.assertEqual(r["verdict"], "unknown")
        self.assertEqual(r["score"], 0)

    def test_score_capped_at_100(self):
        r = autonomy.evaluate(
            "x.exe", 1, locked=True, idle_seconds=600,
            foreground_pid=999,
            parent_cmdline="schtasks /run",
        )
        self.assertLessEqual(r["score"], 100)

    def test_no_foreground_requires_user_away(self):
        # Foreground distinto con el usuario activo: sin flag (evita falsos
        # positivos en navegadores multiproceso).
        r = autonomy.evaluate("chrome.exe", 2, locked=False, idle_seconds=5,
                             foreground_pid=1)
        self.assertNotIn("no_foreground", r["flags"])
        r2 = autonomy.evaluate("chrome.exe", 2, locked=False,
                              idle_seconds=90, foreground_pid=1)
        self.assertIn("no_foreground", r2["flags"])


class TestIdleLiveness(unittest.TestCase):
    """Auto-diagnostico: contador congelado (sesion de servicio) -> None.

    Un contador vivo avanza con el tiempo real; si entre dos probes no
    cambia nada, la senal no es confiable y degrada a None (unknown),
    nunca a autonomia inventada.
    """

    def setUp(self) -> None:
        self._old = autonomy._last_probe

    def tearDown(self) -> None:
        autonomy._last_probe = self._old

    def test_frozen_counter_is_none(self):
        autonomy._last_probe = (time.monotonic() - 2, 1000)
        with unittest.mock.patch.object(
                autonomy, "_probe_ms", return_value=1000):
            self.assertIsNone(autonomy.get_idle_seconds())

    def test_advancing_counter_ok(self):
        autonomy._last_probe = (time.monotonic() - 2, 1000)
        with unittest.mock.patch.object(
                autonomy, "_probe_ms", return_value=3000):
            self.assertEqual(autonomy.get_idle_seconds(), 3)

    def test_first_probe_returns_value(self):
        autonomy._last_probe = None
        with unittest.mock.patch.object(
                autonomy, "_probe_ms", return_value=1234):
            self.assertEqual(autonomy.get_idle_seconds(), 1)

    def test_idle_exceeding_uptime_is_none_immediately(self):
        # Guard inmediato: idle > uptime es imposible -> None sin esperar
        # a que el contador se congele (primera llamada ya).
        autonomy._last_probe = None
        # 10^9 ms (~11.5 dias) > uptime de 1 dia: imposible -> None.
        with unittest.mock.patch.object(
                autonomy, "_probe_ms", return_value=10**9), \
             unittest.mock.patch.object(
                 autonomy, "_uptime_ms", return_value=86_400_000):
            self.assertIsNone(autonomy.get_idle_seconds())

    def test_idle_none_never_autonomous(self):
        # idle=None (senal no confiable) => unknown, nunca autonomous.
        r = autonomy.evaluate("x.exe", idle_seconds=None, locked=False)
        self.assertEqual(r["verdict"], autonomy.UNKNOWN)


class TestSignalsSmoke(unittest.TestCase):
    """Las señales Win32 devuelven el tipo correcto y nunca lanzan."""

    def test_idle_seconds_type(self):
        v = autonomy.get_idle_seconds()
        self.assertTrue(v is None or isinstance(v, int))

    def test_foreground_pid_type(self):
        v = autonomy.get_foreground_pid()
        self.assertTrue(v is None or isinstance(v, int))

    def test_session_locked_type(self):
        v = autonomy.is_session_locked()
        self.assertTrue(v is None or isinstance(v, bool))


class TestStoreAutonomy(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_persists_and_overwrites(self):
        self.store.observe_connection(
            "a.exe", "1.2.3.4", 443, "openai.com", None,
            autonomy_score=70, autonomy_flags="session_locked",
            autonomy_verdict="autonomous")
        row = self.store.list_events(limit=1)[0]
        self.assertEqual(row["autonomy_score"], 70)
        self.assertEqual(row["autonomy_flags"], "session_locked")
        self.assertEqual(row["autonomy_verdict"], "autonomous")
        # Segunda observacion: overwrite con el nuevo estado.
        self.store.observe_connection(
            "a.exe", "1.2.3.4", 443, "openai.com", None,
            autonomy_score=5, autonomy_flags=None,
            autonomy_verdict="user_driven")
        row = self.store.list_events(limit=1)[0]
        self.assertEqual(row["autonomy_score"], 5)
        self.assertIsNone(row["autonomy_flags"])
        self.assertEqual(row["autonomy_verdict"], "user_driven")

    def test_autonomy_events_filters(self):
        self.store.observe_connection(
            "a.exe", "1.2.3.4", 443, None, None,
            autonomy_verdict="scheduled")
        self.store.observe_connection(
            "b.exe", "5.6.7.8", 443, None, None,
            autonomy_verdict="user_driven")
        evs = self.store.autonomy_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["process"], "a.exe")


class TestJevPayload(unittest.TestCase):
    def test_user_active_from_verdict(self):
        ev = {"autonomy_verdict": "autonomous"}
        self.assertEqual(jev_triage._state_for(ev)["user_active"],
                         "autonomous")
        self.assertEqual(jev_triage._state_for({})["user_active"],
                         "unknown")


class AutonomyAlertBase(unittest.TestCase):
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
        server._shadow_alerted.clear()
        server._autonomy_alerted.clear()

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()


class TestAutonomyAlert(AutonomyAlertBase):
    def _ev(self, **kw):
        base = {"id": 1, "process": "svc.exe", "dest_ip": "9.9.9.9",
                "dest_port": 443, "sni_domain": "api.openai.com",
                "catalog_domain": "openai.com", "ai_layer": "catalog"}
        base.update(kw)
        return base

    def _kinds(self):
        return [a["kind"] for a in self.log.list()]

    def test_autonomous_alerts_once_per_pair(self):
        ev = self._ev(autonomy_verdict="autonomous", autonomy_score=70)
        server._on_new_ai_event(ev)
        server._on_new_ai_event(ev)  # dedup: no duplica
        kinds = self._kinds()
        self.assertEqual(kinds.count("autonomous_ai_call"), 1)

    def test_scheduled_alerts(self):
        server._on_new_ai_event(
            self._ev(autonomy_verdict="scheduled", autonomy_score=40))
        self.assertIn("autonomous_ai_call", self._kinds())

    def test_user_driven_does_not_alert_autonomy(self):
        server._on_new_ai_event(
            self._ev(autonomy_verdict="user_driven", autonomy_score=0))
        self.assertNotIn("autonomous_ai_call", self._kinds())

    def test_reset_realerts(self):
        ev = self._ev(autonomy_verdict="autonomous")
        server._on_new_ai_event(ev)
        server._shadow_alerted.clear()
        server._autonomy_alerted.clear()
        server._on_new_ai_event(ev)
        self.assertEqual(self._kinds().count("autonomous_ai_call"), 2)


class TestMonitorLineage(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.m = NetMonitor(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_eid1_cycle_last_wins(self):
        calls = iter([[
            {"record_id": 1, "process": "svc.exe",
             "parent_image": r"C:\Windows\System32\svchost.exe",
             "parent_process": "svchost.exe", "parent_cmdline": ""},
        ], [
            {"record_id": 2, "process": "svc.exe",
             "parent_image": r"C:\Windows\System32\schtasks.exe",
             "parent_process": "schtasks.exe",
             "parent_cmdline": "schtasks /run /tn X"},
        ]])
        self.m._eid1 = lambda: next(calls)
        self.m._eid1_cycle()
        self.assertEqual(self.m._lineage["svc.exe"]["parent_process"],
                         "svchost.exe")
        self.m._eid1_cycle()
        self.assertEqual(self.m._lineage["svc.exe"]["parent_process"],
                         "schtasks.exe")

    def test_autonomy_for_uses_lineage_and_signals(self):
        self.m._lineage = {"agent.exe": {
            "parent_image": r"C:\Windows\System32\schtasks.exe",
            "parent_process": "schtasks.exe",
            "parent_cmdline": "schtasks /run"}}
        self.m._aut_cache = (time.monotonic(),
                            {"idle_seconds": None, "locked": True,
                             "foreground_pid": None})
        r = self.m._autonomy_for("agent.exe", 123)
        self.assertEqual(r["verdict"], "scheduled")

    def test_autonomy_for_unknown_process_is_safe(self):
        self.m._aut_cache = (time.monotonic(),
                            {"idle_seconds": None, "locked": None,
                             "foreground_pid": None})
        r = self.m._autonomy_for("nobody.exe", 1)
        self.assertEqual(r["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
