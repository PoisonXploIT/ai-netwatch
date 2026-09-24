"""Tests v2.2: motor de reglas (reglas por umbral sobre señales existentes).

- Reglas puras: service_ai_call (autonomous/scheduled + no aprobado),
  beacon_unapproved (N>=5, CV<=0.3 + no aprobado), egress pendiente
  (available=False hasta bytes remotos).
- Ciclo del servidor: alerta rule_fired una vez por regla en transicion;
  rules_enabled=False silencia; reset re-alerta.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import rules  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


def _ev(**kw):
    base = {"process": "x.exe", "provider": "evil.example",
            "autonomy_verdict": None, "sessions": 1, "iat_cv": None,
            "unapproved": True}
    base.update(kw)
    return base


class TestRulesEvaluate(unittest.TestCase):
    def test_service_ai_fires(self):
        out = rules.evaluate(
            [_ev(autonomy_verdict="autonomous")], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["service_ai_call"]["fired"])

    def test_service_ai_scheduled_counts(self):
        out = rules.evaluate(
            [_ev(autonomy_verdict="scheduled")], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["service_ai_call"]["fired"])

    def test_service_ai_user_driven_no_fire(self):
        out = rules.evaluate(
            [_ev(autonomy_verdict="user_driven")], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertFalse(r["service_ai_call"]["fired"])

    def test_service_ai_approved_no_fire(self):
        out = rules.evaluate(
            [_ev(autonomy_verdict="autonomous", unapproved=False)],
            egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertFalse(r["service_ai_call"]["fired"])

    def test_beacon_fires(self):
        out = rules.evaluate(
            [_ev(sessions=5, iat_cv=0.1)], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["beacon_unapproved"]["fired"])

    def test_beacon_n_below_min_no_fire(self):
        out = rules.evaluate(
            [_ev(sessions=4, iat_cv=0.1)], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertFalse(r["beacon_unapproved"]["fired"])

    def test_beacon_cv_high_no_fire(self):
        out = rules.evaluate(
            [_ev(sessions=6, iat_cv=0.5)], egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertFalse(r["beacon_unapproved"]["fired"])

    def test_beacon_approved_no_fire(self):
        out = rules.evaluate(
            [_ev(sessions=5, iat_cv=0.1, unapproved=False)],
            egress_mb_per_day=500)
        r = {x["id"]: x for x in out}
        self.assertFalse(r["beacon_unapproved"]["fired"])

    def test_egress_pending_not_available(self):
        out = rules.evaluate([], egress_mb_per_day=123.4)
        r = {x["id"]: x for x in out}
        e = r["egress_volume_unapproved"]
        self.assertFalse(e["available"])
        self.assertFalse(e["fired"])
        self.assertIn("123.4", str(e["reason"]))


class RulesServerBase(unittest.TestCase):
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
                       "alerts_enabled": True,
                       "rules_enabled": True,
                       "rule_egress_mb_per_day": 500.0}
        server._rules_alerted.clear()

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()

    def _kinds(self):
        return [a["kind"] for a in self.log.list()]

    def _fired_rules(self):
        # v2.5(3): cada alerta rule_fired lleva el id de la regla en details.
        return [(a.get("details") or {}).get("rule")
                for a in self.log.list() if a["kind"] == "rule_fired"]


class TestRulesServer(RulesServerBase):
    def test_fired_rule_alerts_once(self):
        # IP destino = proveedor no aprobable -> unapproved.
        self.store.observe_connection("svc.exe", "9.9.9.9", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET autonomy_verdict='autonomous'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        server._rules_cycle()
        # service_ai_call y anomaly_pre_score (evento nuevo: pre_score 50)
        # disparan, cada una una vez.
        fired = self._fired_rules()
        self.assertEqual(fired.count("service_ai_call"), 1)
        self.assertEqual(fired.count("anomaly_pre_score"), 1)
        # Ciclos siguientes: sigue firmando pero no re-alerta.
        server._rules_cycle()
        fired = self._fired_rules()
        self.assertEqual(fired.count("service_ai_call"), 1)
        self.assertEqual(fired.count("anomaly_pre_score"), 1)

    def test_rules_disabled_no_alert(self):
        self.store.observe_connection("svc.exe", "9.9.9.9", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET autonomy_verdict='autonomous'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        server._cfg["rules_enabled"] = False
        server._rules_cycle()
        self.assertNotIn("rule_fired", self._kinds())

    def test_reset_realerts(self):
        self.store.observe_connection("svc.exe", "9.9.9.9", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET autonomy_verdict='autonomous'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        server._rules_cycle()
        server._rules_alerted.clear()  # lo que hace el reset
        server._rules_cycle()
        fired = self._fired_rules()
        self.assertEqual(fired.count("service_ai_call"), 2)
        self.assertEqual(fired.count("anomaly_pre_score"), 2)

    def test_api_rules_shape(self):
        out = server.list_rules()
        ids = [r["id"] for r in out["rules"]]
        self.assertIn("egress_volume_unapproved", ids)
        self.assertIn("service_ai_call", ids)
        self.assertIn("beacon_unapproved", ids)


if __name__ == "__main__":
    unittest.main()
