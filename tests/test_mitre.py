"""D6: mapa MITRE ATT&CK por evento/hallazgo (v2.6(1)).

Mapeo determinista display-only: R1 T1071.001 (canal), R2 T1567
(autonomia), R3 T1041 (beacon), R4 T1109 (proceso/destino nuevo),
R5 T1095 (UDP no 443). Sin senal, no tecnica."""
import tempfile
import unittest
from pathlib import Path

import mitre_map
import server
from store import Store


class TestMapEvent(unittest.TestCase):
    def _ids(self, ev, flags=None):
        return [t["id"] for t in mitre_map.map_event(ev, flags)]

    def test_r1_always(self):
        self.assertEqual(self._ids({}), ["T1071.001"])

    def test_r2_autonomy(self):
        self.assertIn("T1567", self._ids({"autonomy_verdict": "autonomous"}))
        self.assertIn("T1567", self._ids({"autonomy_verdict": "scheduled"}))
        self.assertEqual(
            self._ids({"autonomy_verdict": "user_driven"}), ["T1071.001"])

    def test_r3_beacon_boundaries(self):
        base = {"iat_cv": 0.3, "sessions": 5}
        self.assertIn("T1041", self._ids(base))          # limites inclusivos
        self.assertEqual(
            self._ids({"iat_cv": 0.31, "sessions": 5}), ["T1071.001"])
        self.assertEqual(
            self._ids({"iat_cv": 0.3, "sessions": 4}), ["T1071.001"])
        self.assertEqual(self._ids({"iat_cv": None, "sessions": 9}),
                         ["T1071.001"])

    def test_r4_and_r5_flags(self):
        self.assertIn("T1109", self._ids({}, [{"flag": "new_process"}]))
        self.assertIn("T1109", self._ids({}, [{"flag": "first_time_dest"}]))
        self.assertIn("T1095", self._ids({}, [{"flag": "udp_non443"}]))
        # flag ajeno: no aporta tecnica.
        self.assertEqual(self._ids({}, [{"flag": "off_hours"}]),
                         ["T1071.001"])

    def test_order_and_dedup(self):
        ev = {"autonomy_verdict": "autonomous", "iat_cv": 0.2,
             "sessions": 10}
        flags = [{"flag": "new_process"}, {"flag": "udp_non443"}]
        self.assertEqual(
            self._ids(ev, flags),
            ["T1071.001", "T1567", "T1041", "T1109", "T1095"])

    def test_union_mitre(self):
        a = mitre_map.map_event({"autonomy_verdict": "autonomous"})
        b = mitre_map.map_event({}, [{"flag": "new_process"}])
        u = mitre_map.union_mitre([a, b])
        self.assertEqual([t["id"] for t in u],
                         ["T1071.001", "T1567", "T1109"])


class FindingsMitreBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH")}
        server.store = self.store
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True,
                       "approved_providers": []}

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()


class TestServerMitre(FindingsMitreBase):
    def test_events_rows_have_mitre(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        out = server.list_events(group="none")
        ids = [t["id"] for t in out["events"][0]["mitre"]]
        # evento nuevo: T1071.001 + T1109 (flags new_process/first_time).
        self.assertEqual(ids, ["T1071.001", "T1109"])

    def test_grouped_rows_union_mitre(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        out = server.list_events()  # group="provider" por defecto
        ids = [t["id"] for t in out["events"][0]["mitre"]]
        self.assertEqual(ids, ["T1071.001", "T1109"])

    def test_findings_have_mitre(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        f = server.findings()["findings"][0]
        ids = [t["id"] for t in f["mitre"]]
        self.assertEqual(ids, ["T1071.001", "T1109"])
        self.assertTrue(all(t["porque"] for t in f["mitre"]))


if __name__ == "__main__":
    unittest.main()
