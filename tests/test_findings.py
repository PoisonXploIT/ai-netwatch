"""v2.6 UX: /api/findings — una fila por (proceso, proveedor) con score
combinado 0-100 (pre_score + Jev + autonomia + beaconing + no aprobado).
Display-only: no cambia deteccion ni veredictos."""
import tempfile
import unittest
from pathlib import Path

import server
from store import Store


class FindingsBase(unittest.TestCase):
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

    def _conn(self, process, ip="1.1.1.1", catalog="api.openai.com"):
        self.store.observe_connection(
            process=process, dest_ip=ip, dest_port=443, dest_host=None,
            catalog_domain=catalog, ai_layer="catalog")

    def _row(self, process):
        out = [f for f in server.findings()["findings"]
               if f["process"] == process]
        self.assertEqual(len(out), 1)
        return out[0]


class TestFindings(FindingsBase):
    def test_one_row_per_pair_and_order(self):
        # a.exe -> openai (catalog, aprobado): pre 50.
        # b.exe -> IP sin catalogo: pre 50 + no aprobado 10 = 60.
        self._conn("a.exe")
        self._conn("b.exe", ip="9.9.9.9", catalog=None)
        out = server.findings()["findings"]
        self.assertEqual([f["process"] for f in out], ["b.exe", "a.exe"])
        self.assertEqual(out[0]["score"], 60)
        self.assertTrue(out[0]["unapproved"])
        self.assertFalse(self._row("a.exe")["unapproved"])

    def test_jev_enrichment(self):
        self._conn("a.exe")
        eid = self.store.list_events()[0]["id"]
        # El payload del triaje: verdicts indexados por posicion (str(i)).
        self.store.save_triage(
            "ok", "jev-test",
            {"events": [{"id": eid, "process": "a.exe"}],
             "jev": {"verdicts": {"0": {"verdict": "expected",
                                        "severity_score": 4.0}}}})
        f = self._row("a.exe")
        self.assertEqual(f["jev_verdict"], "expected")
        self.assertEqual(f["jev_severity"], 4.0)
        # pre 50 + jev 4.0*10 = 90.
        self.assertEqual(f["score"], 90)

    def test_review_enrichment(self):
        self._conn("a.exe")
        eid = self.store.list_events()[0]["id"]
        self.store.save_review(eid, "confirm", "coherente con el resto", None)
        f = self._row("a.exe")
        self.assertEqual(f["review"]["evaluacion"], "confirm")

    def test_score_cap_100(self):
        # 5 sesiones para beaconing (sessions >= 5 y iat_cv <= 0.3).
        for _ in range(5):
            self._conn("b.exe", ip="9.9.9.9", catalog=None)
        self.store.conn.execute(
            "UPDATE events SET autonomy_verdict='autonomous',"
            " iat_cv=0.2, sessions=5")
        self.store.conn.commit()
        eid = self.store.list_events()[0]["id"]
        self.store.save_triage(
            "ok", "jev-test",
            {"events": [{"id": eid, "process": "b.exe"}],
             "jev": {"verdicts": {"0": {"verdict": "exfiltration_suspect",
                                        "severity_score": 10.0}}}})
        f = self._row("b.exe")
        # pre 50 + jev 100 + auto 15 + beacon 15 + unapproved 10 = 190 -> 100
        self.assertEqual(f["score"], 100)
        self.assertTrue(f["beaconing"])
        self.assertEqual(f["autonomy_verdict"], "autonomous")

    def test_empty_store(self):
        out = server.findings()
        self.assertEqual(out["findings"], [])


if __name__ == "__main__":
    unittest.main()
