"""I1: dedup de triaje por firma (v2.6(2)).

La firma resume el estado que afecta al veredicto; si no cambio desde
el ultimo triaje OK, el veredicto se reutiliza sin llamar a Jev.
Volatiles (seen_count, last_seen...) NO entran en la firma."""
import tempfile
import unittest
from pathlib import Path

import server
import triage_sig
from store import Store


class TestSignature(unittest.TestCase):
    def _sig(self, **kw):
        base = {"process": "a.exe", "dest_ip": "1.1.1.1", "dest_port": 443,
               "catalog_domain": "api.openai.com", "ai_layer": "catalog",
               "protocol": "tcp", "autonomy_verdict": "user_driven",
               "pre_flags": [{"flag": "off_hours"}]}
        base.update(kw)
        return triage_sig.event_signature(base)

    def test_stable_across_volatile_fields(self):
        # seen_count / last_seen / pre_score exacto: fuera de la firma.
        e1 = {"process": "a.exe", "dest_ip": "1.1.1.1", "dest_port": 443,
              "catalog_domain": "api.openai.com", "ai_layer": "catalog",
              "protocol": "tcp", "autonomy_verdict": "user_driven",
              "pre_flags": [], "seen_count": 1, "last_seen": "2026-09-24",
              "pre_score": 0}
        e2 = dict(e1, seen_count=99, last_seen="2026-09-25", pre_score=70)
        self.assertEqual(triage_sig.event_signature(e1),
                         triage_sig.event_signature(e2))

    def test_changes_with_verdict(self):
        self.assertNotEqual(self._sig(),
                            self._sig(autonomy_verdict="autonomous"))

    def test_changes_with_flags(self):
        self.assertNotEqual(self._sig(),
                            self._sig(pre_flags=[{"flag": "udp_non443"}]))

    def test_flag_order_insensitive(self):
        a = self._sig(pre_flags=[{"flag": "a"}, {"flag": "b"}])
        b = self._sig(pre_flags=[{"flag": "b"}, {"flag": "a"}])
        self.assertEqual(a, b)

    def test_changes_with_identity(self):
        self.assertNotEqual(self._sig(), self._sig(process="b.exe"))
        self.assertNotEqual(self._sig(), self._sig(dest_port=8443))
        self.assertNotEqual(self._sig(),
                            self._sig(catalog_domain="api.anthropic.com"))


class TriageDedupBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH", "triage_events")}
        server.store = self.store
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True, "approved_providers": [],
                       "jev_enabled": True, "jev_api_key": "k",
                       "jev_base_url": "http://127.0.0.1:9/x",
                       "jev_model": "test-model",
                       "llm_enabled": False}
        # Jev simulado: devuelve un veredicto por evento; el 2o triaje
        # (si llega) usa otro veredicto para distinguir nuevo vs reutilizado.
        self.jev_calls: list[list[dict]] = []

        def fake_triage(events: list[dict], api_key: str,
                        base_url: str = "", model: str = "",
                        timeout: int = 30) -> dict:
            self.jev_calls.append([dict(e) for e in events])
            verdicts = {}
            for i, e in enumerate(events):
                round_n = len(self.jev_calls)
                verdicts[str(i)] = {
                    "verdict": ("expected_ai_use" if round_n == 1
                                else "background_exfil_suspect"),
                    "confidence": 0.9, "severity_score": 1 if round_n == 1
                    else 4,
                    "immediate_action": 0, "prob_false_positive": 0.1}
            return {"status": "ok", "model": "test-model",
                    "count": len(events), "partial": False,
                    "verdicts": verdicts}

        server.triage_events = fake_triage

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()

    def _seed(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443,
            dest_host=None, catalog_domain="api.anthropic.com",
            ai_layer="catalog")

    def _post(self):
        return server.triage(server.TriageRequest())


class TestDedupEndpoint(TriageDedupBase):
    def test_first_triage_is_full(self):
        self._seed()
        out = self._post()
        self.assertEqual(out["dedup"], {"reused": 0, "fresh": 2})
        self.assertEqual(len(self.jev_calls), 1)
        self.assertEqual(len(self.jev_calls[0]), 2)
        for e in out["events"]:
            self.assertTrue(e["sig"])
            self.assertFalse(e["reused"])

    def test_second_triage_all_reused_no_jev_call(self):
        self._seed()
        first = self._post()
        second = self._post()
        # Sin cambios: ninguna llamada nueva a Jev.
        self.assertEqual(len(self.jev_calls), 1)
        self.assertEqual(second["dedup"], {"reused": 2, "fresh": 0})
        self.assertEqual(second["jev"]["status"], "ok")
        # Veredictos identicos al primer triaje (reutilizados).
        for i in range(2):
            self.assertEqual(second["jev"]["verdicts"][str(i)],
                             first["jev"]["verdicts"][str(i)])
        for e in second["events"]:
            self.assertTrue(e["reused"])

    def test_changed_event_retried_only_it(self):
        self._seed()
        self._post()
        # Cambia la autonomia de un evento (campo que SI entra en firma).
        self.store.conn.execute(
            "UPDATE events SET autonomy_verdict='autonomous'"
            " WHERE process='a.exe'")
        self.store.conn.commit()
        out = self._post()
        self.assertEqual(len(self.jev_calls), 2)
        # Solo el cambiado viaja a Jev.
        self.assertEqual(len(self.jev_calls[1]), 1)
        self.assertEqual(self.jev_calls[1][0]["process"], "a.exe")
        self.assertEqual(out["dedup"], {"reused": 1, "fresh": 1})
        # Fusion: el cambiado trae veredicto nuevo (round 2), el otro el
        # reutilizado (round 1).
        changed = [e for e in out["events"] if e["process"] == "a.exe"][0]
        idx = out["events"].index(changed)
        self.assertEqual(
            out["jev"]["verdicts"][str(idx)]["verdict"],
            "background_exfil_suspect")
        other = [e for e in out["events"] if e["process"] == "b.exe"][0]
        jidx = out["events"].index(other)
        self.assertEqual(out["jev"]["verdicts"][str(jidx)]["verdict"],
                         "expected_ai_use")

    def test_error_run_resets_reuse_base(self):
        self._seed()
        self._post()  # round 1 ok
        # Simula un triaje con error: el payload guardado deja de ser OK.
        self.store.save_triage("error", "test-model",
                               {"jev": {"status": "error", "reason": "x"},
                                "events": []})
        out = self._post()
        # Auto-sanante: vuelve a triar TODO.
        self.assertEqual(len(self.jev_calls), 2)
        self.assertEqual(len(self.jev_calls[1]), 2)
        self.assertEqual(out["dedup"], {"reused": 0, "fresh": 2})


if __name__ == "__main__":
    unittest.main()
