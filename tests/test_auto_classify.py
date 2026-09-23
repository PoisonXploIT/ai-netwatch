"""Tests del clasificador automatico (v2.0): parse, store y run_cycle."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import auto_classify  # noqa: E402
from store import Store  # noqa: E402


class TestParseVerdict(unittest.TestCase):
    def test_clean_json(self):
        v = auto_classify.parse_verdict(
            '{"is_ai": true, "provider": "openai",'
            ' "category": "chat", "confidence": 1.0}')
        self.assertEqual(v["is_ai"], True)
        self.assertEqual(v["provider"], "openai")
        self.assertEqual(v["category"], "chat")
        self.assertEqual(v["confidence"], 1.0)

    def test_fenced_json(self):
        v = auto_classify.parse_verdict(
            '```json\n{"is_ai": false, "category": "other",'
            ' "confidence": 0.9}\n```')
        self.assertEqual(v["is_ai"], False)
        self.assertIsNone(v["provider"])

    def test_garbage_or_missing_is_ai(self):
        self.assertIsNone(auto_classify.parse_verdict("no hay json aqui"))
        self.assertIsNone(auto_classify.parse_verdict('{"category": "chat"}'))
        self.assertIsNone(auto_classify.parse_verdict(None))
        self.assertIsNone(auto_classify.parse_verdict(""))

    def test_confidence_clamped_and_bad_category(self):
        v = auto_classify.parse_verdict(
            '{"is_ai": true, "category": "nonsense", "confidence": 3.5}')
        self.assertEqual(v["confidence"], 1.0)
        self.assertEqual(v["category"], "other")


class TestStoreClassifications(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _heuristic_event(self, domain, process="a.exe", ip="9.9.9.9"):
        self.store.observe_connection(
            process, ip, 443, domain, None, ai_layer="heuristic")

    def test_upsert_get_roundtrip(self):
        self.store.upsert_classification(
            "Foo.Example", True, "foo", "chat", 0.9, "llm")
        row = self.store.get_classification("foo.example")
        self.assertEqual(row["is_ai"], 1)
        self.assertEqual(row["provider"], "foo")
        self.assertEqual(row["category"], "chat")
        # Upsert actualiza, no duplica.
        self.store.upsert_classification(
            "foo.example", True, "foo2", "chat", 0.95, "llm")
        self.assertEqual(self.store.get_classification("foo.example")["provider"],
                         "foo2")

    def test_pending_excludes_classified_and_catalog(self):
        self._heuristic_event("uno.example")
        self._heuristic_event("dos.example", ip="9.9.9.10")
        # Catalogo: nunca es candidato.
        self.store.observe_connection(
            "b.exe", "1.1.1.1", 443, "openai.com", None, ai_layer="catalog")
        pending = self.store.pending_heuristic_domains()
        self.assertEqual(sorted(pending), ["dos.example", "uno.example"])
        self.store.upsert_classification(
            "uno.example", True, None, "chat", 0.8, "llm")
        self.assertEqual(self.store.pending_heuristic_domains(),
                         ["dos.example"])

    def test_pending_includes_stale_classification(self):
        self._heuristic_event("stale.example")
        self.store.upsert_classification(
            "stale.example", True, None, "chat", 0.8, "llm")
        self.assertEqual(self.store.pending_heuristic_domains(), [])
        # Envejecer la clasificacion mas alla del TTL (30 d).
        with self.store._lock:
            self.store.conn.execute(
                "UPDATE domain_classifications SET ts='2020-01-01 00:00:00Z'")
        self.assertEqual(self.store.pending_heuristic_domains(),
                         ["stale.example"])

    def test_apply_layer_never_overwrites_catalog(self):
        self._heuristic_event("h.example")
        self.store.observe_connection(
            "c.exe", "2.2.2.2", 443, "openai.com", None, ai_layer="catalog")
        n = self.store.apply_classification_layer("h.example", "llm")
        self.assertEqual(n, 1)
        # El catalogo no se toca aunque apunte a otro dominio: solo hay que
        # intentarlo con un dominio catalog real.
        n2 = self.store.apply_classification_layer("openai.com", "llm")
        self.assertEqual(n2, 0)
        ev = self.store.list_events(dest="2.2.2.2")[0]
        self.assertEqual(ev["ai_layer"], "catalog")


class TestRunCycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.store.observe_connection(
            "a.exe", "9.9.9.1", 443, "uno.example", None,
            ai_layer="heuristic")
        self.store.observe_connection(
            "b.exe", "9.9.9.2", 443, "dos.example", None,
            ai_layer="heuristic")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_cycle_classifies_and_updates_layer(self):
        verdict = ('{"is_ai": true, "provider": "uno",'
                   ' "category": "chat", "confidence": 0.85}')
        with mock.patch.object(auto_classify, "_chat", return_value=verdict) \
                as chat:
            out = auto_classify.run_cycle(
                self.store, "http://127.0.0.1:8099", "m", min_interval_s=0)
        self.assertEqual(len(out), 2)
        self.assertEqual(chat.call_count, 2)
        row = self.store.get_classification("uno.example")
        self.assertEqual(row["provider"], "uno")
        # Eventos pasan de 'heuristic' a 'llm' (visible, nunca oculto).
        evs = self.store.list_events()
        self.assertTrue(all(e["ai_layer"] == "llm" for e in evs))

    def test_second_cycle_is_noop_with_cache(self):
        verdict = '{"is_ai": true, "provider": "p", "category": "chat",' \
                  ' "confidence": 0.8}'
        with mock.patch.object(auto_classify, "_chat", return_value=verdict) \
                as chat:
            auto_classify.run_cycle(
                self.store, "http://127.0.0.1:8099", "m", min_interval_s=0)
            out2 = auto_classify.run_cycle(
                self.store, "http://127.0.0.1:8099", "m", min_interval_s=0)
        self.assertEqual(out2, [])
        self.assertEqual(chat.call_count, 2)  # solo del primer ciclo

    def test_llm_down_breaks_cycle_without_storing(self):
        with mock.patch.object(
                auto_classify, "_chat", side_effect=OSError("timeout")):
            out = auto_classify.run_cycle(
                self.store, "http://127.0.0.1:8099", "m", min_interval_s=0)
        self.assertEqual(out, [])
        self.assertIsNone(self.store.get_classification("uno.example"))
        # Sin clasificar: sigue en 0.5 (heuristic), visible.
        evs = self.store.list_events()
        self.assertTrue(all(e["ai_layer"] == "heuristic" for e in evs))


if __name__ == "__main__":
    unittest.main()
