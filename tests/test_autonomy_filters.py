"""A3: /api/autonomy con filtros de vista (verdict/process/provider/group)
y contadores de veredicto sobre todos los eventos vivos.

Display-only: no toca deteccion, aprobaciones ni alertas; el endpoint solo
agrega lo que ya esta persistido por evento.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from store import Store  # noqa: E402


class AutonomyApiBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        self._old_cfg = dict(server._cfg)
        server.store = self.store
        server._cfg = {**server._cfg}
        # 4 eventos: mismo proceso a.exe con dos IPs del mismo proveedor
        # (para probar la agrupacion), uno user_driven y uno sin veredicto.
        self.store.observe_connection(
            "a.exe", "1.1.1.1", 443, "api.openai.com", "openai.com",
            autonomy_score=50, autonomy_flags="session_locked",
            autonomy_verdict="autonomous")
        self.store.observe_connection(
            "a.exe", "5.5.5.5", 443, "api.openai.com", "openai.com",
            autonomy_verdict="scheduled")
        self.store.observe_connection(
            "b.exe", "2.2.2.2", 443, "api.anthropic.com", "anthropic.com",
            autonomy_verdict="user_driven")
        self.store.observe_connection("d.exe", "4.4.4.4", 443, None, None)

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        self.store.close()
        self.tmp.cleanup()


class TestAutonomyCounts(AutonomyApiBase):
    def test_counts_cover_all_live_events_unfiltered(self):
        r = server.autonomy_state()
        self.assertEqual(r["counts"], {"autonomous": 1, "scheduled": 1,
                                       "user_driven": 1, "unknown": 1})
        self.assertEqual(len(r["events"]), 4)
        self.assertFalse(r["grouped"])
        # Las señales globales siguen presentes.
        self.assertIn("signals", r)


class TestAutonomyFilters(AutonomyApiBase):
    def test_verdict_filter_exact(self):
        r = server.autonomy_state(verdict="autonomous")
        self.assertEqual(len(r["events"]), 1)
        self.assertEqual(r["events"][0]["process"], "a.exe")

    def test_verdict_unknown_matches_missing(self):
        r = server.autonomy_state(verdict="unknown")
        self.assertEqual(len(r["events"]), 1)
        self.assertEqual(r["events"][0]["process"], "d.exe")

    def test_provider_filter_substring(self):
        r = server.autonomy_state(provider="openai")
        self.assertEqual({e["process"] for e in r["events"]}, {"a.exe"})
        r2 = server.autonomy_state(provider="anthropic")
        self.assertEqual({e["process"] for e in r2["events"]}, {"b.exe"})

    def test_process_filter_substring(self):
        r = server.autonomy_state(process="b.")
        self.assertEqual(len(r["events"]), 1)
        self.assertEqual(r["events"][0]["process"], "b.exe")

    def test_combined_filters(self):
        r = server.autonomy_state(verdict="autonomous", process="a.",
                                  provider="openai")
        self.assertEqual(len(r["events"]), 1)
        # Combinacion imposible: cero filas, no error.
        r2 = server.autonomy_state(verdict="autonomous",
                                   provider="anthropic")
        self.assertEqual(r2["events"], [])


class TestAutonomyGroup(AutonomyApiBase):
    def test_group_by_provider_collapses_rotating_ips(self):
        r = server.autonomy_state(group="provider")
        self.assertTrue(r["grouped"])
        by_proc = {g["process"]: g for g in r["events"]}
        # a.exe: dos IPs del mismo proveedor -> una fila, ip_count=2.
        self.assertEqual(by_proc["a.exe"]["ip_count"], 2)
        self.assertEqual(by_proc["a.exe"]["seen_count"], 2)
        self.assertEqual(by_proc["a.exe"]["provider"], "api.openai.com")
        # Las demas siguen en su grupo propio.
        self.assertEqual(len(r["events"]), 3)

    def test_flags_present_on_unfiltered_rows(self):
        rows = server.autonomy_state()["events"]
        a = [e for e in rows if e["dest_ip"] == "1.1.1.1"][0]
        self.assertEqual(a["autonomy_flags"], "session_locked")
        self.assertEqual(a["autonomy_verdict"], "autonomous")
