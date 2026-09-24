"""Tests del panel (v2.0): GET /api/dashboard agrega lo que ya existe.

- Actividad diaria, top proveedores/procesos por presencia, capas.
- Shadow count y LLM local (llamadas/tokens/bytes).
- Bytes cloud: no disponible para TLS remoto (no un cero que engane).
- days clamped 1..365; events_since respeta el corte.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from store import LlmCallStore, Store  # noqa: E402


class DashboardBase(unittest.TestCase):
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


class TestDashboard(DashboardBase):
    def test_tops_and_layers(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="mystery-ai.com",
            ai_layer="heuristic")
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443,
            dest_host=None, catalog_domain="huggingface.co",
            ai_layer="catalog")
        out = server.dashboard(days=7)
        self.assertEqual(out["days"], 7)
        provs = {p["name"]: p["seen_count"] for p in out["top_providers"]}
        self.assertEqual(provs, {"mystery-ai.com": 1, "huggingface.co": 1})
        procs = {p["name"] for p in out["top_processes"]}
        self.assertEqual(procs, {"a.exe", "b.exe"})
        layers = {l["layer"]: l["seen_count"] for l in out["layers"]}
        self.assertEqual(layers, {"heuristic": 1, "catalog": 1})
        self.assertTrue(out["daily"])

    def test_top_ordered_by_seen_count(self):
        for _ in range(3):
            self.store.observe_connection(
                process="a.exe", dest_ip="1.1.1.1", dest_port=443,
                dest_host=None, catalog_domain="mystery-ai.com",
                ai_layer="heuristic")
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443,
            dest_host=None, catalog_domain="other-ai.com",
            ai_layer="llm")
        out = server.dashboard(days=7)
        self.assertEqual(out["top_providers"][0]["name"], "mystery-ai.com")
        self.assertEqual(out["top_providers"][0]["seen_count"], 3)

    def test_shadow_count_included(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="mystery-ai.com",
            ai_layer="heuristic")
        out = server.dashboard(days=7)
        self.assertEqual(out["shadow_count"], 1)

    def test_llm_summary(self):
        self.llm.record({
            "ts": "2026-09-23 10:00:00Z", "method": "POST",
            "path": "/v1/chat/completions", "status": 200,
            "model": "m", "streaming": False,
            "prompt_chars": 10, "response_chars": 20,
            "prompt_tokens": 5, "completion_tokens": 7,
            "request_bytes": 100, "response_bytes": 200,
            "latency_ms": 10.0, "client_addr": "127.0.0.1",
            "prompt": "hola", "response": "adios"})
        out = server.dashboard(days=7)
        self.assertEqual(out["llm_calls"]["calls"], 1)
        self.assertEqual(out["llm_calls"]["prompt_tokens"], 5)
        self.assertEqual(out["llm_calls"]["completion_tokens"], 7)
        self.assertEqual(out["llm_calls"]["request_bytes"], 100)
        self.assertEqual(out["llm_calls"]["response_bytes"], 200)

    def test_cloud_bytes_unavailable_not_zero(self):
        out = server.dashboard(days=7)
        self.assertFalse(out["cloud_bytes"]["available"])
        # v2.2: motivo honesto (colector elevado), nunca un cero que engane.
        self.assertIn("ETW", out["cloud_bytes"]["reason"])
        self.assertNotIn("total_bytes", out["cloud_bytes"])

    def test_days_clamped(self):
        self.assertEqual(server.dashboard(days=0)["days"], 1)
        self.assertEqual(server.dashboard(days=9999)["days"], 365)

    def test_events_since_excludes_old(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="mystery-ai.com",
            ai_layer="heuristic")
        # Evento viejo: fuera de cualquier corte razonable.
        self.store.conn.execute(
            "UPDATE events SET last_seen='2000-01-01 00:00:00Z',"
            " first_seen='2000-01-01 00:00:00Z'")
        self.store.conn.commit()
        out = server.dashboard(days=7)
        # No cuenta en el panel...
        self.assertEqual(out["top_providers"], [])
        # ...pero sigue vivo en el store.
        self.assertEqual(len(self.store.list_events(limit=10)), 1)


class TestLlmSummaryDays(DashboardBase):
    def test_summary_days_filter(self):
        self.llm.record({
            "ts": "2000-01-01 00:00:00Z", "method": "POST", "path": "/",
            "status": 200, "model": "m", "streaming": False,
            "prompt_chars": None, "response_chars": None,
            "prompt_tokens": 1, "completion_tokens": 1,
            "request_bytes": 10, "response_bytes": 10,
            "latency_ms": 1.0, "client_addr": None,
            "prompt": "", "response": ""})
        self.llm.record({
            "ts": "2026-09-23 10:00:00Z", "method": "POST", "path": "/",
            "status": 200, "model": "m", "streaming": False,
            "prompt_chars": None, "response_chars": None,
            "prompt_tokens": 2, "completion_tokens": 2,
            "request_bytes": 20, "response_bytes": 20,
            "latency_ms": 1.0, "client_addr": None,
            "prompt": "", "response": ""})
        allsum = self.llm.summary()
        days7 = self.llm.summary(days=7)
        self.assertEqual(allsum["calls"], 2)
        self.assertEqual(days7["calls"], 1)
        self.assertEqual(days7["request_bytes"], 20)


class TestDashboardA4(DashboardBase):
    """A4: top_providers con kind+capa dominante y resumen agregado."""

    def _seed(self) -> None:
        # openai.com (kind web) x2 procesos, capa catalog...
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="openai.com",
            ai_layer="catalog")
        # ...y una repeticion del mismo evento (seen_count=2).
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="openai.com",
            ai_layer="catalog")
        # api.openai.com (kind api) por dest_host, capa llm.
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443,
            dest_host="api.openai.com", catalog_domain=None,
            ai_layer="llm")

    def test_summary_totals(self):
        self._seed()
        out = server.dashboard(days=7)
        s = out["summary"]
        self.assertEqual(s["events"], 2)          # filas vivas (a, b)
        self.assertEqual(s["seen_total"], 3)      # 2 + 1 presencias
        self.assertEqual(s["processes"], 2)
        self.assertEqual(s["providers"], 2)
        self.assertEqual(s["days"], 7)

    def test_top_providers_kind_and_dominant_layer(self):
        self._seed()
        out = server.dashboard(days=7)
        by_name = {p["name"]: p for p in out["top_providers"]}
        # openai.com: 2 presencias catalog -> capa dominante catalog.
        self.assertEqual(by_name["openai.com"]["kind"], "web")
        self.assertEqual(by_name["openai.com"]["layer"], "catalog")
        self.assertEqual(by_name["openai.com"]["seen_count"], 2)
        # api.openai.com: kind api por subdominio, capa llm.
        self.assertEqual(by_name["api.openai.com"]["kind"], "api")
        self.assertEqual(by_name["api.openai.com"]["layer"], "llm")

    def test_top_providers_sorted_by_seen(self):
        self._seed()
        out = server.dashboard(days=7)
        self.assertEqual(out["top_providers"][0]["name"], "openai.com")
        self.assertEqual(out["top_providers"][0]["seen_count"], 2)


if __name__ == "__main__":
    unittest.main()
