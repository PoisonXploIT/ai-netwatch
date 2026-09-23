"""Tests de filtros y agrupacion de la vista de eventos (v2.3).

Cubre: filtros de capa/veredicto/proceso/destino en el store; agrupacion por
proveedor (colapsa IPs rotatorias de CDN), filtros shadow/hide_cdn en el
endpoint. Sin red, sin IA.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from store import Store  # noqa: E402


class EventsFilterBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "e.db")
        self._old_store = server.store
        self._old_cfg = server._cfg
        self._old_path = server.CONFIG_PATH
        server.store = self.store
        server._cfg = {"catalog_approved": True, "approved_providers": [],
                       "alerts_enabled": True}
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        server.CONFIG_PATH = self._old_path
        self.store.close()
        self.tmp.cleanup()

    def _obs(self, process, ip, port=443, catalog="huggingface.co",
             host=None, layer="catalog", verdict=None):
        return self.store.observe_connection(
            process=process, dest_ip=ip, dest_port=port,
            catalog_domain=catalog, dest_host=host, protocol="tcp",
            image=None, ai_layer=layer, autonomy_verdict=verdict)


class TestStoreFilters(EventsFilterBase):
    def test_layer_filter(self):
        self._obs("a.exe", "1.1.1.1", layer="catalog")
        self._obs("b.exe", "2.2.2.2", layer="heuristic")
        rows = self.store.list_events(layer="heuristic")
        self.assertEqual([r["process"] for r in rows], ["b.exe"])

    def test_verdict_filter(self):
        self._obs("a.exe", "1.1.1.1", verdict="autonomous")
        self._obs("b.exe", "2.2.2.2", verdict="user_driven")
        rows = self.store.list_events(verdict="autonomous")
        self.assertEqual([r["process"] for r in rows], ["a.exe"])

    def test_process_and_dest_filters(self):
        self._obs("a.exe", "1.1.1.1", catalog="openai.com")
        self._obs("b.exe", "2.2.2.2", catalog="mistral.ai")
        self.assertEqual(len(self.store.list_events(process="a")), 1)
        self.assertEqual(len(self.store.list_events(dest="mistral")), 1)


class TestGrouping(EventsFilterBase):
    def test_group_by_provider_collapses_ips(self):
        self._obs("python.exe", "2600:1", catalog="huggingface.co")
        self._obs("python.exe", "2600:2", catalog="huggingface.co")
        self._obs("brave.exe", "3.3.3.3", catalog="deepseek.com")
        out = server.list_events(limit=200, group="provider")
        self.assertTrue(out["grouped"])
        self.assertEqual(len(out["events"]), 2)
        hf = [e for e in out["events"]
              if e["provider"] == "huggingface.co"][0]
        self.assertEqual(hf["ip_count"], 2)
        self.assertEqual(hf["process"], "python.exe")

    def test_group_none_returns_flat(self):
        self._obs("python.exe", "2600:1", catalog="huggingface.co")
        self._obs("python.exe", "2600:2", catalog="huggingface.co")
        out = server.list_events(group="none")
        self.assertFalse(out["grouped"])
        self.assertEqual(len(out["events"]), 2)

    def test_shadow_filter_empty_when_catalog_approved(self):
        self._obs("python.exe", "1.1.1.1", catalog="huggingface.co")
        out = server.list_events(shadow=True)
        self.assertEqual(out["events"], [])

    def test_shadow_filter_lists_unapproved(self):
        server._cfg["catalog_approved"] = False
        self._obs("python.exe", "1.1.1.1", catalog="huggingface.co")
        out = server.list_events(shadow=True)
        self.assertEqual(len(out["events"]), 1)

    def test_hide_cdn(self):
        self._obs("a.exe", "1.1.1.1", catalog=None,
                  host="d123.cloudfront.net")
        self._obs("b.exe", "2.2.2.2", catalog=None, host="api.openai.com")
        out = server.list_events(hide_cdn=True)
        provs = {e["provider"] for e in out["events"]}
        self.assertNotIn("d123.cloudfront.net", provs)
        self.assertIn("api.openai.com", provs)


if __name__ == "__main__":
    unittest.main()
