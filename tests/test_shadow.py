"""Tests de Shadow AI (v2.0): IA detectada que no esta aprobada.

- Proveedor = sni > catalogo > cache DNS > IP (mismo orden que alertas).
- Aprobado = catalogo (si catalog_approved) union approved_providers,
  match por sufijo de dominio; IPs, exacto.
- GET /api/shadow agrupa por proveedor.
- Alerta shadow_ai: una por proveedor no aprobado; se reevalua al
  cambiar la aprobacion.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


class ShadowBase(unittest.TestCase):
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

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()


class TestProvider(ShadowBase):
    def test_priority_sni_catalog_host_ip(self):
        ev = {"sni_domain": "api.openai.com",
             "catalog_domain": "openai.com",
             "dest_host": "cdn.other.com",
             "dest_ip": "1.2.3.4"}
        self.assertEqual(server._provider_of(ev), "api.openai.com")
        ev.pop("sni_domain")
        self.assertEqual(server._provider_of(ev), "openai.com")
        ev.pop("catalog_domain")
        self.assertEqual(server._provider_of(ev), "cdn.other.com")
        ev.pop("dest_host")
        self.assertEqual(server._provider_of(ev), "1.2.3.4")

    def test_extra_prefix_stripped(self):
        ev = {"catalog_domain": "extra:mi-servidor.local",
             "dest_ip": "10.0.0.5"}
        self.assertEqual(server._provider_of(ev), "mi-servidor.local")


class TestApproval(ShadowBase):
    def test_catalog_approved_by_default(self):
        # Capa catalog -> proveedor del catalogo -> aprobado por defecto.
        self.store.observe_connection(
            process="python.exe", dest_ip="93.184.216.34", dest_port=443, dest_host=None,
            catalog_domain="huggingface.co", ai_layer="catalog")
        out = server.shadow_providers()
        self.assertEqual(out["count"], 0)

    def test_heuristic_is_shadow_by_default(self):
        self.store.observe_connection(
            process="python.exe", dest_ip="1.2.3.4", dest_port=443, dest_host=None,
            catalog_domain="mystery-ai.com", ai_layer="heuristic")
        out = server.shadow_providers()
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["shadow"][0]["provider"], "mystery-ai.com")

    def test_suffix_match(self):
        server._cfg["approved_providers"] = ["openai.com"]
        self.assertTrue(server._is_approved_provider("api.openai.com"))
        self.assertTrue(server._is_approved_provider("OPENAI.COM"))
        # Sufijo sin frontera de subdominio no pisa: notopenai.com != openai.
        self.assertFalse(server._is_approved_provider("notopenai.com"))

    def test_ip_approval_is_exact_only(self):
        server._cfg["approved_providers"] = ["2.3.4"]
        self.assertFalse(server._is_approved_provider("1.2.3.4"))
        server._cfg["approved_providers"] = ["1.2.3.4"]
        self.assertTrue(server._is_approved_provider("1.2.3.4"))

    def test_catalog_approved_false_makes_catalog_shadow(self):
        server._cfg["catalog_approved"] = False
        self.store.observe_connection(
            process="python.exe", dest_ip="93.184.216.34", dest_port=443, dest_host=None,
            catalog_domain="huggingface.co", ai_layer="catalog")
        out = server.shadow_providers()
        self.assertEqual(out["count"], 1)
        # Aprobado a mano -> deja de ser shadow.
        server._cfg["approved_providers"] = ["huggingface.co"]
        out = server.shadow_providers()
        self.assertEqual(out["count"], 0)

    def test_empty_provider_never_approved(self):
        self.assertFalse(server._is_approved_provider(""))


class TestShadowApi(ShadowBase):
    def test_grouping_by_provider(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443, dest_host=None,
            catalog_domain="mystery-ai.com", ai_layer="heuristic")
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443, dest_host=None,
            catalog_domain="mystery-ai.com", ai_layer="llm")
        out = server.shadow_providers()
        self.assertEqual(out["count"], 1)
        g = out["shadow"][0]
        self.assertEqual(g["provider"], "mystery-ai.com")
        self.assertEqual(g["processes"], ["a.exe", "b.exe"])
        self.assertEqual(g["layers"], ["heuristic", "llm"])
        self.assertEqual(g["seen_count"], 2)
        self.assertEqual(len(g["event_ids"]), 2)
        self.assertTrue(g["first_seen"])
        self.assertTrue(g["last_seen"])

    def test_approved_provider_not_listed(self):
        server._cfg["approved_providers"] = ["mystery-ai.com"]
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443, dest_host=None,
            catalog_domain="mystery-ai.com", ai_layer="heuristic")
        out = server.shadow_providers()
        self.assertEqual(out["count"], 0)


class TestShadowConfig(ShadowBase):
    def test_config_persists_and_clears_dedup(self):
        # Un proveedor ya alertado; al cambiar la aprobacion se reevalua.
        server._shadow_alerted.add("mystery-ai.com")
        server.set_config(server.ConfigRequest(
            approved_providers=["other.com"]))
        self.assertEqual(server._cfg["approved_providers"], ["other.com"])
        self.assertEqual(server._shadow_alerted, set())
        data = json.loads(server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["approved_providers"], ["other.com"])

    def test_catalog_approved_persisted(self):
        server.set_config(server.ConfigRequest(catalog_approved=False))
        self.assertFalse(server._cfg["catalog_approved"])
        data = json.loads(server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertFalse(data["catalog_approved"])


class TestShadowAlert(ShadowBase):
    def _ev(self, provider: str, layer: str) -> dict:
        return {"id": 1, "process": "a.exe",
                "dest_ip": "1.2.3.4", "dest_port": 443,
                "sni_domain": None,
                "catalog_domain": provider,
                "ai_layer": layer}

    def test_one_alert_per_unapproved_provider(self):
        server._on_new_ai_event(self._ev("mystery-ai.com", "heuristic"))
        server._on_new_ai_event(self._ev("mystery-ai.com", "heuristic"))
        rows = [r for r in self.log.list() if r["kind"] == "shadow_ai"]
        self.assertEqual(len(rows), 1)
        self.assertIn("mystery-ai.com:443", rows[0]["message"])

    def test_catalog_provider_does_not_alert(self):
        server._on_new_ai_event(self._ev("huggingface.co", "catalog"))
        rows = [r for r in self.log.list() if r["kind"] == "shadow_ai"]
        self.assertEqual(len(rows), 0)

    def test_second_provider_alerts_too(self):
        server._on_new_ai_event(self._ev("mystery-ai.com", "heuristic"))
        server._on_new_ai_event(self._ev("another-ai.com", "llm"))
        rows = [r for r in self.log.list() if r["kind"] == "shadow_ai"]
        self.assertEqual(len(rows), 2)

    def test_approved_provider_does_not_alert(self):
        server._cfg["approved_providers"] = ["mystery-ai.com"]
        server._on_new_ai_event(self._ev("mystery-ai.com", "heuristic"))
        rows = [r for r in self.log.list() if r["kind"] == "shadow_ai"]
        self.assertEqual(len(rows), 0)


if __name__ == "__main__":
    unittest.main()
