"""Tests de seguridad de AI NetWatch (sin red, sin IA externa).

Cobertura:
- SSRF en llm_base_url (solo http(s) loopback absoluto; bloquea publico,
  metadata cloud, file://, gopher://, rutas relativas).
- jev_base_url NO es configurable por la API (pin a TypeSafe oficial).
- Config persistente: roundtrip y revalidacion SSRF al cargar.
- Endpoints destructivos: reset exige confirm=true.
- Validacion de inputs: limit clamps, hosts extra sanitizados.
- Fail-safe: triaje sin key no lanza hacia fuera ni rompe (404/4xx limpios).

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from store import Store  # noqa: E402


def _fresh_cfg() -> dict:
    return {
        "jev_enabled": True, "jev_api_key": "", "jev_model": "jev-test",
        "jev_base_url": "https://api.typesafe.ai/v1/systemone",
        "llm_enabled": False, "llm_base_url": "", "llm_model": "",
        "extra_hosts": [], "sysmon_enabled": True,
    }


class SecurityBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        self._old_cfg = server._cfg
        self._old_path = server.CONFIG_PATH
        server.store = self.store
        server.monitor = None
        server._cfg = _fresh_cfg()
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        server.CONFIG_PATH = self._old_path
        self.store.close()
        self.tmp.cleanup()


class TestSSRF(SecurityBase):
    """llm_base_url es el unico punto donde el servidor hace HTTP saliente
    a un destino elegido por el usuario: debe ser loopback absoluto."""

    def _set_llm(self, url: str):
        return server.set_config(server.ConfigRequest(llm_base_url=url))

    def test_public_ip_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self._set_llm("http://8.8.8.8:8099")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_cloud_metadata_ip_rejected(self):
        # 169.254.169.254 = metadata de cloud (la via clasica de SSRF).
        with self.assertRaises(HTTPException) as ctx:
            self._set_llm("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_file_scheme_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self._set_llm("file:///C:/Users/Sammi/secret.txt")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_gopher_scheme_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self._set_llm("gopher://127.0.0.1:8099")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_relative_path_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self._set_llm("/v1/chat/completions")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_loopback_accepted_and_persisted(self):
        out = self._set_llm("http://127.0.0.1:8099")
        self.assertEqual(server._cfg["llm_base_url"], "http://127.0.0.1:8099")
        self.assertTrue(server.CONFIG_PATH.exists())

    def test_empty_clears_without_error(self):
        server._cfg["llm_base_url"] = "http://127.0.0.1:8099"
        self._set_llm("")
        self.assertEqual(server._cfg["llm_base_url"], "")

    def test_jev_base_url_not_user_configurable(self):
        # El endpoint Jev esta pinado a TypeSafe oficial; la API no lo toca.
        fields = server.ConfigRequest.model_fields
        self.assertNotIn("jev_base_url", fields)
        self.assertNotIn("jev_model", fields)


class TestConfigPersistence(SecurityBase):
    def test_roundtrip(self):
        server.set_config(server.ConfigRequest(
            jev_api_key="k-test-123", llm_base_url="http://127.0.0.1:8099",
            llm_model="dirk", sysmon_enabled=False))
        data = json.loads(server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["jev_api_key"], "k-test-123")
        # Simular reinicio: cfg a defaults y recargar desde disco.
        server._cfg = _fresh_cfg()
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "k-test-123")
        self.assertEqual(server._cfg["llm_base_url"], "http://127.0.0.1:8099")
        self.assertFalse(server._cfg["sysmon_enabled"])

    def test_load_revalidates_ssrf(self):
        # Un config.json editado a mano con URL publica NO se activa.
        server.CONFIG_PATH.write_text(json.dumps({
            "jev_api_key": "k", "llm_base_url": "http://8.8.8.8:1"}),
            encoding="utf-8")
        server._cfg = _fresh_cfg()
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "k")
        self.assertEqual(server._cfg["llm_base_url"], "")

    def test_corrupt_file_ignored(self):
        server.CONFIG_PATH.write_text("no-json{{", encoding="utf-8")
        server._cfg = _fresh_cfg()
        server._load_config()  # no lanza
        self.assertEqual(server._cfg["jev_api_key"], "")


class TestDestructiveAndInputs(SecurityBase):
    def test_reset_requires_confirm(self):
        with self.assertRaises(HTTPException) as ctx:
            server.reset(server.ResetRequest())
        self.assertEqual(ctx.exception.status_code, 400)

    def test_reset_with_confirm_works(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, None, "")
        out = server.reset(server.ResetRequest(confirm=True))
        self.assertTrue(out["daily_stats_kept"])
        self.assertEqual(len(self.store.list_events()), 0)

    def test_events_limit_clamped(self):
        self.assertIsInstance(server.list_events(limit=0)["events"], list)
        self.assertIsInstance(server.list_events(limit=-5)["events"], list)

    def test_extra_hosts_sanitized(self):
        # El split por coma lo hace el cliente; el servidor sanitiza
        # (trim + lower) y descarta vacios.
        server.set_config(server.ConfigRequest(
            extra_hosts=["  A.COM ", "", "x"]))
        self.assertEqual(server._cfg["extra_hosts"], ["a.com", "x"])

    def test_triage_without_key_is_fail_safe(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, None, "")
        out = server.triage(server.TriageRequest())
        self.assertIn(out["jev"]["status"], ("skipped", "error"))
        self.assertIsNone(out["llm_explanations"])

    def test_triage_empty_store_404(self):
        with self.assertRaises(HTTPException) as ctx:
            server.triage(server.TriageRequest())
        self.assertEqual(ctx.exception.status_code, 404)


class TestExportsStatic(SecurityBase):
    """Los exports no toman nombres de archivo del usuario: el contenido es
    generado en memoria y los headers son fijos (sin path traversal posible)."""

    def test_csv_export_smoke(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, None, "")
        resp = server.export_csv()
        self.assertIn("text/csv", resp.media_type)
        body = resp.body.decode() if isinstance(resp.body, bytes) else str(resp.body)
        self.assertIn("process", body)

    def test_json_export_has_version(self):
        resp = server.export_json()
        data = json.loads(resp.body)
        self.assertEqual(data["version"], server.VERSION)

    def test_pdf_export_valid_and_no_secrets(self):
        # El PDF se construye solo con datos del store: la API key (aunque
        # este configurada) NUNCA debe aparecer en el export.
        self.store.observe_connection("a.exe", "1.1.1.1", 443,
                                      "deepseek.com", "")
        server._cfg["jev_api_key"] = "KEY-SECRETA-NO-PUEDE-SALIR"
        resp = server.export_pdf()
        self.assertEqual(resp.media_type, "application/pdf")
        body = resp.body if isinstance(resp.body, bytes) else str(resp.body).encode()
        self.assertTrue(body.startswith(b"%PDF-1.4"))
        self.assertNotIn(b"KEY-SECRETA-NO-PUEDE-SALIR", body)

    def test_exports_download_headers(self):
        # Los tres exports se descargan (attachment), no se renderizan:
        # evita que el navegador interprete contenido generado.
        for fn in (server.export_json, server.export_csv, server.export_pdf):
            resp = fn()
            cd = resp.headers.get("content-disposition", "")
            self.assertIn("attachment", cd)


if __name__ == "__main__":
    unittest.main()
