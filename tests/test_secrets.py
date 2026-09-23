"""Tests del cifrado en reposo de secretos (DPAPI) y su integracion con la
config persistente de AI NetWatch.

Sin red. En plataformas sin DPAPI (no-Windows) los tests de cifrado se saltan;
el resto (fail-safe, formato) corre siempre.
"""
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import secret_store  # noqa: E402
import server  # noqa: E402

_DPAPI = secret_store.available()


class TestSecretStore(unittest.TestCase):
    def test_is_protected(self):
        self.assertTrue(secret_store.is_protected("dpapi:AAAA"))
        self.assertFalse(secret_store.is_protected("sk-plain"))
        self.assertFalse(secret_store.is_protected(""))

    def test_protect_empty_is_none(self):
        self.assertIsNone(secret_store.protect(""))

    def test_unprotect_bad_tokens_is_none(self):
        self.assertIsNone(secret_store.unprotect(""))
        self.assertIsNone(secret_store.unprotect("no-prefix"))
        self.assertIsNone(secret_store.unprotect("dpapi:@@no-base64@@"))

    @unittest.skipUnless(_DPAPI, "DPAPI no disponible (no-Windows)")
    def test_roundtrip(self):
        token = secret_store.protect("k-secreta-123")
        self.assertIsNotNone(token)
        self.assertTrue(token.startswith(secret_store.PREFIX))
        self.assertNotIn("k-secreta-123", token)
        self.assertEqual(secret_store.unprotect(token), "k-secreta-123")

    @unittest.skipUnless(_DPAPI, "DPAPI no disponible (no-Windows)")
    def test_unprotect_corrupt_blob_is_none(self):
        token = secret_store.protect("k")
        raw = bytearray(base64.b64decode(token[len(secret_store.PREFIX):]))
        raw[0] ^= 0xFF  # corromper el blob
        corrupt = secret_store.PREFIX + base64.b64encode(bytes(raw)).decode()
        self.assertIsNone(secret_store.unprotect(corrupt))


class _CfgBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._old_path = server.CONFIG_PATH
        self._old_dir = server.DATA_DIR
        self._old_cfg = server._cfg
        server.DATA_DIR = Path(self.tmp.name)
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = dict(server._cfg)
        server._cfg["jev_api_key"] = ""

    def tearDown(self) -> None:
        server.CONFIG_PATH = self._old_path
        server.DATA_DIR = self._old_dir
        server._cfg = self._old_cfg
        self.tmp.cleanup()

    def _disk_key(self) -> str:
        return str(json.loads(
            server.CONFIG_PATH.read_text(encoding="utf-8")).get("jev_api_key") or "")


class TestConfigSecretAtRest(_CfgBase):
    @unittest.skipUnless(_DPAPI, "DPAPI no disponible (no-Windows)")
    def test_save_never_writes_plaintext_and_reloads(self):
        server._cfg["jev_api_key"] = "k-en-claro-prohibida"
        server._save_config()
        self.assertNotIn("k-en-claro-prohibida",
                         server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(self._disk_key().startswith(secret_store.PREFIX))
        # Simular reinicio: la key vuelve a memoria descifrada.
        server._cfg = dict(server._cfg)
        server._cfg["jev_api_key"] = ""
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "k-en-claro-prohibida")

    @unittest.skipUnless(_DPAPI, "DPAPI no disponible (no-Windows)")
    def test_migrates_plaintext_config(self):
        server.CONFIG_PATH.write_text(json.dumps(
            {"jev_api_key": "k-antigua", "llm_base_url": ""}), encoding="utf-8")
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "k-antigua")
        self.assertTrue(server._KEY_NEEDS_MIGRATION)
        server._save_config()
        self.assertNotIn("k-antigua",
                         server.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertTrue(self._disk_key().startswith(secret_store.PREFIX))

    @unittest.skipUnless(_DPAPI, "DPAPI no disponible (no-Windows)")
    def test_foreign_blob_fails_safe(self):
        # Blob dpapi: valido en formato pero no descifrable aqui -> sin key,
        # sin lanzar (fail-safe).
        bogus = secret_store.PREFIX + base64.b64encode(b"0" * 64).decode()
        server.CONFIG_PATH.write_text(json.dumps(
            {"jev_api_key": bogus}), encoding="utf-8")
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "")

    def test_plaintext_still_loads_in_memory(self):
        # Compatibilidad: un config en claro (no-Windows o pre-migracion) se
        # carga en memoria igualmente.
        server.CONFIG_PATH.write_text(json.dumps(
            {"jev_api_key": "k-plana"}), encoding="utf-8")
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "k-plana")


if __name__ == "__main__":
    unittest.main()
