"""Tests de alertas (O3): AlertLog (cola + log archivo + webhook)."""
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import server  # noqa: E402


class TestAlertLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = alerts.AlertLog(Path(self.tmp.name) / "alerts.log")

    def tearDown(self):
        self.tmp.cleanup()

    def test_push_list_since_id_and_cap(self):
        for i in range(5):
            self.log.push("k", f"m{i}")
        self.assertEqual(len(self.log.list()), 5)
        self.assertEqual(len(self.log.list(since_id=3)), 2)
        self.assertEqual(self.log.list(since_id=99), [])
        # Cap acotado: no crece sin limite.
        for i in range(210):
            self.log.push("k", "x")
        self.assertLessEqual(len(self.log.list()), 200)

    def test_file_log_lines_jsonl(self):
        self.log.push("new_ai_destination", "hola", {"a": 1})
        lines = (Path(self.tmp.name) / "alerts.log").read_text(
            encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["kind"], "new_ai_destination")
        self.assertEqual(row["details"], {"a": 1})

    def test_webhook_delivery(self):
        received = threading.Event()
        body = {}

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body["data"] = json.loads(self.rfile.read(n))
                self.send_response(200)
                self.end_headers()
                received.set()

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.log.webhook_url = (
                f"http://127.0.0.1:{srv.server_address[1]}/alert")
            self.log.push("new_ai_destination", "hola", {"a": 1})
            self.assertTrue(received.wait(5))
            self.assertEqual(body["data"]["kind"], "new_ai_destination")
            self.assertEqual(body["data"]["details"], {"a": 1})
        finally:
            srv.shutdown()

    def test_log_rotation_by_size(self):
        log = alerts.AlertLog(Path(self.tmp.name) / "a.log",
                              max_log_bytes=512)
        big = "x" * 300
        for _ in range(4):
            log.push("k", big)
        cur = Path(self.tmp.name) / "a.log"
        backup = Path(self.tmp.name) / "a.log.1"
        self.assertTrue(backup.exists())
        # La generacion activa no pasa de ~max_log_bytes + un push.
        self.assertLess(cur.stat().st_size, 512 + 400)

    def test_webhook_failure_does_not_raise(self):
        # Puerto cerrado: el push nunca lanza.
        self.log.webhook_url = "http://127.0.0.1:1/alert"
        item = self.log.push("k", "m")
        self.assertEqual(item["kind"], "k")


class TestNewAiEventMessage(unittest.TestCase):
    """El mensaje prefiere SNI/catalogo antes que la IP cruda."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = alerts.AlertLog(Path(self.tmp.name) / "alerts.log")
        self._cfg = dict(server._cfg)
        self._alerts = server.alerts
        server._cfg["alerts_enabled"] = True
        server.alerts = self.log
        server._new_dest_alerted.clear()

    def tearDown(self):
        server._cfg.clear()
        server._cfg.update(self._cfg)
        server.alerts = self._alerts
        self.tmp.cleanup()


    def test_prefers_catalog_domain_over_raw_ip(self):
        ev = {"id": 1, "process": "python.exe",
             "dest_ip": "2600:9000::1", "dest_port": 443,
             "sni_domain": None,
             "catalog_domain": "huggingface.co"}
        server._on_new_ai_event(ev)
        row = self.log.list()[-1]
        self.assertIn("huggingface.co:443", row["message"])
        self.assertNotIn("2600:9000", row["message"])

    def test_sni_beats_catalog(self):
        ev = {"id": 2, "process": "x.exe",
             "dest_ip": "1.2.3.4", "dest_port": 443,
             "sni_domain": "api.openai.com",
             "catalog_domain": "openai.com"}
        server._on_new_ai_event(ev)
        row = self.log.list()[-1]
        self.assertIn("api.openai.com:443", row["message"])

    def test_raw_ip_is_last_resort(self):
        ev = {"id": 3, "process": "x.exe",
              "dest_ip": "1.2.3.4", "dest_port": 443}
        server._on_new_ai_event(ev)
        row = self.log.list()[-1]
        self.assertIn("1.2.3.4:443", row["message"])

    def test_dedup_same_process_provider_different_ip(self):
        # v2.3: misma pareja (proceso, proveedor) con IP distinta (CDN con
        # IPv6 rotatoria) -> una sola alerta new_ai_destination.
        base = {"process": "python.exe", "dest_port": 443,
                "catalog_domain": "huggingface.co"}
        server._on_new_ai_event({**base, "id": 1, "dest_ip": "2600:9000::1"})
        server._on_new_ai_event({**base, "id": 2, "dest_ip": "2600:9000::2"})
        rows = [r for r in self.log.list()
                if r["kind"] == "new_ai_destination"]
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
