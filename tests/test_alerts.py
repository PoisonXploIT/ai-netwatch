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

    def test_webhook_failure_does_not_raise(self):
        # Puerto cerrado: el push nunca lanza.
        self.log.webhook_url = "http://127.0.0.1:1/alert"
        item = self.log.push("k", "m")
        self.assertEqual(item["kind"], "k")


if __name__ == "__main__":
    unittest.main()
