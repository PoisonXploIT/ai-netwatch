"""S-18: export de las llamadas del LLM Inspector como log legible.

Cubre los tres formatos (txt, csv, jsonl), el rechazo de un formato
desconocido y que el log incluya prompt y respuesta cuando se guardan.
No toca la config real: se trabaja con una base temporal.
"""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import server
from store import LlmCallStore


class LlmExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._old = {k: getattr(server, k) for k in ("llm_calls", "llm_proxy")}
        st = LlmCallStore(Path(self.tmp.name) / "llm.db")
        st.record({"ts": "2026-11-21T10:00:00Z", "method": "POST",
                   "path": "/v1/chat/completions", "status": 200,
                   "model": "modelo-a", "streaming": 0, "prompt_chars": 12,
                   "response_chars": 7, "prompt_tokens": 3,
                   "completion_tokens": 2, "request_bytes": 120,
                   "response_bytes": 70, "latency_ms": 42,
                   "client_addr": "127.0.0.1:51000",
                   "prompt": "PROMPT DE PRUEBA", "response": "RESPUESTA DE PRUEBA"})
        st.record({"ts": "2026-11-21T11:00:00Z", "method": "POST",
                   "path": "/v1/embeddings", "status": 200, "model": "modelo-b",
                   "streaming": 0, "prompt_chars": 5, "response_chars": 0,
                   "prompt_tokens": 1, "completion_tokens": 0,
                   "request_bytes": 50, "response_bytes": 0, "latency_ms": 10,
                   "client_addr": "127.0.0.1:51001",
                   "prompt": "otro prompt", "response": ""})
        server.llm_calls = st
        server.llm_proxy = None

    def tearDown(self) -> None:
        self.llm_close()
        for k, v in self._old.items():
            setattr(server, k, v)
        self.tmp.cleanup()

    def llm_close(self) -> None:
        st = getattr(server, "llm_calls", None)
        if st is not None:
            st.close()

    def test_txt_log_is_readable(self) -> None:
        resp = server.export_llm_calls(format="txt", limit=50)
        text = resp.body.decode("utf-8")
        self.assertIn("log de llamadas LLM", text)
        self.assertIn("PROMPT DE PRUEBA", text)
        self.assertIn("RESPUESTA DE PRUEBA", text)
        self.assertIn("otro prompt", text)
        # Más reciente primero: la segunda llamada aparece antes.
        self.assertLess(text.index("11:00:00Z"), text.index("10:00:00Z"))
        self.assertIn("llamadas: 2", text)
        self.assertIn('filename="ai-netwatch-llm-', resp.headers["content-disposition"])
        self.assertEqual(resp.media_type, "text/plain; charset=utf-8")

    def test_csv_round_trip(self) -> None:
        resp = server.export_llm_calls(format="csv", limit=50)
        rows = list(csv.DictReader(io.StringIO(resp.body.decode("utf-8"))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["prompt"], "otro prompt")
        self.assertEqual(rows[1]["response"], "RESPUESTA DE PRUEBA")
        self.assertEqual(float(rows[1]["latency_ms"]), 42.0)
        self.assertEqual(rows[1]["prompt_tokens"], "3")

    def test_jsonl_one_line_per_call(self) -> None:
        resp = server.export_llm_calls(format="jsonl", limit=50)
        lines = [ln for ln in resp.body.decode("utf-8").splitlines() if ln]
        self.assertEqual(len(lines), 2)
        obj = json.loads(lines[0])
        self.assertEqual(obj["path"], "/v1/embeddings")

    def test_unknown_format_is_rejected(self) -> None:
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            server.export_llm_calls(format="xml", limit=5)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_limit_is_respected(self) -> None:
        resp = server.export_llm_calls(format="csv", limit=1)
        rows = list(csv.DictReader(io.StringIO(resp.body.decode("utf-8"))))
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
