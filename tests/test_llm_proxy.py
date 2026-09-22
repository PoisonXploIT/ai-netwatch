"""Tests del LLM Inspector (R3): reverse proxy stdlib + store de llamadas.

Cobertura:
- Proxy reenvia un request no-stream y lo registra (modelo, tokens, prompt).
- Proxy pasa el streaming SSE tal cual y lo registra (contenido acumulado).
- El proxy solo escucha en loopback.
- Config: target del proxy solo loopback (mismo criterio SSRF que
  llm_base_url), puerto validado, toggle en vivo arranca/para.
- Persistencia: un config.json editado a mano no apunta el proxy fuera.
- Endpoint reset exige confirm=true.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from llm_proxy import LlmProxy  # noqa: E402
from store import LlmCallStore  # noqa: E402


class _Upstream(BaseHTTPRequestHandler):
    """LLM falso OpenAI-compatible en loopback (no-stream y SSE)."""

    def log_message(self, *a):  # silencio
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        d = json.loads(self.rfile.read(n) or b"{}")
        if d.get("stream"):
            chunks = [
                {"model": "test-model",
                 "choices": [{"delta": {"content": "hola "}}]},
                {"model": "test-model", "choices": [],
                 "usage": {"prompt_tokens": 7, "completion_tokens": 2}},
                {"model": "test-model",
                 "choices": [{"delta": {"content": "mundo"}}]},
            ]
            frames = [b"data: " + json.dumps(c).encode() + b"\n\n"
                      for c in chunks]
            frames.append(b"data: [DONE]\n\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for f in frames:
                self.wfile.write(hex(len(f)).encode() + b"\r\n" + f + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            resp = {"model": d.get("model"),
                    "choices": [{"message": {"content": "respuesta de prueba"}}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 3}}
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


def _start_upstream():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post(port: int, path: str, payload: dict):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(payload).encode(),
        method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read()


def _wait_calls(store: LlmCallStore, n: int = 1, deadline_s: float = 3.0):
    """El registro ocurre tras el EOF del response: se espera con polling."""
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        calls = store.list_calls()
        if len(calls) >= n:
            return calls
        time.sleep(0.05)
    return store.list_calls()


class ProxyBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LlmCallStore(Path(self.tmp.name) / "llm.db")
        self.upstream = _start_upstream()
        _, tport = self.upstream.server_address
        self.proxy = LlmProxy(bind_host="127.0.0.1", bind_port=0,
                              target=("127.0.0.1", tport),
                              on_call=self.store.record)
        self.proxy.bind()
        self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.stop()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.store.close()
        self.tmp.cleanup()


class TestProxyForwarding(ProxyBase):

    def test_non_stream_forwarded_and_recorded(self):
        status, body = _post(
            self.proxy.bound_port, "/v1/chat/completions",
            {"model": "test-model",
             "messages": [{"role": "user", "content": "di hola"}]})
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["choices"][0]["message"]["content"],
                         "respuesta de prueba")
        calls = _wait_calls(self.store)
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertEqual(c["status"], 200)
        self.assertEqual(c["model"], "test-model")
        self.assertFalse(c["streaming"])
        self.assertEqual(c["prompt_tokens"], 5)
        self.assertEqual(c["completion_tokens"], 3)
        self.assertIn("di hola", c["prompt"])
        self.assertIn("user:", c["prompt"])
        self.assertEqual(c["response_chars"], len("respuesta de prueba"))
        self.assertGreater(c["latency_ms"], 0)
        self.assertTrue(c["client_addr"].startswith("127.0.0.1:"))

    def test_streaming_passthrough_and_recorded(self):
        status, body = _post(
            self.proxy.bound_port, "/v1/chat/completions",
            {"model": "test-model", "stream": True,
             "messages": [{"role": "user", "content": "stream"}]})
        self.assertEqual(status, 200)
        txt = body.decode()
        # El framing SSE llega tal cual al cliente.
        self.assertIn("data: ", txt)
        self.assertIn("[DONE]", txt)
        calls = _wait_calls(self.store)
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertTrue(c["streaming"])
        self.assertEqual(c["model"], "test-model")
        self.assertEqual(c["response"], "hola mundo")
        self.assertEqual(c["prompt_tokens"], 7)
        self.assertEqual(c["completion_tokens"], 2)

    def test_proxy_binds_loopback_only(self):
        host, port = self.proxy.server_sock.getsockname()[:2]
        self.assertEqual(host, "127.0.0.1")
        self.assertGreater(port, 0)


def _fresh_cfg() -> dict:
    return {
        "jev_enabled": True, "jev_api_key": "", "jev_model": "jev-test",
        "jev_base_url": "https://api.typesafe.ai/v1/systemone",
        "llm_enabled": False, "llm_base_url": "", "llm_model": "",
        "llm_proxy_enabled": False, "llm_proxy_port": 8098,
        "llm_proxy_target": "127.0.0.1:8099",
        "extra_hosts": [], "sysmon_enabled": True,
    }


class ConfigBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LlmCallStore(Path(self.tmp.name) / "llm.db")
        self._old = {
            "store": server.store, "cfg": server._cfg,
            "path": server.CONFIG_PATH, "calls": server.llm_calls,
            "proxy": server.llm_proxy,
        }
        server.store = None
        server.monitor = None
        server._cfg = _fresh_cfg()
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server.llm_calls = self.store
        server.llm_proxy = None

    def tearDown(self) -> None:
        if server.llm_proxy:
            server.llm_proxy.stop()
        server.store = self._old["store"]
        server._cfg = self._old["cfg"]
        server.CONFIG_PATH = self._old["path"]
        server.llm_calls = self._old["calls"]
        server.llm_proxy = None
        self.store.close()
        self.tmp.cleanup()


class TestProxyConfig(ConfigBase):

    def test_public_target_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            server.set_config(
                server.ConfigRequest(llm_proxy_target="8.8.8.8:8099"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_cloud_metadata_target_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            server.set_config(server.ConfigRequest(
                llm_proxy_target="169.254.169.254:80"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_domain_without_port_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            server.set_config(
                server.ConfigRequest(llm_proxy_target="openai.com"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_loopback_target_accepted(self):
        server.set_config(server.ConfigRequest(
            llm_proxy_target="127.0.0.1:8123"))
        self.assertEqual(server._cfg["llm_proxy_target"], "127.0.0.1:8123")

    def test_bad_ports_rejected(self):
        for port in (0, 65536, -1):
            with self.assertRaises(HTTPException) as ctx:
                server.set_config(
                    server.ConfigRequest(llm_proxy_port=port))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_toggle_starts_and_stops(self):
        server.set_config(server.ConfigRequest(
            llm_proxy_port=18099, llm_proxy_target="127.0.0.1:8099"))
        server.set_config(server.ConfigRequest(llm_proxy_enabled=True))
        self.assertTrue(server.llm_proxy is not None)
        self.assertEqual(server.get_config()["llm_proxy_running"], True)
        server.set_config(server.ConfigRequest(llm_proxy_enabled=False))
        self.assertIsNone(server.llm_proxy)
        self.assertEqual(server.get_config()["llm_proxy_running"], False)

    def test_load_revalidates_proxy_target(self):
        # Un config.json editado a mano no apunta el proxy fuera.
        server.CONFIG_PATH.write_text(json.dumps({
            "llm_proxy_enabled": True, "llm_proxy_port": 8098,
            "llm_proxy_target": "8.8.8.8:443",
        }), encoding="utf-8")
        server._load_config()
        self.assertEqual(server._cfg["llm_proxy_target"], "127.0.0.1:8099")

    def test_list_calls_shape_and_reset(self):
        calls = server.list_llm_calls()["calls"]
        self.assertEqual(calls, [])
        self.store.record({
            "ts": "2026-01-01 00:00:00Z", "method": "POST",
            "path": "/v1/chat/completions", "status": 200,
            "model": "m", "streaming": 0, "prompt_chars": 3,
            "response_chars": 4, "prompt_tokens": 1, "completion_tokens": 2,
            "latency_ms": 1.0, "client_addr": "127.0.0.1:9",
            "prompt": "hola", "response": "adios"})
        out = server.list_llm_calls()["calls"]
        self.assertEqual(len(out), 1)
        self.assertIn("client_pid", out[0])
        with self.assertRaises(HTTPException):
            server.reset_llm_calls(server.ResetRequest(confirm=False))
        r = server.reset_llm_calls(server.ResetRequest(confirm=True))
        self.assertEqual(r["calls_removed"], 1)


if __name__ == "__main__":
    unittest.main()
