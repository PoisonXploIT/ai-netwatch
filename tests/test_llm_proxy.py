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
import llm_proxy  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from llm_proxy import LlmProxy  # noqa: E402
from store import LlmCallStore  # noqa: E402


class _Upstream(BaseHTTPRequestHandler):
    """LLM falso OpenAI-compatible en loopback (no-stream y SSE)."""

    def log_message(self, *a):  # silencio
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) or b"{}"
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            d = {}
        if self.path == "/v1/embeddings":
            resp = {"model": "emb", "data": [{"embedding": [0.123456789, 0.2, 0.3]}],
                    "usage": {"prompt_tokens": 2}}
        elif self.path == "/v1/images/generations":
            resp = {"model": "img", "data": [{"b64_json": "aGVsbG8="}]}
        elif "/audio/" in self.path:
            resp = {"text": "transcrito"}
        else:
            resp = None
        if resp is not None:
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif d.get("stream"):
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
        # Latencia informativa: en loopback in-process puede redondear a 0.0.
        self.assertIsInstance(c["latency_ms"], (int, float))
        self.assertGreaterEqual(c["latency_ms"], 0)
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


class TestEndpointCoverage(ProxyBase):

    def test_embeddings_metadata_only(self):
        status, body = _post(self.proxy.bound_port, "/v1/embeddings",
                             {"model": "emb", "input": "hola mundo"})
        self.assertEqual(status, 200)
        calls = _wait_calls(self.store)
        c = calls[0]
        self.assertIn("vector", c["response"])
        self.assertNotIn("0.123456789", c["response"])  # sin float crudo
        self.assertEqual(c["prompt"], "hola mundo")

    def test_images_b64_marker(self):
        status, body = _post(self.proxy.bound_port, "/v1/images/generations",
                             {"model": "img", "prompt": "un gato", "n": 1})
        self.assertEqual(status, 200)
        calls = _wait_calls(self.store)
        c = calls[0]
        self.assertIn("imagen b64", c["response"])
        self.assertNotIn("aGVsbG8=", c["response"])
        self.assertIn("un gato", c["prompt"])

    def test_audio_multipart_metadata(self):
        body = (b'--X\r\nContent-Disposition: form-data; name="file"; '
               b'filename="a.wav"\r\nContent-Type: audio/wav\r\n\r\nFAKEDATA'
               b'\r\n--X--\r\n')
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.proxy.bound_port}/v1/audio/transcriptions",
            data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=X"})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
        self.assertEqual(d["text"], "transcrito")
        calls = _wait_calls(self.store)
        c = calls[0]
        self.assertIn("a.wav", c["prompt"])
        self.assertNotIn("FAKEDATA", c["prompt"])
        self.assertEqual(c["response"], "transcrito")


class TestUpstreamDown(unittest.TestCase):
    """Un intento que no conecta al upstream queda registrado (status 0)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LlmCallStore(Path(self.tmp.name) / "llm.db")
        # Puerto 1: nada lo escucha en loopback -> ECONNREFUSED inmediato.
        self.proxy = LlmProxy(bind_host="127.0.0.1", bind_port=0,
                              target=("127.0.0.1", 1),
                              on_call=self.store.record)
        self.proxy.bind()
        self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.stop()
        self.store.close()
        self.tmp.cleanup()

    def test_failed_upstream_recorded(self):
        import socket as _s
        c = _s.create_connection(("127.0.0.1", self.proxy.bound_port),
                                timeout=5)
        req = json.dumps({"model": "m",
                          "messages": [{"role": "user", "content": "x"}]}).encode()
        c.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\n"
                  b"Content-Type: application/json\r\n"
                  b"Content-Length: %d\r\n\r\n%s" % (len(req), req))
        data = b""
        while True:
            ch = c.recv(65536)
            if not ch:
                break
            data += ch
        self.assertEqual(data, b"")  # el cliente no recibe respuesta
        calls = _wait_calls(self.store)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["status"], 0)
        self.assertIn("sin respuesta", calls[0]["response"])
        self.assertIn("x", calls[0]["prompt"])  # el prompt si se ve


class TestLinkCalls(unittest.TestCase):
    """Enlace local: llamada -> evento de red (destino+proceso+ventana)."""

    def _events(self):
        return [
            {"id": 1, "dest_ip": "127.0.0.1", "dest_port": 8099,
             "process": "myclient.exe",
             "last_seen": "2026-01-01 00:00:30Z"},
            {"id": 2, "dest_ip": "127.0.0.1", "dest_port": 8099,
             "process": "other.exe",
             "last_seen": "2026-01-01 00:00:30Z"},
            {"id": 3, "dest_ip": "10.0.0.1", "dest_port": 443,
             "process": "myclient.exe",
             "last_seen": "2026-01-01 00:00:30Z"},
            {"id": 4, "dest_ip": "127.0.0.1", "dest_port": 8099,
             "process": "myclient.exe",
             "last_seen": "2026-01-01 00:10:00Z"},  # fuera de ventana
        ]

    def test_link_matches_dest_process_window(self):
        calls = [{"ts": "2026-01-01 00:00:00Z", "client_pid": 4242}]
        server._link_calls(calls, self._events(), "127.0.0.1", 8099,
                          {4242: "myclient.exe"})
        self.assertEqual(calls[0]["related_event_ids"], [1])
        self.assertEqual(calls[0]["client_process"], "myclient.exe")

    def test_link_empty_when_no_match(self):
        calls = [{"ts": "2026-01-01 00:00:00Z", "client_pid": 9999}]
        server._link_calls(calls, self._events(), "127.0.0.1", 8099,
                          {9999: "unknown.exe"})
        self.assertEqual(calls[0]["related_event_ids"], [])


class TestEffectiveLlmBase(ConfigBase):
    """Auto-observacion: las llamadas propias pasan por el proxy."""

    def test_rewrite_when_proxy_matches_target(self):
        class FakeProxy:
            target = ("127.0.0.1", 8099)
            bind_host = "127.0.0.1"
            bound_port = 18099

        server._cfg["llm_base_url"] = "http://127.0.0.1:8099"
        server.llm_proxy = FakeProxy()
        try:
            self.assertEqual(server._effective_llm_base(),
                             "http://127.0.0.1:18099")
        finally:
            server.llm_proxy = None

    def test_no_rewrite_when_proxy_off_or_different(self):
        server._cfg["llm_base_url"] = "http://127.0.0.1:8099"
        self.assertEqual(server._effective_llm_base(),
                         "http://127.0.0.1:8099")  # proxy apagado

        class FakeProxy:
            target = ("127.0.0.1", 8099)
            bind_host = "127.0.0.1"
            bound_port = 18099

        server._cfg["llm_base_url"] = "http://127.0.0.1:9999"  # distinto upstream
        server.llm_proxy = FakeProxy()
        try:
            self.assertEqual(server._effective_llm_base(),
                             "http://127.0.0.1:9999")
        finally:
            server.llm_proxy = None


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


class TestEgressBytes(unittest.TestCase):
    """Egress real medido (bytes del cuerpo que sale / bytes que vuelven)."""

    def test_extract_record_bytes(self):
        req = b'{"prompt":"hola mundo"}'
        resp = b'{"choices":[{"message":{"content":"adios"}}]}'
        rec = llm_proxy._extract_record(
            "POST", "/v1/chat/completions", 200, req, resp,
            False, 12.3, "127.0.0.1:1")
        self.assertEqual(rec["request_bytes"], len(req))
        self.assertEqual(rec["response_bytes"], len(resp))

    def test_upstream_down_zero_response_bytes(self):
        req = b'{"prompt":"x"}'
        rec = llm_proxy._extract_record(
            "POST", "/v1/chat/completions", 0, req, b"",
            False, 5.0, "127.0.0.1:1")
        self.assertEqual(rec["status"], 0)
        self.assertEqual(rec["request_bytes"], len(req))
        self.assertEqual(rec["response_bytes"], 0)

    def test_response_bytes_counts_full_stream_over_parse_buf(self):
        # Regresion: resp_raw se corta en MAX_PARSE_BUF; response_bytes debe
        # usar el contador total del bucle de recv, no len(resp_raw).
        big = b"x" * (llm_proxy.MAX_PARSE_BUF + 50_000)
        truncated = big[:llm_proxy.MAX_PARSE_BUF]
        rec = llm_proxy._extract_record(
            "POST", "/v1/chat/completions", 200, b"{}", truncated,
            True, 10.0, "127.0.0.1:1", len(big))
        self.assertEqual(rec["response_bytes"], len(big))

    def test_bytes_persisted_to_store(self):
        tmp = tempfile.TemporaryDirectory()
        st = LlmCallStore(Path(tmp.name) / "c.db")
        req = b'{"prompt":"abc"}'
        resp = b'{"ok":true}'
        rec = llm_proxy._extract_record(
            "POST", "/v1/chat/completions", 200, req, resp,
            False, 1.0, "127.0.0.1:1")
        st.record(rec)
        row = st.list_calls()[0]
        self.assertEqual(row["request_bytes"], len(req))
        self.assertEqual(row["response_bytes"], len(resp))
        st.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
