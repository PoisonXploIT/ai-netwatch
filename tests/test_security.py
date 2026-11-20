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
import asyncio
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _free_port(start: int = 8123) -> int:
    """Puerto loopback libre: si el inspector esta activo, 8123 no lo esta."""
    for port in range(start, start + 40):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            continue
    raise RuntimeError("no hay puerto loopback libre para el proxy")

import server  # noqa: E402
import audit  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
import secret_store  # noqa: E402
from store import LlmCallStore, Store  # noqa: E402


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
        self._old_audit = server.audit_log
        server.store = self.store
        server.monitor = None
        server._cfg = _fresh_cfg()
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server.audit_log = audit.AuditLog(Path(self.tmp.name) / "audit.log")

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        server.CONFIG_PATH = self._old_path
        server.audit_log = self._old_audit
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
        self._set_llm("http://127.0.0.1:8099")
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
        # La key no queda en claro en disco: se cifra con DPAPI (cuando esta).
        if secret_store.available():
            self.assertNotEqual(data["jev_api_key"], "k-test-123")
            self.assertTrue(data["jev_api_key"].startswith(secret_store.PREFIX))
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


class TestOriginGuard(SecurityBase):
    """S2/S3: ningun origen distinto de la consola puede POSTar.

    Sin TestClient (no hay httpx en el venv) se invoca el middleware con un
    scope Starlette minimo: es lo mismo que ve el server en una peticion real.
    """

    def _req(self, method: str, host: str, origin: str | None = None,
             token: bool = True) -> Request:
        headers = [(b"host", host.encode())]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        if token and method in server._STATE_CHANGING:
            headers.append((b"x-netwatch-token", server._SESSION_TOKEN.encode()))
        return Request({"type": "http", "method": method, "path": "/api/config",
                        "headers": headers, "query_string": b"",
                        "scheme": "http"})

    @staticmethod
    async def _pass_through(request):
        return JSONResponse({"ok": True}, status_code=200)

    def _run(self, request) -> int:
        return asyncio.run(server._origin_guard(request, self._pass_through)).status_code

    def test_rebinding_host_blocked(self):
        # evil.com resuelto a 127.0.0.1: el Host sigue siendo evil.com.
        self.assertEqual(self._run(self._req("POST", "evil.com:8790")), 403)

    def test_cross_origin_post_blocked(self):
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            "https://evil.com")), 403)

    def test_null_origin_blocked(self):
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790", "null")), 403)

    def test_same_origin_allowed(self):
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            "http://127.0.0.1:8790")), 200)
        self.assertEqual(self._run(self._req("POST", "localhost:8790",
                                            "http://localhost:8790")), 200)

    def test_local_cli_without_origin_allowed(self):
        # curl / watchdog local: no mandan Origin, el Host es loopback.
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790")), 200)

    def test_get_from_foreign_host_blocked(self):
        # La lectura de /api/config tambien esta sujeta al guard de Host.
        self.assertEqual(self._run(self._req("GET", "evil.com")), 403)

    def test_security_headers_present(self):
        resp = asyncio.run(server._origin_guard(
            self._req("GET", "127.0.0.1:8790"), self._pass_through))
        for header in ("x-content-type-options", "x-frame-options",
                       "referrer-policy", "content-security-policy"):
            self.assertIn(header, resp.headers)
        self.assertEqual(resp.headers["x-frame-options"], "DENY")
        csp = resp.headers["content-security-policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)  # sin unsafe-inline
        self.assertIn("style-src 'self'", csp)   # sin unsafe-inline
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_cors_deny_all_configured(self):
        cors = [m for m in server.app.user_middleware
                if "allow_origins" in getattr(m, "kwargs", {})]
        self.assertTrue(cors, "no se ha registrado CORSMiddleware")
        self.assertEqual(cors[0].kwargs["allow_origins"], [])
        self.assertFalse(cors[0].kwargs.get("allow_credentials"))

    def test_post_without_session_token_blocked(self):
        # Un proceso local que no conoce el token no puede POSTar.
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            token=False)), 403)

    def test_post_with_wrong_token_blocked(self):
        req = Request({"type": "http", "method": "POST", "path": "/api/reset",
                       "headers": [(b"host", b"127.0.0.1:8790"),
                                   (b"x-netwatch-token", b"no-es-el-token")],
                       "query_string": b"", "scheme": "http"})
        self.assertEqual(self._run(req), 403)

    def test_get_no_token_needed(self):
        self.assertEqual(self._run(self._req("GET", "127.0.0.1:8790",
                                            token=False)), 200)

    def test_audit_records_state_changing(self):
        asyncio.run(server._origin_guard(
            self._req("POST", "127.0.0.1:8790"), self._pass_through))
        tail = server.audit_log.tail(5)
        self.assertTrue(tail)
        self.assertEqual(tail[-1]["path"], "/api/config")
        self.assertEqual(tail[-1]["status"], 200)
        self.assertEqual(tail[-1]["method"], "POST")

    def test_audit_records_blocked_attempts(self):
        asyncio.run(server._origin_guard(
            self._req("POST", "127.0.0.1:8790", "https://evil.com"),
            self._pass_through))
        tail = server.audit_log.tail(5)
        self.assertEqual(tail[-1]["action"], "blocked")
        self.assertEqual(tail[-1]["status"], 403)
        self.assertEqual(tail[-1]["origin"], "https://evil.com")

    def test_token_not_persisted_on_disk(self):
        # El token vive en memoria: no debe aparecer en config.json.
        server._save_config()
        text = server.CONFIG_PATH.read_text(encoding="utf-8")
        self.assertNotIn(server._SESSION_TOKEN, text)

    def test_s10_token_compare_is_constant_time_and_total(self):
        self.assertTrue(server._token_ok(server._SESSION_TOKEN))
        self.assertFalse(server._token_ok(""))
        self.assertFalse(server._token_ok("ñ-no-ascii"))  # no lanza TypeError

    def test_s11_origin_must_match_port(self):
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            "http://localhost:3000")), 403)
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            "https://127.0.0.1:8790")), 403)
        self.assertEqual(self._run(self._req("POST", "127.0.0.1:8790",
                                            "http://127.0.0.1:8790")), 200)


class TestLlmContentEncryption(SecurityBase):
    """S-03: el contenido del LLM Inspector no queda en claro en SQLite."""

    def setUp(self) -> None:
        super().setUp()
        self.llm = LlmCallStore(Path(self.tmp.name) / "llm.db")

    def tearDown(self) -> None:
        self.llm.close()
        super().tearDown()

    def test_prompt_stored_encrypted(self):
        self.llm.record({"ts": "2026-10-25 10:00:00Z", "method": "POST",
                         "path": "/v1/chat/completions", "status": 200,
                         "model": "m", "prompt": "CLAVE-SECRETA-EN-EL-PROMPT",
                         "response": "respuesta con PII"})
        raw = self.llm.path.read_bytes()
        if secret_store.available():
            self.assertNotIn(b"CLAVE-SECRETA-EN-EL-PROMPT", raw)
            self.assertNotIn(b"respuesta con PII", raw)
            self.assertIn(secret_store.PREFIX.encode(), raw)
        else:
            self.assertIn(b"CLAVE-SECRETA-EN-EL-PROMPT", raw)

    def test_roundtrip_returns_plaintext(self):
        call_id = self.llm.record({"ts": "2026-10-25 10:00:00Z",
                                   "prompt": "hola", "response": "adios"})
        got = self.llm.get_call(call_id)
        self.assertEqual(got["prompt"], "hola")
        self.assertEqual(got["response"], "adios")
        self.assertEqual(self.llm.list_calls(10)[0]["prompt"], "hola")

    def test_legacy_plaintext_row_is_readable_and_migratable(self):
        self.llm.conn.execute(
            "INSERT INTO llm_calls (ts, prompt, response) VALUES (?,?,?)",
            ("2026-01-01 00:00:00Z", "viejo-en-claro", "resp vieja"))
        self.llm.conn.commit()
        self.assertEqual(self.llm.list_calls(1)[0]["prompt"], "viejo-en-claro")
        if secret_store.available():
            self.assertEqual(self.llm.protect_existing(), 1)
            raw = self.llm.path.read_bytes()
            self.assertNotIn(b"viejo-en-claro", raw)
            self.assertEqual(self.llm.list_calls(1)[0]["prompt"], "viejo-en-claro")

    def test_empty_content_does_not_break(self):
        call_id = self.llm.record({"ts": "2026-10-25 10:00:00Z",
                                   "prompt": None, "response": ""})
        got = self.llm.get_call(call_id)
        self.assertEqual(got["prompt"] or "", "")
        self.assertEqual(got["response"] or "", "")


class TestProxyPortGuard(SecurityBase):
    """S-08: el puerto del inspector no puede interponerse en otro servicio."""

    def test_out_of_range_rejected(self):
        for port in (1, 7999, 10000, 65535):
            with self.assertRaises(HTTPException) as ctx:
                server.set_config(server.ConfigRequest(llm_proxy_port=port))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_same_as_target_rejected(self):
        server._cfg["llm_proxy_target"] = "127.0.0.1:8099"
        with self.assertRaises(HTTPException) as ctx:
            server.set_config(server.ConfigRequest(llm_proxy_port=8099))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_allowed_range_accepted(self):
        server._cfg["llm_proxy_target"] = "127.0.0.1:8099"
        server._cfg["llm_proxy_port"] = 8098
        port = _free_port()
        server.set_config(server.ConfigRequest(llm_proxy_port=port))
        self.assertEqual(server._cfg["llm_proxy_port"], port)

    def test_busy_port_rejected(self):
        import socket as _socket
        srv = None
        port = None
        for candidate in (8123, 8124, 8125, 8126):
            try:
                srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                srv.bind(("127.0.0.1", candidate))
                srv.listen(1)
                port = candidate
                break
            except OSError:
                srv.close()
        if port is None:
            self.skipTest("sin puerto libre en el rango del inspector")
        try:
            server._cfg["llm_proxy_target"] = "127.0.0.1:8099"
            with self.assertRaises(HTTPException) as ctx:
                server.set_config(server.ConfigRequest(llm_proxy_port=port))
            self.assertEqual(ctx.exception.status_code, 409)
        finally:
            srv.close()

    def test_audit_records_changed_fields(self):
        server.set_config(server.ConfigRequest(llm_model="dirk",
                                              retention_days=45))
        tail = server.audit_log.tail(5)
        entry = [e for e in tail if e["action"] == "config_change"][-1]
        self.assertEqual(sorted(entry["detail"]["campos"]),
                         ["llm_model", "retention_days"])
        # Los valores no se escriben en el audit (pueden ser secretos).
        self.assertNotIn("dirk", json.dumps(server.audit_log.tail(20)))


class TestVersionSingleSource(SecurityBase):
    """U-02: una unica fuente de version (server.VERSION)."""

    def test_version_is_not_the_alpha_placeholder(self):
        self.assertNotEqual(server.VERSION, "2.0-alpha")
        self.assertRegex(server.VERSION, r"^\d+\.\d+$")

    def test_console_renders_the_server_version(self):
        html = server.index().body.decode("utf-8")
        self.assertIn(f"v{server.VERSION}", html)
        self.assertNotIn("{{VERSION}}", html)
        self.assertIn('<span class="badge-ver" id="ver-badge">', html)

    def test_html_has_no_hardcoded_version(self):
        raw = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("badge-ver\">v2", raw)
        self.assertNotIn("AI NetWatch v2", raw)

    def test_health_and_exports_share_the_version(self):
        self.assertEqual(server.health()["version"], server.VERSION)
        data = json.loads(server.export_json().body)
        self.assertEqual(data["version"], server.VERSION)
        self.store.observe_connection("a.exe", "1.1.1.1", 443, "api.openai.com", "")
        stix = server.evidence_stix(days=7).body.decode("utf-8", "replace")
        self.assertIn(server.VERSION, stix)


class TestHealth(SecurityBase):
    """S9: el watchdog necesita un endpoint que diga si el monitor vive."""

    def test_health_reports_status_and_sources(self):
        out = server.health()
        self.assertIn(out["status"], ("ok", "degradado"))
        self.assertEqual(out["status"], "degradado")  # monitor=None en tests
        self.assertEqual(out["version"], server.VERSION)
        self.assertGreaterEqual(out["uptime_seconds"], 0)
        self.assertIn("monitor", out["sources"])
        self.assertIn("jev_key_set", out["sources"])
        self.assertFalse(out["sources"]["jev_key_set"])

    def test_health_counts_events(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, None, "")
        out = server.health()
        self.assertEqual(out["events"], 1)
        self.assertTrue(out["last_event"])

    def test_index_injects_token(self):
        resp = server.index()
        html = resp.body.decode("utf-8")
        self.assertIn('name="netwatch-token"', html)
        self.assertIn(server._SESSION_TOKEN, html)
        # Sin esto, el navegador sirve la copia cacheada y la UI queda vieja.
        self.assertEqual(resp.headers.get("cache-control"), "no-store")

    def test_no_inline_script_in_console(self):
        # La CSP solo vale si no hay scripts inline: el tema es externo.
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", html)
        self.assertIn('<script src="/static/theme.js?v={{ASSETV}}"></script>', html)
        self.assertIn('<script src="/static/app.js?v={{ASSETV}}"></script>', html)
        # El sello cambia con el mtime de los assets: ?v=VERSION solo no
        # busteaba la cache y el navegador seguia sirviendo el JS viejo.
        self.assertIn("{{ASSETV}}", html)
        self.assertIn("_asset_stamp", (ROOT / "server.py").read_text(encoding="utf-8"))

    def test_no_inline_styles(self):
        # style="..." obligaria a permitir 'unsafe-inline' en la CSP.
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("style=", html)

    def test_esc_covers_single_quote(self):
        # S-02: esc() debe escapar la comilla simple, usada en atributos.
        js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("replace(/'/g, \"&#39;\")", js)

    def test_collector_artifacts_pruned(self):
        # S-04: los ETL/XML/JSONL huercos del colector no entran en la
        # retencion de SQLite; se limpian tras 24 h.
        old_dir = server.DATA_DIR
        server.DATA_DIR = Path(self.tmp.name)
        try:
            stale = Path(self.tmp.name) / "netprobe_123.jsonl"
            stale.write_text("{}", encoding="utf-8")
            os.utime(stale, (0, 0))  # mtime de 1970: claramente antiguo
            fresh = Path(self.tmp.name) / "netprobe_456.jsonl"
            fresh.write_text("{}", encoding="utf-8")
            removed = server._prune_collector_artifacts()
            self.assertEqual(removed, 1)
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
        finally:
            server.DATA_DIR = old_dir


class TestJevKeyProtection(SecurityBase):
    """U-01: la key no puede destruirse por accidente ni exponerse.

    El GET devuelve cadena vacia + `jev_api_key_set`; el POST ignora la
    mascara '***' y el campo vacio. Solo se borra con el flag explicito.
    """

    def _set_key(self, value):
        server.set_config(server.ConfigRequest(jev_api_key=value))
        return server._cfg["jev_api_key"]

    def test_get_never_returns_the_key(self):
        server._cfg["jev_api_key"] = "KEY-REAL"
        masked = server._mask(server._cfg)
        self.assertEqual(masked["jev_api_key"], "")
        self.assertTrue(masked["jev_api_key_set"])
        self.assertNotIn("KEY-REAL", json.dumps(masked))

    def test_mask_sentinel_is_ignored(self):
        server._cfg["jev_api_key"] = "KEY-REAL"
        self.assertEqual(self._set_key("***"), "KEY-REAL")

    def test_empty_field_is_ignored(self):
        server._cfg["jev_api_key"] = "KEY-REAL"
        self.assertEqual(self._set_key(""), "KEY-REAL")
        self.assertEqual(self._set_key("   "), "KEY-REAL")

    def test_real_key_replaces_and_is_dpapi(self):
        self.assertEqual(self._set_key("KEY-NUEVA"), "KEY-NUEVA")
        server._save_config()
        data = json.loads(server.CONFIG_PATH.read_text(encoding="utf-8"))
        if secret_store.available():
            self.assertTrue(data["jev_api_key"].startswith(secret_store.PREFIX))
            self.assertNotIn("KEY-NUEVA", json.dumps(data))
        server._cfg["jev_api_key"] = ""
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "KEY-NUEVA")

    def test_clear_flag_is_the_only_way_to_delete(self):
        server._cfg["jev_api_key"] = "KEY-REAL"
        server.set_config(server.ConfigRequest(jev_api_key_clear=True))
        self.assertEqual(server._cfg["jev_api_key"], "")
        out = server._mask(server._cfg)
        self.assertFalse(out["jev_api_key_set"])

    def test_roundtrip_survives_ui_repost(self):
        # Simula el flujo de la UI: GET (vacio) -> Guardar sin escribir -> GET.
        self._set_key("KEY-REAL")
        server.set_config(server.ConfigRequest(jev_api_key=""))
        server._save_config()
        server._cfg["jev_api_key"] = ""
        server._load_config()
        self.assertEqual(server._cfg["jev_api_key"], "KEY-REAL")


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
