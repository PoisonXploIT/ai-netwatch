"""v2.4: Investigar con LLM local (asesoria display-only por evento).

- Mock del LLM -> confirm / refuta / insuficiente; campos truncados.
- Sin LLM configurado -> 'no disponible' sin llamar al LLM (fail-safe).
- Sin veredicto Jev previo -> investiga igual (contexto con jev=None).
- Evento inexistente -> 404. JSON malo del LLM -> unavailable.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import llm_local  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


class InvestigateBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        self._old_llm_calls = server.llm_calls
        self._old_cfg = dict(server._cfg)
        server.store = self.store
        server.llm_calls = None
        server._cfg = {
            **server._cfg,
            "llm_enabled": True,
            "llm_base_url": "http://127.0.0.1:8099",
            "llm_model": "test-model",
        }

    def tearDown(self) -> None:
        server.store = self._old_store
        server.llm_calls = self._old_llm_calls
        server._cfg = self._old_cfg
        self.store.close()
        self.tmp.cleanup()

    def _seed_event(self) -> int:
        e = self.store.observe_connection(
            process="python.exe", dest_ip="1.2.3.4", dest_port=443,
            dest_host="openai.com", catalog_domain="openai.com",
            ai_layer="catalog")
        return int(e["id"])


class TestInvestigateLlm(InvestigateBase):
    def _run(self, content: str) -> dict:
        with mock.patch.object(llm_local, "_chat", return_value=content) as m:
            r = server.investigate(server.InvestigateRequest(event_id=self._id))
        self.assertTrue(m.called)
        return r

    def test_confirm(self):
        self._id = self._seed_event()
        r = self._run(json.dumps({"evaluacion": "confirm",
                                  "porque": "trafico coherente con SDK",
                                  "evidencia_faltante": "ninguna"}))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["evaluacion"], "confirm")

    def test_refuta_and_insuficiente(self):
        self._id = self._seed_event()
        r = self._run(json.dumps({"evaluacion": "refuta",
                                  "porque": "puerto no coherente",
                                  "evidencia_faltante": "captura del flujo"}))
        self.assertEqual(r["evaluacion"], "refuta")
        self._id = self._seed_event()
        r = self._run(json.dumps({"evaluacion": "insuficiente",
                                  "porque": "solo 1 muestra",
                                  "evidencia_faltante": "mas sesiones"}))
        self.assertEqual(r["evaluacion"], "insuficiente")

    def test_fields_truncated(self):
        self._id = self._seed_event()
        r = self._run(json.dumps({"evaluacion": "confirm",
                                  "porque": "x" * 500,
                                  "evidencia_faltante": "y" * 500}))
        self.assertEqual(len(r["porque"]), 400)
        self.assertEqual(len(r["evidencia_faltante"]), 400)

    def test_bad_json_unavailable(self):
        self._id = self._seed_event()
        r = self._run("esto no es json")
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["reason"], "bad_json")

    def test_context_has_no_jev_when_never_triaged(self):
        """Sin triaje previo se investiga igual, con jev=None en contexto."""
        self._id = self._seed_event()
        with mock.patch.object(
                llm_local, "_chat",
                return_value=json.dumps({"evaluacion": "insuficiente",
                                         "porque": "sin datos",
                                         "evidencia_faltante": "triage"})) as m:
            r = server.investigate(server.InvestigateRequest(event_id=self._id))
        self.assertEqual(r["status"], "ok")
        ctx = json.loads(m.call_args[0][3])
        self.assertIsNone(ctx["jev"])
        self.assertEqual(ctx["evento"]["process"], "python.exe")
        self.assertIn("destino", ctx)
        self.assertIn("beaconing", ctx)

    def test_missing_event_404(self):
        with self.assertRaises(server.HTTPException):
            server.investigate(server.InvestigateRequest(event_id=99999))


class TestInvestigateNoLlm(InvestigateBase):
    def test_not_configured_no_call(self):
        self._id = self._seed_event()
        server._cfg["llm_enabled"] = False
        with mock.patch.object(llm_local, "_chat") as m:
            r = server.investigate(server.InvestigateRequest(event_id=self._id))
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["reason"], "llm_no_configurado")
        m.assert_not_called()
