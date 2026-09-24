"""B: revision LLM local por lote (asesoria display-only, sin auto).

- scope autonomous/unapproved/flagged/untriaged -> conjunto correcto.
- event_ids explicitos; tope llm_review_max respetado (resto pendiente).
- Revisiones ok persistidas en llm_reviews; fallos transitorios no.
- Sin LLM configurado -> 'no disponible' sin llamar al LLM (fail-safe).
- flagged sin triage ok -> vacio (no inventa marcas).
- reset limpia llm_reviews.

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


CONFIRM = json.dumps({"evaluacion": "confirm", "porque": "p",
                      "evidencia_faltante": "e"})


class ReviewBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        self._old_cfg = dict(server._cfg)
        server.store = self.store
        server._cfg = {
            **server._cfg,
            "llm_enabled": True,
            "llm_base_url": "http://127.0.0.1:8099",
            "llm_model": "test-model",
            "catalog_approved": True,
            "approved_providers": [],
        }

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        self.store.close()
        self.tmp.cleanup()

    def _seed_all(self) -> dict:
        a = self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="openai.com",
            ai_layer="catalog", autonomy_verdict="autonomous")
        s = self.store.observe_connection(
            process="s.exe", dest_ip="4.4.4.4", dest_port=443,
            dest_host=None, catalog_domain="anthropic.com",
            ai_layer="catalog", autonomy_verdict="scheduled")
        u = self.store.observe_connection(
            process="u.exe", dest_ip="5.5.5.5", dest_port=443,
            dest_host="evil-ai.example", catalog_domain=None,
            ai_layer="heuristic")
        p = self.store.observe_connection(
            process="p.exe", dest_ip="6.6.6.6", dest_port=443,
            dest_host=None, catalog_domain="openai.com",
            ai_layer="catalog")
        return {k: int(v["id"])
                for k, v in {"a": a, "s": s, "u": u, "p": p}.items()}

    def _run(self, req):
        with mock.patch.object(llm_local, "_chat",
                               return_value=CONFIRM) as m:
            r = server.review(req)
        return r, m


class TestReviewScopes(ReviewBase):
    def test_scope_autonomous_includes_scheduled(self):
        ids = self._seed_all()
        r, m = self._run(server.ReviewRequest(scope="autonomous"))
        self.assertEqual(r["status"], "ok")
        # Misma segunda de creacion: el orden no es estable; comparar como
        # conjunto (a y s son autonomous/scheduled; u y p no).
        self.assertEqual({x["event_id"] for x in r["reviews"]},
                         {ids["a"], ids["s"]})
        self.assertTrue(m.called)

    def test_scope_unapproved_only_shadow(self):
        ids = self._seed_all()
        r, _ = self._run(server.ReviewRequest(scope="unapproved"))
        # u.exe: dominio fuera de catalogo (shadow). El resto esta aprobado.
        self.assertEqual([x["event_id"] for x in r["reviews"]], [ids["u"]])

    def test_scope_bad_400(self):
        with self.assertRaises(server.HTTPException) as ctx:
            server.review(server.ReviewRequest(scope="nope"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_event_ids_explicit_order_kept(self):
        ids = self._seed_all()
        r, _ = self._run(
            server.ReviewRequest(event_ids=[ids["p"], ids["a"]]))
        self.assertEqual(r["scope"], "event_ids")
        self.assertEqual([x["event_id"] for x in r["reviews"]],
                         [ids["p"], ids["a"]])

    def test_cap_respected_rest_pending(self):
        self._seed_all()
        server._cfg["llm_review_max"] = 1
        r, m = self._run(server.ReviewRequest(scope="autonomous"))
        self.assertEqual(len(r["reviews"]), 1)
        self.assertEqual(r["requested"], 2)
        self.assertEqual(r["cap"], 1)
        self.assertEqual(m.call_count, 1)

    def test_flagged_uses_triage_verdicts(self):
        ids = self._seed_all()
        # Triage ok: evento 0 (ids['a']) marcado (severity 3), el resto
        # expected. flagged -> solo a; untriaged -> los otros 3 vivos.
        self.store.save_triage("ok", "m", {
            "events": [{"id": ids[k]} for k in ("a", "s", "u", "p")],
            "llm": {},
            "jev": {"status": "ok", "model": "m", "verdicts": {
                "0": {"verdict": "data_exfiltration", "severity_score": 3},
                "1": {"verdict": "expected_ai_use", "severity_score": 0},
                "2": {"verdict": "expected_ai_use", "severity_score": 0},
                "3": {"verdict": "expected_ai_use", "severity_score": 0},
            }},
        })
        r, _ = self._run(server.ReviewRequest(scope="flagged"))
        self.assertEqual([x["event_id"] for x in r["reviews"]], [ids["a"]])
        r2, _ = self._run(server.ReviewRequest(scope="untriaged"))
        self.assertEqual([x["event_id"] for x in r2["reviews"]], [])

    def test_flagged_without_ok_triage_is_empty(self):
        self._seed_all()
        # Sin triage guardado: no hay marcas fiables -> vacio, no inventar.
        r, m = self._run(server.ReviewRequest(scope="flagged"))
        self.assertEqual(r["reviews"], [])
        m.assert_not_called()


class TestReviewPersistence(ReviewBase):
    def test_ok_persisted_fail_not(self):
        ids = self._seed_all()
        # Primera llamada ok (persiste); segunda con JSON malo (no).
        with mock.patch.object(
                llm_local, "_chat",
                side_effect=[CONFIRM, "esto no es json"]):
            r = server.review(server.ReviewRequest(event_ids=[ids["a"], ids["p"]]))
        self.assertEqual(r["reviews"][0]["evaluacion"], "confirm")
        self.assertIsNone(r["reviews"][1]["evaluacion"])
        self.assertEqual(r["reviews"][1]["reason"], "bad_json")
        rows = self.store.list_reviews(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], ids["a"])
        self.assertEqual(rows[0]["evaluacion"], "confirm")

    def test_reset_clears_reviews(self):
        ids = self._seed_all()
        self._run(server.ReviewRequest(event_ids=[ids["a"]]))
        out = self.store.reset()
        self.assertGreaterEqual(out["llm_reviews_removed"], 1)
        self.assertEqual(self.store.list_reviews(limit=10), [])


class TestReviewNoLlm(ReviewBase):
    def test_not_configured_no_call(self):
        ids = self._seed_all()
        server._cfg["llm_enabled"] = False
        with mock.patch.object(llm_local, "_chat") as m:
            r = server.review(server.ReviewRequest(scope="autonomous"))
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["reason"], "llm_no_configurado")
        self.assertEqual(r["reviews"], [])
        m.assert_not_called()
        # Y nada persistido.
        self.assertEqual(self.store.list_reviews(limit=10), [])


if __name__ == "__main__":
    unittest.main()
