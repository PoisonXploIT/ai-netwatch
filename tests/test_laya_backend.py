"""Backend local (laya-serve) conmutable con cloud (Jev).

Contrato y fail-safe (PLAN-laya-backend.md seccion 9):
- default backend=cloud: misma URL/model que antes (sin cambio de comportamiento).
- backend=local contra laya-serve caido -> status "error" sin lanzar.
- contrato de salida: las 5 claves y tipos actuales en ambos backends.
- C1/C2 local: noul P(true) float -> 'yes'/'no' por umbral 0.5;
  prob_false_positive = 1 - answer_confidence (NO la 'confidence' de laya).
"""
import unittest
from unittest import mock

import jev_triage


def _local_batch_result(choice="expected_ai_use", ac=0.9, score=1.0, noul=0.1):
    return {"model": "laya-rl-agent",
            "answers": {
                "class": {"type": "choice", "choice": choice,
                          "confidence": 0.5, "answer_confidence": ac},
                "sev": {"type": "score", "score": score,
                        "confidence": 0.4, "answer_confidence": 0.5},
                "act": {"type": "noul", "noul": noul,
                        "confidence": max(noul, 1 - noul),
                        "answer_confidence": max(noul, 1 - noul)},
            }}


class TestBackendSelector(unittest.TestCase):
    def test_default_backend_is_cloud(self):
        # Sin backend explicitado: la URL debe ser la de Jev (comportamiento
        # actual) y las preguntas indexadas f{i} (camino cloud intacto).
        captured = {}

        def fake(url, body, key, timeout=30):
            captured["url"] = url
            return {"model": "jev-1.13.0",
                    "answers": {"f0_class": {"choice": "expected_ai_use",
                                              "confidence": 0.9}}}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            jev_triage.triage_events([{"process": "a"}], "k")
        self.assertEqual(captured["url"], jev_triage.DEFAULT_BASE_URL)

    def test_local_uses_laya_url_and_batch(self):
        captured = {}

        def fake(url, body, key, timeout=30):
            captured["url"] = url
            return {"results": [_local_batch_result()]}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake), \
                mock.patch.dict("os.environ", {"LAYA_API_KEY": "lk"}):
            r = jev_triage.triage_events([{"process": "a"}], "k",
                                         backend="local")
        self.assertTrue(captured["url"].endswith("/v1/systemone/batch"))
        self.assertEqual(r["status"], "ok")

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            jev_triage.triage_events([{"process": "a"}], "k", backend="otro")


class TestLocalContract(unittest.TestCase):
    def _run_local(self, noul=0.1, ac=0.9, score=1.0):
        with mock.patch.object(
                jev_triage, "_http_post_json",
                side_effect=lambda url, body, key, timeout=30: {
                    "results": [_local_batch_result(ac=ac, score=score,
                                                    noul=noul)]}):
            return jev_triage.triage_events([{"process": "a"}], "k",
                                            backend="local")

    def test_five_keys_and_types(self):
        r = self._run_local()
        v = r["verdicts"]["0"]
        self.assertEqual(
            set(v), {"verdict", "confidence", "severity_score",
                     "immediate_action", "prob_false_positive"})
        self.assertEqual(v["verdict"], "expected_ai_use")
        self.assertIsInstance(v["confidence"], float)
        self.assertIsInstance(v["severity_score"], float)  # C3: float tal cual
        self.assertEqual(v["immediate_action"], "no")

    def test_noul_threshold(self):
        # noul es P(true) float, NO etiqueta (C1 + A3).
        self.assertEqual(self._run_local(noul=0.5)["verdicts"]["0"]
                         ["immediate_action"], "yes")
        self.assertEqual(self._run_local(noul=0.49)["verdicts"]["0"]
                         ["immediate_action"], "no")

    def test_prob_fp_uses_answer_confidence(self):
        # C2: prob_false_positive = 1 - answer_confidence (NO 'confidence').
        r = self._run_local(ac=0.7)
        self.assertEqual(r["verdicts"]["0"]["prob_false_positive"], 0.3)

    def test_batch_results_map_by_position(self):
        # results[i] -> evento i, aunque lleguen en el mismo orden de entrada.
        # La simulacion se hace con side_effect; no hace falta una lista previa.

        def fake(url, body, key, timeout=30):
            assert len(body["states"]) == 2
            return {"results": [
                _local_batch_result(choice="expected_ai_use"),
                _local_batch_result(choice="background_exfil_suspect",
                                    noul=0.8),
            ]}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events(
                [{"process": "a"}, {"process": "b"}], "k", backend="local")
        self.assertEqual(r["verdicts"]["0"]["verdict"], "expected_ai_use")
        self.assertEqual(r["verdicts"]["1"]["verdict"],
                         "background_exfil_suspect")
        self.assertEqual(r["verdicts"]["1"]["immediate_action"], "yes")


class TestLocalFailSafe(unittest.TestCase):
    def test_dead_server_returns_error_without_raising(self):
        # laya-serve caido: URLError/OSError -> status error, sin lanzar.
        with mock.patch.object(
                jev_triage, "_http_post_json",
                side_effect=OSError("connection refused")):
            r = jev_triage.triage_events([{"process": "a"}, {"process": "b"}],
                                         "k", backend="local")
        self.assertEqual(r["status"], "error")

    def test_bad_batch_shape_falls_back_per_event(self):
        # /batch responde pero sin results (version antigua) -> 1 llamada
        # por evento a /v1/systemone.
        calls = []

        def fake(url, body, key, timeout=30):
            calls.append(url)
            if url.endswith("/batch"):
                return {"detail": "no batch"}
            return _local_batch_result()
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events([{"process": "a"}, {"process": "b"}],
                                         "k", backend="local")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(any(u.endswith("/v1/systemone") for u in calls))

    def test_partial_when_one_event_missing(self):
        def fake(url, body, key, timeout=30):
            return {"results": [_local_batch_result(), {}]}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events(
                [{"process": "a"}, {"process": "b"}], "k", backend="local")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["partial"])
        self.assertIsNone(r["verdicts"]["1"]["verdict"])


if __name__ == "__main__":
    unittest.main()
