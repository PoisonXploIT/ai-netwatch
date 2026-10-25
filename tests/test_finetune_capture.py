"""Fase F: captura cruda de Jev para el dataset de finetuning.

- triage_events expone las answers crudas en un campo ADITIVO 'raw'
  (claves f{gi}_class/_sev/_act) sin tocar el contrato existente.
- POST /api/triage aneja {event_id, ts, state, questions, raw} a
  data/finetune/jev_raw.jsonl mapeando f{gi} -> event_id real; sin
  duplicados por event_id. Fail-safe: un fallo no rompe el triaje.
- raw_to_cases convierte el crudo a casos {state, questions, gold}.

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

import jev_triage  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


def _raw_answer(choice="expected_ai_use", conf=0.9, score=1.0, noul=0.1):
    return {
        "class": {"type": "choice", "choice": choice, "confidence": conf,
                  "probabilities": {"expected_ai_use": 0.9,
                                   "background_exfil_suspect": 0.1}},
        "sev": {"type": "score", "score": score,
                "probabilities": {"0": 0.2, "1": 0.8, "2": 0.0, "3": 0.0}},
        "act": {"type": "noul", "noul": noul},
    }


class TestTriageRawField(unittest.TestCase):
    def test_cloud_result_exposes_raw_additive(self):
        body = {"answers": {
            "f0_class": _raw_answer()["class"],
            "f0_sev": _raw_answer()["sev"],
            "f0_act": _raw_answer()["act"],
            "f1_class": _raw_answer(choice="telemetry_noise")["class"],
            "f1_sev": _raw_answer(score=2.0)["sev"],
            "f1_act": _raw_answer(noul=0.8)["act"],
        }}

        def fake(url, body_q, key, timeout=30):
            return body

        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events([{"process": "a"}, {"process": "b"}],
                                         "k")
        self.assertEqual(r["status"], "ok")
        # Contrato existente intacto.
        for k in ("status", "model", "count", "partial", "verdicts"):
            self.assertIn(k, r)
        self.assertEqual(set(r["verdicts"]["0"]),
                         {"verdict", "confidence", "severity_score",
                          "immediate_action", "prob_false_positive"})
        # Campo aditivo: crudo completo por evento.
        self.assertEqual(set(r["raw"]), {"0", "1"})
        self.assertEqual(set(r["raw"]["0"]),
                         {"f0_class", "f0_sev", "f0_act"})
        self.assertEqual(r["raw"]["0"]["f0_class"]["probabilities"],
                         {"expected_ai_use": 0.9,
                          "background_exfil_suspect": 0.1})
        self.assertEqual(r["raw"]["1"]["f1_act"]["noul"], 0.8)


class TriageLiveCaptureBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.finetune = Path(self.tmp.name) / "finetune"
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH",
                               "triage_events", "FINE_TUNE_DIR")}
        server.store = self.store
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server.FINE_TUNE_DIR = self.finetune
        server._cfg = {"catalog_approved": True, "approved_providers": [],
                       "jev_enabled": True, "jev_api_key": "k",
                       "jev_base_url": "http://127.0.0.1:9/x",
                       "jev_model": "test-model",
                       "llm_enabled": False}

        def fake_triage(events, api_key, base_url="", model="", timeout=30):
            verdicts, raw = {}, {}
            for i, _ in enumerate(events):
                a = _raw_answer()
                raw[str(i)] = {f"f{i}_class": a["class"],
                               f"f{i}_sev": a["sev"],
                               f"f{i}_act": a["act"]}
                verdicts[str(i)] = {
                    "verdict": a["class"]["choice"],
                    "confidence": 0.9, "severity_score": 1.0,
                    "immediate_action": 0.1,
                    "prob_false_positive": 0.1}
            return {"status": "ok", "model": "test-model",
                    "count": len(events), "partial": False,
                    "verdicts": verdicts, "raw": raw}

        server.triage_events = fake_triage

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()

    def _seed(self):
        self.store.observe_connection(
            process="a.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="api.openai.com",
            ai_layer="catalog")
        self.store.observe_connection(
            process="b.exe", dest_ip="2.2.2.2", dest_port=443,
            dest_host=None, catalog_domain="api.anthropic.com",
            ai_layer="catalog")

    def _post(self):
        return server.triage(server.TriageRequest())


class TestLiveCapture(TriageLiveCaptureBase):
    def test_triage_appends_raw_by_event_id(self):
        self._seed()
        out = self._post()
        path = self.finetune / "jev_raw.jsonl"
        self.assertTrue(path.exists())
        lines = [json.loads(l) for l in
                path.read_text(encoding="utf-8").splitlines()]
        ids = sorted(int(e["id"]) for e in out["events"])
        self.assertEqual([r["event_id"] for r in lines], ids)
        for r in lines:
            self.assertIn("ts", r)
            self.assertIsInstance(r["state"], dict)
            self.assertIn("questions", r)
            # f{gi} mapeado al event_id real: el crudo lleva las claves
            # del indice de llamada y el id real en su campo.
            self.assertEqual(len(r["raw"]), 3)
        self.assertIn("f0_class", lines[0]["raw"])
        self.assertEqual(lines[0]["raw"]["f0_class"]["probabilities"],
                         {"expected_ai_use": 0.9,
                          "background_exfil_suspect": 0.1})

    def test_no_duplicates_on_second_triage(self):
        self._seed()
        self._post()
        # Segundo triaje: todo reutilizado (mismas firmas) -> sin nuevas
        # lineas en el jsonl.
        out2 = self._post()
        self.assertEqual(out2["dedup"]["reused"], 2)
        path = self.finetune / "jev_raw.jsonl"
        lines = [json.loads(l) for l in
                path.read_text(encoding="utf-8").splitlines()]
        ids = [r["event_id"] for r in lines]
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_raw_in_result_is_harmless(self):
        # Un triaje sin campo raw (p. ej. todo reutilizado) no rompe nada.
        def fake_no_raw(events, api_key, base_url="", model="", timeout=30):
            return {"status": "ok", "model": "test-model", "count": 0,
                    "partial": False, "verdicts": {}}

        self._seed()
        server.triage_events = fake_no_raw
        out = self._post()
        self.assertEqual(out["dedup"]["fresh"], 2)
        # Sin campo raw: nada se escribe (fail-safe silencioso).
        self.assertFalse((self.finetune / "jev_raw.jsonl").exists())


class TestRawToCases(unittest.TestCase):
    def test_to_case_builds_state_questions_gold(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import raw_to_cases
        rec = {"event_id": 7, "ts": "2026-09-30T12:00:00",
               "state": {"process": "a.exe", "dest_ip": "1.1.1.1"},
               "questions": {},
               "raw": {
                   "f3_class": _raw_answer()["class"],
                   "f3_sev": _raw_answer(score=2.0)["sev"],
                   "f3_act": _raw_answer(noul=0.7)["act"],
               }}
        case = raw_to_cases.to_case(rec)
        self.assertIsNotNone(case)
        self.assertEqual(set(case), {"state", "questions", "gold"})
        self.assertEqual(case["state"]["process"], "a.exe")
        self.assertEqual(set(case["questions"]),
                         {"f0_class", "f0_sev", "f0_act"})
        self.assertEqual(case["gold"]["f0_class"],
                         {"probabilities": {"expected_ai_use": 0.9,
                                            "background_exfil_suspect": 0.1}})
        self.assertEqual(case["gold"]["f0_sev"],
                         {"probabilities": {"0": 0.2, "1": 0.8,
                                            "2": 0.0, "3": 0.0}})
        act = case["gold"]["f0_act"]["probabilities"]
        self.assertAlmostEqual(act["true"], 0.7)
        self.assertAlmostEqual(act["false"], 0.3)

    def test_to_case_rejects_without_gold(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import raw_to_cases
        rec = {"event_id": 8, "state": {"process": "b.exe"},
               "questions": {}, "raw": {}}
        self.assertIsNone(raw_to_cases.to_case(rec))


if __name__ == "__main__":
    unittest.main()
