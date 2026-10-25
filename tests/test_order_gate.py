# -*- coding: utf-8 -*-
"""Gate de orden: la primera clave de `criteria` debe ser la opcion LIVE.

El bug de `sort_keys` (RUNBOOK-LAYA-FINETUNING.md, seccion 7) ordena
alfabeticamente las claves de `criteria`, que son POSICIONALES: el modelo
acierta la posicion pero la herramienta etiqueta otra opcion, y el acuerdo cae
de 68 a 24. Este test lo protege en el cliente (netwatch), en el paquete de
entrenamiento y en sec-dashboard, para que no pueda volver.
"""
import ast
import json
import unittest
from pathlib import Path

import jev_triage

DATA = Path(r"C:\Users\Sammi\AI\laya-data")
TRAIN = DATA / "paquete_laya" / "train.jsonl"
SEC_DRIVER = Path(r"C:\Users\Sammi\sec-dashboard\backend\jev.py")


class TestOrderGate(unittest.TestCase):
    def test_class_criteria_live_order(self):
        self.assertEqual(next(iter(jev_triage._CLASS_CRITERIA)), "expected_ai_use")

    def test_local_questions_live_order(self):
        crit = jev_triage._local_questions()["class"]["criteria"]
        self.assertEqual(next(iter(crit)), "expected_ai_use")

    def test_train_package_live_order(self):
        if not TRAIN.is_file():
            self.skipTest("no existe %s" % TRAIN)
        errores = []
        with TRAIN.open(encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                for qid, q in (obj.get("questions") or {}).items():
                    if not isinstance(q, dict) or q.get("type") != "choice":
                        continue
                    crit = q.get("criteria")
                    if not isinstance(crit, dict):
                        continue
                    claves = set(crit)
                    primera = next(iter(crit))
                    if "expected_ai_use" in claves and primera != "expected_ai_use":
                        errores.append((ln, qid, "netwatch", primera))
                    if "true_positive" in claves and primera != "true_positive":
                        errores.append((ln, qid, "finding", primera))
                if len(errores) > 10:
                    break
        self.assertFalse(errores, "criteria NO en orden live en train.jsonl: %s" % (errores[:10],))

    def test_sec_dashboard_verdict_live_order(self):
        if not SEC_DRIVER.is_file():
            self.skipTest("no existe %s" % SEC_DRIVER)
        tree = ast.parse(SEC_DRIVER.read_text(encoding="utf-8", errors="replace"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "_VERDICT_CRITERIA" for t in node.targets
            ):
                d = ast.literal_eval(node.value)
                self.assertEqual(
                    next(iter(d)), "true_positive",
                    "_VERDICT_CRITERIA debe empezar por true_positive; empieza por %s"
                    % next(iter(d)),
                )
                return
        self.fail("no encontre _VERDICT_CRITERIA en sec-dashboard/backend/jev.py")


if __name__ == "__main__":
    unittest.main()
