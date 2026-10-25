"""Pipeline completo de punta a punta (bloque de pruebas 2026-10-25).

Ruta verificada en un store temporal, sin red:

  colector (poll + sesiones) -> store -> baseline/anomalia -> triaje Jev
  (stub) -> findings -> dashboard -> exports (JSON/CSV/PDF/chain/STIX)
  -> audit log

No sustituye los tests unitarios: comprueba que las piezas ENCAJAN (el
score de un hallazgo, la cadena de hashes, que un export no lleve secretos).
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402
from evidence import verify_chain  # noqa: E402
from store import Store  # noqa: E402

FAKE_KEY = "clave-falsa-de-prueba-NO-ES-UNA-KEY-REAL"

# (process, ip, port, catalog, host, protocol, image, layer, verdict)
SEED = [
    ("python.exe", "20.30.11.9", 443, "typesafe.ai", "api.typesafe.ai", "tcp",
     "C:\\Python\\python.exe", "catalog", "scheduled"),
    ("chrome.exe", "104.18.23.10", 443, "openai.com", "api.openai.com", "tcp",
     "C:\\Program Files\\Chrome\\chrome.exe", "catalog", "user_driven"),
    ("svchost.exe", "172.217.12.4", 443, "google.com", "www.google.com", "tcp",
     "C:\\Windows\\System32\\svchost.exe", "heuristic", "unknown"),
    ("Code.exe", "13.107.42.14", 443, "github.com", "api.githubcopilot.com",
     "tcp", "C:\\Users\\Sammi\\Code.exe", "catalog", "autonomous"),
]


def fake_triage(events, api_key, base_url=None, model=None, timeout=30,
                backend="cloud", minimal=False):
    """Stub de Jev: veredictos deterministas por indice."""
    verdicts = {}
    for i, e in enumerate(events):
        sev = 3 if e.get("autonomy_verdict") == "autonomous" else 1
        verdicts[str(i)] = {
            "verdict": "background_exfil_suspect" if sev == 3 else "expected_ai_use",
            "confidence": 0.82,
            "severity_score": sev,
            "action_immediate": 0.4 if sev == 3 else 0.1,
        }
    return {"status": "ok", "model": "jev-stub", "count": len(events),
            "verdicts": verdicts, "raw": {}}


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "pipeline.db")
        self._store_orig = server.store
        self._cfg_orig = dict(server._cfg)
        server.store = self.store
        server._cfg.update({
            "jev_enabled": True,
            "jev_api_key": FAKE_KEY,
            "laya_enabled": False,
            "monitoring_enabled": True,
            "jev_minimal": True,
            "blacklist": [],
            "suppressed_findings": [],
            "approved_providers": ["typesafe.ai"],
            "catalog_approved": True,
        })

    def tearDown(self):
        server.store = self._store_orig
        server._cfg.clear()
        server._cfg.update(self._cfg_orig)
        self.store.close()
        self.tmp.cleanup()

    def _feed_collector(self):
        """Lo que produce un ciclo de polling: polls + sesiones + SNI + DNS."""
        for proc, ip, port, catalog, host, proto, image, layer, verdict in SEED:
            for _ in range(4):
                self.store.observe_connection(proc, ip, port, catalog, host,
                                             protocol=proto, image=image,
                                             ai_layer=layer,
                                             autonomy_verdict=verdict)
            for _ in range(6):
                self.store.record_session(proc, ip, port)
        self.store.attach_sni("104.18.23.10", 443, "api.openai.com", "openai.com")
        self.store.record_dns_resolution("172.217.12.4", "www.google.com")
        self.store.ingest_net_bytes(
            [{"ts": "2026-10-25T10:00:00", "dest_ip": "104.18.23.10",
              "dest_port": 443, "bytes": 2_500_000, "processes": ["chrome.exe"]}],
            "2026-10-25T10:00:00")

    def test_pipeline_end_to_end(self):
        self._feed_collector()

        # 1) deteccion: los eventos viven y tienen capa/procesos
        events = self.store.list_events(limit=100)
        self.assertEqual(len(events), len(SEED), "el colector no registro eventos")
        self.assertTrue(all(e["seen_count"] == 4 for e in events))
        self.assertTrue(all(e["sessions"] >= 1 for e in events))

        # 2) baseline y anomalia determinista
        base = server.baseline_api()
        self.assertTrue(base["groups"], "baseline sin grupos")
        self.assertTrue(any(g["current"] for g in base["groups"]))

        # 3) triaje con Jev (stub) y dedup por firma. La captura de finetuning
        # se neutraliza: escribiria muestras falsas en data/finetune real.
        stub = mock.Mock(side_effect=fake_triage)
        with mock.patch.object(server, "triage_events", stub), \
             mock.patch.object(server, "_finetune_capture", lambda *a, **k: None):
            tri = server.triage(server.TriageRequest())
        self.assertEqual(tri["jev"]["status"], "ok")
        self.assertEqual(len(tri["jev"]["verdicts"]), len(SEED))
        self.assertEqual(stub.call_count, 1, "el primer triaje debe llamar a Jev")
        # Segundo triaje: todo reutilizado (misma firma) => 0 llamadas nuevas.
        with mock.patch.object(server, "triage_events", stub), \
             mock.patch.object(server, "_finetune_capture", lambda *a, **k: None):
            tri2 = server.triage(server.TriageRequest())
        self.assertEqual(stub.call_count, 1,
                         "el dedup por firma no funciona: Jev se vuelve a llamar")
        self.assertEqual(tri2["jev"]["count"], 0)
        self.assertEqual(tri2["dedup"]["reused"], len(SEED))

        # 4) hallazgos: score combinado y cuarentena
        find = server.findings()
        self.assertTrue(find["findings"], "sin hallazgos con eventos vivos")
        scores = [f["score"] for f in find["findings"]]
        self.assertTrue(all(0 <= s <= 100 for s in scores))
        top = max(find["findings"], key=lambda f: f["score"])
        self.assertEqual(top["process"], "Code.exe",
                         "el proceso autonomo debe ser el hallazgo de mayor score")

        # 5) shadow AI: lo no aprobado aparece; typesafe.ai (aprobada) no.
        # El catalogo aprobado cubre por sufijo: openai.com -> api.openai.com.
        shadow = server.shadow_providers()
        provs = {g["provider"] for g in shadow["shadow"]}
        self.assertNotIn("typesafe.ai", provs)
        self.assertIn("google.com", provs,
                      "una IA detectada por heuristica debe aparecer en shadow")
        self.assertNotIn("api.openai.com", provs,
                        "el catalogo aprobado aprueba por sufijo (openai.com)")

        # 6) autonomia y panel
        aut = server.autonomy_state(group="provider")
        self.assertTrue(aut["events"])
        self.assertGreaterEqual(aut["counts"]["autonomous"], 1)
        dash = server.dashboard(days=7)
        self.assertTrue(dash["top_providers"])
        self.assertTrue(dash["layers"])
        self.assertGreater(dash["cloud_bytes"]["total_bytes"], 0)
        self.assertGreaterEqual(dash["shadow_count"], 1)

        # 7) exports: todos con la misma version y sin secretos
        js = json.loads(server.export_json().body)
        self.assertEqual(js["version"], server.VERSION)
        self.assertEqual(len(js["events"]), len(SEED))
        csv_body = server.export_csv().body
        pdf = server.export_pdf().body
        for blob in (json.dumps(js).encode(), csv_body, pdf):
            self.assertNotIn(FAKE_KEY.encode(), blob,
                            "un export contiene la API key")

        # 8) evidencia: cadena de hashes verificable y manipulable
        chain_body = server.evidence_chain(days=7).body.decode("utf-8")
        rows = [json.loads(line) for line in chain_body.splitlines() if line]
        self.assertTrue(verify_chain(rows), "la cadena emitida no verifica")
        tampered = [dict(r) for r in rows]
        tampered[1]["event"]["seen_count"] = 9999
        self.assertFalse(verify_chain(tampered),
                         "alterar una fila debe romper la cadena")

        stix = json.loads(server.evidence_stix(days=7).body)
        self.assertEqual(stix["type"], "bundle")
        self.assertGreater(len(stix["objects"]), 1)

        # 9) el audit log no escribe valores de secretos
        audit = (ROOT / "data" / "audit.log").read_text(encoding="utf-8")
        self.assertNotIn(FAKE_KEY, audit)

    def test_kill_switch_detiene_el_colector(self):
        server._cfg["monitoring_enabled"] = False
        with mock.patch.object(server, "_spawn_netcollector") as spawn:
            server._netbytes_cycle()
        spawn.assert_not_called()

    def test_uac_fallback_no_se_repita(self):
        """Sin tarea elevada, el UAC se intenta UNA vez (no cada ciclo)."""
        with mock.patch.object(server, "_netbytes_task_exists", return_value=False), \
             mock.patch.object(server, "subprocess", mock.MagicMock()) as sp:
            server._uac_attempted = False
            first = server._spawn_netcollector(30, Path("out.jsonl"))
            second = server._spawn_netcollector(30, Path("out.jsonl"))
        self.assertEqual(first, "uac")
        self.assertEqual(second, "none")
        self.assertEqual(sp.Popen.call_count, 1,
                         "el fallback UAC lanza una ventana por ciclo")


if __name__ == "__main__":
    unittest.main()
