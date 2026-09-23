"""v2.3: fingerprinting de SDK IA por proceso + artefactos (sin TLS).

- sdk_fingerprint puro: python/node con SDKs en su arbol -> label;
  sin artefacto verificable -> None (nunca inventa).
- Sysmon EID1 expone CommandLine del propio proceso.
- Monitor: _eid1_cycle puebla el mapa imagen->fingerprint.
- Server: /api/processes + label 'sdk' en top_processes del dashboard.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import monitor as monitor_mod  # noqa: E402
import sdk_fingerprint  # noqa: E402
import server  # noqa: E402
import sysmon_source  # noqa: E402
from store import LlmCallStore, Store  # noqa: E402


def _mkvenv(root: Path) -> Path:
    """Crea <root>/.venv con Scripts/python.exe y un site-packages."""
    venv = root / ".venv"
    (venv / "Scripts").mkdir(parents=True, exist_ok=True)
    (venv / "Lib" / "site-packages").mkdir(parents=True, exist_ok=True)
    exe = venv / "Scripts" / "python.exe"
    exe.touch()
    return exe


class TestFingerprintPure(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_venv_python_with_sdks(self):
        exe = _mkvenv(self.root)
        sp = exe.parent.parent / "Lib" / "site-packages"
        (sp / "openai").mkdir()
        (sp / "anthropic").mkdir()
        fp = sdk_fingerprint.fingerprint_process("python.exe", str(exe))
        self.assertIsNotNone(fp)
        self.assertEqual(fp["runtime"], "python")
        self.assertTrue(fp["venv"])
        self.assertEqual(fp["sdks"], ["anthropic", "openai"])
        self.assertEqual(fp["label"], "python-sdk(anthropic, openai)")

    def test_system_python_without_sdks_is_none(self):
        # Sin artefacto verificable: None, nunca un label inventado.
        exe = self.root / "sys" / "Python312" / "python.exe"
        exe.parent.mkdir(parents=True)
        exe.touch()
        self.assertIsNone(
            sdk_fingerprint.fingerprint_process("python.exe", str(exe)))

    def test_system_python_with_sdks_not_venv(self):
        exe = self.root / "sys" / "Python312" / "python.exe"
        sp = self.root / "sys" / "Python312" / "Lib" / "site-packages"
        sp.mkdir(parents=True)
        (sp / "langchain_core").mkdir()
        exe.touch()
        fp = sdk_fingerprint.fingerprint_process("python.exe", str(exe))
        self.assertFalse(fp["venv"])
        self.assertEqual(fp["sdks"], ["langchain"])

    def test_node_with_scoped_sdk(self):
        node = self.root / "nodejs" / "node.exe"
        node.parent.mkdir(parents=True)
        node.touch()
        appdata = self.root / "appdata"
        scoped = appdata / "npm" / "node_modules" / "@anthropic-ai" / "sdk"
        scoped.mkdir(parents=True)
        with mock.patch.dict(os.environ, {"APPDATA": str(appdata)}):
            fp = sdk_fingerprint.fingerprint_process("node.exe", str(node))
        self.assertEqual(fp["runtime"], "node")
        self.assertEqual(fp["sdks"], ["@anthropic-ai/sdk"])
        self.assertEqual(fp["label"], "node-sdk(@anthropic-ai/sdk)")

    def test_node_without_sdks_is_none(self):
        node = self.root / "nodejs" / "node.exe"
        node.parent.mkdir(parents=True)
        node.touch()
        with mock.patch.dict(os.environ, {"APPDATA": ""}):
            self.assertIsNone(
                sdk_fingerprint.fingerprint_process("node.exe", str(node)))

    def test_unknown_process_is_none(self):
        self.assertIsNone(sdk_fingerprint.fingerprint_process(
            "chrome.exe", str(self.root / "x" / "chrome.exe")))

    def test_cmdline_fallback_when_exe_missing(self):
        exe = _mkvenv(self.root)
        sp = exe.parent.parent / "Lib" / "site-packages"
        (sp / "openai").mkdir()
        # Sin ruta: se extrae del primer token de la command line.
        fp = sdk_fingerprint.fingerprint_process(
            "python.exe", "", f'"{exe}" -m uvicorn server:app')
        self.assertIsNotNone(fp)
        self.assertEqual(fp["sdks"], ["openai"])


class TestEid1Cmdline(unittest.TestCase):
    """Sysmon EID1 expone la CommandLine del propio proceso (v2.3)."""

    XML = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>1</EventID></System>"
        "<EventData>"
        "<Data Name='UtcTime'>2026-09-23 10:00:00.000</Data>"
        "<Data Name='ProcessId'>4242</Data>"
        "<Data Name='Image'>C:\\x\\.venv\\Scripts\\python.exe</Data>"
        "<Data Name='CommandLine'>"
        "C:\\x\\.venv\\Scripts\\python.exe -m uvicorn server:app"
        "</Data>"
        "<Data Name='ProcessName'>python.exe</Data>"
        "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
        "<Data Name='ParentCommandLine'>cmd /c start</Data>"
        "</EventData></Event>"
    )

    def test_cmdline_parsed(self):
        sample = json.dumps([{"RecordId": "100", "Xml": self.XML}])
        with mock.patch.object(sysmon_source, "_run_ps",
                               return_value=sample):
            evs = sysmon_source.poll_sysmon_process_creation()
        self.assertEqual(len(evs), 1)
        self.assertIn("uvicorn", evs[0]["cmdline"])
        self.assertTrue(evs[0]["image"].endswith("python.exe"))

    def test_no_processname_derived_from_image(self):
        # Sysmon que no emite ProcessName/ParentProcessName: el nombre se
        # deriva del basename de Image (regresion: antes todo era "" y el
        # poll devolvía []).
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='UtcTime'>2026-09-23 10:00:00.000</Data>"
            "<Data Name='ProcessId'>4242</Data>"
            "<Data Name='Image'>C:\\x\\.venv\\Scripts\\python.exe</Data>"
            "<Data Name='CommandLine'>C:\\x\\.venv\\Scripts\\python.exe app.py</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>cmd /c start</Data>"
            "</EventData></Event>"
        )
        sample = json.dumps([{"RecordId": "101", "Xml": xml}])
        with mock.patch.object(sysmon_source, "_run_ps",
                               return_value=sample):
            evs = sysmon_source.poll_sysmon_process_creation()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["process"], "python.exe")
        self.assertEqual(evs[0]["parent_process"], "cmd.exe")


class ServerSdkBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.llm = LlmCallStore(Path(self.tmp.name) / "llm.db")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH", "llm_calls",
                               "monitor")}
        server.store = self.store
        server.llm_calls = self.llm
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True,
                       "approved_providers": []}
        # NetMonitor real con el mapa de fingerprint sembrado (mismo
        # patron que los tests de EID22).
        self.mon = monitor_mod.NetMonitor(self.store)
        self.mon._sdk_fp = {
            r"C:\x\.venv\Scripts\python.exe":
            {"runtime": "python", "venv": True,
             "sdks": ["openai"], "label": "python-sdk(openai)"}}
        server.monitor = self.mon

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.llm.close()
        self.tmp.cleanup()


class TestServerSdkFichas(ServerSdkBase):
    def test_processes_endpoint(self):
        out = server.processes_fichas()
        self.assertEqual(len(out["processes"]), 1)
        row = out["processes"][0]
        self.assertTrue(row["image"].endswith("python.exe"))
        self.assertEqual(row["label"], "python-sdk(openai)")

    def test_dashboard_top_processes_sdk_label(self):
        self.store.observe_connection(
            process="python.exe", dest_ip="1.1.1.1", dest_port=443,
            dest_host=None, catalog_domain="openai.com")
        out = server.dashboard(days=7)
        procs = {p["name"]: p.get("sdk", "") for p in out["top_processes"]}
        self.assertEqual(procs, {"python.exe": "python-sdk(openai)"})

    def test_no_monitor_empty(self):
        server.monitor = None
        self.assertEqual(server.processes_fichas(), {"processes": []})


class TestMonitorSdkCycle(unittest.TestCase):
    """v2.3: _eid1_cycle puebla imagen->fingerprint (NetMonitor real)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.exe = _mkvenv(Path(self.tmp.name))
        sp = self.exe.parent.parent / "Lib" / "site-packages"
        (sp / "openai").mkdir()

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_cycle_populates_sdk_map(self):
        evs = [{
            "record_id": 1, "ts": "", "process": "python.exe",
            "image": str(self.exe), "pid": 123,
            "cmdline": f'"{self.exe}" app.py',
            "parent_image": "", "parent_process": "",
            "parent_cmdline": "",
        }]
        m = monitor_mod.NetMonitor(self.store, eid1_fn=lambda: evs)
        m._eid1_cycle()
        fmap = m.sdk_fingerprint_map()
        self.assertIn(str(self.exe), fmap)
        self.assertEqual(fmap[str(self.exe)]["sdks"], ["openai"])

    def test_non_runtime_process_ignored(self):
        evs = [{
            "record_id": 1, "ts": "", "process": "chrome.exe",
            "image": str(Path(self.tmp.name) / "chrome.exe"), "pid": 123,
            "cmdline": "", "parent_image": "", "parent_process": "",
            "parent_cmdline": "",
        }]
        m = monitor_mod.NetMonitor(self.store, eid1_fn=lambda: evs)
        m._eid1_cycle()
        self.assertEqual(m.sdk_fingerprint_map(), {})
