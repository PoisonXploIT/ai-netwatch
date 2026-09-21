"""Tests sin red para AI NetWatch (catalogo, store, monitor, Jev, LLM local).

Ejecutar desde la raiz del proyecto:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ai_catalog  # noqa: E402
import jev_triage  # noqa: E402
import llm_local  # noqa: E402
import monitor as mon  # noqa: E402
from store import Store  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_match_domain(self):
        self.assertEqual(ai_catalog.match_domain("api.typesafe.ai"), "typesafe.ai")
        self.assertEqual(ai_catalog.match_domain("API.OPENAI.COM:443"), "openai.com")
        self.assertEqual(ai_catalog.match_domain("eu.api.anthropic.com"), "anthropic.com")
        self.assertIsNone(ai_catalog.match_domain("example.com"))
        self.assertIsNone(ai_catalog.match_domain(""))

    def test_process_hint(self):
        self.assertTrue(ai_catalog.process_hint("ollama.exe"))
        self.assertFalse(ai_catalog.process_hint("chrome.exe"))


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_observe_increments_seen_count(self):
        a = self.store.observe_connection("ollama.exe", "1.2.3.4", 443, "openai.com", None)
        b = self.store.observe_connection("ollama.exe", "1.2.3.4", 443, "openai.com", None)
        c = self.store.observe_connection("ollama.exe", "1.2.3.4", 8443, "openai.com", None)
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["id"], c["id"])
        self.assertEqual(self.store.get_event(b["id"])["seen_count"], 2)

    def test_list_filters(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, "openai.com", None)
        self.store.observe_connection("b.exe", "2.2.2.2", 443, "groq.com", None)
        self.assertEqual(len(self.store.list_events(process="a.exe")), 1)
        self.assertEqual(len(self.store.list_events(dest="groq")), 1)

    def test_triage_roundtrip(self):
        self.store.save_triage("ok", "jev-1.13.0", {"a": 1})
        t = self.store.latest_triage()
        self.assertEqual(t["status"], "ok")
        self.assertEqual(t["payload"], {"a": 1})

    def test_protocol_stored(self):
        a = self.store.observe_connection("a.exe", "1.1.1.1", 443, "openai.com",
                                          None, protocol="udp")
        b = self.store.observe_connection("b.exe", "2.2.2.2", 8443, "groq.com",
                                          None)  # default tcp
        self.assertEqual(self.store.get_event(a["id"])["protocol"], "udp")
        self.assertEqual(self.store.get_event(b["id"])["protocol"], "tcp")

    def test_daily_stats_survive_reset(self):
        for _ in range(3):
            self.store.observe_connection("a.exe", "1.1.1.1", 443, "openai.com",
                                          None)
        self.store.save_triage("ok", "jev-1.13.0", {})
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        s = {r["date"]: r for r in self.store.stats(days=7)}
        self.assertEqual(s[day]["events"], 3)
        self.assertEqual(s[day]["triages"], 1)
        # Reset borra vivos, conserva el rollup
        ev = self.store.list_events()[0]
        self.assertEqual(ev["seen_count"], 3)  # dedupe: misma conexion
        out = self.store.reset()
        self.assertEqual(out["events_removed"], 1)
        self.assertEqual(len(self.store.list_events()), 0)
        s2 = {r["date"]: r for r in self.store.stats(days=7)}
        self.assertEqual(s2[day]["events"], 3)

    def test_stats_fills_missing_days(self):
        rows = self.store.stats(days=7)
        self.assertEqual(len(rows), 7)
        self.assertTrue(all(r["events"] == 0 and r["triages"] == 0 for r in rows))


class TestMonitor(unittest.TestCase):
    def _mk(self, conns):
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        m = mon.NetMonitor(store, poll_fn=lambda: conns, pidmap_fn=lambda: {},
                           dns_fn=lambda: {})
        return tmp, store, m

    def _cleanup(self, tmp, store):
        store.close()
        tmp.cleanup()

    def test_only_catalog_destinations_stored(self):
        tmp, store, m = self._mk([
            {"remote_ip": "api.typesafe.ai", "remote_port": 443, "pid": 1},
            {"remote_ip": "8.8.8.8", "remote_port": 53, "pid": 2},
        ])
        m._cycle()
        events = store.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["process"], "pid:1")
        self._cleanup(tmp, store)

    def test_extra_host_match(self):
        tmp, store, m = self._mk([{"remote_ip": "10.9.8.7", "remote_port": 443, "pid": 5}])
        m.extra_hosts = ["10.9.8.7"]
        m._cycle()
        events = store.list_events()
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["catalog_domain"].startswith("extra:"))
        self._cleanup(tmp, store)

    def test_udp_endpoints_parsed_and_stored(self):
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        m = mon.NetMonitor(store, poll_fn=lambda: [], pidmap_fn=lambda: {},
                           dns_fn=lambda: {})
        with mock.patch.object(mon, "_run_ps",
                               return_value='{"RemoteAddress":"10.0.0.9",'
                                           '"RemotePort":443,"OwningProcess":3}'):
            conns = mon.poll_udp_endpoints()
        self.assertEqual(conns[0]["protocol"], "udp")
        m._catalog_ip_cache = {"10.0.0.9": "deepseek.com"}
        m._cycle(conns)
        ev = store.list_events()[0]
        self.assertEqual(ev["protocol"], "udp")
        self._cleanup(tmp, store)

    def test_pidmap_used_when_present(self):
        tmp, store, m = self._mk([{"remote_ip": "api.groq.com", "remote_port": 443, "pid": 7}])
        m._pidmap_cache = {7: "ollama.exe"}
        m._cycle()
        self.assertEqual(store.list_events()[0]["process"], "ollama.exe")
        self._cleanup(tmp, store)


class TestDnsCacheAndCatalogViaDns(unittest.TestCase):
    def test_parse_win10_format(self):
        out = (
            "   DNS Address . . . . . . . . . . : api.openai.com\n"
            "   Addresses: 1.2.3.4\n"
            "   TTL is 300\n"
            "   DNS Address . . . . . . . . . . : example.org\n"
            "   Addresses: 5.6.7.8\n"
        )
        with mock.patch.object(mon, "_run_ps", return_value=out):
            dns = mon.poll_dns_cache()
        self.assertEqual(dns.get("1.2.3.4"), "api.openai.com")
        self.assertEqual(dns.get("5.6.7.8"), "example.org")

    def test_parse_win7_format(self):
        out = (
            "Name is        : api.groq.com\n"
            "Address        : 9.9.9.9\n"
        )
        with mock.patch.object(mon, "_run_ps", return_value=out):
            dns = mon.poll_dns_cache()
        self.assertEqual(dns.get("9.9.9.9"), "api.groq.com")

    def test_parse_spanish_format(self):
        out = (
            "    api.deepseek.com\n"
            "    ----------------------------------------\n"
            "    Nombre de registro  . : d3bbv8sr76az5s.cloudfront.net\n"
            "    Tipo de registro  . . : 1\n"
            "    Longitud de datos . . : 4\n"
            "    Un registro (host). . : 3.173.21.63\n"
        )
        with mock.patch.object(mon, "_run_ps", return_value=out):
            dns = mon.poll_dns_cache()
        self.assertEqual(dns.get("3.173.21.63"), "d3bbv8sr76az5s.cloudfront.net")

    def test_catalog_match_via_active_ip_map_cname(self):
        """Caso real: api.deepseek.com -> CNAME cloudfront; la caché DNS no
        ayuda, pero el mapa IP activo del catalogo si."""
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        m = mon.NetMonitor(store, poll_fn=lambda: [
            {"remote_ip": "3.173.21.63", "remote_port": 443, "pid": 1}],
            pidmap_fn=lambda: {}, dns_fn=lambda: {})
        m._dns_cache = {"3.173.21.63": "d3bbv8sr76az5s.cloudfront.net"}
        m._catalog_ip_cache = {"3.173.21.63": "deepseek.com"}
        m._cycle()
        events = store.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["catalog_domain"], "deepseek.com")
        self.assertEqual(events[0]["dest_host"], "d3bbv8sr76az5s.cloudfront.net")
        store.close()
        tmp.cleanup()

    def test_catalog_match_via_dns(self):
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        m = mon.NetMonitor(store, poll_fn=lambda: [
            {"remote_ip": "1.2.3.4", "remote_port": 443, "pid": 1}],
            pidmap_fn=lambda: {}, dns_fn=lambda: {})
        m._dns_cache = {"1.2.3.4": "api.openai.com"}
        m._cycle()
        events = store.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["catalog_domain"], "openai.com")
        store.close()
        tmp.cleanup()


class TestJevTriage(unittest.TestCase):
    def test_skipped(self):
        r = jev_triage.triage_events([], "k")
        self.assertEqual(r["status"], "skipped")
        r = jev_triage.triage_events([{"process": "a"}], "")
        self.assertEqual(r["status"], "skipped")

    def test_ok_maps_and_derives_prob_fp(self):
        answers = {
            "f0_class": {"choice": "expected_ai_use", "confidence": 0.95},
            "f0_sev": {"score": 0}, "f0_act": {"noul": 0.1},
            "f1_class": {"choice": "background_exfil_suspect", "confidence": 0.8},
            "f1_sev": {"score": 3}, "f1_act": {"noul": 0.9},
        }
        with mock.patch.object(jev_triage, "_http_post_json",
                               return_value={"model": "jev-1.13.0", "answers": answers}):
            r = jev_triage.triage_events([{"process": "a"}, {"process": "b"}], "k")
        self.assertEqual(r["status"], "ok")
        v0 = r["verdicts"]["0"]
        v1 = r["verdicts"]["1"]
        self.assertEqual(v0["prob_false_positive"], 0.05)
        self.assertEqual(v1["prob_false_positive"], 0.8)
        self.assertEqual(v1["severity_score"], 3)

    def test_error_on_network_failure(self):
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=OSError("boom")):
            r = jev_triage.triage_events([{"process": "a"}], "k")
        self.assertEqual(r["status"], "error")

    def test_cap(self):
        calls = {}
        def fake(url, body, key, timeout=30):
            calls["n"] = len(body["state"])
            return {"model": "jev-1.13.0", "answers": {}}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            jev_triage.triage_events([{"process": f"p{i}"} for i in range(80)], "k")
        self.assertEqual(calls["n"], jev_triage.TRIAGE_CAP)


class TestLlmLocal(unittest.TestCase):
    def test_loopback(self):
        self.assertTrue(llm_local.is_loopback_url("http://127.0.0.1:8099"))
        self.assertTrue(llm_local.is_loopback_url("http://localhost:1/v1"))
        self.assertFalse(llm_local.is_loopback_url("http://example.com"))

    def test_explain_parses_spanish_json(self):
        content = json.dumps({"resumen": "R.", "porque": "P.", "sugerencia": "S."})
        with mock.patch.object(llm_local, "_chat", return_value=content):
            out = llm_local.explain_events("http://127.0.0.1:8099", "dirk",
                                           [{"process": "a.exe", "dest_ip": "1.1.1.1",
                                             "dest_port": 443}])
        self.assertEqual(out[0]["status"], "ok")
        self.assertEqual(out[0]["resumen"], "R.")

    def test_explain_unparseable(self):
        with mock.patch.object(llm_local, "_chat", return_value="no es json"):
            out = llm_local.explain_events("http://127.0.0.1:8099", "dirk",
                                           [{"process": "a.exe", "dest_ip": "1.1.1.1",
                                             "dest_port": 443}])
        self.assertEqual(out[0]["status"], "unavailable")

    def test_non_loopback_refused(self):
        out = llm_local.explain_events("http://example.com", "dirk",
                                       [{"process": "a"}])
        self.assertEqual(out[0]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
