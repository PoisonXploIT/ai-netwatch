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
import ai_classifier  # noqa: E402
import sysmon_source  # noqa: E402
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

    def test_prune_removes_old_keeps_recent(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, "openai.com", None)
        self.store.save_triage("ok", "m", {"x": 1})
        old = "2020-01-01 00:00:00Z"
        with self.store._lock:
            self.store.conn.execute(
                "UPDATE events SET ts=?, last_seen=? WHERE process='a.exe'",
                (old, old))
            self.store.conn.execute("UPDATE triages SET ts=?", (old,))
        out = self.store.prune(90)
        self.assertEqual(out["events_removed"], 1)
        self.assertEqual(out["triages_removed"], 1)
        self.assertEqual(self.store.list_events(), [])

    def test_prune_keeps_recent_events(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443, "openai.com", None)
        out = self.store.prune(90)
        self.assertEqual(out["events_removed"], 0)
        self.assertEqual(len(self.store.list_events()), 1)

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

    @staticmethod
    def _answers_for(qids):
        answers = {}
        for qid in qids:
            if qid.endswith("_class"):
                answers[qid] = {"choice": "expected_ai_use", "confidence": 0.9}
            elif qid.endswith("_sev"):
                answers[qid] = {"score": 1}
            else:
                answers[qid] = {"noul": 0.2}
        return answers

    def test_chunked_fallback_merges(self):
        def fake(url, body, key, timeout=30):
            qs = list(body["questions"].keys())
            if len(qs) > 30:  # llamada completa (25 eventos) -> falla
                raise RuntimeError("HTTP 422: detail")
            return {"model": "jev-1.13.0",
                    "answers": self._answers_for(qs)}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events(
                [{"process": f"p{i}"} for i in range(25)], "k")
        self.assertEqual(r["status"], "ok")
        self.assertFalse(r["partial"])
        self.assertEqual(len(r["verdicts"]), 25)

    def test_partial_when_chunk_fails(self):
        def fake(url, body, key, timeout=30):
            qs = list(body["questions"].keys())
            if len(qs) > 30:
                raise RuntimeError("HTTP 422")
            first = int(list(qs)[0][1:].split("_")[0])
            if first >= 10:  # segundo chunk muere
                raise RuntimeError("HTTP 500")
            return {"model": "jev-1.13.0",
                    "answers": self._answers_for(qs)}
        with mock.patch.object(jev_triage, "_http_post_json", side_effect=fake):
            r = jev_triage.triage_events(
                [{"process": f"p{i}"} for i in range(20)], "k")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["partial"])
        self.assertIsNone(r["verdicts"]["15"]["verdict"])

    def test_http_error_body_captured(self):
        import io
        import urllib.error
        detail = b'{"detail":[{"msg":"Input should be a valid dictionary"}]}'
        err = urllib.error.HTTPError("u", 422, "Unprocessable Entity",
                                     {}, io.BytesIO(detail))
        with mock.patch.object(jev_triage.urllib.request, "urlopen",
                               side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                jev_triage._http_post_json("https://x", {"a": 1}, "k")
        self.assertIn("422", str(ctx.exception))
        self.assertIn("valid dictionary", str(ctx.exception))

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

    def test_chat_rejects_relative_or_empty_url(self):
        for bad in ("", "/v1", "localhost:8099"):
            with self.assertRaises(ValueError):
                llm_local._chat(bad, "dirk", "s", "u")


_XML1 = (

        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>3</EventID></System>"
        "<EventData>"
        "<Data Name='RuleName'>Usermode</Data>"
        "<Data Name='UtcTime'>2026-09-22 07:34:55.655</Data>"
        "<Data Name='ProcessId'>17312</Data>"
        "<Data Name='Image'>C:\\Users\\Sammi\\AppData\\Local\\python.exe</Data>"
        "<Data Name='Protocol'>udp</Data>"
        "<Data Name='DestinationIp'>192.168.5.255</Data>"
        "<Data Name='DestinationPort'>21027</Data>"
        "</EventData></Event>"
)
_XML2 = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>3</EventID></System>"
        "<EventData>"
        "<Data Name='UtcTime'>2026-09-22 07:34:56.000</Data>"
        "<Data Name='ProcessId'>21240</Data>"
        "<Data Name='Image'>C:\\Program Files\\Python312\\python.exe</Data>"
        "<Data Name='Protocol'>TCP</Data>"
        "<Data Name='DestinationIp'>3.173.21.63</Data>"
        "<Data Name='DestinationPort'>443</Data>"
        "</EventData></Event>"
)
_SAMPLE_STR = json.dumps([
    {"RecordId": "100", "Xml": _XML1},
    {"RecordId": "101", "Xml": _XML2},
])


class TestSysmonSource(unittest.TestCase):
    SAMPLE = _SAMPLE_STR

    def test_parse_v15_fields(self):
        with mock.patch.object(sysmon_source, "_run_ps", return_value=self.SAMPLE):
            evs = sysmon_source.poll_sysmon_events()
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0]["record_id"], 100)
        self.assertEqual(evs[0]["protocol"], "udp")
        self.assertEqual(evs[1]["dest_ip"], "3.173.21.63")
        self.assertTrue(evs[1]["image"].endswith("python.exe"))

    def test_single_object_quirk(self):
        one = json.loads(self.SAMPLE)[0]
        with mock.patch.object(sysmon_source, "_run_ps",
                               return_value=json.dumps(one)):
            evs = sysmon_source.poll_sysmon_events()
        self.assertEqual(len(evs), 1)

    def test_xml_fields_parsed(self):
        f = sysmon_source._xml_fields(_XML2)
        self.assertEqual(f["DestinationIp"], "3.173.21.63")
        self.assertEqual(f["Protocol"], "TCP")
        self.assertTrue(f["Image"].endswith("python.exe"))
        self.assertEqual(sysmon_source._xml_fields("no-xml"), {})
        self.assertEqual(sysmon_source._xml_fields(""), {})

    def test_empty_and_garbage(self):
        with mock.patch.object(sysmon_source, "_run_ps", return_value=""):
            self.assertEqual(sysmon_source.poll_sysmon_events(), [])
        with mock.patch.object(sysmon_source, "_run_ps", return_value="no-json"):
            self.assertEqual(sysmon_source.poll_sysmon_events(), [])

    def test_available(self):
        with mock.patch.object(sysmon_source, "_run_ps", return_value="1\n"):
            self.assertTrue(sysmon_source.sysmon_available())
        with mock.patch.object(sysmon_source, "_run_ps", return_value="0\n"):
            self.assertFalse(sysmon_source.sysmon_available())


class TestMonitorSysmon(unittest.TestCase):
    def _mk(self, tmp, events_by_call):
        store = Store(Path(tmp.name) / "t.db")
        m = mon.NetMonitor(store, poll_fn=lambda: [], pidmap_fn=lambda: {},
                           dns_fn=lambda: {},
                           sysmon_fn=lambda: events_by_call.pop(0))
        return store, m

    def test_watermark_no_backfill_then_store(self):
        tmp = tempfile.TemporaryDirectory()
        ev1 = [{"record_id": 50, "ts": "t", "image": r"C:\x\python.exe",
                "protocol": "tcp", "dest_ip": "3.173.21.63",
                "dest_port": 443, "pid": 1}]
        ev2 = [{"record_id": 50, "ts": "t", "image": r"C:\x\python.exe",
                "protocol": "tcp", "dest_ip": "3.173.21.63",
                "dest_port": 443, "pid": 1}]
        ev3 = [{"record_id": 50, "ts": "t", "image": r"C:\x\python.exe",
                "protocol": "tcp", "dest_ip": "3.173.21.63",
                "dest_port": 443, "pid": 1},
               {"record_id": 51, "ts": "t", "image": r"C:\y\curl.exe",
                "protocol": "tcp", "dest_ip": "3.173.21.63",
                "dest_port": 443, "pid": 2}]
        store, m = self._mk(tmp, [ev1, ev2, ev3])
        m._catalog_ip_cache = {"3.173.21.63": "deepseek.com"}
        m._sysmon_cycle()  # primera: fija watermark, sin backfill
        self.assertEqual(len(store.list_events()), 0)
        m._sysmon_cycle()  # mismo max -> nada nuevo
        self.assertEqual(len(store.list_events()), 0)
        m._sysmon_cycle()  # llega el 51
        events = store.list_events()
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["process"], "curl.exe")  # basename de Image
        self.assertEqual(e["image"], r"C:\y\curl.exe")
        self.assertEqual(e["catalog_domain"], "deepseek.com")
        self._cleanup(tmp, store)

    def _cleanup(self, tmp, store):
        store.close()
        tmp.cleanup()


class TestClassifier(unittest.TestCase):
    def test_catalog_layer(self):
        c = ai_classifier.classify_domain("eu.api.anthropic.com")
        self.assertTrue(c.is_ai)
        self.assertEqual(c.layer, "catalog")
        self.assertEqual(c.provider, "anthropic.com")
        self.assertEqual(c.confidence, 1.0)

    def test_heuristic_tld_and_token(self):
        c = ai_classifier.classify_domain("api.brandnew.ai")
        self.assertTrue(c.is_ai)
        self.assertEqual(c.layer, "heuristic")
        self.assertEqual(c.confidence, 0.5)
        c2 = ai_classifier.classify_domain("inference.internal-corp.com")
        self.assertEqual(c2.layer, "heuristic")  # token 'inference'

    def test_unlisted(self):
        c = ai_classifier.classify_domain("example.com")
        self.assertFalse(c.is_ai)
        self.assertEqual(c.layer, "unlisted")

    def test_llm_layer_with_cache(self):
        calls = []

        def llm(d):
            calls.append(d)
            return d == "internal-corp.example.net"

        cache = {}
        c1 = ai_classifier.classify_domain(
            "internal-corp.example.net", llm_fn=llm, cache=cache)
        self.assertEqual(c1.layer, "llm")
        self.assertTrue(c1.is_ai)
        n = len(calls)
        c2 = ai_classifier.classify_domain(
            "internal-corp.example.net", llm_fn=llm, cache=cache)
        self.assertEqual(len(calls), n)  # cache: sin nueva llamada al LLM
        self.assertEqual(c2.layer, "llm")

    def test_llm_failsafe_on_exception(self):
        def bad(d):
            raise RuntimeError("boom")

        c = ai_classifier.classify_domain(
            "weird-corp.example.net", llm_fn=bad)
        self.assertFalse(c.is_ai)  # el fallo no rompe ni afirma
        self.assertEqual(c.layer, "unlisted")

    def test_empty(self):
        c = ai_classifier.classify_domain("")
        self.assertFalse(c.is_ai)
        self.assertEqual(c.layer, "unlisted")


class TestEid22Join(unittest.TestCase):
    def _mk(self):
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        return tmp, store

    def test_eid22_ai_domain_stored_when_unlisted_catalog(self):
        tmp, store = self._mk()
        m = mon.NetMonitor(store, poll_fn=lambda: [], pidmap_fn=lambda: {},
                           dns_fn=lambda: {}, eid22_fn=lambda: [
                               {"record_id": 1, "ts": "t",
                                "image": r"C:\x\ollama.exe", "pid": 9,
                                "query_name": "api.somenewprovider.ai",
                                "ips": ["93.184.216.34"]}])
        m._eid22_cycle()
        # Conexion a esa IP sin catalogo/dns/extra: solo EID22 la clasifica.
        m._cycle([{"remote_ip": "93.184.216.34", "remote_port": 443, "pid": 9}])
        events = store.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["catalog_domain"], "api.somenewprovider.ai")
        self.assertEqual(events[0]["ai_layer"], "heuristic")  # TLD .ai
        store.close()
        tmp.cleanup()

    def test_eid22_non_ai_not_stored(self):
        tmp, store = self._mk()
        m = mon.NetMonitor(store, poll_fn=lambda: [], pidmap_fn=lambda: {},
                           dns_fn=lambda: {}, eid22_fn=lambda: [
                               {"record_id": 1, "ts": "t",
                                "image": r"C:\x\chrome.exe", "pid": 3,
                                "query_name": "github.com",
                                "ips": ["140.82.112.6"]}])
        m._eid22_cycle()
        m._cycle([{"remote_ip": "140.82.112.6", "remote_port": 443, "pid": 3}])
        self.assertEqual(len(store.list_events()), 0)  # no-IA: no inundar
        store.close()
        tmp.cleanup()

    def test_eid22_cycle_builds_ip_map(self):
        tmp, store = self._mk()
        m = mon.NetMonitor(store, poll_fn=lambda: [], pidmap_fn=lambda: {},
                           dns_fn=lambda: {}, eid22_fn=lambda: [
                               {"record_id": 1, "ts": "t", "image": "",
                                "pid": 1, "query_name": "a.ai",
                                "ips": ["1.1.1.1"]},
                               {"record_id": 2, "ts": "t", "image": "",
                                "pid": 1, "query_name": "b.ai",
                                "ips": ["2.2.2.2"]}])
        m._eid22_cycle()
        self.assertEqual(m._eid22_cache["1.1.1.1"], "a.ai")
        self.assertEqual(m._eid22_cache["2.2.2.2"], "b.ai")
        store.close()
        tmp.cleanup()


class TestPollSysmonDns(unittest.TestCase):
    def test_parse_query_results(self):
        ips = sysmon_source._parse_query_results(
            "2606:50c0::1;::ffff:185.199.110.133;; 185.199.108.133")
        self.assertEqual(ips, ["2606:50c0::1", "185.199.110.133",
                               "185.199.108.133"])

    def test_poll_dns_events(self):
        xml = (
            "<Event><EventData>"
            "<Data Name='ProcessId'>18872</Data>"
            "<Data Name='QueryName'>raw.githubusercontent.com</Data>"
            "<Data Name='Image'>C:\\Obsidian\\Obsidian.exe</Data>"
            "<Data Name='UtcTime'>2026-09-23 07:39:17.084</Data>"
            "<Data Name='QueryResults'>::ffff:185.199.110.133;</Data>"
            "</EventData></Event>")
        sample = json.dumps([{"RecordId": "15962372", "Xml": xml}])
        with mock.patch.object(sysmon_source, "_run_ps", return_value=sample):
            evs = sysmon_source.poll_sysmon_dns()
        self.assertEqual(len(evs), 1)
        e = evs[0]
        self.assertEqual(e["record_id"], 15962372)
        self.assertEqual(e["query_name"], "raw.githubusercontent.com")
        self.assertEqual(e["pid"], 18872)
        self.assertTrue(e["image"].endswith("Obsidian.exe"))
        self.assertEqual(e["ips"], ["185.199.110.133"])

    def test_empty_and_garbage(self):
        with mock.patch.object(sysmon_source, "_run_ps", return_value=""):
            self.assertEqual(sysmon_source.poll_sysmon_dns(), [])
        with mock.patch.object(sysmon_source, "_run_ps",
                               return_value="no-json"):
            self.assertEqual(sysmon_source.poll_sysmon_dns(), [])


if __name__ == "__main__":
    unittest.main()
