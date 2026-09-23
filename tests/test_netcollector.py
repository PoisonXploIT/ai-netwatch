"""Tests v2.2: bytes remotos (colector elevado ETW Kernel-Network).

- parse_xml con el ESQUEMA REAL de tracerpt -of XML (<Event> con
  <System><Task>/<EventID> y <EventData><Data Name=...>), inmune a
  namespaces: solo copia de datos (TCP 10/18/26/27/34, UDP 11), size>0,
  sin loopback, sin DNS (dport 53).
- aggregate: suma por (dest_ip, dest_port).
- store.ingest_net_bytes: acumula entre ciclos; net_bytes_sum ordenado;
  reset limpia.
- Dashboard: cloud_bytes disponible con datos, 'no disponible' sin ellos.
- Regla egress: dispara sobre umbral a no aprobados, no a aprobados.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ai_classifier as classifier  # noqa: E402
import alerts  # noqa: E402
import monitor as monitor_mod  # noqa: E402
import netcollector  # noqa: E402
import rules  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402

# Esquema REAL de tracerpt -of XML (verificado contra un trace de 71
# eventos): <Event> con <System><Task>/<EventID> y <EventData><Data
# Name=...>. El ultimo evento va namespaced a proposito: el parser debe
# ser inmune a namespaces.
XML_SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<TraceEvents>
  <Event name="TCPEDataCopy">
    <System>
      <ProviderGuid>{6814A424-D860-11D3-9981-00C04F7958C2}</ProviderGuid>
      <Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">10</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">438</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
      <Data Name="sport">51000</Data><Data Name="dport">443</Data>
    </EventData>
  </Event>
  <Event name="TCPEDataCopy">
    <System>
      <Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">18</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">1360</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
      <Data Name="sport">51000</Data><Data Name="dport">443</Data>
    </EventData>
  </Event>
  <Event name="TCPEConnect">
    <System>
      <Task Name="TCPIP">12</Task>
      <EventID Name="TCPEConnect">12</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">0</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
      <Data Name="sport">51000</Data><Data Name="dport">443</Data>
    </EventData>
  </Event>
  <Event name="TCPEDataCopy">
    <System>
      <Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">26</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">999</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">127.0.0.1</Data>
      <Data Name="sport">51001</Data><Data Name="dport">8080</Data>
    </EventData>
  </Event>
  <Event name="TCPEDataCopy">
    <System>
      <Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">27</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">29</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">8.8.8.8</Data>
      <Data Name="sport">53000</Data><Data Name="dport">53</Data>
    </EventData>
  </Event>
  <Event name="UDPIPDataCopy">
    <System>
      <Task Name="UDPIP">11</Task>
      <EventID Name="UDPIPDataCopy">11</EventID>
    </System>
    <EventData>
      <Data Name="PID">20184</Data><Data Name="size">512</Data>
      <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">5.6.7.8</Data>
      <Data Name="sport">53001</Data><Data Name="dport">5300</Data>
    </EventData>
  </Event>
  <ns:Event name="TCPEDataCopy" xmlns:ns="urn:test">
    <ns:System>
      <ns:Task Name="TCPIP">10</ns:Task>
      <ns:EventID Name="TCPEDataCopy">26</ns:EventID>
    </ns:System>
    <ns:EventData>
      <ns:Data Name="PID">777</ns:Data><ns:Data Name="size">11</ns:Data>
      <ns:Data Name="saddr">192.168.1.50</ns:Data>
      <ns:Data Name="daddr">9.8.7.6</ns:Data>
      <ns:Data Name="sport">51002</ns:Data><ns:Data Name="dport">443</ns:Data>
    </ns:EventData>
  </ns:Event>
</TraceEvents>
"""


class TestParseXml(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "t.xml"
        self.path.write_text(XML_SAMPLE, encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_only_data_events_with_size(self):
        rows = netcollector.parse_xml(self.path)
        # TCP data 438+1360 (mismo destino), UDP 512, namespaced 11;
        # connect/loopback/DNS fuera.
        self.assertEqual(
            sorted((r["dest_ip"], r["dest_port"], r["bytes"])
                   for r in rows),
            [("1.2.3.4", 443, 438), ("1.2.3.4", 443, 1360),
             ("5.6.7.8", 5300, 512), ("9.8.7.6", 443, 11)])

    def test_pids_kept(self):
        rows = netcollector.parse_xml(self.path)
        self.assertEqual(
            sorted(r["pid"] for r in rows), [777, 20184, 20184, 20184])

    def test_stats_distinguish_ran_from_failed(self):
        rows, stats = netcollector.parse_xml_with_stats(self.path)
        self.assertEqual(len(rows), 4)
        # 7 <Event> vistos; 4 filas tras filtros.
        self.assertEqual(stats["events_seen"], 7)
        self.assertEqual(stats["rows"], 4)
        self.assertTrue(stats["xml_ok"])

    def test_write_jsonl_includes_meta_line(self):
        out = Path(self.tmp.name) / "o.jsonl"
        netcollector.write_jsonl(
            out, [{"dest_ip": "1.2.3.4", "dest_port": 443,
                   "bytes": 5}],
            {"events_seen": 7, "rows": 1, "xml_ok": True,
             "etl_found": True})
        lines = [json.loads(l) for l in
                out.read_text(encoding="utf-8").splitlines() if l]
        self.assertEqual(len(lines), 2)
        self.assertIn("meta", lines[-1])

    def test_missing_file_empty(self):
        self.assertEqual(
            netcollector.parse_xml(Path(self.tmp.name) / "nope.xml"), [])


class TestAggregate(unittest.TestCase):
    def test_sums_per_dest(self):
        rows = [{"pid": 1, "dest_ip": "1.2.3.4", "dest_port": 443,
                 "bytes": 10},
                {"pid": 2, "dest_ip": "1.2.3.4", "dest_port": 443,
                 "bytes": 5},
                {"pid": 1, "dest_ip": "9.9.9.9", "dest_port": 8443,
                 "bytes": 7}]
        agg = netcollector.aggregate(rows)
        self.assertEqual(agg[("1.2.3.4", 443)], 15)
        self.assertEqual(agg[("9.9.9.9", 8443)], 7)


class NetBytesServerBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.log = alerts.AlertLog(Path(self.tmp.name) / "alerts.log")
        self._old = {k: getattr(server, k)
                     for k in ("store", "_cfg", "CONFIG_PATH", "alerts",
                               "DATA_DIR")}
        self._old_meta = server._net_last_meta
        server.store = self.store
        server.alerts = self.log
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server.DATA_DIR = Path(self.tmp.name) / "data"
        server.DATA_DIR.mkdir()
        server._cfg = {"catalog_approved": True,
                       "approved_providers": [],
                       "alerts_enabled": True,
                       "rules_enabled": True,
                       "rule_egress_mb_per_day": 500.0}
        server._net_last_meta = None
        server._rules_alerted.clear()

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        server._net_last_meta = self._old_meta
        self.store.close()
        self.tmp.cleanup()


class TestSpawnNetCollector(NetBytesServerBase):
    """v2.2.1: spawn por tarea programada (sin prompt) o fallback UAC."""

    def test_task_path_writes_cmd_and_runs_schtasks(self):
        outp = Path(self.tmp.name) / "o.jsonl"
        with mock.patch.object(
                 server, "_netbytes_task_exists", return_value=True), \
             mock.patch("subprocess.run") as run_mock:
            method = server._spawn_netcollector(30, outp)
        self.assertEqual(method, "task")
        args = run_mock.call_args[0][0]
        self.assertEqual(args[:2], ["schtasks", "/run"])
        self.assertIn(server.NETBYTES_TASK_NAME, args)
        cmd = json.loads(server._netbytes_cmd_file()
                         .read_text(encoding="utf-8"))
        self.assertEqual(cmd["duration_s"], 30)
        self.assertEqual(cmd["out_path"], str(outp))
        self.assertTrue(cmd["script"].endswith("netcollector.py"))

    def test_uac_fallback_when_no_task(self):
        outp = Path(self.tmp.name) / "o.jsonl"
        with mock.patch.object(
                 server, "_netbytes_task_exists", return_value=False), \
             mock.patch("subprocess.Popen") as popen_mock:
            method = server._spawn_netcollector(30, outp)
        self.assertEqual(method, "uac")
        argv = popen_mock.call_args[0][0]
        self.assertIn("-Verb RunAs", argv[-1])
        # El cmd file solo se escribe en el camino de tarea.
        self.assertFalse(server._netbytes_cmd_file().exists())

    def test_write_netbytes_cmd_contents(self):
        outp = Path(self.tmp.name) / "o.jsonl"
        server._write_netbytes_cmd(45, outp)
        cmd = json.loads(server._netbytes_cmd_file()
                         .read_text(encoding="utf-8"))
        self.assertEqual(cmd["duration_s"], 45)
        self.assertEqual(cmd["out_path"], str(outp))
        self.assertIn("python", cmd["python"])

    def test_netbytes_log_appends(self):
        server._netbytes_log("ciclo inicio dur=30s tarea=si")
        server._netbytes_log("spawn task")
        lines = (server.DATA_DIR / "netbytes.log").read_text(
            encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("ciclo inicio", lines[0])
        self.assertIn("spawn task", lines[1])


class TestConfigPersistence(NetBytesServerBase):
    """Regresion v2.2.1: las claves de v2.1/v2.2 debían sobrevivir un
    restart (_load_config). Antes del fix, _load_config no las cargaba:
    POST enabled=true + watchdog/restart => revertia a false y el
    colector nunca disparaba (spawn_method=null)."""

    def _reload(self, payload: dict) -> None:
        server.CONFIG_PATH.write_text(json.dumps(payload),
                                       encoding="utf-8")
        server._cfg = {}
        server._load_config()

    def test_v22_keys_survive_restart(self):
        self._reload({"net_bytes_enabled": True,
                      "net_bytes_duration_s": 45,
                      "net_bytes_cycle_s": 120,
                      "rules_enabled": False,
                      "rule_egress_mb_per_day": 42})
        self.assertIs(server._cfg["net_bytes_enabled"], True)
        self.assertEqual(server._cfg["net_bytes_duration_s"], 45)
        self.assertEqual(server._cfg["net_bytes_cycle_s"], 120)
        self.assertIs(server._cfg["rules_enabled"], False)
        self.assertEqual(server._cfg["rule_egress_mb_per_day"], 42)

    def test_bad_values_fall_to_defaults(self):
        self._reload({"net_bytes_enabled": "banana",
                      "net_bytes_duration_s": -5,
                      "net_bytes_cycle_s": "x",
                      "rules_enabled": 3,
                      "rule_egress_mb_per_day": -1})
        self.assertIs(server._cfg["net_bytes_enabled"], False)
        self.assertEqual(server._cfg["net_bytes_duration_s"], 30)
        self.assertEqual(server._cfg["net_bytes_cycle_s"], 600)
        self.assertIs(server._cfg["rules_enabled"], True)
        self.assertEqual(server._cfg["rule_egress_mb_per_day"], 500.0)

    def test_post_then_reload_via_endpoint(self):
        # Flujo exacto: POST /api/config => restart (_load_config).
        server.set_config(server.ConfigRequest(
            net_bytes_enabled=True, rule_egress_mb_per_day=42))
        server._cfg = {}
        server._load_config()
        self.assertIs(server._cfg["net_bytes_enabled"], True)
        self.assertEqual(server._cfg["rule_egress_mb_per_day"], 42)


class TestTaskScripts(unittest.TestCase):
    """Los scripts de la tarea programada existen y son coherentes."""

    def test_wrapper_and_setup_exist(self):
        root = Path(__file__).resolve().parent.parent
        w = (root / "netcollector_task.ps1").read_text(encoding="utf-8")
        s = (root / "setup_netbytes_task.ps1").read_text(encoding="utf-8")
        self.assertIn("netcollector_cmd.json", w)
        self.assertIn(server.NETBYTES_TASK_NAME, s)
        self.assertIn("RunLevel Highest", s)

    def test_setup_uses_valid_settings_params(self):
        # Regresion: los 3 parametros invalidos que rompian el registro
        # (AllowStartOnDemand / MultipleInstancePolicy / StartWhenAvailable
        # como valorado) no pueden volver.
        root = Path(__file__).resolve().parent.parent
        s = (root / "setup_netbytes_task.ps1").read_text(encoding="utf-8")
        self.assertNotIn("AllowStartOnDemand", s)
        self.assertNotIn("MultipleInstancePolicy", s)
        self.assertNotIn("-StartWhenAvailable $false", s)
        self.assertIn("-MultipleInstances IgnoreNew", s)


class TestNetBytesStore(NetBytesServerBase):
    def test_ingest_accumulates_across_cycles(self):
        n = self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 100}],
            "2026-09-23T10:00:00")
        self.assertEqual(n, 1)
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 50},
             {"dest_ip": "9.9.9.9", "dest_port": 8443, "bytes": 10}],
            "2026-09-23T10:10:00")
        out = self.store.net_bytes_sum()
        self.assertEqual(out[0]["dest_ip"], "1.2.3.4")
        self.assertEqual(out[0]["bytes"], 150)
        self.assertEqual(out[1]["bytes"], 10)

    def test_ingest_ignores_bad_rows(self):
        n = self.store.ingest_net_bytes(
            [{"dest_ip": "", "dest_port": 443, "bytes": 5},
             {"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": -1},
             {"dest_port": 443}],
            "2026-09-23T10:00:00")
        self.assertEqual(n, 0)

    def test_reset_clears_net_bytes(self):
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 100}],
            "2026-09-23T10:00:00")
        self.store.reset()
        self.assertEqual(self.store.net_bytes_sum(), [])


class TestReadNetJsonl(NetBytesServerBase):
    def test_meta_line_not_ingested_as_bytes(self):
        p = Path(self.tmp.name) / "c.jsonl"
        p.write_text(
            '{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 7}\n'
            '{"meta": {"events_seen": 3, "rows": 1, "xml_ok": true,'
            ' "etl_found": true}}\n',
            encoding="utf-8")
        rows, meta = server._read_netjsonl(p)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bytes"], 7)
        self.assertEqual(meta["events_seen"], 3)

    def test_last_meta_shown_in_dashboard(self):
        server._net_last_meta = {"events_seen": 805, "rows": 225,
                                 "xml_ok": True, "etl_found": True}
        out = server.dashboard(days=7)
        self.assertEqual(
            out["cloud_bytes"]["last_meta"]["events_seen"], 805)

    def test_spawn_method_exposed(self):
        server._netbytes_spawn_method = "task"
        out = server.dashboard(days=7)
        self.assertEqual(out["cloud_bytes"]["spawn_method"], "task")


class TestDashboardCloudBytes(NetBytesServerBase):
    def test_unavailable_without_data(self):
        out = server.dashboard(days=7)
        self.assertFalse(out["cloud_bytes"]["available"])

    def test_available_with_data(self):
        # IP mapeada a proveedor via evento.
        self.store.observe_connection("svc.exe", "1.2.3.4", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET catalog_domain='deepseek.com'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 123456}],
            "2026-09-23T10:00:00")
        out = server.dashboard(days=7)
        cb = out["cloud_bytes"]
        self.assertTrue(cb["available"])
        self.assertEqual(cb["total_bytes"], 123456)
        self.assertEqual(cb["by_provider"][0]["provider"], "deepseek.com")


class TestEgressRule(NetBytesServerBase):
    def test_fires_over_threshold_unapproved(self):
        # IP sin evento => proveedor 'desconocido' (no aprobado).
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443,
              "bytes": int(600 * 1024 * 1024)}],
            "2026-09-23T10:00:00")
        out = rules.evaluate([], egress_mb_per_day=500.0,
                             egress=server._egress_rows() or None)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["egress_volume_unapproved"]["available"])
        self.assertTrue(r["egress_volume_unapproved"]["fired"])

    def test_no_fire_below_threshold(self):
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443, "bytes": 1024}],
            "2026-09-23T10:00:00")
        out = rules.evaluate([], egress_mb_per_day=500.0,
                             egress=server._egress_rows() or None)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["egress_volume_unapproved"]["available"])
        self.assertFalse(r["egress_volume_unapproved"]["fired"])

    def test_no_fire_when_approved(self):
        # deepseek.com esta en el catalogo (aprobado por defecto).
        self.store.observe_connection("svc.exe", "1.2.3.4", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET catalog_domain='deepseek.com'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        self.store.ingest_net_bytes(
            [{"dest_ip": "1.2.3.4", "dest_port": 443,
              "bytes": int(600 * 1024 * 1024)}],
            "2026-09-23T10:00:00")
        out = rules.evaluate([], egress_mb_per_day=500.0,
                             egress=server._egress_rows() or None)
        r = {x["id"]: x for x in out}
        self.assertTrue(r["egress_volume_unapproved"]["available"])
        self.assertFalse(r["egress_volume_unapproved"]["fired"])


class TestByProviderEid22Mapping(NetBytesServerBase):
    """v2.3: by_provider mapea las IPs de net_bytes cruzando TODA la senal
    (eventos + EID 22 en memoria del monitor), no solo los 500 eventos
    recientes. Antes, una IP sin evento salia siempre 'desconocido'."""

    @staticmethod
    def _fake_monitor(m: dict) -> object:
        class _M:
            def eid22_provider_map(self):
                return m
        return _M()

    def test_eid22_maps_ip_without_event(self):
        # IP sin evento alguno: solo la resuelve el EID 22 del monitor.
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        old = server.monitor
        server.monitor = self._fake_monitor({"5.6.7.8": "openai.com"})
        try:
            rows = server._egress_rows()
        finally:
            server.monitor = old
        self.assertEqual(rows[0]["provider"], "openai.com")
        self.assertFalse(rows[0]["unapproved"])  # openai esta en catalogo

    def test_event_wins_over_eid22(self):
        # El evento (SNI/catalogo) es definitivo: gana sobre el EID 22.
        self.store.observe_connection("svc.exe", "5.6.7.8", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET catalog_domain='deepseek.com'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 2000}],
            "2026-09-23T10:00:00")
        old = server.monitor
        server.monitor = self._fake_monitor({"5.6.7.8": "openai.com"})
        try:
            rows = server._egress_rows()
        finally:
            server.monitor = old
        self.assertEqual(rows[0]["provider"], "deepseek.com")

    def test_unresolved_ip_stays_desconocido(self):
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        rows = server._egress_rows()
        self.assertEqual(rows[0]["provider"], "desconocido")
        self.assertTrue(rows[0]["unapproved"])

    def test_persisted_dns_maps_ai_ip(self):
        # v2.3: resolucion EID22 persistida (sin evento, sin monitor vivo)
        # mapea la IP a proveedor IA y el label sale del hostname.
        self.store.record_dns_resolution("5.6.7.8", "openrouter.ai")
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        rows = server._egress_rows()
        self.assertEqual(rows[0]["provider"], "openrouter.ai")
        self.assertEqual(rows[0]["kind"], "api")  # TLD .ai
        self.assertFalse(rows[0]["unapproved"])

    def test_persisted_dns_non_ai_stays_desconocido_with_label(self):
        # v2.3: dominio no-IA resuelto -> provider sigue 'desconocido' (no es
        # proveedor IA) pero el hostname y el label SI se muestran.
        self.store.record_dns_resolution(
            "5.6.7.8", "d3bbv8sr76az5s.cloudfront.net")
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        rows = server._egress_rows()
        self.assertEqual(rows[0]["provider"], "desconocido")
        self.assertEqual(
            rows[0]["host"], "d3bbv8sr76az5s.cloudfront.net")
        self.assertEqual(rows[0]["kind"], "cdn")
        self.assertTrue(rows[0]["unapproved"])

    def test_cloud_bytes_api_exposes_host_and_kind(self):
        # v2.3: la superficie del API (dashboard) expone host y kind, no
        # solo provider/bytes.
        self.store.record_dns_resolution(
            "5.6.7.8", "d3bbv8sr76az5s.cloudfront.net")
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        cb = server._cloud_bytes()
        self.assertTrue(cb["available"])
        row = cb["by_provider"][0]
        self.assertEqual(row["provider"], "desconocido")
        self.assertEqual(
            row["host"], "d3bbv8sr76az5s.cloudfront.net")
        self.assertEqual(row["kind"], "cdn")

    def test_event_wins_over_persisted_dns(self):
        # v2.3: el evento (SNI/catalogo) es definitivo sobre la tabla DNS,
        # tanto para el provider como para el hostname mostrado.
        self.store.record_dns_resolution("5.6.7.8", "openrouter.ai")
        self.store.observe_connection("svc.exe", "5.6.7.8", 443, None, None)
        self.store.conn.execute(
            "UPDATE events SET catalog_domain='deepseek.com'"
            " WHERE process='svc.exe'")
        self.store.conn.commit()
        self.store.ingest_net_bytes(
            [{"dest_ip": "5.6.7.8", "dest_port": 443, "bytes": 1000}],
            "2026-09-23T10:00:00")
        rows = server._egress_rows()
        self.assertEqual(rows[0]["provider"], "deepseek.com")
        self.assertEqual(rows[0]["host"], "deepseek.com")


class TestEid22ProviderMap(unittest.TestCase):
    """Monitor.eid22_provider_map (NetMonitor real): solo expone dominios
    clasificados IA; el resto no se atribuye a ningun proveedor."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self.m = monitor_mod.NetMonitor(self.store)
        self.m._eid22_cache = {
            "1.1.1.1": "api.openai.com",
            "2.2.2.2": "example.com",
            "3.3.3.3": "huggingface.co",
        }

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_only_ai_domains_exposed(self):
        m = self.m.eid22_provider_map()
        self.assertEqual(m.get("1.1.1.1"), "api.openai.com")
        self.assertEqual(m.get("3.3.3.3"), "huggingface.co")
        self.assertNotIn("2.2.2.2", m)

    def test_cycle_persists_resolutions(self):
        # v2.3: el ciclo EID 22 persiste ip->dominio (cualquier dominio) en
        # dns_resolutions, para que sobreviva el restart y cierre el hueco
        # 'desconocido' de net_bytes.
        evs = [
            {"query_name": "api.openai.com", "ips": ["9.9.9.9"]},
            {"query_name": "example.com", "ips": ["8.8.4.4"]},
        ]
        m2 = monitor_mod.NetMonitor(self.store, eid22_fn=lambda: evs)
        m2._eid22_cycle()
        d = self.store.dns_resolution_map()
        self.assertEqual(d.get("9.9.9.9"), "api.openai.com")
        self.assertEqual(d.get("8.8.4.4"), "example.com")  # no-IA tambien


class TestDnsResolutionsStore(unittest.TestCase):
    """v2.3: store.dns_resolutions (ip->dominio, el mas reciente gana)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_upsert_latest_wins(self):
        self.store.record_dns_resolution("1.2.3.4", "a.com")
        self.store.record_dns_resolution("1.2.3.4", "b.com")
        self.assertEqual(
            self.store.dns_resolution_map().get("1.2.3.4"), "b.com")

    def test_blank_ignored(self):
        self.store.record_dns_resolution("", "x.com")
        self.store.record_dns_resolution("1.2.3.4", "")
        self.assertEqual(self.store.dns_resolution_map(), {})

    def test_reset_clears(self):
        self.store.record_dns_resolution("1.2.3.4", "a.com")
        out = self.store.reset()
        self.assertEqual(out.get("dns_resolutions_removed"), 1)
        self.assertEqual(self.store.dns_resolution_map(), {})

    def test_prune_retention(self):
        self.store.record_dns_resolution("1.2.3.4", "a.com")
        # Envejecer la fila mas alla del corte de retencion.
        self.store.conn.execute(
            "UPDATE dns_resolutions SET last_seen='2000-01-01 00:00:00Z'")
        self.store.conn.commit()
        out = self.store.prune(30)
        self.assertEqual(out.get("dns_resolutions_removed"), 1)
        self.assertEqual(self.store.dns_resolution_map(), {})


class TestDestinationKind(unittest.TestCase):
    """v2.3: label api/web/cdn por hostname (heuristica de display)."""

    def test_api_subdomain_and_tld(self):
        self.assertEqual(
            classifier.destination_kind("api.openai.com"), "api")
        self.assertEqual(
            classifier.destination_kind("api.typesafe.ai"), "api")
        self.assertEqual(
            classifier.destination_kind("openrouter.ai"), "api")  # .ai

    def test_cdn_markers(self):
        self.assertEqual(
            classifier.destination_kind(
                "d3bbv8sr76az5s.cloudfront.net"), "cdn")
        self.assertEqual(
            classifier.destination_kind("a248.e.akamai.net"), "cdn")
        self.assertEqual(
            classifier.destination_kind("assets.example-cdn.com"), "cdn")

    def test_web_and_degraded(self):
        self.assertEqual(
            classifier.destination_kind("huggingface.co"), "web")
        self.assertEqual(classifier.destination_kind(""), "")
        self.assertEqual(classifier.destination_kind("1.2.3.4"), "")
        self.assertEqual(
            classifier.destination_kind("2001:db8::1"), "")


if __name__ == "__main__":
    unittest.main()
