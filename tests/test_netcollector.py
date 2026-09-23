"""Tests v2.2: bytes remotos (colector elevado ETW Kernel-Network).

- parse_xml por NOMBRE (<Data Name="PID">...): solo copia de datos
  (TCP 10/18/26/27/34, UDP 11), size>0, sin loopback, sin DNS (dport 53).
- aggregate: suma por (dest_ip, dest_port).
- store.ingest_net_bytes: acumula entre ciclos; net_bytes_sum ordenado;
  reset limpia.
- Dashboard: cloud_bytes disponible con datos, 'no disponible' sin ellos.
- Regla egress: dispara sobre umbral a no aprobados, no a aprobados.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402
import netcollector  # noqa: E402
import rules  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402

XML_SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<TraceEvents>
  <TraceEvent>
    <Header Name="TCPEDataCopy"><Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">10</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">438</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
    <Data Name="sport">51000</Data><Data Name="dport">443</Data>
  </TraceEvent>
  <TraceEvent>
    <Header Name="TCPEDataCopy"><Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">18</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">1360</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
    <Data Name="sport">51000</Data><Data Name="dport">443</Data>
  </TraceEvent>
  <TraceEvent>
    <Header Name="TCPEConnect"><Task Name="TCPIP">12</Task>
      <EventID Name="TCPEConnect">12</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">0</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">1.2.3.4</Data>
    <Data Name="sport">51000</Data><Data Name="dport">443</Data>
  </TraceEvent>
  <TraceEvent>
    <Header Name="TCPEDataCopy"><Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">26</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">999</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">127.0.0.1</Data>
    <Data Name="sport">51001</Data><Data Name="dport">8080</Data>
  </TraceEvent>
  <TraceEvent>
    <Header Name="TCPEDataCopy"><Task Name="TCPIP">10</Task>
      <EventID Name="TCPEDataCopy">27</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">29</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">8.8.8.8</Data>
    <Data Name="sport">53000</Data><Data Name="dport">53</Data>
  </TraceEvent>
  <TraceEvent>
    <Header Name="UDPIPDataCopy"><Task Name="UDPIP">11</Task>
      <EventID Name="UDPIPDataCopy">11</EventID></Header>
    <Data Name="PID">20184</Data><Data Name="size">512</Data>
    <Data Name="saddr">192.168.1.50</Data><Data Name="daddr">5.6.7.8</Data>
    <Data Name="sport">53001</Data><Data Name="dport">5300</Data>
  </TraceEvent>
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
        # TCP data 438+1360 (mismo destino), UDP 512; connect/loopback/DNS
        # fuera.
        self.assertEqual(
            sorted((r["dest_ip"], r["dest_port"], r["bytes"])
                   for r in rows),
            [("1.2.3.4", 443, 438), ("1.2.3.4", 443, 1360),
             ("5.6.7.8", 5300, 512)])

    def test_pids_kept(self):
        rows = netcollector.parse_xml(self.path)
        self.assertTrue(all(r["pid"] == 20184 for r in rows))

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
                     for k in ("store", "_cfg", "CONFIG_PATH", "alerts")}
        server.store = self.store
        server.alerts = self.log
        server.CONFIG_PATH = Path(self.tmp.name) / "config.json"
        server._cfg = {"catalog_approved": True,
                       "approved_providers": [],
                       "alerts_enabled": True,
                       "rules_enabled": True,
                       "rule_egress_mb_per_day": 500.0}
        server._rules_alerted.clear()

    def tearDown(self) -> None:
        for k, v in self._old.items():
            setattr(server, k, v)
        self.store.close()
        self.tmp.cleanup()


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


if __name__ == "__main__":
    unittest.main()
