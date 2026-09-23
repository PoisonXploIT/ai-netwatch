"""Tests del pipeline SNI (tshark) de AI NetWatch.

Sin procesos reales: parseo de lineas, decodificacion UTF-16LE (el formato
real que tshark escribe al redirigir en Windows), store.attach_sni y el
ciclo del monitor con un drain mockeado.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from monitor import NetMonitor  # noqa: E402
from store import Store  # noqa: E402
from tshark_source import (  # noqa: E402
    _decode_maybe_utf16, parse_sni_line)


class TestParseSniLine(unittest.TestCase):
    # Formato (6 campos): t_rel, ip4_dst, ipv6_dst, tcpport, udpport, sni.
    # TCP TLS llena tcpport; QUIC/HTTP-3 llena udpport (N1).

    def test_old_format_skipped(self):
        # 4 y 5 campos (formatos antiguos) -> None: se exige el de 6.
        self.assertIsNone(
            parse_sni_line("21.227114000,3.173.21.63,443,api.deepseek.com"))
        self.assertIsNone(
            parse_sni_line("21.227114000,3.173.21.63,,443,api.deepseek.com"))

    def test_tcp_ipv4(self):
        r = parse_sni_line(
            "21.227114000,3.173.21.63,,443,,api.deepseek.com")
        self.assertEqual(r["dst_ip"], "3.173.21.63")
        self.assertEqual(r["dst_port"], 443)
        self.assertEqual(r["sni"], "api.deepseek.com")

    def test_tcp_ipv6_dst(self):
        # huggingface.co via IPv6: ip.dst vacio, ipv6.dst lleno.
        r = parse_sni_line(
            "28.208196000,,2600:9000:24de:2c00::1,443,,huggingface.co")
        self.assertEqual(r["dst_ip"], "2600:9000:24de:2c00::1")
        self.assertEqual(r["sni"], "huggingface.co")

    def test_quic_udp_port(self):
        # Muestra real del probe (Edge headless -> H3): tcpport vacio,
        # udpport=443, SNI extraido del paquete Initial.
        r = parse_sni_line(
            "1.404107000,,2001:4860:482c:7700::,,443,www.google.com")
        self.assertEqual(r["dst_ip"], "2001:4860:482c:7700::")
        self.assertEqual(r["dst_port"], 443)
        self.assertEqual(r["sni"], "www.google.com")

    def test_quic_ipv4(self):
        r = parse_sni_line("5.0,1.2.3.4,,,443,example.com")
        self.assertEqual(r["dst_ip"], "1.2.3.4")
        self.assertEqual(r["dst_port"], 443)

    def test_missing_sni_skipped(self):
        self.assertIsNone(parse_sni_line("1.0,1.2.3.4,,443,,"))

    def test_missing_dst_skipped(self):
        self.assertIsNone(parse_sni_line("1.0,,,443,,example.com"))

    def test_bad_port_skipped(self):
        self.assertIsNone(
            parse_sni_line("1.0,1.2.3.4,,abc,,example.com"))

    def test_no_port_skipped(self):
        # Sin tcpport ni udpport no hay con que casar el evento.
        self.assertIsNone(parse_sni_line("1.0,1.2.3.4,,,,example.com"))

    def test_short_line_skipped(self):
        self.assertIsNone(parse_sni_line("1.0,1.2.3.4"))

    def test_crlf_tolerated_by_caller(self):
        # parse_sni_line recibe la linea ya sin \r (lo hace el bucle);
        # pero un \r colado en el SNI no debe romper nada:
        r = parse_sni_line("1.0,1.2.3.4,,443,,example.com\r")
        self.assertEqual(r["sni"], "example.com")


class TestDecodeMaybeUtf16(unittest.TestCase):
    def test_utf16le_no_bom(self):
        raw = "a,b,c".encode("utf-16-le")
        self.assertEqual(_decode_maybe_utf16(raw), "a,b,c")

    def test_utf16_with_bom_marker(self):
        raw = b"\xff\xfe" + "hello".encode("utf-16-le")
        self.assertEqual(_decode_maybe_utf16(raw), "hello")

    def test_utf8_fallback(self):
        self.assertEqual(_decode_maybe_utf16("plain,ascii".encode()),
                         "plain,ascii")


class TestAttachSni(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_fills_sni_and_empty_catalog(self):
        self.store.observe_connection("a.exe", "3.173.21.63", 443,
                                     None, "d3bbv8.cloudfront.net")
        n = self.store.attach_sni("3.173.21.63", 443, "api.deepseek.com",
                                 catalog="deepseek.com")
        self.assertEqual(n, 1)
        e = self.store.list_events()[0]
        self.assertEqual(e["sni_domain"], "api.deepseek.com")
        self.assertEqual(e["catalog_domain"], "deepseek.com")

    def test_does_not_overwrite_existing_catalog(self):
        self.store.observe_connection("a.exe", "1.1.1.1", 443,
                                     "openai.com", "cdn.example.net")
        n = self.store.attach_sni("1.1.1.1", 443, "api.openai.com",
                                 catalog="openai.com")
        self.assertEqual(n, 1)
        e = self.store.list_events()[0]
        # catalog previo se conserva (ya era openai.com aqui, pero si fuera
        # otro dominio no lo pisaria):
        self.assertEqual(e["catalog_domain"], "openai.com")
        self.assertEqual(e["sni_domain"], "api.openai.com")

    def test_no_match_returns_zero(self):
        self.assertEqual(
            self.store.attach_sni("9.9.9.9", 443, "x.com"), 0)


class TestCaptureLifecycle(unittest.TestCase):
    def test_iface_none_rejected(self):
        from tshark_source import SniCapture
        with self.assertRaises(ValueError):
            SniCapture("/fake/tshark", None)

    def test_find_interface_skips_junk_first_pass(self):
        import tshark_source as ts
        orig_list, orig_probe = ts.list_interfaces, ts._probe_interface
        try:
            ts.list_interfaces = lambda t: [(1, "VMware VMnet8"),
                                            (2, "Wi-Fi")]
            # Con el probe en True para todos, la primera pasada (sin junk)
            # debe elegir Wi-Fi aunque VMware "capture".
            ts._probe_interface = lambda t, i: True
            self.assertEqual(ts.find_active_interface("/fake/tshark"), 2)
        finally:
            ts.list_interfaces, ts._probe_interface = orig_list, orig_probe


class TestMonitorSniCycle(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _monitor(self, records):
        q = list(records)

        def drain():
            out = []
            while q:
                out.append(q.pop(0))
            return out

        return NetMonitor(self.store, sni_fn=drain)

    def test_cycle_attaches_records(self):
        self.store.observe_connection("a.exe", "3.173.21.63", 443,
                                     None, "cloudfront.net")
        m = self._monitor([{"dst_ip": "3.173.21.63", "dst_port": 443,
                           "sni": "api.deepseek.com"}])
        m._sni_cycle()
        e = self.store.list_events()[0]
        self.assertEqual(e["sni_domain"], "api.deepseek.com")
        # match_domain(api.deepseek.com) -> deepseek.com:
        self.assertEqual(e["catalog_domain"], "deepseek.com")

    def test_no_fn_is_noop(self):
        m = NetMonitor(self.store, sni_fn=None)
        m._sni_cycle()  # no lanza


if __name__ == "__main__":
    unittest.main()
