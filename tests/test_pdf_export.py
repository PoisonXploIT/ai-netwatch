"""Tests del export PDF de AI NetWatch (writer stdlib + builder del informe).

Sin red, sin archivos: bytes en memoria. Verifica estructura PDF minima
valida, wrapping, escapes, cp1252 y el contenido del informe.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pdf_export import PdfDoc, build_report_pdf, wrap_line  # noqa: E402
from store import Store  # noqa: E402


class TestPdfWriter(unittest.TestCase):
    def test_header_and_trailer(self):
        doc = PdfDoc()
        doc.add("Hola mundo")
        out = doc.render()
        self.assertTrue(out.startswith(b"%PDF-1.4"))
        self.assertTrue(out.rstrip().endswith(b"%%EOF"))

    def test_text_present_escaped(self):
        doc = PdfDoc()
        doc.add("cafe (con parentesis) y \\ barra")
        out = doc.render()
        # Los caracteres especiales van escapados en el stream:
        self.assertIn(rb"\(con parentesis\)", out)
        self.assertIn(rb"\\ barra", out)

    def test_cp1252_accents(self):
        doc = PdfDoc()
        doc.add("español ñ á é í ó ú")
        out = doc.render()
        # WinAnsiEncoding: los bytes cp1252 de las tildes deben estar ahi.
        self.assertIn("español".encode("cp1252"), out)

    def test_non_cp1252_replaced(self):
        doc = PdfDoc()
        doc.add("ok \u2603 fin")  # snowman: no existe en cp1252
        out = doc.render()
        self.assertIn(b"ok ? fin", out)

    def test_wrapping_long_line(self):
        words = " ".join(f"w{i}" for i in range(200))
        lines = wrap_line(words, 10.0)
        self.assertGreater(len(lines), 1)
        for line in lines:
            # Ancho maximo a 10pt: int(505 / (10 * 0.52)) = 97
            self.assertLessEqual(len(line), 97)

    def test_multiline_preserved(self):
        lines = wrap_line("a\nb\nc", 10.0)
        self.assertEqual(lines, ["a", "b", "c"])

    def test_page_break(self):
        # ~55 lineas/pagina a 10pt: 60 lineas -> 2 paginas exactas.
        doc = PdfDoc()
        for i in range(60):
            doc.add(f"linea {i}")
        out = doc.render()
        self.assertIn(b"/Count 2", out)
        self.assertEqual(out.count(b"/Type /Page "), 2)

    def test_empty_doc_valid(self):
        out = PdfDoc().render()
        self.assertTrue(out.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Count 1", out)


class TestBuildReport(unittest.TestCase):
    def _events(self):
        return [
            {"process": "a.exe", "dest_ip": "1.1.1.1", "dest_port": 443,
             "dest_host": "", "sni_domain": "api.example.com",
             "catalog_domain": "example.com", "protocol": "tcp",
             "seen_count": 5, "image": None},
            {"process": "b.exe", "dest_ip": "2.2.2.2", "dest_port": 8443,
             "dest_host": "cdn.other.net", "sni_domain": "",
             "catalog_domain": "", "protocol": "udp",
             "seen_count": 1, "image": None},
        ]

    def _triage(self):
        return {"events": [
            {"id": 1, "process": "a.exe", "dest": "api.example.com:443",
             "catalog": "example.com", "seen_count": 5},
        ],
         "jev": {"status": "ok", "model": "jev-test",
                 "verdicts": {"0": {"verdict": "expected_ai_use",
                                    "confidence": 0.9,
                                    "severity_score": 1.0,
                                    "immediate_action": 0.1,
                                    "prob_false_positive": 0.1}}},
         "llm_explanations": None}

    def test_full_report(self):
        daily = [{"date": "2026-09-22", "events": 3, "triages": 1}]
        out = build_report_pdf("1.2", self._events(), self._triage(), daily)
        text = out.decode("cp1252", "replace")
        self.assertIn("AI NetWatch 1.2", text)
        self.assertIn("a.exe", text)
        self.assertIn("api.example.com", text)
        self.assertIn("expected_ai_use", text)
        self.assertIn("2026-09-22", text)

    def test_empty_store(self):
        out = build_report_pdf("1.2", [], None, [])
        text = out.decode("cp1252", "replace")
        self.assertIn("Sin eventos registrados.", text)
        self.assertIn("Sin datos diarios todavia.", text)

    def test_no_triage_section(self):
        out = build_report_pdf("1.2", self._events(), None, [])
        self.assertNotIn(b"Ultimo triaje Jev", out)


class TestReportFromStore(unittest.TestCase):
    """El informe se construye desde el store (camino real del endpoint)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_store_roundtrip_in_report(self):
        self.store.observe_connection("x.exe", "3.3.3.3", 443,
                                     "deepseek.com", "")
        events = self.store.list_events(limit=10)
        out = build_report_pdf("1.2", events, None, self.store.stats(7))
        text = out.decode("cp1252", "replace")
        self.assertIn("x.exe", text)
        self.assertIn("deepseek.com", text)


if __name__ == "__main__":
    unittest.main()
