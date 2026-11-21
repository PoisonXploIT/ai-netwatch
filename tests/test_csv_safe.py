"""v2.9.2: los CSV no abren fórmulas en Excel y los textos de cifrado son correctos."""
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server  # noqa: E402

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")


class CsvSafeTest(TestCase):
    def test_x01_formula_cells_are_neutralised(self):
        for v in ('=HYPERLINK("http://x")', "+1", "-2+3", "@SUM(A1)", "\tx"):
            self.assertEqual(server._csv_safe(v), "'" + v)
        for v in ("brave.exe", "api.openai.com", 42, None, ""):
            self.assertEqual(server._csv_safe(v), v)

    def test_x01_both_csv_exports_use_the_safe_writer(self):
        src = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertEqual(src.count("_SafeCsv(buf)"), 2)
        self.assertEqual(src.count("csv.writer(buf)"), 1)
