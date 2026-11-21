"""Regresiones del plan v2.8 (estaticas, sin navegador)."""
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static import js_paths, read_js  # noqa: E402

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
JS = read_js()


class UiV28Test(TestCase):
    def test_a01_js_is_read_in_load_order(self):
        paths = js_paths()
        self.assertEqual(paths[-1].name, "app.js")
        self.assertIn("function bind()", JS)
        self.assertIn("function esc(", JS)

    def test_a02_stamp_covers_static_js(self):
        import os
        import tempfile
        import server
        old = server.STATIC_DIR
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for f in ("app.js", "styles.css", "theme.js"):
                (d / f).write_text("", encoding="utf-8")
            (d / "js").mkdir()
            part = d / "js" / "01-base.js"
            part.write_text("", encoding="utf-8")
            server.STATIC_DIR = d
            try:
                first = server._asset_stamp()
                os.utime(part, (1, 10_000_000))
                second = server._asset_stamp()
            finally:
                server.STATIC_DIR = old
        self.assertNotEqual(first, second)

    def test_a03_console_js_is_split_in_classic_scripts(self):
        names = [p.name for p in js_paths()]
        self.assertEqual(len(names), 12, names)
        self.assertEqual(names[0], "01-base.js")
        self.assertEqual(names[-1], "app.js")
        on_disk = sorted(p.name for p in (ROOT / "static" / "js").glob("*.js"))
        self.assertEqual(on_disk, names[:-1])
        for p in js_paths():
            self.assertLessEqual(p.read_text(encoding="utf-8").count("\n"), 500, p.name)
        self.assertNotIn('type="module"', HTML)

    def test_a03_refresh_jobs_live_in_the_last_script(self):
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const REFRESH_JOBS = [", app)
        self.assertIn('document.addEventListener("DOMContentLoaded"', app)

    def test_v01_triage_tables_start_with_ten_rows(self):
        self.assertIn("const TRIAGE_ROWS = 10;", JS)
