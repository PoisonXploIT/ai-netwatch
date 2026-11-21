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
