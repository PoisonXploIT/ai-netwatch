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
