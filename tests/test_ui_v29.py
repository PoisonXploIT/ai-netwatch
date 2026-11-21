"""Regresiones del plan v2.9: segunda pasada estética (estaticas, sin navegador)."""
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static import read_js  # noqa: E402

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
JS = read_js()


class UiV29Test(TestCase):
    def test_e01_process_path_does_not_widen_tables(self):
        self.assertIn("td > div.small.mono { max-width: 36ch; overflow: hidden;", CSS)
        self.assertIn("thead th { white-space: nowrap; }", CSS)

    def test_e02_native_controls_follow_the_theme(self):
        self.assertIn('html[data-theme="dark"] { color-scheme: dark; }', CSS)
        self.assertIn("scrollbar-color: var(--border) transparent;", CSS)
