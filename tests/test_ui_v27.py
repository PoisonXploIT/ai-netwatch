"""Regresiones de UI del plan v2.7 (estaticas, sin navegador)."""
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")


class UiV27Test(TestCase):
    def test_b01_strip_reads_key_state_from_sources(self):
        self.assertIn("(h.sources || {}).jev_key_set", JS)
        self.assertNotIn("${h.jev_key_set ?", JS)

    def test_b02_axis_mid_tick_only_when_integer(self):
        self.assertIn("const showMid = Number.isInteger(mid) && mid > 0;", JS)
        self.assertNotIn("Math.round(max / 2)", JS)
