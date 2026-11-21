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

    def test_e03_rows_merge_by_organization(self):
        self.assertIn("function orgOf(host)", JS)
        self.assertIn("function mergeRows(events)", JS)
        self.assertIn('id="ev-org" checked', HTML)
        self.assertIn('$("ev-org").checked = true;', JS)

    def test_e04_one_primary_action_per_card(self):
        self.assertEqual(HTML.count('class="primary"'), 2)
        self.assertNotIn('class="primary review-quarantine"', JS)
        self.assertIn("tbody button.small:not(.primary) {", CSS)

    def test_e05_active_subtab_is_visible(self):
        self.assertIn(".ttab.active, .subtab.active {", CSS)
        self.assertIn(".card[hidden] { display: none; }", CSS)

    def test_e06_subtabs_in_three_panels(self):
        import re
        self.assertEqual(HTML.count('<nav class="subtabs"'), 3)
        targets = re.findall(r'data-sub="([a-z-]+)"', HTML)
        self.assertEqual(len(targets), 8)
        for target in targets:
            self.assertIn(f'id="{target}"', HTML)
        self.assertIn("function wireSubtabs()", JS)
        self.assertIn("  wireSubtabs();", JS)
