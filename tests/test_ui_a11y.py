"""Accesibilidad y responsive de la consola (#6, parte barata).

Verifica en los ficheros estaticos lo que se puede verificar sin navegador:
roles ARIA en las pestanas, aria-live en el toast, aria-expanded en el
detalle de eventos y la existencia de @media.
"""
import re
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

TABS = ("resumen", "hallazgos", "eventos", "ia", "config")


class A11yTest(TestCase):
    def test_tablist_and_tabs(self):
        self.assertIn('role="tablist"', HTML)
        for tab in TABS:
            self.assertIn(f'id="tab-{tab}"', HTML, f"pestanja {tab} sin id")
            self.assertIn(f'aria-controls="panel-{tab}"', HTML,
                         f"pestanja {tab} sin aria-controls")
        self.assertEqual(HTML.count('role="tab"'), len(TABS))

    def test_panels_exist_for_every_tab(self):
        sections = re.findall(r'<section class="card" data-tab="([a-z]+)"', HTML)
        self.assertEqual(HTML.count('role="tabpanel"'), len(sections),
                         "cada seccion de pestana debe ser un tabpanel")
        for tab in TABS:
            self.assertIn(tab, sections, f"no hay panel para {tab}")

    def test_showtab_maintains_aria_selected(self):
        self.assertIn('setAttribute("aria-selected"', JS)

    def test_toast_is_a_live_region(self):
        self.assertIn('<div id="toast" role="status" aria-live="polite">', HTML)

    def test_event_detail_buttons_have_aria_expanded(self):
        self.assertIn('data-detail="ev-d-', JS)
        self.assertIn('aria-expanded', JS)

    def test_responsive_rules_exist(self):
        self.assertIn("@media", CSS)
        self.assertGreaterEqual(CSS.count("@media"), 2)


if __name__ == "__main__":
    from unittest import main
    main()
