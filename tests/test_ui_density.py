"""Densidad y UX de la consola (bloque UI 2026-10-25, parte B).

Criterios que se verifican sin navegador, sobre los ficheros estaticos:
la guia es una pestana mas, la config esta agrupada, el LLM Inspector y la
tarjeta Autonomia no pintan listas infinitas, y el estado del sistema se ve
sin abrir ninguna pestana.
"""
import os
import re
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")


class GuideIsATabTest(TestCase):
    def test_guide_has_its_own_panel(self):
        self.assertIn('id="panel-guia"', HTML)
        self.assertIn('data-tab="guia"', HTML)
        self.assertIn('id="tab-guia"', HTML)
        # Ya no es un bloque suelto oculto debajo de las pestanas.
        self.assertNotIn("guide-hidden", HTML)
        self.assertNotIn("guide-hidden", CSS)

    def test_guide_button_targets_the_panel(self):
        self.assertIn('aria-controls="panel-guia"', HTML)
        self.assertIn('showTab("guia")', JS)


class ConfigGroupingTest(TestCase):
    def test_config_is_grouped(self):
        groups = re.findall(r'<div class="cfg-group">', HTML)
        self.assertGreaterEqual(len(groups), 3,
                                "la config sigue siendo una lista plana de .row")
        self.assertGreaterEqual(HTML.count('<h3>'), len(groups),
                                "cada grupo debe tener su titulo")

    def test_groups_are_balanced(self):
        block = re.search(r'id="cfg-card".*?</section>', HTML, re.S).group(0)
        opens = len(re.findall(r"<div\b", block))
        closes = len(re.findall(r"</div>", block))
        self.assertEqual(opens, closes, "divs sin cerrar en la tarjeta de config")


class PaginationTest(TestCase):
    def test_llm_inspector_is_paginated(self):
        self.assertIn("llmCallsShown", JS)
        self.assertIn("btn-llm-more", JS)
        # No se vuelca la respuesta completa al DOM sin recortar.
        self.assertNotIn("innerHTML = llmCallsHtml(d.calls)", JS)

    def test_autonomy_is_paginated(self):
        self.assertIn("autShown", JS)
        self.assertIn("btn-aut-more", JS)
        self.assertIn("aut-table", JS)

    def test_dashboard_providers_are_paginated(self):
        self.assertIn("dashProvShown", JS)
        self.assertIn("btn-prov-more", JS)

    def test_no_unbounded_row_lists_in_dashboard(self):
        # Las listas compactas usan chips; una .row por item era el problema.
        self.assertIn('class="chips"', JS)
        self.assertIn(".chips {", CSS)


class StatusStripTest(TestCase):
    def test_strip_exists_and_is_polled(self):
        self.assertIn('id="status-strip"', HTML)
        self.assertIn("refreshHealth", JS)
        m = re.search(r"const REFRESH_JOBS = \[(.*?)\n\];", JS, re.S)
        self.assertIsNotNone(m)
        self.assertIn('fn: refreshHealth', m.group(1))

    def test_kill_switch_is_explained(self):
        # "degradado" con monitor pausado no debe leerse como un fallo.
        self.assertIn("kill switch", JS)


class KeyboardTest(TestCase):
    def test_tab_shortcuts_exist(self):
        self.assertIn('"1": "resumen"', JS)
        self.assertIn('"6": "guia"', JS)
        # No se activan mientras se escribe en un campo.
        self.assertIn("INPUT|SELECT|TEXTAREA", JS)


class AssetCacheTest(TestCase):
    """El `?v=VERSION` no busteaba la cache: la version no sube con cada
    commit y el navegador servia un app.js viejo (bug del 2026-10-25)."""

    def test_index_uses_the_stamp(self):
        self.assertIn("?v={{ASSETV}}", HTML)
        self.assertNotIn("app.js?v={{VERSION}}", HTML)

    def test_stamp_moves_with_the_file(self):
        import server
        path = ROOT / "static" / "app.js"
        st = path.stat()
        first = server._asset_stamp()
        os.utime(path, (st.st_mtime, st.st_mtime + 1))
        try:
            second = server._asset_stamp()
        finally:
            os.utime(path, (st.st_mtime, st.st_mtime))
        self.assertNotEqual(first, second,
                           "el sello de assets no cambia al tocar el fichero")
        self.assertIn("v2.6-", second)


if __name__ == "__main__":
    from unittest import main
    main()
