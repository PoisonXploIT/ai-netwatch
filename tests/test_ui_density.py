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
        self.assertIn('"6": "guia"', JS)  # B-08: la guía se abre desde su pestaña y el atajo 6


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

    def test_panel_has_visual_charts(self):
        # El Panel no es solo texto: KPIs, serie de barras diaria, donut de
        # capas, donut de gobernanza, histograma por hora y barras de proveedor.
        for sel in (".kpis", ".charts", ".chart-svg", ".donut-seg",
                    ".prov-row", ".hbar-fill", ".col", ".grid"):
            self.assertIn(sel, CSS, f"falta el estilo de {sel}")
        for fn in ("activityChart", "hourChart", "donut", "providerBars",
                   "panelTakeaway", "kpiHtml"):
            self.assertIn(fn, JS)
        # La CSP (style-src 'self') no permite style="...": la geometria del
        # SVG va en atributos y el color en la hoja de estilos.
        self.assertNotIn('class="chart-svg" style=', JS)
        self.assertIn('stroke-dasharray="', JS)
        self.assertIn('class="takeaway"', JS)


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


class TriageTabsTest(TestCase):
    """Las pestanas Jev/LAYA/Discrepancias deben funcionar con CSP estricta
    (script-src 'self' bloquea los onclick inline) y mostrar las
    discrepancias sin tener que cambiar de pestana."""

    def test_no_inline_onclick_in_generated_triage(self):
        self.assertNotIn('onclick="ttabShow', JS)
        self.assertIn('data-tt="jev"', JS)
        self.assertIn('closest(".ttab")', JS)

    def test_jev_table_shows_vs_laya(self):
        self.assertIn('<th>vs LAYA</th>', JS)
        self.assertIn("function vsCell", JS)

    def test_discrepancy_panel_exists(self):
        self.assertIn("Discrepancias Jev vs LAY", JS)
        self.assertIn('id="ttab-disc"', JS)
        self.assertIn("function ttabShow", JS)
        self.assertIn('d.hidden = which !== "disc"', JS)

    def test_agreement_counter_is_not_stuck_at_zero(self):
        # El bug clasico: se contaba cmpN pero nunca cmpOk.
        self.assertIn("CMP_OK = CMP.filter((r) => r.agree).length", JS)
        self.assertIn("CMP_N = CMP.filter((r) => r.both).length", JS)

    def test_review_history_shows_the_prose(self):
        self.assertIn('class="juicio"', JS)
        self.assertIn("r.ev_process", JS)
        self.assertIn("evidencia_faltante", JS)

    def test_inspector_has_aggregate_stats(self):
        self.assertIn("function llmSummary", JS)
        self.assertIn("latencia media", JS)
        self.assertIn('class="latbar"', JS)

    def test_css_has_the_new_classes(self):
        for cls in (".tcompare", ".vs-ok", ".vs-bad", ".revrow", ".latbar"):
            self.assertIn(cls, CSS)


if __name__ == "__main__":
    from unittest import main
    main()
