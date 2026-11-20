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

    def test_b03_wide_tables_scroll_inside_their_wrapper(self):
        self.assertIn(".tab-panel, .tab-panel > .card { min-width: 0; }", CSS)
        for wid in ("findings-wrap", "baseline-wrap", "autonomy-wrap",
                    "triage-results", "events-wrap"):
            self.assertIn(f'id="{wid}" class="table-wrap"', HTML, wid)

    def test_b04_main_and_header_are_centered(self):
        self.assertIn("max-width: 1280px; margin: 0 auto; }", CSS)
        self.assertIn("header { max-width: 1280px; margin: 0 auto; }", CSS)

    def test_b05_findings_use_spanish_autonomy_label(self):
        self.assertNotIn('badge-warn">${esc(f.autonomy_verdict)}', JS)
        self.assertIn("autonomyBadge(f.autonomy_verdict, f.autonomy_score)", JS)

    def test_b06_no_parenthesised_plurals(self):
        self.assertIn("function plural(n, uno, varios)", JS)
        for bad in ("proceso(s)", "proveedor(es)", "sesión(es)", "aprobado(s)"):
            self.assertNotIn(bad, JS, bad)

    def test_b07_visible_text_has_accents(self):
        for bad in ("Ultima vez</option>", "<th>Catalogo</th>", "Una linea por",
                    "que engane", "sin revision</span>", "reanudalo"):
            self.assertNotIn(bad, HTML + JS, bad)

    def test_b07b_remaining_visible_text_has_accents(self):
        for bad in ("Asesoria display-only", "El trafico TLS", '["ultima vez"',
                    '["anomalia"', "<th>Ultima vez</th>", "Capa de deteccion",
                    'catalog: "catalogo"', '"sin senal:', "(sesion sin",
                    "monitoreo esta pausado"):
            self.assertNotIn(bad, HTML + JS, bad)

    def test_b08_guide_has_a_single_entry_point(self):
        self.assertNotIn("btn-guide", HTML)
        self.assertNotIn("btn-guide", JS)
        self.assertIn('id="tab-guia"', HTML)

    def test_b09_strip_explains_pause_and_last_event(self):
        self.assertIn("function ago(ts)", JS)
        self.assertIn('h.monitoring_enabled === false ? "en pausa" : h.status', JS)
        self.assertIn("ago(h.last_event)", JS)

    def test_b10_strip_shows_inspector_state(self):
        self.assertIn('(h.sources || {}).llm_proxy ? "activo" : "parado"', JS)

    def test_b11_pid_processes_are_grouped(self):
        self.assertIn("<optgroup label=\"Sin nombre (${pids.length} PID)\">", JS)
        self.assertEqual(JS.count('"Todos los procesos", procOptions)'), 2)





