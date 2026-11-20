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






    def test_b12_only_first_reviews_start_open(self):
        self.assertIn('<details${i < 3 ? " open" : ""}>', JS)
        self.assertNotIn('<div class="revrow"><details open>', JS)

    def test_b13_finding_actions_use_words(self):
        self.assertNotIn("⊘", JS)
        self.assertIn(">Aislar</button>", JS)
        self.assertIn(">Ocultar</button>", JS)

    def test_b14_controls_have_accessible_names(self):
        import re
        for cid in ("btn-theme", "dash-days", "ev-days", "f-order", "ev-layer",
                    "ev-verdict", "ev-process", "ev-dest", "aut-verdict",
                    "aut-process", "aut-provider", "llm-proxy-port",
                    "llm-proxy-target", "laya-url", "laya-model", "llm-url",
                    "llm-model", "extra-hosts", "alert-webhook",
                    "retention-days", "retention-llm-days"):
            tag = re.search(r'<[^>]*id="%s"[^>]*>' % cid, HTML + JS)
            self.assertIsNotNone(tag, cid)
            self.assertIn("aria-label=", tag.group(0), cid)

    def test_b15_tabs_support_arrow_keys(self):
        self.assertIn("t.tabIndex = on ? 0 : -1;", JS)
        for key in ('"ArrowRight"', '"ArrowLeft"', '"Home"', '"End"'):
            self.assertIn(key, JS, key)

    def test_s13a_exports_send_the_session_token(self):
        self.assertNotIn("window.location.href", JS)
        self.assertEqual(JS.count("download("), 6)  # 1 definicion + 5 usos

    def test_s15_destructive_actions_use_own_dialog(self):
        self.assertIn('<dialog id="confirm-dialog"', HTML)
        self.assertIn("function askConfirm(text)", JS)
        self.assertEqual(JS.count("await askConfirm("), 3)  # U-07 suma la confirmacion al pausar el monitoreo
        self.assertNotIn("if (!confirm(", JS)

    def test_d01_scale_tokens_exist(self):
        for token in ("--fs-xs: 11px", "--fs-md: 13px", "--fs-xl: 20px",
                      "--r-sm: 4px", "--r-lg: 12px", "--sp-4: 16px", "--font-mono:"):
            self.assertIn(token, CSS, token)

    def test_d02_font_sizes_come_from_the_scale(self):
        import re
        sizes = re.findall(r"font-size:\s*([^;]+);", CSS)
        literal = [s for s in sizes if not s.strip().startswith("var(--fs-")
                   and s.strip() not in ("inherit",)]
        self.assertEqual(literal, [], literal)

    def test_d03_radii_come_from_the_scale(self):
        import re
        radii = re.findall(r"border-radius:\s*([^;]+);", CSS)
        literal = [r for r in radii if "var(--r-" not in r and r.strip() not in ("0", "50%")]
        self.assertEqual(literal, [], literal)

    def test_d11_donut_label_outside_ring_and_legend_colors(self):
        self.assertNotIn('class="donut-lbl"', JS)
        self.assertNotIn(".donut-lbl", CSS)
        self.assertIn('<div class="donut-cap">', JS)
        self.assertIn('dominant-baseline="central"', JS)
        self.assertIn(".chip .dot.s-bad { background: var(--v-bad); }", CSS)

    def test_d13_base_font_size_and_family_tokens(self):
        self.assertIn("font-family: var(--font-ui);\n  font-size: var(--fs-md);", CSS)
        self.assertIn(".mono, .mono * { font-family: var(--font-mono); }", CSS)

    def test_d04_no_hex_colors_outside_theme_blocks(self):
        import re
        body = re.sub(r":root\s*\{.*?\}", "", CSS, count=1, flags=re.S)
        body = re.sub(r'html\[data-theme="dark"\]\s*\{.*?\}', "", body, count=1, flags=re.S)
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", body), [])

    def test_d14_chips_do_not_wrap_inside(self):
        self.assertIn("font-size: var(--fs-sm);\n  white-space: nowrap;\n}", CSS)

    def test_d05_header_is_a_single_sticky_bar(self):
        head = HTML.split("</header>")[0]
        self.assertNotIn('class="sub"', head)
        self.assertIn("header { position: sticky; top: 0;", CSS)

    def test_d06_score_has_text_level(self):
        self.assertIn('function scoreLabel(s)', JS)
        self.assertIn("${scoreLabel(f.score)}", JS)

    def test_d07_table_rules(self):
        self.assertIn("font-variant-numeric: tabular-nums", CSS)
        self.assertIn("td.mono { overflow-wrap: anywhere; }", CSS)

    def test_d08_wrappers_start_with_a_loading_state(self):
        import re
        empty = re.findall(r'<div id="[a-z-]+-wrap"[^>]*></div>', HTML)
        self.assertEqual(empty, [], empty)

    def test_d09_reduced_motion_and_focus(self):
        self.assertIn("prefers-reduced-motion: reduce", CSS)
        self.assertIn("summary:focus-visible", CSS)

    def test_d10_theme_pairs_meet_aa_contrast(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import contrast_check
        self.assertEqual(contrast_check.failures(), [])

    def test_u01_events_have_a_search_box(self):
        self.assertIn('id="ev-search"', HTML)
        self.assertIn('$("ev-search").addEventListener("input"', JS)

    def test_u02_last_seen_is_relative_with_utc_title(self):
        self.assertIn("function whenCell(ts)", JS)
        self.assertEqual(JS.count("whenCell("), 5)  # 1 definicion + 4 usos

    def test_u03_event_detail_is_lazy(self):
        self.assertNotIn("${eventDetailHtml(e)}</td>", JS)
        self.assertNotIn("${groupDetailHtml(e)}</td>", JS)
        self.assertIn("let EVENT_ROWS = [];", JS)

    def test_u04_finding_rows_are_keyboard_operable(self):
        self.assertIn('class="finding-row" data-fi="${i}" tabindex="0" role="button"', JS)
        self.assertIn('ev.key === "Enter" || ev.key === " "', JS)

    def test_u05_summary_opens_with_attention_list(self):
        self.assertIn('id="attention-card"', HTML)
        self.assertIn("fn: refreshAttention", JS)

    def test_u06_triage_button_reports_progress(self):
        self.assertIn('btn.textContent = "Triando…";', JS)
        self.assertIn('btn.setAttribute("aria-busy", "true");', JS)
        self.assertIn('btn.removeAttribute("aria-busy");', JS)
        self.assertIn("const dd = data.dedup;", JS)

    def test_u07_pausing_monitoring_asks_first(self):
        self.assertIn("Monitoreo en pausa · reanudar", JS)
        self.assertIn("no se registran conexiones, SNI, bytes ni llamadas LLM", JS)

    def test_u08_narrow_layout_hides_secondary_columns(self):
        self.assertIn("/* U-08:", CSS)
