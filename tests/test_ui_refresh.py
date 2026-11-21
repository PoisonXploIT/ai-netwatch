"""#10: el refresco periodico se acota a la pestaña visible.

Criterio vigente: <= 12 req/min en la pestaña activa. La prueba lee app.js y
reconstruye la tabla de tareas (tab, intervalo) sin ejecutar el navegador.
"""
import re
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static import read_js  # A-01: el JS puede estar repartido en varios scripts
MAX_REQ_PER_MIN = 12


class RefreshBudgetTest(TestCase):
    def setUp(self):
        self.js = read_js()

    def _jobs(self):
        block = re.search(r"const REFRESH_JOBS = \[(.*?)\n\];", self.js, re.S)
        self.assertIsNotNone(block, "no existe la tabla REFRESH_JOBS")
        jobs = []
        for line in block.group(1).splitlines():
            m = re.search(r'\{ tab: (null|"[a-z]+"), fn: (\w+), every: (\d+) \}', line)
            if m:
                tab = None if m.group(1) == "null" else m.group(1)
                jobs.append((tab, m.group(2), int(m.group(3))))
        return jobs

    def test_no_bare_setinterval(self):
        # Todo refresco periodico debe pasar por la tabla (con guarda de pestaña),
        # no por un setInterval directo de funcion.
        hits = re.findall(r"setInterval\(\w+,\s*\d+\)", self.js)
        self.assertEqual(hits, [], f"setInterval sin guarda de pestaña: {hits}")

    def test_every_tab_is_guarded(self):
        self.assertIn("activeTabName() !== job.tab", self.js)
        self.assertIn("document.hidden", self.js)

    def test_active_tab_budget(self):
        jobs = self._jobs()
        self.assertTrue(jobs, "REFRESH_JOBS vacio")
        global_rate = sum(60000 / every for tab, _fn, every in jobs if tab is None)
        for tab in {t for t, _f, _e in jobs if t}:
            rate = global_rate + sum(60000 / every for t, _f, every in jobs if t == tab)
            self.assertLessEqual(rate, MAX_REQ_PER_MIN,
                                 f"pestaña {tab}: {rate:g} req/min (limite {MAX_REQ_PER_MIN})")

    def test_events_not_polled_every_5s(self):
        self.assertNotIn("setInterval(refreshEvents, 5000)", self.js)


if __name__ == "__main__":
    from unittest import main
    main()
