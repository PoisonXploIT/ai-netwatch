"""v2.6(3): etiqueta del estado del senal idle (display-only).

El veredicto solo ve los segundos o None; la etiqueta explica el
estado en el panel (sin senal: congelado/API/imposible; o senal valida
con 'sin entrada desde el arranque') en vez de un '?' silencioso."""
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import autonomy  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


class TestIdleDegradeReason(unittest.TestCase):
    def setUp(self) -> None:
        self._probe = autonomy._probe_ms
        self._up = autonomy._uptime_ms
        self._last_probe = autonomy._last_probe
        self._reason = autonomy.idle_signal_note()

    def tearDown(self) -> None:
        autonomy._probe_ms = self._probe
        autonomy._uptime_ms = self._up
        autonomy._last_probe = self._last_probe
        # Restaurar el motivo (llamar con senal sana lo limpia).
        autonomy._probe_ms = self._probe
        autonomy._uptime_ms = self._up
        if sys.platform == "win32":
            autonomy.get_idle_seconds()
        autonomy._last_signal_note = self._reason

    def test_counter_frozen_labels(self):
        # Probe previo con el mismo ms hace 2 s -> congelado.
        autonomy._probe_ms = lambda: 5000
        autonomy._uptime_ms = lambda: 99999999
        autonomy._last_probe = (time.monotonic() - 2.0, 5000)
        self.assertIsNone(autonomy.get_idle_seconds())
        self.assertEqual(autonomy.idle_signal_note(), "counter_frozen")

    def test_healthy_clears_reason(self):
        # Primero congelado (motivo visible)...
        autonomy._probe_ms = lambda: 5000
        autonomy._uptime_ms = lambda: 99999999
        autonomy._last_probe = (time.monotonic() - 2.0, 5000)
        self.assertIsNone(autonomy.get_idle_seconds())
        self.assertEqual(autonomy.idle_signal_note(), "counter_frozen")
        # ...y con el contador avanzando la senal vuelve y el motivo se limpia.
        autonomy._probe_ms = lambda: 4000
        v = autonomy.get_idle_seconds()
        self.assertEqual(v, 4)
        self.assertIsNone(autonomy.idle_signal_note())

    def test_impossible_idle_gt_uptime_labels(self):
        autonomy._probe_ms = lambda: 99999999
        autonomy._uptime_ms = lambda: 5000
        autonomy._last_probe = None
        self.assertIsNone(autonomy.get_idle_seconds())
        self.assertEqual(autonomy.idle_signal_note(), "idle_gt_uptime")

    def test_api_error_labels(self):
        autonomy._probe_ms = lambda: None
        self.assertIsNone(autonomy.get_idle_seconds())
        self.assertEqual(autonomy.idle_signal_note(), "api_error")

    def test_no_input_since_boot_labels_valid_value(self):
        # El contador va (avanza) pero la ultima entrada fue en el boot:
        # senal valida + etiqueta (no degradacion).
        autonomy._probe_ms = lambda: 355221000   # ms desde la entrada
        autonomy._uptime_ms = lambda: 355224000  # uptime (diferencia 3 s)
        autonomy._last_probe = None
        v = autonomy.get_idle_seconds()
        self.assertEqual(v, 355221)
        self.assertEqual(autonomy.idle_signal_note(), "no_input_since_boot")

    def test_normal_idle_no_label(self):
        # Idle normal (muy por debajo del uptime): senal valida, sin nota.
        autonomy._probe_ms = lambda: 120000
        autonomy._uptime_ms = lambda: 355224000
        autonomy._last_probe = None
        v = autonomy.get_idle_seconds()
        self.assertEqual(v, 120)
        self.assertIsNone(autonomy.idle_signal_note())

    def test_fresh_boot_no_label(self):
        # Uptime < margen: sin contexto suficiente para etiquetar.
        autonomy._probe_ms = lambda: 30000
        autonomy._uptime_ms = lambda: 30000
        autonomy._last_probe = None
        v = autonomy.get_idle_seconds()
        self.assertEqual(v, 30)
        self.assertIsNone(autonomy.idle_signal_note())


class TestEndpointExposesLabel(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        self._old_cfg = dict(server._cfg)
        server.store = self.store
        server._cfg = {**server._cfg}
        self.store.observe_connection("a.exe", "1.1.1.1", 443, None, None)

    def tearDown(self) -> None:
        server.store = self._old_store
        server._cfg = self._old_cfg
        self.store.close()
        self.tmp.cleanup()

    def test_signals_carry_idle_note(self):
        r = server.autonomy_state()
        sig = r["signals"]
        self.assertIn("idle_note", sig)
        # Coherencia: senal None -> nota de degradacion (una de las 4);
        # senal valida -> nota None o no_input_since_boot.
        degraded = {"no_win", "api_error", "idle_gt_uptime",
                    "counter_frozen"}
        if sig["idle_seconds"] is None:
            self.assertIn(sig["idle_note"], degraded)
        else:
            self.assertIn(sig["idle_note"], (None, "no_input_since_boot"))


if __name__ == "__main__":
    unittest.main()
