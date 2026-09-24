"""Regresion: uso concurrente del Store (lecturas + escrituras) sin errores
de sqlite. Antes del fix, list_events/stats/... no tenian lock y el pool de
hilos de uvicorn intercalaba executes sobre la misma conexion
(sqlite3.InterfaceError / IndexError en produccion)."""
import tempfile
import threading
import unittest
from pathlib import Path

from store import Store


class TestStoreConcurrency(unittest.TestCase):
    THREADS = 8
    ITERS = 100

    def test_mixed_reads_writes_no_errors(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        store = Store(Path(tmp.name) / "t.db")
        # semilla: unos eventos para que las lecturas tengan datos.
        for i in range(5):
            store.observe_connection(
                process=f"p{i % 2}.exe", dest_ip="1.1.1.1",
                dest_port=443, dest_host=None,
                catalog_domain="api.openai.com", ai_layer="catalog")

        errors: list[str] = []
        barrier = threading.Barrier(self.THREADS)

        def worker(n: int) -> None:
            try:
                barrier.wait(timeout=10)
                for i in range(self.ITERS):
                    store.list_events(limit=50)
                    store.stats(days=7)
                    store.latest_triage()
                    store.autonomy_events(limit=20)
                    if n % 2 == 0:
                        store.observe_connection(
                            process=f"w{n}.exe", dest_ip="2.2.2.2",
                            dest_port=443, dest_host=None,
                            catalog_domain="api.openai.com",
                            ai_layer="catalog")
            except Exception as e:  # noqa: BLE001 - el test falla con todo
                errors.append(f"{type(e).__name__}: {e}")

        threads = [threading.Thread(target=worker, args=(n,))
                   for n in range(self.THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        store.close()
        tmp.cleanup()

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
