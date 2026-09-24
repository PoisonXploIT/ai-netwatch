"""v2.6: los subprocess de polls no abren ventanas (CREATE_NO_WINDOW).

Regression: antes, monitor._run_ps y el spawn del colector usaban flags
inexistentes o 0x0800 (que es DETACH_PROCESS), y saltaba una consola en
cada poll."""
import subprocess
import unittest
from unittest import mock

import monitor


class TestNoWindow(unittest.TestCase):
    def test_run_ps_uses_create_no_window(self):
        with mock.patch.object(monitor.subprocess, "run") as m:
            m.return_value = mock.Mock(stdout="ok")
            monitor._run_ps("Get-Process")
            kw = m.call_args.kwargs
            self.assertEqual(kw.get("creationflags"),
                             subprocess.CREATE_NO_WINDOW)


if __name__ == "__main__":
    unittest.main()
