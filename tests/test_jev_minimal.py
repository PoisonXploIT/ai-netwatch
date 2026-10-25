"""S-07: modo "solo dominios" de Jev (jev_minimal).

Documenta y verifica que, con jev_minimal=True, el state enviado a Jev no
contiene proceso, IP, puerto ni host local. Sin red: la llamada HTTP se
sustituye por un fake que captura el payload.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import jev_triage  # noqa: E402

EVENT = {
    "id": 1, "ts": "2026-10-25T10:00:00", "process": "chrome.exe",
    "image": "C:\\Program Files\\Chrome\\chrome.exe",
    "dest_ip": "93.184.216.34", "dest_port": 443, "dest_host": "example.com",
    "sni_domain": "api.openai.com", "catalog_domain": "openai.com",
    "protocol": "tcp", "seen_count": 4, "first_seen": "2026-10-20T09:00:00",
    "last_seen": "2026-10-25T09:55:00", "autonomy_verdict": "user_driven",
    "sessions": 6, "iat_cv": 0.2,
}

FORBIDDEN = ("process", "image", "dest_ip", "dest_port", "user_active")


class JevMinimalTest(unittest.TestCase):
    def test_full_state_has_identifiers(self):
        s = jev_triage._state_for(EVENT)
        self.assertEqual(s["process"], "chrome.exe")
        self.assertEqual(s["dest_ip"], "93.184.216.34")

    def test_minimal_state_drops_identifiers(self):
        s = jev_triage._state_for(EVENT, minimal=True)
        for key in FORBIDDEN:
            self.assertNotIn(key, s, f"el modo solo dominios filtra {key}")
        self.assertEqual(s["sni_domain"], "api.openai.com")
        self.assertEqual(s["sessions"], 6)
        self.assertTrue(s["beaconing"])
        # El title no puede filtrar el proceso ni la IP.
        self.assertNotIn("chrome.exe", s["title"])
        self.assertNotIn("93.184.216.34", s["title"])

    def test_triage_sends_minimal_states(self):
        captured = {}

        def fake_post(url, payload, key, timeout):
            captured["payload"] = payload
            return {"answers": {}}

        with mock.patch.object(jev_triage, "_http_post_json", fake_post):
            jev_triage.triage_events([EVENT], "key", minimal=True)
        states = captured["payload"]["state"]
        self.assertEqual(len(states), 1)
        for key in FORBIDDEN:
            self.assertNotIn(key, states[0])

    def test_default_is_still_full(self):
        captured = {}

        def fake_post(url, payload, key, timeout):
            captured["payload"] = payload
            return {"answers": {}}

        with mock.patch.object(jev_triage, "_http_post_json", fake_post):
            jev_triage.triage_events([EVENT], "key")
        self.assertIn("process", captured["payload"]["state"][0])


if __name__ == "__main__":
    unittest.main()
