"""v2.3: Evidence exportable — cadena de hashes + bundle STIX 2.1.

- Cadena: determinista, encadenada, verificable offline; cualquier
  alteracion (evento, hash, indice, orden) la rompe.
- STIX: estructura 2.1 valida (IDs por tipo, refs resueltas,
  resolves_to_refs), determinista, IPv6 -> ipv6-addr.
- Server: /api/evidence/chain y /api/evidence/stix bajan el fichero;
  ventana vacia -> 404.

Ejecutar desde la raiz:  python -m unittest discover tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import evidence  # noqa: E402
import server  # noqa: E402
from store import Store  # noqa: E402


def _ev(id_, proc="python.exe", ip="1.2.3.4", port=443, host=None,
        sni=None, img="", first="2026-09-20 10:00:00.000",
        last="2026-09-20 10:05:00.000"):
    return {
        "id": id_, "ts": first, "process": proc, "dest_ip": ip,
        "dest_port": port, "dest_host": host, "catalog_domain": None,
        "protocol": "tcp", "image": img, "sni_domain": sni,
        "ai_layer": "catalog", "seen_count": 3,
        "first_seen": first, "last_seen": last,
    }


EVS = [
    _ev(1, ip="1.2.3.4", port=443, host="openai.com", sni="api.openai.com",
        img=r"C:\x\python.exe"),
    _ev(2, proc="node.exe", ip="2001:db8::1", port=8443, host=None),
]


class TestHashChain(unittest.TestCase):
    def test_deterministic_and_linked(self):
        a = evidence.hash_chain(EVS)
        b = evidence.hash_chain([dict(e) for e in EVS])
        self.assertEqual(a, b)
        self.assertEqual(a[0]["prev"], evidence.GENESIS)
        self.assertEqual(a[1]["prev"], a[0]["hash"])
        self.assertTrue(evidence.verify_chain(a))

    def test_tamper_event_breaks(self):
        rows = evidence.hash_chain(EVS)
        rows[0]["event"]["dest_ip"] = "9.9.9.9"
        self.assertFalse(evidence.verify_chain(rows))

    def test_tamper_hash_breaks(self):
        rows = evidence.hash_chain(EVS)
        rows[1]["hash"] = "f" * 64
        self.assertFalse(evidence.verify_chain(rows))

    def test_drop_or_reorder_breaks(self):
        rows = evidence.hash_chain(EVS)
        self.assertFalse(evidence.verify_chain(rows[1:]))
        self.assertFalse(evidence.verify_chain(list(reversed(rows))))

    def test_single_event(self):
        rows = evidence.hash_chain([EVS[0]])
        self.assertTrue(evidence.verify_chain(rows))


class TestStixBundle(unittest.TestCase):
    def test_structure_and_refs(self):
        b = evidence.stix_bundle(EVS)
        self.assertEqual(b["type"], "bundle")
        self.assertTrue(b["id"].startswith("bundle--"))
        objs = {o["id"]: o for o in b["objects"]}
        # Todo SDO: type/id/created/modified y prefijo de id coherente.
        for o in b["objects"]:
            self.assertTrue(o["id"].startswith(o["type"] + "--"))
            self.assertIn("created", o)
            self.assertIn("modified", o)
        # Refs resueltas en cada network-traffic.
        nts = [o for o in b["objects"] if o["type"] == "network-traffic"]
        self.assertEqual(len(nts), 2)
        for nt in nts:
            self.assertIn(nt["src_ref"], objs)
            self.assertIn(nt["dst_ref"], objs)
            self.assertIn(nt["dst_port"], objs)
        # IPv4 e IPv6 por tipo.
        types = {o["type"] for o in b["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("ipv6-addr", types)
        self.assertIn("process", types)
        self.assertIn("port", types)
        self.assertIn("domain-name", types)
        self.assertIn("report", types)
        # El dominio se enlaza a la IP via resolves_to_refs.
        dom = next(o for o in b["objects"]
                   if o["type"] == "domain-name")
        ip4 = objs[nts[0]["dst_ref"]]
        self.assertEqual(ip4["type"], "ipv4-addr")
        self.assertIn(dom["id"], ip4.get("resolves_to_refs", []))

    def test_deterministic(self):
        a = evidence.stix_bundle(EVS)
        b = evidence.stix_bundle([dict(e) for e in EVS])
        self.assertEqual(
            json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_empty_events_ok(self):
        b = evidence.stix_bundle([])
        self.assertEqual(b["type"], "bundle")
        self.assertEqual(len(b["objects"]), 1)  # solo el report


class EvidenceServerBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "t.db")
        self._old_store = server.store
        server.store = self.store

    def tearDown(self) -> None:
        server.store = self._old_store
        self.store.close()
        self.tmp.cleanup()


class TestEvidenceEndpoints(EvidenceServerBase):
    def _seed(self) -> None:
        self.store.observe_connection(
            process="python.exe", dest_ip="1.2.3.4", dest_port=443,
            dest_host="openai.com", catalog_domain="openai.com",
            ai_layer="catalog")

    def test_chain_download(self):
        self._seed()
        resp = server.evidence_chain(days=7)
        self.assertEqual(resp.media_type, "application/x-ndjson")
        lines = [l for l in resp.body.decode("utf-8").splitlines() if l]
        self.assertTrue(lines)
        rows = [json.loads(l) for l in lines]
        self.assertTrue(evidence.verify_chain(rows))

    def test_stix_download(self):
        self._seed()
        resp = server.evidence_stix(days=7)
        self.assertIn("stix+json", resp.media_type)
        b = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(b["type"], "bundle")
        types = {o["type"] for o in b["objects"]}
        self.assertIn("network-traffic", types)

    def test_empty_window_404(self):
        with self.assertRaises(server.HTTPException):
            server.evidence_chain(days=7)
        with self.assertRaises(server.HTTPException):
            server.evidence_stix(days=7)
