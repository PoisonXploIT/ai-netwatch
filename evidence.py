"""v2.3: Evidence exportable — cadena de hashes + bundle STIX 2.1.

Cadena de hashes: ledger append-only sobre los eventos. Cada fila liga
indice + hash anterior + evento; alterar cualquier evento rompe todas
las filas siguientes y es verificable offline (verify_chain) sin ningun
estado extra. Genesis fijo (64 ceros), documentado.

STIX 2.1: bundle con objetos network-traffic / process / ipv4-addr /
ipv6-addr / port / domain-name + report (metadatos). IDs deterministas
(uuid5 sobre clave estable): mismos eventos -> mismo bundle, reproducible
para evidencia. Sin librerias externas: STIX es JSON puro.

Modulo puro: sin IO; el servidor solo serializa y baja el fichero.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid

GENESIS = "0" * 64

_STIX_VERSION = "2.1"
_ID_NS = uuid.NAMESPACE_URL


def _canon(obj: object) -> str:
    """JSON canónico (claves ordenadas, sin espacios): estable y único."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def hash_chain(events: list[dict]) -> list[dict]:
    """Cadena de hashes sobre `events` (orden dado; el servidor los ordena
    por first_seen/id). Fila i = {i, prev, hash, event} donde
    hash = sha256(canonical({i, prev, event})) y prev = hash anterior
    (GENESIS para la primera)."""
    rows: list[dict] = []
    prev = GENESIS
    for i, ev in enumerate(events):
        h = hashlib.sha256(
            _canon({"i": i, "prev": prev, "event": ev}).encode("utf-8")
        ).hexdigest()
        rows.append({"i": i, "prev": prev, "hash": h, "event": ev})
        prev = h
    return rows


def verify_chain(rows: list[dict]) -> bool:
    """Recomputa la cadena y comprueba indices, encadenado y hashes.
    True si toda la cadena es coherente; False en cualquier alteracion."""
    prev = GENESIS
    for k, r in enumerate(rows):
        if not isinstance(r, dict) or r.get("i") != k:
            return False
        if r.get("prev") != prev:
            return False
        h = hashlib.sha256(
            _canon({"i": k, "prev": prev, "event": r.get("event")}
                   ).encode("utf-8")).hexdigest()
        if r.get("hash") != h:
            return False
        prev = h
    return True


def _stix_id(stype: str, key: str) -> str:
    """ID STIX determinista: <tipo>--<uuid5(espacio fijo, clave estable)>."""
    u = uuid.uuid5(_ID_NS, "ai-netwatch:" + key)
    return f"{stype}--{u.hex}"


def _iso(ts: str) -> str:
    """Timestamp del store ('YYYY-MM-DD HH:MM:SS.mmm') a ISO-8601."""
    t = str(ts or "").strip()
    if not t:
        return "1970-01-01T00:00:00"
    return t.replace(" ", "T", 1)


def _addr_type(ip: str) -> str:
    try:
        return "ipv4-addr" if ipaddress.ip_address(ip).version == 4 \
            else "ipv6-addr"
    except ValueError:
        return "ipv4-addr"


def stix_bundle(events: list[dict], title: str = "",
                description: str = "") -> dict:
    """Bundle STIX 2.1 sobre `events` (orden dado).

    Un objeto por entidad unica (process por imagen, addr por IP, port
    por ip:puerto, domain por hostname) + un network-traffic por evento
    + report con metadatos. Determinista: mismos eventos -> mismo bundle."""
    objects: dict[str, dict] = {}

    def add(obj: dict) -> None:
        objects[obj["id"]] = obj

    nt_refs: list[str] = []
    firsts: list[str] = []
    lasts: list[str] = []
    for i, ev in enumerate(events):
        ip = str(ev.get("dest_ip") or "")
        try:
            port = int(ev.get("dest_port") or 0)
        except (TypeError, ValueError):
            port = 0
        proc = str(ev.get("process") or "?")
        img = str(ev.get("image") or "")
        proto = str(ev.get("protocol") or "tcp").lower()
        first = _iso(str(ev.get("first_seen") or ""))
        last = _iso(str(ev.get("last_seen") or ""))
        firsts.append(first)
        lasts.append(last)

        # process (por imagen; sin ruta, por nombre)
        pkey = img or proc
        pid_ = _stix_id("process", f"proc:{pkey}")
        if pid_ not in objects:
            name = pkey.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            obj = {"type": "process", "spec_version": _STIX_VERSION,
                   "id": pid_, "created": first, "modified": last,
                   "name": name}
            if img:
                obj["path"] = img
            add(obj)

        # dominio (SNI > dest_host), enlazado a la IP via resolves_to_refs
        host = str(ev.get("sni_domain") or ev.get("dest_host") or "").lower()
        dom_id: str | None = None
        if host:
            dom_id = _stix_id("domain-name", f"dom:{host}")
            if dom_id not in objects:
                add({"type": "domain-name", "spec_version": _STIX_VERSION,
                     "id": dom_id, "created": first, "modified": last,
                     "value": host})

        # direccion destino (+resolves_to si hay dominio)
        atype = _addr_type(ip)
        aid = _stix_id(atype, f"ip:{ip}")
        addr = objects.get(aid)
        if addr is None:
            addr = {"type": atype, "spec_version": _STIX_VERSION,
                    "id": aid, "created": first, "modified": last,
                    "value": ip}
            if dom_id:
                addr["resolves_to_refs"] = [dom_id]
            add(addr)
        elif dom_id and dom_id not in addr.get("resolves_to_refs", []):
            refs = list(addr.get("resolves_to_refs") or [])
            refs.append(dom_id)
            addr["resolves_to_refs"] = refs

        # puerto
        port_id = _stix_id("port", f"port:{ip}:{port}")
        if port_id not in objects:
            add({"type": "port", "spec_version": _STIX_VERSION,
                 "id": port_id, "created": first, "modified": last,
                 "value": port})

        # network-traffic (uno por evento)
        nkey = f"nt:{proc}|{ip}|{port}|{proto}|{first}"
        nid = _stix_id("network-traffic", nkey)
        add({"type": "network-traffic", "spec_version": _STIX_VERSION,
             "id": nid, "created": first, "modified": last,
             "src_ref": pid_, "dst_ref": aid, "dst_port": port_id,
             "protocol": proto})
        nt_refs.append(nid)

    # report: metadatos del bundle (nombre/descripcion + refs al trafico)
    created = min(firsts) if firsts else "1970-01-01T00:00:00"
    modified = max(lasts) if lasts else "1970-01-01T00:00:00"
    add({"type": "report", "spec_version": _STIX_VERSION,
         "id": _stix_id("report", "report"), "created": created,
         "modified": modified,
         "name": title or "AI-NETWATCH evidencia",
         "description": description or "",
         "object_refs": nt_refs})

    return {"type": "bundle", "id": _stix_id("bundle", "bundle"),
            "objects": list(objects.values())}
