"""Humo contra el servidor vivo (solo stdlib). Uso: python tools/smoke.py"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8790"
NEED = ("content-security-policy", "x-content-type-options", "x-frame-options",
        "referrer-policy", "permissions-policy", "cross-origin-opener-policy")


def get(path: str):
    try:
        with urllib.request.urlopen(BASE + path, timeout=5) as r:
            return r.status, dict((k.lower(), v) for k, v in r.headers.items()), r.read()
    except urllib.error.HTTPError as e:
        return e.code, {}, b""


def main() -> int:
    bad = []
    status, headers, body = get("/api/health")
    if status != 200:
        bad.append(f"/api/health -> {status}")
    else:
        h = json.loads(body)
        print("version", h.get("version"), "| estado", h.get("status"),
              "| monitor", h.get("monitoring_enabled"), "| eventos", h.get("events"))
    for name in NEED:
        if name not in headers:
            bad.append(f"falta cabecera {name}")
    if "unsafe-inline" in headers.get("content-security-policy", ""):
        bad.append("CSP con unsafe-inline")
    for path in ("/api/llm/calls", "/api/export/json", "/api/evidence/chain"):
        code = get(path)[0]
        if code != 403:
            bad.append(f"{path} sin token -> {code} (esperado 403)")
    for line in bad:
        print("FALLA", line)
    print("OK" if not bad else f"{len(bad)} fallo(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
