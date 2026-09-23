"""Fuente de dominios reales via tshark (SNI en ClientHello TLS).

Por que existe: la caché DNS y la resolucion activa del catalogo dan el
dominio "mejor esfuerzo"; el SNI es lo que el cliente dice realmente en el
handshake, y funciona incluso con CNAME/CDN (api.deepseek.com sobre una
IP de CloudFront).

v2.5 (N1): tambien cubre QUIC/HTTP-3. El primer paquete Initial de QUIC
va cifrado con clave fija derivable, asi que tshark 4.x descompone su
frame CRYPTO como TLS y el SNI sale en los mismos campos
(`tls.handshake.*`). Un solo proceso captura TCP+UDP 443 a la vez.
Nota BPF/Npcap: `(tcp or udp) port 443` NO se parsea; lo valido es
`udp port 443 or tcp port 443` (medido).

Hechos medidos en esta maquina (tshark 4.6.6, Npcap):
- Captura SIN elevar en la interfaz fisica (Wi-Fi/Ethernet).
- tshark escribe STDOUT en UTF-16LE al redirigir (Windows); se decodifica
  incremental y se tolera BOM.
- Destinos IPv6 dejan `ip.dst` vacio: por eso se emite `ipv6.dst` aparte.

El proceso tshark corre de forma continua; si muere, se relanza con
backoff. Sin tshark instalado, todo esto es inerte (fail-safe).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
from pathlib import Path
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

_IFACE_LINE = re.compile(r"^(\d+)\.\s+\\Device\\NPF_")


def tshark_path() -> str | None:
    """Ruta a tshark.exe o None."""
    found = shutil.which("tshark")
    if found:
        return found
    for cand in TSHARK_CANDIDATES:
        if Path(cand).exists():
            return cand
    return None


def list_interfaces(tshark: str) -> list[tuple[int, str]]:
    """[(indice, nombre), ...] de `tshark -D` (solo interfaces NPF reales)."""
    out = subprocess.run([tshark, "-D"], capture_output=True, timeout=15)
    text = _decode_maybe_utf16(out.stdout)
    result: list[tuple[int, str]] = []
    for line in text.splitlines():
        m = _IFACE_LINE.match(line.strip())
        if m:
            idx = int(m.group(1))
            name = line.split("(", 1)[1].rstrip(")").strip() if "(" in line else ""
            result.append((idx, name))
    return result


def _probe_interface(tshark: str, idx: int) -> bool:
    """True si la interfaz captura al menos 1 paquete TCP en ~1.5 s."""
    try:
        out = subprocess.run(
            [tshark, "-i", str(idx), "-f", "tcp", "-a", "duration:1.5",
             "-c", "1", "-l", "-T", "fields", "-e", "frame.number"],
            capture_output=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        return False
    body = _decode_maybe_utf16(out.stdout).strip()
    return bool(body)


_JUNK_IFACE_HINTS = ("vmware", "bluetooth", "virtualbox", "hyper-v")


def find_active_interface(tshark: str) -> int | None:
    """Prueba en paralelo las interfaces y devuelve la primera con trafico.

    Primera pasada sin VMware/Bluetooth/VirtualBox (adaptadores que pueden
    tener trafico propio pero no el de la maquina); si ninguna captura, se
    prueba el resto. Ninguna -> None (el monitor sigue sin SNI).
    """
    ifaces = list_interfaces(tshark)
    if not ifaces:
        return None
    first = [p for p in ifaces
             if not any(h in p[1].lower() for h in _JUNK_IFACE_HINTS)]
    rest = [p for p in ifaces if p not in first]
    for group in (first, rest):
        if not group:
            continue
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda p: _probe_interface(tshark, p[0]), group))
        for (idx, _name), ok in zip(group, results):
            if ok:
                return idx
    return None


def _looks_utf16(raw: bytes) -> bool:
    """Heuristica: UTF-16LE real llena de \x00; ASCII/UTF-8 no."""
    sample = raw[:512]
    return bool(sample) and sample.count(0) / len(sample) > 0.25


def _decode_maybe_utf16(raw: bytes) -> str:
    """tshark en Windows: UTF-16LE al redirigir a fichero, ASCII/UTF-8 por
    pipe. Se detecta por densidad de bytes nulo; tolera BOM."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if _looks_utf16(raw):
        return raw.decode("utf-16-le", errors="replace").lstrip("\ufeff")
    return raw.decode("utf-8", errors="replace")


def parse_sni_line(line: str) -> dict | None:
    """Una linea `t_rel, ip4_dst, ipv6_dst, tcpport, udpport, sni` -> record.

    Campos vacios (p. ej. destino IPv6 sin ip4; TCP sin udpport o QUIC sin
tcpport) se toleran: el puerto de destino es el primero no vacio. Si falta
el IP de destino, un puerto valido o el SNI, la linea no aporta nada y se
descarta.
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 6:
        return None
    t_rel, ip4, ip6, tcp_port, udp_port, sni = parts[:6]
    dst_ip = ip4 or ip6
    if not dst_ip or not sni:
        return None
    port_raw = tcp_port or udp_port
    try:
        port_i = int(port_raw)
    except ValueError:
        return None
    return {"t_rel": float(t_rel) if t_rel else 0.0,
            "dst_ip": dst_ip, "dst_port": port_i, "sni": sni}


class SniCapture(threading.Thread):
    """Proceso tshark continuo que emite records {dst_ip, dst_port, sni}.

    Comando (medido y verificado en vivo; TCP TLS + QUIC/HTTP-3):
      tshark -i <iface> -f "udp port 443 or tcp port 443"
             -Y "tls.handshake.type==1" -l
             -T fields -E separator=, -e frame.time_relative -e ip.dst
             -e ipv6.dst -e tcp.dstport -e udp.dstport
             -e tls.handshake.extensions_server_name
    En QUIC el SNI sale del paquete Initial (CRYPTO descompuesto como
    TLS) y el puerto llega en udp.dstport.
    """

    def __init__(self, tshark: str, iface: int):
        if iface is None:
            raise ValueError("no hay interfaz activa para capturar")
        super().__init__(name="sni-capture", daemon=True)
        self._tshark = tshark
        self._iface = iface
        self._q: Queue[dict] = Queue()
        self._stop = threading.Event()
        self._proc: subprocess.Popen | None = None
        self.last_error = ""

    def _spawn(self) -> subprocess.Popen:
        return subprocess.Popen(
            [self._tshark, "-i", str(self._iface),
             "-f", "udp port 443 or tcp port 443",
             "-Y", "tls.handshake.type==1",
             "-l", "-T", "fields", "-E", "separator=,",
             "-e", "frame.time_relative",
             "-e", "ip.dst", "-e", "ipv6.dst",
             "-e", "tcp.dstport", "-e", "udp.dstport",
             "-e", "tls.handshake.extensions_server_name"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def run(self) -> None:  # noqa: PLR6204 - bucle con backoff
        import time
        backoff = 5.0
        while not self._stop.is_set():
            proc = self._spawn()
            self._proc = proc
            if proc.stdout is None:
                break
            first_checked = False
            try:
                # readline() SI entrega en vivo; read(n) se bloquea en
                # pipes de Windows (verificado). Por pipe tshark emite
                # ASCII/UTF-8; UTF-16 solo ocurre con redirección a
                # fichero, que aquí no usamos.
                while not self._stop.is_set():
                    line = proc.stdout.readline()
                    if not line:
                        break
                    if not first_checked:
                        first_checked = True
                        if _looks_utf16(line):
                            self.last_error = (
                                "tshark emite UTF-16 por pipe (se esperaba"
                                " ASCII); SNI inactivo")
                            return
                    text = line.decode("utf-8", "replace")
                    rec = parse_sni_line(text.replace("\r", ""))
                    if rec:
                        self._q.put(rec)
            finally:
                # Nunca dejar huérfanos: un tshark vivo interfiere con los
                # probes de interfaz y consume el dispositivo Npcap.
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
            if not self._stop.is_set():
                self.last_error = f"tshark exito {proc.returncode}"
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    def poll_records(self) -> list[dict]:
        out: list[dict] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except Exception:
                return out

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.kill()
            except (ProcessLookupError, OSError):
                pass


def sni_available() -> bool:
    return tshark_path() is not None
