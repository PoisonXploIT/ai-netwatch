"""R2 — Autonomia: senales de quien hace la salida a IA (v2.1).

Detectar IA no dice QUIEN decide la salida. R2 agrega el veredicto
user_driven | autonomous | scheduled | unknown por evento, derivado de
senales locales (ctypes/stdlib, sin spawns extra):

- idle global: GetLastInputInfo (segundos desde la ultima entrada).
- sesion bloqueada / pantalla apagada: presencia de LogonUI.exe.
- foreground PID: GetForegroundWindow + GetWindowThreadProcessId.
- linaje de autonomia: padre del proceso via Sysmon EID 1
  (servicio svchost / tarea programada schtasks).

Derivado: autonomy_score 0-100 + flags + veredicto, persistido por
evento. Fail-safe: cualquier senal no disponible -> None; el veredicto
degrada a 'unknown', nunca lanza ni rompe el monitor.
"""
from __future__ import annotations

import ctypes
import sys
import time

USER_DRIVEN = "user_driven"
AUTONOMOUS = "autonomous"
SCHEDULED = "scheduled"
UNKNOWN = "unknown"

_IDLE_AUTONOMOUS_S = 300  # idle >= 5 min: fuerte senal de autonomia
_IDLE_SUSPECT_S = 60      # idle >= 1 min: sospecha, no basta solo


_last_probe: tuple[float, int] | None = None  # (monotonic, ms) del probe previo


def _probe_ms() -> int | None:
    """GetLastInputInfo una sola vez -> dwMilliseconds o None."""

    class _LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint),
                    ("dwMilliseconds", ctypes.c_uint)]

    try:
        lib = ctypes.windll.user32
        info = _LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(info)
        if not lib.GetLastInputInfo(ctypes.byref(info)):
            return None
        return int(info.dwMilliseconds)
    except Exception:
        return None


def get_idle_seconds() -> int | None:
    """Segundos desde la ultima entrada del usuario (global).

    Auto-diagnostico de vida: si el contador no avanza con el tiempo real
    (delta 0 entre probes), el monitor corre en una sesion sin entrada
    (servicio/sesion 0) y el valor NO es confiable -> None. Nunca inventa:
    una senal inutil degrada a unknown, no a autonomia falsa.
    """
    if sys.platform != "win32":
        return None
    global _last_probe
    ms = _probe_ms()
    if ms is None:
        return None
    now = time.monotonic()
    if _last_probe is not None:
        prev_t, prev_ms = _last_probe
        dt = now - prev_t
        if dt >= 1.0 and (ms - prev_ms) == 0:
            # Congelado: sesion sin entrada. No confiable.
            _last_probe = (now, ms)
            return None
    _last_probe = (now, ms)
    return int(ms // 1000)


def get_foreground_pid() -> int | None:
    """PID del proceso con la ventana en primer plano."""
    if sys.platform != "win32":
        return None
    try:
        lib = ctypes.windll.user32
        hwnd = lib.GetForegroundWindow()
        if not hwnd:
            return None
        pid = ctypes.c_uint(0)
        if not lib.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
            return None
        return int(pid.value) or None
    except Exception:
        return None


def is_session_locked() -> bool | None:
    """Sesion bloqueada / pantalla apagada = LogonUI.exe corriendo.

    None si no se puede determinar (no-Windows o fallo de snapshot)."""
    if sys.platform != "win32":
        return None
    try:
        k32 = ctypes.windll.kernel32
        TH32CS_SNAPPROCESS = 0x2

        # Layout verificado empiricamente contra la API (tlhelp32.h):
        # 10 DWORDs, szExeFile[260] en offset 44, y cola hasta el dwSize
        # que Process32First acepta (312). El struct minimo
        # (dwSize+szExeFile) falla con ERROR_MORE_DATA (24).
        class _PROCESSENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", ctypes.c_uint),
                        ("_pad", ctypes.c_uint * 9),
                        ("szExeFile", ctypes.c_char * 260),
                        ("_tail", ctypes.c_char * 12)]

        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap:
            return None
        try:
            entry = _PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            if not k32.Process32First(snap, ctypes.byref(entry)):
                return None
            found = False
            while True:
                name = (bytes(entry.szExeFile).split(b"\x00")[0]
                        .decode("utf-8", "ignore").lower())
                if name == "logonui.exe":
                    found = True
                    break
                entry.dwSize = ctypes.sizeof(entry)
                if not k32.Process32Next(snap, ctypes.byref(entry)):
                    break
            return found
        finally:
            k32.CloseHandle(snap)
    except Exception:
        return None


def evaluate(process: str, pid: int | None = None, *,
             idle_seconds: int | None = None,
             locked: bool | None = None,
             foreground_pid: int | None = None,
             parent_image: str | None = None,
             parent_process: str | None = None,
             parent_cmdline: str | None = None) -> dict:
    """Deriva la autonomia de un evento. Funcion pura (senales inyectadas):
    testable sin Windows. Devuelve {score, flags, verdict}."""
    flags: list[str] = []
    score = 0
    if locked:
        score += 50
        flags.append("session_locked")
    elif idle_seconds is not None:
        if idle_seconds >= _IDLE_AUTONOMOUS_S:
            score += 30
            flags.append(f"user_idle_{idle_seconds}s")
        elif idle_seconds >= _IDLE_SUSPECT_S:
            score += 15
            flags.append(f"user_idle_{idle_seconds}s")
    # no_foreground solo cuenta con el usuario ausente (>=60 s): un navegador
    # multiproceso con el usuario activo no debe dar falsos positivos.
    if (foreground_pid is not None and pid is not None
            and foreground_pid != pid
            and idle_seconds is not None
            and idle_seconds >= _IDLE_SUSPECT_S):
        score += 10
        flags.append("no_foreground")
    pi = (parent_image or "").lower()
    pp = (parent_process or "").lower()
    pc = (parent_cmdline or "").lower()
    if "schtasks" in pc or "task scheduler" in pc or pp == "tasks.exe":
        score += 40
        flags.append("scheduled_task")
    elif "svchost" in pi:
        score += 25
        flags.append("service_parent")
    score = min(score, 100)
    if "scheduled_task" in flags:
        verdict = SCHEDULED
    elif (locked or (idle_seconds is not None
                     and idle_seconds >= _IDLE_AUTONOMOUS_S)
            or score >= 60):
        # Bloqueo o ausencia del usuario (>=5 min) son autonomia por si
        # mismas; el resto de combinaciones puntuan hasta el umbral.
        verdict = AUTONOMOUS
    elif (locked is False and idle_seconds is not None
            and idle_seconds < _IDLE_SUSPECT_S):
        verdict = USER_DRIVEN
    else:
        verdict = UNKNOWN
    return {"score": score, "flags": flags, "verdict": verdict}
