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
_NO_INPUT_MARGIN_S = 60   # idle >= uptime - margen: sin entrada desde el boot


_last_probe: tuple[float, int] | None = None  # (monotonic, ms) del probe previo
_last_signal_note: str | None = None  # etiqueta de la senal idle (display-only)


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


def _uptime_ms() -> int | None:
    """Milisegundos desde el boot (GetTickCount64). None si no hay."""
    try:
        k32 = ctypes.windll.kernel32
        v = int(k32.GetTickCount64())
        return v if v > 0 else None
    except Exception:
        return None


def get_idle_seconds() -> int | None:
    """Segundos desde la ultima entrada del usuario (global).

    Dos guardas de honestidad (nunca inventar autonomia):
    - idle > uptime es imposible: valor basura (p. ej. sesion sin entrada
      reportando un contador viejo) -> None de inmediato.
    - Auto-diagnostico de vida: si el contador no avanza con el tiempo
      real (delta 0 entre probes), la senal no es confiable -> None.
    La etiqueta del estado queda visible via idle_signal_note()
    (display-only; el veredicto solo ve los segundos o la None).
    """
    global _last_probe, _last_signal_note
    if sys.platform != "win32":
        _last_signal_note = "no_win"
        return None
    ms = _probe_ms()
    if ms is None:
        _last_signal_note = "api_error"
        return None
    up = _uptime_ms()
    if up is not None and ms > up:
        # Imposible: mas idle que uptime. Basura -> no confiable.
        _last_probe = (time.monotonic(), ms)
        _last_signal_note = "idle_gt_uptime"
        return None
    now = time.monotonic()
    if _last_probe is not None:
        prev_t, prev_ms = _last_probe
        dt = now - prev_t
        if dt >= 1.0 and (ms - prev_ms) == 0:
            # Congelado: sesion sin entrada. No confiable.
            _last_probe = (now, ms)
            _last_signal_note = "counter_frozen"
            return None
    note: str | None = None
    # Guard de arranque fresco: con uptime < margen no hay suficiente
    # contexto para etiquetar (evita falsos positivos los primeros
    # segundos del boot).
    if up is not None and up >= _NO_INPUT_MARGIN_S * 1000 \
            and ms >= up - _NO_INPUT_MARGIN_S * 1000:
        # Ultima entrada en el arranque (o antes): sesion sin HID. La
        # senal va (el numero es valido); la nota lo etiqueta.
        note = "no_input_since_boot"
    _last_probe = (now, ms)
    _last_signal_note = note
    return int(ms // 1000)


def idle_signal_note() -> str | None:
    """Etiqueta del estado de la senal idle (None si va sin matiz).

    Display-only: sirve para etiquetar el estado en el panel/autonomia
    en vez de dejar un '?' silencioso o un numero sin contexto.
    Valores: no_win, api_error, idle_gt_uptime, counter_frozen
    (los cuatro con senal None) y no_input_since_boot (senal valida:
    nadie ha tecleado desde el arranque, p. ej. sesion sin HID).
    """
    return _last_signal_note


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


class _PROCESSENTRY32(ctypes.Structure):
    """PROCESSENTRY32W (tlhelp32.h), layout verificado empiricamente contra
    la API: dwSize + 9 DWORDs (Flags, LinkCount, ProcessID, ThreadID,
    InheritedHandle, ParentPID, PriorityClass, BasePriority, ContiguousItems),
    szExeFile[260] en offset 40 y cola hasta el dwSize que Process32First
    acepta (312). El struct minimo (dwSize+szExeFile) falla con
    ERROR_MORE_DATA (24)."""

    _fields_ = [("dwSize", ctypes.c_uint),
                ("ContiguousItems", ctypes.c_uint),
                ("Flags", ctypes.c_uint),
                ("LinkCount", ctypes.c_uint),
                ("ProcessID", ctypes.c_uint),
                ("ThreadID", ctypes.c_uint),
                ("InheritedHandle", ctypes.c_uint),
                ("ParentPID", ctypes.c_uint),
                ("PriorityClass", ctypes.c_ulong),
                ("BasePriority", ctypes.c_ulong),
                ("szExeFile", ctypes.c_char * 260),
                ("_tail", ctypes.c_char * 12)]


def _process_snapshot() -> list[tuple[int, str]] | None:
    """Snapshot de procesos: [(pid, nombre_exe_bajo), ...]. None si no se
    puede (no-Windows o fallo)."""
    if sys.platform != "win32":
        return None
    try:
        k32 = ctypes.windll.kernel32
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)
        if not snap:
            return None
        out: list[tuple[int, str]] = []
        try:
            entry = _PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            if not k32.Process32First(snap, ctypes.byref(entry)):
                return None
            while True:
                name = (bytes(entry.szExeFile).split(b"\x00")[0]
                        .decode("utf-8", "ignore").lower())
                out.append((int(entry.ProcessID), name))
                entry.dwSize = ctypes.sizeof(entry)
                if not k32.Process32Next(snap, ctypes.byref(entry)):
                    break
            return out
        finally:
            k32.CloseHandle(snap)
    except Exception:
        return None


def pid_name_map() -> dict[int, str]:
    """{pid: nombre_exe} de todos los procesos. Vacio si no se puede."""
    snap = _process_snapshot()
    return dict(snap) if snap else {}


def is_session_locked() -> bool | None:
    """Sesion bloqueada / pantalla apagada = LogonUI.exe corriendo.

    None si no se puede determinar (no-Windows o fallo de snapshot)."""
    snap = _process_snapshot()
    if snap is None:
        return None
    return any(name == "logonui.exe" for _, name in snap)


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
