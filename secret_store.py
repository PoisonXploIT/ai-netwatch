"""Cifrado en reposo de secretos con DPAPI de Windows (solo ctypes).

Objetivo: la API key de Jev no debe quedar en claro en `data/config.json`.
DPAPI (`CryptProtectData`/`CryptUnprotectData`) cifra el secreto ligado a la
cuenta de usuario de Windows: el blob solo se descifra en la misma cuenta y
maquina. Cero dependencias (ctypes stdlib), coherente con el resto del tool.

Fail-safe: si DPAPI no esta disponible (no-Windows) o el blob no descifra
(p. ej. `config.json` copiado a otra cuenta), se trata como "sin secreto";
nunca lanza ni rompe el arranque.
"""
from __future__ import annotations

import base64
import ctypes
import sys
from ctypes import wintypes

PREFIX = "dpapi:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """True si la plataforma soporta DPAPI (Windows)."""
    return sys.platform == "win32"


def is_protected(value: str) -> bool:
    """True si `value` es un blob DPAPI persistido ('dpapi:<b64>')."""
    return bool(value) and value.startswith(PREFIX)


def _crypt32():
    lib = ctypes.WinDLL("crypt32", use_last_error=True)
    lib.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    lib.CryptProtectData.restype = wintypes.BOOL
    lib.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    lib.CryptUnprotectData.restype = wintypes.BOOL
    return lib


def _kernel32():
    lib = ctypes.WinDLL("kernel32", use_last_error=True)
    lib.LocalFree.argtypes = [wintypes.HLOCAL]
    lib.LocalFree.restype = wintypes.HLOCAL
    return lib


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buf = ctypes.create_string_buffer(data, len(data))
    ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
    return _DataBlob(len(data), ptr), buf


def _protect(data: bytes) -> bytes | None:
    try:
        crypt32, kernel32 = _crypt32(), _kernel32()
        blob_in, _keep = _blob(data)
        blob_out = _DataBlob()
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0,
            ctypes.byref(blob_out))
        if not ok:
            return None
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))
    except Exception:
        return None


def _unprotect(data: bytes) -> bytes | None:
    try:
        crypt32, kernel32 = _crypt32(), _kernel32()
        blob_in, _keep = _blob(data)
        blob_out = _DataBlob()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0,
            ctypes.byref(blob_out))
        if not ok:
            return None
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))
    except Exception:
        return None


def protect(secret: str) -> str | None:
    """Cifra `secret` -> 'dpapi:<b64>', o None si no se puede cifrar."""
    if not secret or not available():
        return None
    blob = _protect(secret.encode("utf-8"))
    if blob is None:
        return None
    return PREFIX + base64.b64encode(blob).decode("ascii")


def unprotect(token: str) -> str | None:
    """Descifra 'dpapi:<b64>' -> str, o None si no descifra (otro usuario)."""
    if not is_protected(token) or not available():
        return None
    try:
        blob = base64.b64decode(token[len(PREFIX):])
    except (ValueError, TypeError):
        return None
    raw = _unprotect(blob)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
