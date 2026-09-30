"""Portable server encryption with legacy Windows DPAPI read support."""
import os
import base64
import ctypes
from ctypes import wintypes

def is_protected(value):
    return isinstance(value, str) and value.startswith(("dpapi:", "fernet:"))

def _portable_cipher():
    key = os.environ.get("SUBTOOLS_SECRET_KEY")
    path = os.environ.get("SUBTOOLS_SECRET_KEY_FILE")
    if not key and path:
        from pathlib import Path
        key = Path(path).read_text(encoding="ascii").strip()
    if key:
        from cryptography.fernet import Fernet
        return Fernet(key.encode("ascii"))
    return None

def protect_secret(value: str) -> str:
    """Use the configured Fernet server key, otherwise Windows DPAPI.

    The ``dpapi:`` prefix makes the format explicit and lets older plaintext
    settings continue to be read and migrated. Unsupported or failed encryption
    deliberately returns an empty value; credentials must never fall back to
    plaintext on disk.
    """
    value = str(value or "")
    if value and (os.environ.get("SUBTOOLS_SECRET_KEY") or os.environ.get("SUBTOOLS_SECRET_KEY_FILE")):
        return "fernet:" + _portable_cipher().encrypt(value.encode("utf-8")).decode("ascii")
    if not value or os.name != "nt":
        return ""
    try:
        class _Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        raw = value.encode("utf-8")
        src = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        in_blob = _Blob(len(raw), src)
        out_blob = _Blob()
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            return ""
        try:
            encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return "dpapi:" + base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return ""


def unprotect_secret(value: str) -> str:
    value = str(value or "")
    if value.startswith("fernet:"):
        try:
            return _portable_cipher().decrypt(value[7:].encode("ascii")).decode("utf-8")
        except Exception:
            return ""
    if not value.startswith("dpapi:"):
        return value
    if os.name != "nt":
        return ""
    try:
        class _Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        raw = base64.b64decode(value[6:].encode("ascii"), validate=True)
        src = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        in_blob = _Blob(len(raw), src)
        out_blob = _Blob()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            return ""
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8")
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""
