# kasa/src/vault/encryption.py

"""
KASA - Platform Bağımsız Anahtar Koruması (DPAPI & Fallback KDF)

- Windows: Windows DPAPI (CryptProtectData) ile kullanıcı oturumuna bağlı donanım/işletim sistemi seviyesinde şifreleme.
- Linux / macOS / Container: `cryptography` tabanlı AES-GCM / PBKDF2 fallback anahtar yöneticisi.
  Asla düz metin (plaintext) bırakılmaz; makine kimliğine (machine-id) ve yerel vault anahtarına bağlanır.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import hashlib
import os
import platform
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char))
        ]

    crypt_protect_data = ctypes.windll.crypt32.CryptProtectData
    crypt_protect_data.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB)
    ]
    crypt_protect_data.restype = ctypes.wintypes.BOOL

    crypt_unprotect_data = ctypes.windll.crypt32.CryptUnprotectData
    crypt_unprotect_data.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(ctypes.wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB)
    ]
    crypt_unprotect_data.restype = ctypes.wintypes.BOOL

    local_free = ctypes.windll.kernel32.LocalFree
    local_free.argtypes = [ctypes.wintypes.HLOCAL]
    local_free.restype = ctypes.wintypes.HLOCAL


def _get_fallback_machine_key() -> bytes:
    """Linux/macOS/Docker ortamları için donanım/ortam türevli anahtar üretir."""
    env_key = os.environ.get("KASA_MASTER_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()

    # /etc/machine-id veya hostname tabanlı deterministik tuz
    seed = platform.node() or "kasa-default-seed"
    machine_id_path = "/etc/machine-id"
    if os.path.exists(machine_id_path):
        try:
            with open(machine_id_path, "r") as f:
                seed += f.read().strip()
        except Exception:
            pass

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"kasa_sovereign_ai_salt_v1",
        iterations=100_000,
    )
    return kdf.derive(seed.encode("utf-8"))


def protect_data(data: bytes, description: str = "Kasa Anahtarı") -> bytes:
    """Verilen byte dizisini Windows'ta DPAPI, diğer platformlarda AES-256-GCM ile şifreler."""
    if IS_WINDOWS:
        blob_in = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if crypt_protect_data(
            ctypes.byref(blob_in),
            description,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out)
        ):
            encrypted_data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            local_free(blob_out.pbData)
            return encrypted_data
        else:
            raise RuntimeError("DPAPI ile veri şifreleme başarısız oldu.")
    else:
        # Non-Windows Fallback: AES-256-GCM
        key = _get_fallback_machine_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, description.encode("utf-8"))
        # Format: b"KASAGCM:" + nonce + ciphertext
        return b"KASAGCM:" + nonce + ciphertext


def unprotect_data(encrypted_data: bytes, description: str = "Kasa Anahtarı") -> bytes:
    """Şifrelenmiş veriyi platformuna göre çözer."""
    if encrypted_data.startswith(b"KASAGCM:"):
        raw = encrypted_data[len(b"KASAGCM:"):]
        nonce = raw[:12]
        ciphertext = raw[12:]
        key = _get_fallback_machine_key()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, description.encode("utf-8"))

    if IS_WINDOWS:
        blob_in = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if crypt_unprotect_data(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out)
        ):
            decrypted_data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            local_free(blob_out.pbData)
            return decrypted_data
        else:
            raise RuntimeError("DPAPI ile veri çözme başarısız oldu.")
    else:
        raise RuntimeError("Windows DPAPI ile şifrelenmiş veri Linux/macOS ortamında çözülemez.")
