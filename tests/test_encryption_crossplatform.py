# tests/test_encryption_crossplatform.py

"""
KASA - Cross-Platform Encryption Unit Tests
Doğrulanacaklar:
- Windows DPAPI şifreleme/çözme roundtrip
- Non-Windows Fallback (AES-256-GCM) roundtrip
- Canlı ortamda asla plaintext dönmemesi
"""

import pytest
from src.vault.encryption import protect_data, unprotect_data, _get_fallback_machine_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def test_encryption_roundtrip():
    """Mevcut platformda şifreleme ve çözme tam tutarlı olmalı."""
    secret = b"super_secret_kasa_vault_key_1234567890"
    encrypted = protect_data(secret, description="Test Key")
    assert encrypted != secret
    assert len(encrypted) > len(secret)

    decrypted = unprotect_data(encrypted, description="Test Key")
    assert decrypted == secret


def test_fallback_kcm_format_roundtrip():
    """Linux/macOS AESGCM formatı doğrudan test edilir."""
    secret = b"cross_platform_payload_for_linux"
    key = _get_fallback_machine_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    desc = "Linux Test Key"
    ct = aesgcm.encrypt(nonce, secret, desc.encode("utf-8"))
    payload = b"KASAGCM:" + nonce + ct

    # unprotect_data fonksiyonu KASAGCM başlığını tanımalı
    decrypted = unprotect_data(payload, description=desc)
    assert decrypted == secret
