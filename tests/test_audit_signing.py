# EN: Faz-1 — Ed25519-signed audit entries + Merkle checkpoint.
# Turkce not: imzali kayit dogrulanir; imza kurcalanirsa zincir bozuk; public key ile BAGIMSIZ
# dogrulama calisir; imza anahtarsiz (legacy) yol yalniz hash-zinciriyle gecerli kalir; checkpoint
# Merkle kokunu saklar.
import sqlite3

from src.vault import schema
from src.vault.audit import AuditChain


def test_signed_entry_verifies_and_independent_pubkey(vault):
    ac = vault.audit_chain
    ac.record("agentA", "profile_read", {"k": "v"})
    ac.record("agentB", "profile_write", {"k": "v2"})
    assert ac.verify_chain() is True

    row = vault.get_connection().execute(
        "SELECT entry_hash, signature FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    entry_hash, sig = row[0], row[1]
    assert sig is not None  # imzalandi

    pub = vault.audit_public_key_hex()
    assert AuditChain.verify_entry_signature(entry_hash, sig, pub) is True
    assert AuditChain.verify_entry_signature(entry_hash, sig, "00" * 32) is False   # yanlis anahtar
    assert AuditChain.verify_entry_signature("deadbeef", sig, pub) is False          # yanlis mesaj


def test_signature_tamper_detected(vault):
    ac = vault.audit_chain
    ac.record("agentA", "x", {})
    conn = vault.get_connection()
    rid, sig = conn.execute("SELECT id, signature FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    bad = ("f" if sig[0] != "f" else "0") + sig[1:]   # gecerli hex, gecersiz imza
    conn.execute("UPDATE audit SET signature=? WHERE id=?", (bad, rid))
    conn.commit()
    assert ac.verify_chain() is False


def test_legacy_unsigned_still_hash_verifies():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(schema.CREATE_AUDIT_TABLE)
    conn.execute(schema.CREATE_AUDIT_CHECKPOINT_TABLE)
    conn.commit()
    ac = AuditChain(conn)  # signing_key YOK
    ac.record("a", "x", {})
    assert ac.verify_chain() is True
    assert conn.execute("SELECT signature FROM audit LIMIT 1").fetchone()[0] is None  # NULL
    conn.execute("UPDATE audit SET action='tampered' WHERE id=1")
    conn.commit()
    assert ac.verify_chain() is False   # hash-zinciri hala koruyor


def test_checkpoint_stores_merkle_root(vault):
    ac = vault.audit_chain
    ac.record("a", "x", {})
    ac.record("b", "y", {})
    cp = ac.create_checkpoint()
    assert cp["status"] == "success"
    root = cp.get("merkle_root")
    assert root and len(root) == 64   # sha256 hex
    stored = vault.get_connection().execute(
        "SELECT merkle_root FROM audit_checkpoint ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert stored == root
