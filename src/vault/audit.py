# kasa/src/vault/audit.py

"""
Değişmez, hash-zincirli denetim (audit) kaydı mekanizması.
Her yeni kayıt, bir önceki kaydın hash'ini içerir, bu da
aradan kayıt silmeyi veya değiştirmeyi tespit edilebilir kılar.
"""

import sqlite3
import hashlib
import time
import json

def _merkle_root(hashes: list) -> str:
    """SHA-256 binary Merkle root over hex leaf hashes (odd level duplicates the last node).

    Turkce not (Faz-1): checkpoint, kapsanan tum entry_hash'lere TEK bir kok ile baglanir;
    ileride belli bir kaydin dahil oldugu inclusion-proof uretilebilir. Bos liste -> sabit tohum.
    """
    if not hashes:
        return hashlib.sha256(b"empty-merkle").hexdigest()
    level = [hashlib.sha256(h.encode("utf-8")).digest() for h in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


class AuditChain:
    def __init__(self, connection: sqlite3.Connection, key: bytes = None, signing_key=None):
        """
        AuditChain'i başlatır.

        Args:
            connection: Aktif veritabanı bağlantısı.
            key: (L2) verilirse audit.details ENCRYPT-THEN-HASH ile at-rest sifrelenir.
                 None ise details duz metin kalir (test/legacy harness'lari icin).
            signing_key: (Faz-1) Ed25519 private key. Verilirse her kayit entry_hash uzerinden
                 IMZALANIR ve verify_chain imzayi public key ile URETICIDEN BAGIMSIZ dogrular.
                 None ise imzalama yok (legacy/test) -> yalniz hash-zinciri korunur.
        """
        self.conn = connection
        self._key = key
        self._signing_key = signing_key
        self._public_key = signing_key.public_key() if signing_key is not None else None

    @staticmethod
    def verify_entry_signature(entry_hash: str, signature_hex: str, public_key_hex: str) -> bool:
        """Independent check: is `signature_hex` a valid Ed25519 signature of `entry_hash`?"""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pk.verify(bytes.fromhex(signature_hex), entry_hash.encode("utf-8"))
            return True
        except Exception:
            return False

    def _get_last_hash(self) -> str:
        """Veritabanındaki son denetim kaydının hash'ini alır."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        if result:
            return result[0]
        # DEBI-2: tablo bos ama arsivlenmis bir zincir varsa yeni kayit genesis'ten DEGIL
        # son checkpoint muhurunden devam eder (zincir surekliligi korunur).
        try:
            cursor.execute("SELECT upto_hash FROM audit_checkpoint ORDER BY id DESC LIMIT 1")
            cp = cursor.fetchone()
            if cp:
                return cp[0]
        except sqlite3.OperationalError:
            pass  # standalone/legacy kullanim: checkpoint tablosu yok -> genesis
        # "Genesis block" hash'i
        return hashlib.sha256(b"genesis").hexdigest()

    def record(self, agent_id: str, action: str, details: dict = None) -> str:
        """
        Denetim zincirine yeni bir kayıt ekler.

        Args:
            agent_id: İşlemi yapan ajanın kimliği.
            action: Yapılan işlemin adı (örn: 'profile_read').
            details: İşlemle ilgili ek detayları içeren bir sözlük.

        Returns:
            Oluşturulan yeni denetim kaydının hash'i.
        """
        timestamp = time.time()
        details_json = json.dumps(details) if details else "{}"

        # L2 ENCRYPT-THEN-HASH: details_json'i once SIFRELE, sonra SAKLANAN (ciphertext) uzerinden
        # hash'le ve onu sakla. verify_chain saklanan baytı yeniden hash'ledigi icin DEGISMEZ
        # (yeniden sifreleme yok -> rasgele nonce verify'i bozmaz). GCM tag plaintext butunlugunu,
        # hash-zinciri ciphertext'i korur; AAD satir-takasini engeller.
        if self._key is not None:
            from .cell_crypt import encrypt_cell, aad_audit
            details_stored = encrypt_cell(details_json, self._key, aad_audit(agent_id, action, timestamp))
        else:
            details_stored = details_json

        previous_hash = self._get_last_hash()

        # Yeni kaydın hash'ini hesapla (SAKLANAN details uzerinden)
        hasher = hashlib.sha256()
        hasher.update(str(timestamp).encode('utf-8'))
        hasher.update(agent_id.encode('utf-8'))
        hasher.update(action.encode('utf-8'))
        hasher.update(details_stored.encode('utf-8'))
        hasher.update(previous_hash.encode('utf-8'))
        entry_hash = hasher.hexdigest()

        # Faz-1: entry_hash'i Ed25519 ile imzala (varsa) -> bagimsiz dogrulanabilirlik.
        signature = None
        if self._signing_key is not None:
            signature = self._signing_key.sign(entry_hash.encode("utf-8")).hex()

        # Veritabanına kaydet
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit (timestamp, agent_id, action, details, previous_hash, entry_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, agent_id, action, details_stored, previous_hash, entry_hash, signature)
        )
        self.conn.commit()

        return entry_hash

    def verify_chain(self) -> bool:
        """
        Tüm denetim zincirinin bütünlüğünü doğrular.

        Returns:
            Zincir geçerliyse True, değilse False.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, timestamp, agent_id, action, details, previous_hash, entry_hash, signature FROM audit ORDER BY id ASC")
        rows = cursor.fetchall()

        last_hash = hashlib.sha256(b"genesis").hexdigest()
        # DEBI-2 muhur tohumu: arsiv sonrasi kalan ilk satirin previous_hash'i genesis degil,
        # checkpoint muhuru olabilir. Muhur TABLODA dogrulanir (yalnizca iddia degil):
        # eslesen upto_hash + daha kucuk upto_id yoksa zincir bozuk sayilir.
        if rows and rows[0]['previous_hash'] != last_hash:
            try:
                cp = self.conn.execute(
                    "SELECT 1 FROM audit_checkpoint WHERE upto_hash = ? AND upto_id < ?",
                    (rows[0]['previous_hash'], rows[0]['id'])).fetchone()
            except sqlite3.OperationalError:
                cp = None  # checkpoint tablosu yok -> genesis bekleniyordu, uyusmadi
            if cp is not None:
                last_hash = rows[0]['previous_hash']

        for row in rows:
            # Beklenen previous_hash'i kontrol et
            if row['previous_hash'] != last_hash:
                print(f"Hata: Kayıt {row['id']} için hash zinciri bozuk! Beklenen: {last_hash}, Gelen: {row['previous_hash']}")
                return False

            # Mevcut kaydın hash'ini yeniden hesapla ve doğrula
            hasher = hashlib.sha256()
            hasher.update(str(row['timestamp']).encode('utf-8'))
            hasher.update(row['agent_id'].encode('utf-8'))
            hasher.update(row['action'].encode('utf-8'))
            hasher.update(row['details'].encode('utf-8'))
            hasher.update(row['previous_hash'].encode('utf-8'))
            recalculated_hash = hasher.hexdigest()

            if recalculated_hash != row['entry_hash']:
                print(f"Hata: Kayıt {row['id']} için içerik değiştirilmiş! Hash uyuşmazlığı.")
                return False

            # Faz-1: imza varsa Ed25519 ile bagimsiz dogrula (public key). Legacy (NULL) satir
            # -> yalniz hash-zinciri gecerli. Imza var ama gecersiz -> kurcalama, zincir bozuk.
            sig = row['signature'] if 'signature' in row.keys() else None
            if sig and self._public_key is not None:
                try:
                    self._public_key.verify(bytes.fromhex(sig), row['entry_hash'].encode('utf-8'))
                except Exception:
                    print(f"Hata: Kayıt {row['id']} imzası geçersiz (Ed25519).")
                    return False

            last_hash = recalculated_hash

        return True

    def create_checkpoint(self) -> dict:
        """
        Zinciri o anki son kayıtta MÜHÜRLER (DEBI-2 checkpoint).

        Sebep: zincir yalnızca uca ekler, aradan silinemez; sınırsız büyür.
        Sonuç: son entry_hash ayrı tabloya sabitlenir; ondan eski kayıtlar
        archive_up_to() ile silinebilir, verify_chain mühürden tohumlanır
        (T7 "değişiklik tespit edilebilir" garantisi korunur).
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, entry_hash FROM audit ORDER BY id DESC LIMIT 1")
        last = cursor.fetchone()
        if last is None:
            return {"status": "empty", "checkpoint_id": None}
        cursor.execute("SELECT entry_hash FROM audit WHERE id <= ? ORDER BY id ASC", (last["id"],))
        leaves = [r["entry_hash"] for r in cursor.fetchall()]
        entry_count = len(leaves)
        merkle_root = _merkle_root(leaves)  # Faz-1: kapsanan entry_hash'lerin Merkle koku
        cursor.execute(
            "INSERT INTO audit_checkpoint (created_at, upto_id, upto_hash, entry_count, merkle_root) VALUES (?, ?, ?, ?, ?)",
            (time.time(), last["id"], last["entry_hash"], entry_count, merkle_root))
        self.conn.commit()
        return {"status": "success", "checkpoint_id": cursor.lastrowid,
                "upto_id": last["id"], "upto_hash": last["entry_hash"], "entry_count": entry_count,
                "merkle_root": merkle_root}

    def archive_up_to(self, checkpoint_id: int) -> dict:
        """
        Verilen checkpoint'in kapsadığı eski audit satırlarını siler (arşivleme).

        Yalnızca MÜHÜRLENMİŞ aralık silinebilir -> mühürsüz kayıt asla kaybolmaz;
        checkpoint yoksa ValueError. Silme sonrası zincir, kalan ilk satırın
        previous_hash'i = mühür hash'i olduğu için doğrulanabilir kalır.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT upto_id FROM audit_checkpoint WHERE id = ?", (checkpoint_id,))
        cp = cursor.fetchone()
        if cp is None:
            raise ValueError(f"Checkpoint bulunamadı: {checkpoint_id}")
        cursor.execute("DELETE FROM audit WHERE id <= ?", (cp["upto_id"],))
        deleted = cursor.rowcount
        self.conn.commit()
        return {"status": "success", "deleted": deleted, "upto_id": cp["upto_id"]}

if __name__ == '__main__':
    # Test kodu
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    
    # Şemayı oluştur
    from . import schema
    cursor = conn.cursor()
    cursor.execute(schema.CREATE_AUDIT_TABLE)
    conn.commit()

    audit_chain = AuditChain(conn)

    print("Denetim kayıtları oluşturuluyor...")
    audit_chain.record("copilot", "vault_init", {"status": "success"})
    time.sleep(0.1)
    audit_chain.record("user", "profile_read", {"scope": "user_preferences.seating"})
    time.sleep(0.1)
    audit_chain.record("distill_agent", "profile_write", {"key": "user_preferences.seating", "value": "aisle"})

    print("\nDenetim zinciri doğrulanıyor...")
    is_valid = audit_chain.verify_chain()
    print(f"Zincir geçerli mi? -> {is_valid}")
    assert is_valid

    # Zinciri bozmayı dene
    print("\nZincir bozuluyor (test amaçlı)...")
    cursor.execute("UPDATE audit SET action = 'tampered' WHERE id = 2")
    conn.commit()

    print("Bozuk zincir doğrulanıyor...")
    is_valid_after_tamper = audit_chain.verify_chain()
    print(f"Bozuk zincir geçerli mi? -> {is_valid_after_tamper}")
    assert not is_valid_after_tamper

    print("\nAuditChain testi başarıyla tamamlandı.")
    conn.close()
