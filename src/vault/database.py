# kasa/src/vault/database.py

"""
SQLite veritabanı bağlantısını ve temel operasyonları yöneten Vault sınıfı.
Bu sınıf, SQLCipher yerine dosya tabanlı şifreleme için DPAPI kullanır.
Veritabanı dosyası şifrelenmez, ancak veritabanını açmak için gereken
anahtar şifrelenir. Bu, SQLCipher'ın Windows'taki derleme zorluklarını aşar.
"""

import sqlite3
import os
import shutil
import hashlib
import time
from . import schema
from . import encryption
from .audit import AuditChain

# Anahtarın saklanacağı dosya adı
KEY_FILE_NAME = ".vaultkey"
# Parola-KDF tuzu (opsiyonel parola katmani aktifse) + iterasyon sayisi.
SALT_FILE_NAME = ".vaultsalt"
# Faz-1: audit zinciri Ed25519 imza anahtari (DPAPI-korumali seed). Public key export
# edilebilir -> audit satirlari uretici surece GUVENMEDEN dogrulanabilir. Bu dosya .vaultkey
# gibi diskte KALMALI: silinirse yeni anahtar cifti uretilir ve eski imzalar dogrulanamaz.
SIGN_KEY_FILE_NAME = ".auditsignkey"
PBKDF2_ITERATIONS = 200_000  # PBKDF2-HMAC-SHA256 tur sayisi (offline brute-force maliyeti)

class Vault:
    def __init__(self, vault_path: str, vault_password: str = None):
        """
        Kasa'yı başlatır.

        Args:
            vault_path: Kasa veritabanı dosyasının yolu.
            vault_password: (Opsiyonel) Ek bir parola. Belirtilirse, DPAPI anahtarı
                            bu parolayla birleştirilerek daha güçlü hale getirilir.
        """
        self.vault_path = vault_path
        os.makedirs(vault_path, exist_ok=True)
        self.db_path = os.path.join(vault_path, "kasa.db")
        self.key_path = os.path.join(vault_path, KEY_FILE_NAME)
        self.salt_path = os.path.join(vault_path, SALT_FILE_NAME)
        self.sign_key_path = os.path.join(vault_path, SIGN_KEY_FILE_NAME)
        self._password = vault_password
        self._db_key = self._get_or_create_db_key()
        self._audit_signing_key = self._get_or_create_audit_signing_key()
        
        self.conn = None
        self.audit_chain = None

    def _get_or_create_db_key(self) -> bytes:
        """
        Veritabanı anahtarını DPAPI ile korunan dosyadan okur veya oluşturur.
        """
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                encrypted_key = f.read()
            db_key = encryption.unprotect_data(encrypted_key)
        else:
            # 32 byte (256-bit) rastgele anahtar oluştur
            db_key = os.urandom(32)
            encrypted_key = encryption.protect_data(db_key)
            with open(self.key_path, "wb") as f:
                f.write(encrypted_key)
        
        # Eğer ek parola varsa, anahtarı PAROLA-KDF ile turet (DPAPI + parola iki-faktor).
        # ONCEKI zayif sema (sha256(db_key + password), tuzsuz/tek-tur) yerine PBKDF2-HMAC-SHA256:
        # kalici tuz + yuksek iterasyon -> zayif parolada offline brute-force'u pahalilastirir.
        # `password`=kullanici parolasi, `salt`=(kalici tuz + DPAPI-korumali db_key): boylece
        # turetilmis anahtar HEM parolaya HEM DPAPI-sirrina baglidir (birini bilmek yetmez).
        if self._password:
            salt = self._get_or_create_salt()
            return hashlib.pbkdf2_hmac(
                "sha256", self._password.encode("utf-8"), salt + db_key,
                PBKDF2_ITERATIONS, dklen=32)

        return db_key

    def _get_or_create_salt(self) -> bytes:
        """Parola-KDF icin kalici 16-byte tuz (.vaultsalt). Yoksa uretir ve saklar."""
        if os.path.exists(self.salt_path):
            with open(self.salt_path, "rb") as f:
                return f.read()
        salt = os.urandom(16)
        with open(self.salt_path, "wb") as f:
            f.write(salt)
        return salt

    def _get_or_create_audit_signing_key(self):
        """Ed25519 private key for audit signatures, from a DPAPI-protected 32-byte seed.

        Turkce not (Faz-1): hash-zinciri depo-ICI kurcalamayi yakalar; Ed25519 imza ise
        her satiri URETICIDEN BAGIMSIZ dogrulanabilir kilar (public key ile). Private seed
        .vaultkey ile ayni sekilde DPAPI ile korunur (aynı-OS kullanicisi imzalar). Public
        key gizli DEGIL: audit_public_key_hex() ile disariya verilip bagimsiz dogrulama yapilir.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        if os.path.exists(self.sign_key_path):
            with open(self.sign_key_path, "rb") as f:
                seed = encryption.unprotect_data(f.read())
        else:
            seed = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
            with open(self.sign_key_path, "wb") as f:
                f.write(encryption.protect_data(seed))
        return Ed25519PrivateKey.from_private_bytes(seed)

    def audit_public_key_hex(self) -> str:
        """Hex-encoded Ed25519 public key — share this to verify audit signatures independently."""
        from cryptography.hazmat.primitives import serialization
        return self._audit_signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def rotate_db_key(self) -> dict:
        """Cell-crypt anahtarini DONDURUR (on-demand re-key): yeni ham anahtar uret, tum K1:
        hucreleri (profile.value, events.content, audit.details) eski->yeni anahtarla yeniden
        sifreler; DPAPI-korumali .vaultkey'i degistirir (once .bak yedegi). Islem-guvenli:
        tum DB guncellemeleri tek transaction'da; hata olursa rollback + eski anahtar korunur.

        AUDIT ZINCIRI: details ENCRYPT-THEN-HASH ile saklanir; ciphertext degisince entry_hash
        de degisir -> zincir SIRAYLA yeniden kurulur (aksi halde verify_chain bozulur).
        Parola aktifse yeni turetilmis anahtar ayni parola+tuz ile hesaplanir.

        Doner: {"status": "success", "rotated": {profile, events, audit sayaclari}}."""
        from . import cell_crypt
        if not self.conn:
            self.connect()
        conn = self.conn
        old_key = self._db_key
        new_raw = os.urandom(32)
        if self._password:
            salt = self._get_or_create_salt()
            new_key = hashlib.pbkdf2_hmac(
                "sha256", self._password.encode("utf-8"), salt + new_raw,
                PBKDF2_ITERATIONS, dklen=32)
        else:
            new_key = new_raw

        counts = {"profile": 0, "events": 0, "audit": 0}
        cur = conn.cursor()
        try:
            # profile.value  (AAD = aad_profile(key))
            for row in cur.execute("SELECT id, key, value FROM profile").fetchall():
                if cell_crypt.is_encrypted(row["value"]):
                    aad = cell_crypt.aad_profile(row["key"])
                    plain = cell_crypt.decrypt_cell(row["value"], old_key, aad)
                    conn.execute("UPDATE profile SET value=? WHERE id=?",
                                 (cell_crypt.encrypt_cell(plain, new_key, aad), row["id"]))
                    counts["profile"] += 1

            # events.content  (AAD = aad_event())
            for row in cur.execute("SELECT id, content FROM events").fetchall():
                if cell_crypt.is_encrypted(row["content"]):
                    aad = cell_crypt.aad_event()
                    plain = cell_crypt.decrypt_cell(row["content"], old_key, aad)
                    conn.execute("UPDATE events SET content=? WHERE id=?",
                                 (cell_crypt.encrypt_cell(plain, new_key, aad), row["id"]))
                    counts["events"] += 1

            # audit.details + hash-zinciri yeniden kur (encrypt-then-hash gereksinimi).
            # DEBI-2 zincir tohumu: arsivlenmis zincirde ilk satirin previous_hash'i genesis
            # DEGIL checkpoint muhurudur -> mevcut tohumu KORU (genesis'e zorlama, aksi halde
            # rotate sonrasi verify_chain checkpoint eslesmesini kaybeder).
            _first = cur.execute("SELECT previous_hash FROM audit ORDER BY id ASC LIMIT 1").fetchone()
            last_hash = _first["previous_hash"] if _first else hashlib.sha256(b"genesis").hexdigest()
            for row in cur.execute(
                    "SELECT id, timestamp, agent_id, action, details FROM audit ORDER BY id ASC").fetchall():
                details_stored = row["details"]
                if cell_crypt.is_encrypted(details_stored):
                    aad = cell_crypt.aad_audit(row["agent_id"], row["action"], row["timestamp"])
                    plain = cell_crypt.decrypt_cell(details_stored, old_key, aad)
                    details_stored = cell_crypt.encrypt_cell(plain, new_key, aad)
                    counts["audit"] += 1
                hasher = hashlib.sha256()
                hasher.update(str(row["timestamp"]).encode("utf-8"))
                hasher.update(row["agent_id"].encode("utf-8"))
                hasher.update(row["action"].encode("utf-8"))
                hasher.update(details_stored.encode("utf-8"))
                hasher.update(last_hash.encode("utf-8"))
                entry_hash = hasher.hexdigest()
                conn.execute("UPDATE audit SET details=?, previous_hash=?, entry_hash=? WHERE id=?",
                             (details_stored, last_hash, entry_hash, row["id"]))
                last_hash = entry_hash

            # DEBI-2: satiri hala tabloda olan checkpoint muhurlerini yeni hash'e tasi.
            # Aksi halde "checkpoint -> rotate -> arsiv" sirasi verify_chain'i kirar
            # (muhur eski hash'i gosterir, kalan ilk satirin previous_hash'i yenidir).
            conn.execute(
                """UPDATE audit_checkpoint
                   SET upto_hash = (SELECT entry_hash FROM audit WHERE audit.id = audit_checkpoint.upto_id)
                   WHERE EXISTS (SELECT 1 FROM audit WHERE audit.id = audit_checkpoint.upto_id)""")

            conn.commit()
        except Exception:
            conn.rollback()
            raise  # DB dokunulmadi (rollback); eski .vaultkey hala gecerli -> kasa acilir kalir

        # DB basariyla yeniden sifrelendi -> yeni ham anahtari DPAPI ile sakla (once yedek).
        if os.path.exists(self.key_path):
            shutil.copy2(self.key_path, self.key_path + ".bak")
        with open(self.key_path, "wb") as f:
            f.write(encryption.protect_data(new_raw))
        self._db_key = new_key
        if self.audit_chain is not None:
            self.audit_chain._key = new_key  # sonraki audit yazimlari yeni anahtarla
        return {"status": "success", "rotated": counts}

    def connect(self):
        """Veritabanına bağlanır ve şemayı oluşturur."""
        if self.conn:
            return

        # pysqlcipher3 yerine standart sqlite3 ve pragma key kullanıyoruz.
        # Bu, SQLCipher'ın sisteme kurulmuş olmasını gerektirir.
        # Daha basit bir yaklaşım için, bu satırı normal sqlite3 bağlantısıyla değiştirebiliriz.
        # Şimdilik, SQLCipher'ın olmadığını varsayarak ilerleyelim.
        # Veritabanı şifrelemesi şimdilik atlanmıştır. Anahtar yönetimi DPAPI ile yapılıyor.
        
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA secure_delete=ON")

        self._init_schema()
        # L2: audit.details at-rest sifreleme icin _db_key gecilir (encrypt-then-hash).
        # Faz-1: Ed25519 signing_key -> her audit satiri imzalanir (bagimsiz dogrulanabilir).
        self.audit_chain = AuditChain(self.conn, key=self._db_key, signing_key=self._audit_signing_key)

    def _init_schema(self):
        """Veritabanı şemasını ve indekslerini oluşturur."""
        cursor = self.conn.cursor()
        for table_sql in schema.ALL_TABLES:
            cursor.execute(table_sql)
        for index_sql in schema.ALL_INDEXES:
            cursor.execute(index_sql)
        self.conn.commit()
        # Mevcut DB'ler için idempotent migration
        for migration in (
            "ALTER TABLE profile ADD COLUMN supersedes INTEGER",
            "ALTER TABLE events ADD COLUMN distilled INTEGER DEFAULT 0",
            # DEBI-1: dedup kolonlari (content_hash HMAC kimligi + tekrar sayaci)
            "ALTER TABLE events ADD COLUMN content_hash TEXT",
            "ALTER TABLE events ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE events ADD COLUMN last_seen REAL",
            # Faz-1: audit imza + Merkle kolonlari (eski DB'lerde ekle; NULL = legacy/unsigned)
            "ALTER TABLE audit ADD COLUMN signature TEXT",
            "ALTER TABLE audit_checkpoint ADD COLUMN merkle_root TEXT",
            # KORTEX Decay (Çürüme) - Güven skoru (weight) eklenmesi
            "ALTER TABLE profile ADD COLUMN weight REAL DEFAULT 1.0",
        ):
            try:
                self.conn.execute(migration)
                self.conn.commit()
            except Exception:
                pass  # Sütun zaten var
        # DEBI-1 dedup indeksi: content_hash kolonu migration ile geldigi icin indeks
        # ALL_INDEXES'te DEGIL, migration SONRASI burada kurulur (eski DB'de sira hatasi olmasin).
        self.conn.execute(schema.CREATE_EVENTS_HASH_INDEX)
        self.conn.commit()

    def close(self):
        """Veritabanı bağlantısını kapatır."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_connection(self):
        """Ham veritabanı bağlantısını döndürür."""
        if not self.conn:
            self.connect()
        return self.conn

if __name__ == '__main__':
    # Test kodu
    test_vault_dir = "test_vault"
    if not os.path.exists(test_vault_dir):
        os.makedirs(test_vault_dir)

    print("Kasa oluşturuluyor ve bağlanılıyor...")
    with Vault(test_vault_dir) as vault:
        conn = vault.get_connection()
        cursor = conn.cursor()
        
        # Test verisi ekle
        ts = time.time()
        cursor.execute(
            "INSERT INTO events (timestamp, session_id, source, type, content, ttl_expiry) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, "test_session_123", "test_script", "test_event", '{"data": "hello"}', ts + 86400)
        )
        conn.commit()
        
        # Veriyi oku
        cursor.execute("SELECT * FROM events")
        row = cursor.fetchone()
        print("\nOkunan test verisi:")
        print(dict(row))
        assert row['session_id'] == "test_session_123"

    print("\nTest başarılı. Kasa veritabanı ve anahtar dosyası 'test_vault' klasöründe oluşturuldu.")
    # Cleanup
    # import shutil
    # shutil.rmtree(test_vault_dir)
