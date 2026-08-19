# kasa/src/vault/schema.py

"""
Veritabanı şemasını (DDL - Data Definition Language) tanımlar.
Bu script doğrudan çalıştırılmaz, database.py tarafından kullanılır.
"""

# Olaylar (Events): Ham etkileşim kayıtları, kısa süreli (TTL).
CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL, -- e.g., 'browser_extension', 'manual_entry'
    type TEXT NOT NULL, -- e.g., 'page_view', 'form_submit'
    content TEXT NOT NULL, -- JSON blob of event data
    ttl_expiry REAL NOT NULL, -- Timestamp when this event should be deleted
    content_hash TEXT, -- HMAC-SHA256(vault-key, source|type|content): dedup kimligi (DEBI-1)
    occurrence_count INTEGER NOT NULL DEFAULT 1, -- ayni olayin kac kez gozlendigi
    last_seen REAL -- son tekrarin zamani (ilk kayitta = timestamp)
);
"""

CREATE_EVENTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
"""



# DEBI-1 dedup arama indeksi. ALL_INDEXES'e EKLENMEZ: eski DB'lerde content_hash kolonu
# ALTER-migration ile gelir; indeks migration SONRASI database._init_schema'da kurulur.
CREATE_EVENTS_HASH_INDEX = """
CREATE INDEX IF NOT EXISTS idx_events_content_hash ON events (content_hash);
"""

# Profil (Profile): Damıtılmış, kalıcı, insan tarafından okunabilir bilgiler.
CREATE_PROFILE_TABLE = """
CREATE TABLE IF NOT EXISTS profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    provenance TEXT NOT NULL, -- JSON array of event IDs
    supersedes INTEGER,       -- önceki versiyonun satır ID'si
    weight REAL NOT NULL DEFAULT 1.0, -- KORTEX güven skoru (0.0 - 1.0 arası)
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""

CREATE_PROFILE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_profile_key ON profile (key);
"""

# Karantina (Faz-2 / G3 / ASI06): scope-gecerli AMA supheli (enjekte gibi) bir profil yazimi
# CANLIYA girmez; burada TUTULUR -> sahip inceleyip release_quarantined ile serbest birakir.
# value at-rest AES-GCM sifreli (profile.value ile ayni AAD); agent_id atif, reason ise
# deterministik bayrak nedeni. Iddia: "onleme" degil "tespit + karantina + atif".
CREATE_PROFILE_QUARANTINE_TABLE = """
CREATE TABLE IF NOT EXISTS profile_quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,        -- AES-GCM encrypted (AAD = profile|value|key)
    provenance TEXT NOT NULL,   -- JSON array of event IDs (lineage)
    agent_id TEXT NOT NULL,     -- yazimi deneyen ajan (attribution)
    reason TEXT NOT NULL,       -- karantina nedeni (deterministik bayrak)
    created_at REAL NOT NULL
);
"""

# İzinler (Permissions): Ajanların hangi kapsamlara erişebileceğini belirler.
CREATE_PERMISSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL, -- The unique identifier for the agent/client
    scope TEXT NOT NULL, -- e.g., 'profile:read:all', 'events:read'
    granted_at REAL NOT NULL,
    revoked_at REAL,
    UNIQUE(agent_id, scope)
);
"""

# Denetim (Audit): Tüm sistem erişim ve değişikliklerinin değişmez kaydı.
CREATE_AUDIT_TABLE = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL, -- e.g., 'profile_read', 'forget'
    details TEXT, -- JSON blob with action parameters and result summary
    previous_hash TEXT NOT NULL, -- SHA-256 of the previous audit entry
    entry_hash TEXT UNIQUE NOT NULL, -- SHA-256 of this entry (timestamp + ... + previous_hash)
    signature TEXT -- Ed25519(sign_key, entry_hash) hex; NULL for legacy/unsigned rows (Faz-1)
);
"""

CREATE_AUDIT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit (timestamp);
"""

# Denetim kontrol noktalari (DEBI-2): zincirin donemsel kapanis muhurleri.
# Sebep: audit zinciri yalnizca uca ekler, aradan silinemez -> sinirsiz buyur.
# Checkpoint son entry_hash'i ayri tabloya sabitler; ondan eski kayitlar arsivlenebilir,
# verify_chain genesis yerine muhurden tohumlanir (T7 garantisi bozulmaz).
CREATE_AUDIT_CHECKPOINT_TABLE = """
CREATE TABLE IF NOT EXISTS audit_checkpoint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    upto_id INTEGER NOT NULL, -- muhurlenen son audit satirinin id'si
    upto_hash TEXT NOT NULL, -- muhurlenen son audit satirinin entry_hash'i
    entry_count INTEGER NOT NULL, -- muhur anindaki kapsanan kayit sayisi
    merkle_root TEXT -- SHA-256 Merkle root of covered entry_hashes (Faz-1); NULL for legacy
);
"""

# Kör İndeks (Blind Indexing) tablosu: Şifreli events üzerinde O(1) hızında arama yapabilmek için.
CREATE_SEARCH_INDEX_TABLE = """
CREATE TABLE IF NOT EXISTS search_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    word_hash TEXT NOT NULL, -- HMAC(word)
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);
"""

CREATE_SEARCH_HASH_INDEX = """
CREATE INDEX IF NOT EXISTS idx_search_word_hash ON search_index (word_hash);
"""

# Ajan kimlik bagi (F-IMP kok-neden fix): bir token'i BIR ajan kimligine baglar.
#
# SEBEP (olculdu, docs/MCP_CANLI_TEST_EYLEM_PLANI_2026-08-02.md §F-IMP): eskiden tek bir
# paylasilan bearer token vardi ve agent_id ISTEK GOVDESINDEN geliyordu. Token hangi ajana
# ait oldugunu BILMEDIGI icin dogrulanamiyordu; token sahibi agent_id="browser" diyip o
# kimligin iznini devralabiliyordu (event_ingest -> HTTP 200). Ayni kok neden hiz sinirini
# da deliyordu: kova beyan edilen kimlige anahtarlandigi icin donen kimlikle 150 istekte
# 0 adet 429 uretiliyordu.
#
# token_hash NEDEN duz SHA-256 (yavas KDF degil): token'lar `secrets` ile uretilen
# yuksek-entropili rastgele dizelerdir (parola DEGIL). Yavas KDF'in amaci dusuk-entropili
# sirlarda sozluk saldirisini pahalilastirmaktir; 256-bit entropide sozluk saldirisi diye
# bir sey yoktur. Buradaki hash'in isi gizlilik degil ARAMA: diskte duz token tutmamak.
CREATE_AGENT_TOKENS_TABLE = """
CREATE TABLE IF NOT EXISTS agent_tokens (
    agent_id TEXT PRIMARY KEY, -- token'in BAGLI oldugu kimlik (istemci beyani DEGIL)
    token_hash TEXT NOT NULL UNIQUE, -- SHA-256(token); duz token asla saklanmaz
    created_at REAL NOT NULL,
    revoked_at REAL -- NULL = etkin
);
"""

CREATE_AGENT_TOKENS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_agent_tokens_hash ON agent_tokens (token_hash);
"""

# Tüm DDL komutlarını bir listede topla
ALL_TABLES = [
    CREATE_EVENTS_TABLE,
    CREATE_PROFILE_TABLE,
    CREATE_PROFILE_QUARANTINE_TABLE,
    CREATE_PERMISSIONS_TABLE,
    CREATE_AUDIT_TABLE,
    CREATE_AUDIT_CHECKPOINT_TABLE,
    CREATE_SEARCH_INDEX_TABLE,
    CREATE_AGENT_TOKENS_TABLE,
]

ALL_INDEXES = [
    CREATE_EVENTS_INDEX,
    CREATE_PROFILE_INDEX,
    CREATE_AUDIT_INDEX,
    CREATE_SEARCH_HASH_INDEX,
    CREATE_AGENT_TOKENS_INDEX,
]
