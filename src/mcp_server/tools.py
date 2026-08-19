# kasa/src/mcp_server/tools.py

"""
MCP (Model Context Protocol) sunucusu tarafından ajanlara sunulacak
araçların (tools) implementasyonu. Gerçek vault DB operasyonlarını içerir.

Her araç çağrısı: izin kontrolü (permissions tablosu) → işlem → audit kaydı.
"""

import json
import re
import time
import hashlib
import hmac
import sqlite3
from ..vault.database import Vault
from ..vault import cell_crypt
from ..vault import redact


def _digest(value) -> str:
    """Audit'e ham deger yerine yazilacak deterministik ozet (sir degismez zincire girmez)."""
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


# Faz-2 (G3/ASI06): karantina bayragi PAYLASILAN modulde -> agent yazimi (bu dosya) ve distill
# motoru AYNI deterministik kurali kullanir (kapsam butunlugu).
from ..vault.quarantine import quarantine_reason as _quarantine_reason


class VaultTools:
    def __init__(self, vault: Vault, agent_id: str):
        self.vault = vault
        self.agent_id = agent_id
        self.audit_chain = vault.audit_chain

    def _db(self) -> sqlite3.Connection:
        """Vault'un aktif DB bağlantısını döndürür."""
        return self.vault.get_connection()

    def _key(self) -> bytes:
        """L2 hucre-sifreleme anahtari (DPAPI-korumali _db_key)."""
        return self.vault._db_key

    def _check_permission(self, scope: str) -> bool:
        """
        permissions tablosundan ajan izni kontrol eder (deny-by-default).
        MVP-0: 'system' ajanına her şey açık; diğerleri DB'den kontrol edilir.
        """
        if self.agent_id == "system":
            return True
        cursor = self._db().cursor()
        cursor.execute(
            "SELECT 1 FROM permissions WHERE agent_id=? AND scope=? AND revoked_at IS NULL",
            (self.agent_id, scope)
        )
        return cursor.fetchone() is not None

    def _check_rate_limit(self, action: str, limit: int, window_sec: int) -> None:
        """
        Circuit Breaker (Sigorta): Ajanın belirli bir süre içindeki işlem sayısını denetler.
        Sistem (system) ajanı bu kuraldan muaftır. (Ajan ele geçirilmesine karşı)
        """
        if self.agent_id == "system":
            return
            
        cursor = self._db().cursor()
        now = time.time()
        start_time = now - window_sec
        cursor.execute(
            "SELECT COUNT(*) FROM audit WHERE agent_id = ? AND action = ? AND timestamp >= ?",
            (self.agent_id, action, start_time)
        )
        count = cursor.fetchone()[0]
        if count >= limit:
            self.audit_chain.record(self.agent_id, f"rate_limit_{action}", {"result": "circuit_breaker_tripped", "limit": limit})
            raise PermissionError(f"Circuit Breaker (Sigorta) Tetiklendi: Ajan '{self.agent_id}' son {window_sec} saniyede {limit} işlem limitini aştı.")

    def grant_permission(self, scope: str) -> None:
        """Ajan için belirli bir kapsam izni verir (sistem aracı, MVP-0 helper).

        GUVENLIK: izin yukseltmeyi onlemek icin 'admin:grant' kapsami gerekir.
        Ag katmani bunu zaten PUBLIC_TOOLS allow-list'i disinda tutar (C7); bu, in-process
        cagrilar icin derinlemesine savunmadir. 'system' (in-process distill/bakim) muaftir.
        """
        if not self._check_permission("admin:grant"):
            raise PermissionError(f"Ajan '{self.agent_id}' icin izin verme (grant) yetkisi yok.")
        cursor = self._db().cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?,?,?)",
            (self.agent_id, scope, time.time())
        )
        self._db().commit()

    def profile_read(self, scope: str, reason: str) -> dict:
        """
        Profil veritabanından bir veya daha fazla anahtar-değer çiftini okur.

        Args:
            scope: Okunacak anahtar (örn: 'user.name') veya kapsam (örn: 'user.*').
            reason: (Bağlamsal Bilet) Ajanın bu veriyi neden okuduğunu açıklayan sebep.


        Returns:
            Okunan verileri içeren bir sözlük.
        """
        action = "profile_read"
        details = {"scope": scope, "reason": reason}
        
        if not reason:
            self.audit_chain.record(self.agent_id, action, {**details, "result": "invalid_input"})
            raise ValueError("profile_read çağrısı için 'reason' (Bağlamsal Bilet) zorunludur.")
        
        if not self._check_permission(f"profile:read:{scope}"):
            self.audit_chain.record(self.agent_id, action, {**details, "result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için '{scope}' okuma izni yok.")

        cursor = self._db().cursor()
        # scope 'user.*' gibi wildcard içeriyorsa prefix araması yap
        if scope.endswith('*'):
            prefix = scope[:-1]
            cursor.execute(
                "SELECT key, value, provenance, updated_at FROM profile WHERE key LIKE ?",
                (prefix + '%',)
            )
        else:
            cursor.execute(
                "SELECT key, value, provenance, updated_at FROM profile WHERE key = ?",
                (scope,)
            )
        rows = cursor.fetchall()
        # L2: value at-rest sifreli -> decrypt (AAD = profile|value|key). Legacy plaintext seffaf gecer.
        key_bytes = self._key()
        data = [
            {"key": r[0],
             "value": json.loads(cell_crypt.decrypt_cell(r[1], key_bytes, cell_crypt.aad_profile(r[0]))),
             "provenance": json.loads(r[2]), "updated_at": r[3]}
            for r in rows
        ]
        result = {"status": "success", "count": len(data), "data": data}

        self.audit_chain.record(self.agent_id, action, {**details, "result": "success", "count": len(data)})
        return result

    def profile_write(self, key: str, value: any, provenance: list, quarantine: bool = None) -> dict:
        """
        Profil veritabanına yeni bir damıtılmış bilgi yazar veya günceller.

        Args:
            key: Yazılacak bilginin anahtarı.
            value: Bilginin değeri (JSON-serileştirilebilir).
            provenance: Bu bilginin hangi olaylardan (event) türetildiğini gösteren ID listesi.
            quarantine: (Faz-2) None -> deterministik bayrakla otomatik degerlendir; True -> zorla
                karantina; False -> zorla aktif (release yolu, tekrar bayraklamaya girme).

        Returns:
            İşlem sonucunu belirten bir sözlük. Karantinaya alindiysa status="quarantined".
        """
        action = "profile_write"
        
        # HIZ SINIRI (Circuit Breaker): 60 saniyede maksimum 50 profil yazma işlemi
        self._check_rate_limit(action, limit=50, window_sec=60)
        
        # BOYUT SINIRI (Schema & Length Enforcer): Maksimum 10KB (10240 byte)
        payload_size = len(json.dumps(value, ensure_ascii=False).encode('utf-8'))
        if payload_size > 10240:
            self.audit_chain.record(self.agent_id, action, {"key": key, "result": "structural_violation", "reason": "payload_too_large", "size": payload_size})
            raise ValueError(f"Yapısal İhlal: Yazılmak istenen veri ({payload_size} byte) KASA maksimum limitini (10240 byte) aşıyor. DoS (Denial of Service) kalkanı tetiklendi.")
            
        # L2: audit'e ham `value` YAZILMAZ (tools.py:109 yan-kanal) -> digest. provenance ID'ler, plaintext.
        details = {"key": key, "value": _digest(value), "provenance": provenance}

        if not self._check_permission("profile:write"):
            self.audit_chain.record(self.agent_id, action, {**details, "result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için yazma izni yok.")

        now = time.time()
        conn = self._db()
        cursor = conn.cursor()
        # Mevcut satır varsa ID'sini al — supersedes zinciri için
        cursor.execute("SELECT id FROM profile WHERE key = ?", (key,))
        old_row = cursor.fetchone()
        supersedes_id = old_row[0] if old_row else None

        # GUVENLIK ICERIK KAPISI: sir/yuksek-entropi (yapi-koruyan) maskele, SONRA sifrele.
        value, _red_hits = redact.scan(value)
        # L2: value at-rest AES-GCM sifrelenir (AAD = profile|value|key). provenance = event-ID'ler, plaintext.
        enc_value = cell_crypt.encrypt_cell(json.dumps(value), self._key(), cell_crypt.aad_profile(key))

        # YAPISAL SAVUNMA (Namespace Isolation)
        # Eger ajan (system disinda) kritik bir isim uzayina yazmaya calisiyorsa, icerige bakilmaksizin karantinaya alinir.
        is_protected_namespace = False
        if self.agent_id != "system":
            # Kritik on-ekler veya son-ekler
            if key.startswith(("system.", "admin.", "config.", "security.")):
                is_protected_namespace = True
            elif key.endswith((".role", ".permissions", ".auth", ".token")):
                is_protected_namespace = True

        if is_protected_namespace:
            reason = f"structural-violation: unauthorized write attempt to protected namespace '{key}'"
        else:
            # F-POISON FIX: Ajan ve Distiller yazımları (system hariç) bağımsız bir 'Hakem (Judge)' 
            # tarafından epistemik olarak (iddia vs kaynak metin) doğrulanana kadar karantinada bekler.
            if self.agent_id != "system" and quarantine is None:
                reason = "pending-semantic-validation"
            else:
                # Faz-2 (G3/ASI06): karantina degerlendirmesi.
                reason = ("forced" if quarantine else None) if quarantine is not None else _quarantine_reason(value)
            
        if reason:
            cursor.execute(
                "INSERT INTO profile_quarantine (key, value, provenance, agent_id, reason, created_at) VALUES (?,?,?,?,?,?)",
                (key, enc_value, json.dumps(provenance), self.agent_id, reason, now),
            )
            conn.commit()
            self.audit_chain.record(self.agent_id, action, {**details, "result": "quarantined", "reason": reason})
            return {"status": "quarantined", "key": key, "reason": reason}
        cursor.execute(
            """INSERT OR REPLACE INTO profile (id, key, value, provenance, supersedes, created_at, updated_at)
               SELECT old.id, ?, ?, ?, ?, COALESCE(old.created_at, ?), ?
               FROM (SELECT NULL as id, NULL as created_at) as fallback
               LEFT JOIN profile old ON old.key = ?""",
            (key, enc_value, json.dumps(provenance), supersedes_id, now, now, key)
        )
        conn.commit()
        result = {"status": "success", "key": key}

        self.audit_chain.record(self.agent_id, action, {**details, "result": "success"})
        return result

    def list_quarantined(self) -> dict:
        """Faz-2: karantinadaki (bekleyen) profil yazimlarini listeler (owner inceleme yuzeyi)."""
        if not self._check_permission("profile:read"):
            raise PermissionError(f"Ajan '{self.agent_id}' için karantina okuma izni yok.")
        cur = self._db().cursor()
        cur.execute(
            "SELECT id, key, value, provenance, agent_id, reason, created_at FROM profile_quarantine ORDER BY id")
        kb = self._key()
        items = []
        for r in cur.fetchall():
            try:
                val = json.loads(cell_crypt.decrypt_cell(r[2], kb, cell_crypt.aad_profile(r[1])))
            except Exception:
                val = None
            items.append({"id": r[0], "key": r[1], "value": val, "provenance": json.loads(r[3]),
                          "agent_id": r[4], "reason": r[5], "created_at": r[6]})
        self.audit_chain.record(self.agent_id, "quarantine_list", {"count": len(items)})
        return {"status": "success", "count": len(items), "data": items}

    def release_quarantined(self, quarantine_id: int) -> dict:
        """Faz-2: bir karantina kaydini AKTIF profile tasir (sahibin bilincli onayi).

        admin:grant gerektirir (forget/grant ile ayni owner-katmani). aktife yazarken
        quarantine=False -> tekrar bayraklanip donguye girmez.
        """
        if not self._check_permission("admin:grant"):
            raise PermissionError(f"Ajan '{self.agent_id}' için karantina serbest bırakma izni yok.")
        cur = self._db().cursor()
        cur.execute("SELECT key, value, provenance FROM profile_quarantine WHERE id = ?", (quarantine_id,))
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"Karantina kaydı bulunamadı: {quarantine_id}")
        key = row[0]
        val = json.loads(cell_crypt.decrypt_cell(row[1], self._key(), cell_crypt.aad_profile(key)))
        provenance = json.loads(row[2])
        self.profile_write(key, val, provenance, quarantine=False)   # zorla aktif
        cur.execute("DELETE FROM profile_quarantine WHERE id = ?", (quarantine_id,))
        self._db().commit()
        self.audit_chain.record(self.agent_id, "quarantine_release", {"id": quarantine_id, "key": key})
        return {"status": "released", "id": quarantine_id, "key": key}

    def forget(self, topic: str) -> dict:
        """
        Belirli bir konuyla ilgili tüm bilgileri Kasa'dan kalıcı olarak siler.

        Args:
            topic: Silinecek konu.

        Returns:
            İşlem sonucunu belirten bir sözlük.
        """
        action = "forget"
        details = {"topic": topic}

        if not self._check_permission("admin:forget"):
            self.audit_chain.record(self.agent_id, action, {**details, "result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için 'forget' işlemi izni yok.")

        conn = self._db()
        cursor = conn.cursor()
        # Profile satırlarını sil (anahtar plaintext -> prefix eşleşmesi calisir)
        cursor.execute("DELETE FROM profile WHERE key LIKE ?", (topic + '%',))
        profile_deleted = cursor.rowcount

        # L2 Kör İndeks (Blind Indexing) ile O(1) hızında arama:
        topic_words = set(re.findall(r'\b\w{3,}\b', topic.lower()))
        if not topic_words:
            topic_words = {topic.lower()}
        match_ids_set = set()
        for tw in topic_words:
            whash = hmac.new(self._key(), tw.encode('utf-8'), hashlib.sha256).hexdigest()
            cursor.execute("SELECT DISTINCT event_id FROM search_index WHERE word_hash = ?", (whash,))
            match_ids_set.update(r[0] for r in cursor.fetchall())
        match_ids = list(match_ids_set)
        
        events_scanned = 0 # search_index kullanıldığı için tam tarama (scan) maliyeti 0
        events_matched = len(match_ids)
        if match_ids:
            placeholders = ",".join("?" * len(match_ids))
            cursor.execute(f"DELETE FROM events WHERE id IN ({placeholders})", match_ids)
            events_deleted = cursor.rowcount
        else:
            events_deleted = 0

        # SESSIZ-SIFIR GUARD: eslesme bulundu ama silinmediyse artik sessizce "success" DONMEZ.
        if events_matched != events_deleted:
            raise RuntimeError(f"forget guard ihlali: matched={events_matched} != deleted={events_deleted}")

        # Audit zincirinde tombstone kaydı (scanned/matched/deleted ayri raporlanir)
        self.audit_chain.record(self.agent_id, "forget_tombstone",
                                {"topic": topic, "profile_deleted": profile_deleted,
                                 "events_scanned": events_scanned, "events_matched": events_matched,
                                 "events_deleted": events_deleted})
        conn.commit()
        result = {"status": "success", "topic": topic,
                  "profile_deleted": profile_deleted, "events_scanned": events_scanned,
                  "events_matched": events_matched, "events_deleted": events_deleted}

        self.audit_chain.record(self.agent_id, action, {**details, "result": "success"})
        return result

    def audit_read(self, start_index: int = 0, count: int = 100) -> dict:
        """
        Denetim (audit) zincirinden kayıtları okur.

        Args:
            start_index: Başlangıç kaydı.
            count: Okunacak kayıt sayısı.

        Returns:
            Denetim kayıtlarını içeren bir sözlük.
        """
        action = "audit_read"
        scope = f"audit:read:{start_index}:{count}"
        details = {"start_index": start_index, "count": count}

        if not self._check_permission("audit:read"):
            # C2-GAP fix (2026-08-02): ret de denetim izine YAZILMALI (diger araclarla tutarli).
            # Sebep: yetkisiz denetim-okuma denemesi sessiz kaliyordu -> adli iz birakmiyordu;
            # canli saldiri araci bunu "saldirgan denedi, audit bos" uyusmazligi olarak olctu.
            self.audit_chain.record(self.agent_id, action, {**details, "result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için denetim okuma izni yok.")

        cursor = self._db().cursor()
        cursor.execute(
            "SELECT id, timestamp, agent_id, action, details, entry_hash FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
            (count, start_index)
        )
        rows = cursor.fetchall()
        # L2: audit.details at-rest sifreli -> decrypt (AAD = audit|details|agent|action|ts). Legacy seffaf.
        key_bytes = self._key()
        data = [
            {"id": r[0], "timestamp": r[1], "agent_id": r[2], "action": r[3],
             "details": json.loads(cell_crypt.decrypt_cell(r[4], key_bytes, cell_crypt.aad_audit(r[2], r[3], r[1]))),
             "entry_hash": r[5]}
            for r in rows
        ]
        result = {"status": "success", "count": len(data), "records": data}

        self.audit_chain.record(self.agent_id, action, {**details, "result": "success"})
        return result

    def audit_checkpoint(self) -> dict:
        """Denetim zincirini mühürler (DEBI-2). PUBLIC_TOOLS dışıdır: ağdan çağrılamaz,
        sahip/bakım (in-process) aracıdır. 'admin:audit' kapsamı gerekir."""
        if not self._check_permission("admin:audit"):
            raise PermissionError(f"Ajan '{self.agent_id}' için audit checkpoint izni yok.")
        result = self.audit_chain.create_checkpoint()
        # Muhur islemi de zincire yazilir (kendinden SONRAKI kayit olarak; muhur kapsami disi).
        self.audit_chain.record(self.agent_id, "audit_checkpoint",
                                {"checkpoint_id": result.get("checkpoint_id"),
                                 "upto_id": result.get("upto_id"),
                                 "entry_count": result.get("entry_count"),
                                 "result": result["status"]})
        return result

    def audit_archive(self, checkpoint_id: int) -> dict:
        """Mühürlenmiş aralığı denetim tablosundan siler (DEBI-2 arşiv). Mühürsüz kayıt
        silinemez (audit.archive_up_to ValueError verir). 'admin:audit' kapsamı gerekir."""
        if not self._check_permission("admin:audit"):
            raise PermissionError(f"Ajan '{self.agent_id}' için audit arşiv izni yok.")
        result = self.audit_chain.archive_up_to(checkpoint_id)
        self.audit_chain.record(self.agent_id, "audit_archive",
                                {"checkpoint_id": checkpoint_id, "deleted": result["deleted"],
                                 "upto_id": result["upto_id"], "result": "success"})
        return result

    def prune_expired_events(self) -> dict:
        """Süresi dolmuş ve damıtılmış event'leri siler; ardından VACUUM çalıştırır.

        DEBI-3 TOMBSTONE: profile.provenance'ın işaret ettiği satırlar SİLİNMEZ,
        içeriği yok edilip mezar taşına çevrilir. Sebep: provenance event-ID listesidir;
        satır tamamen giderse "bu profil bilgisi nereden türedi" zinciri kopar.
        Sonuç: hassas içerik diskten gider (secure_delete=ON), satır kimliği ve
        denetlenebilirlik kalır. forget() bu korumadan MUAF: unutulma hakkı (T5)
        köken zincirinden üstündür, orada gerçek silme sürer.
        """
        if not self._check_permission("admin:prune"):
            # C2-GAP fix (2026-08-02): yetkisiz prune (yikici temizlik) denemesi de iz birakmali.
            self.audit_chain.record(self.agent_id, "prune_expired_events", {"result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için prune izni yok.")

        conn = self._db()
        now = time.time()
        cursor = conn.cursor()

        # Provenance'ta referanslanan event-ID'ler (JSON array, plaintext).
        referenced = set()
        for row in cursor.execute("SELECT provenance FROM profile").fetchall():
            try:
                referenced.update(int(x) for x in json.loads(row["provenance"]))
            except (ValueError, TypeError):
                pass  # bozuk provenance satiri referans dondurmez; ilgili event silinebilir

        cursor.execute(
            "SELECT id, content_hash FROM events WHERE ttl_expiry < ? AND distilled = 1 "
            "AND content NOT LIKE 'tombstone:%'",
            (now,))
        expired = cursor.fetchall()
        tombstoned = 0
        delete_ids = []
        for r in expired:
            if r["id"] in referenced:
                # Icerik yerine sabit isaret + dedup kimligi (varsa): satir kalir, sir gider.
                conn.execute("UPDATE events SET content = ? WHERE id = ?",
                             ("tombstone:" + (r["content_hash"] or ""), r["id"]))
                tombstoned += 1
            else:
                delete_ids.append(r["id"])
        deleted = 0
        if delete_ids:
            placeholders = ",".join("?" * len(delete_ids))
            cursor.execute(f"DELETE FROM events WHERE id IN ({placeholders})", delete_ids)
            deleted = cursor.rowcount
        conn.commit()
        try:
            conn.execute("VACUUM")
        except Exception:
            pass  # WAL modunda veya başka bağlantı varsa sessizce atla

        self.audit_chain.record(self.agent_id, "prune_expired_events",
                                {"deleted": deleted, "tombstoned": tombstoned, "pruned_at": now})
        return {"status": "success", "deleted": deleted, "tombstoned": tombstoned}

    def event_ingest(self, source: str, type: str, content: dict, ttl_days: int = 30) -> dict:
        """
        Olayları Vault'a alır ve TTL süresine göre saklar.

        Args:
            source: Olayın kaynağı.
            type: Olayın türü.
            content: Olayın içeriği (JSON-serileştirilebilir).
            ttl_days: Olayın saklanma süresi (gün cinsinden).

        Returns:
            İşlem sonucunu belirten bir sözlük.
        """
        action = "event_ingest"
        
        # HIZ SINIRI (Circuit Breaker): 60 saniyede maksimum 100 olay girişi
        self._check_rate_limit(action, limit=100, window_sec=60)
        
        # BOYUT SINIRI: Maksimum 50KB olay hacmi
        payload_size = len(json.dumps(content, ensure_ascii=False).encode('utf-8'))
        if payload_size > 51200:
            self.audit_chain.record(self.agent_id, action, {"source": source, "result": "structural_violation", "reason": "payload_too_large"})
            raise ValueError(f"Yapısal İhlal: Olay boyutu ({payload_size} byte) maksimum 50KB sınırını aşıyor.")
        
        # L2: ham `content` audit'e YAZILMAZ -> digest (forget/unutulma-hakki ile tutarli).
        details = {"source": source, "type": type, "content": _digest(content), "ttl_days": ttl_days}

        if not self._check_permission("events:write"):
            self.audit_chain.record(self.agent_id, action, {**details, "result": "permission_denied"})
            raise PermissionError(f"Ajan '{self.agent_id}' için olay yazma izni yok.")

        if len(source) > 64 or len(type) > 64:
            self.audit_chain.record(self.agent_id, action, {**details, "result": "invalid_input"})
            raise ValueError("Kaynak ve tür en fazla 64 karakter olmalıdır.")

        if not (1 <= ttl_days <= 365):
            self.audit_chain.record(self.agent_id, action, {**details, "result": "invalid_input"})
            raise ValueError("TTL gün sayısı 1 ile 365 arasında olmalıdır.")

        now = time.time()
        ttl_expiry = now + ttl_days * 86400
        conn = self._db()
        cursor = conn.cursor()
        # GUVENLIK ICERIK KAPISI: sir/yuksek-entropi (yapi-koruyan) maskele, SONRA sifrele.
        content, _red_hits = redact.scan(content)

        # DEBI-1 DEDUP: ayni (source|type|icerik) tekrari yeni satir ACMAZ; sayac artar.
        # Sebep: "her sabah mail acti" gibi rutinler 365 satir yerine 1 satir + sayac olmali;
        # sinirsiz tekrar hem diski sisirir hem forget'in decrypt-scan maliyetini buyutur.
        # Kimlik ANAHTARLI ozet (HMAC, vault anahtari): duz SHA-256 dusuk-entropili icerige
        # sozluk saldirisina izin verirdi; HMAC anahtari DPAPI-korumali -> DB dosyasi tek
        # basina esitlik bilgisi sizdirmaz. Redact SONRASI hesaplanir (ayni ham -> ayni maske).
        content_hash = hmac.new(
            self._key(),
            f"{source}|{type}|{json.dumps(content, sort_keys=True, ensure_ascii=False)}".encode("utf-8"),
            hashlib.sha256).hexdigest()
        cursor.execute(
            "SELECT id FROM events WHERE content_hash = ? AND content NOT LIKE 'tombstone:%' LIMIT 1",
            (content_hash,))
        dup = cursor.fetchone()
        if dup is not None:
            # Tekrar: sayac + last_seen + TTL uzat; distilled=0 -> yukselen frekans damitmaya
            # yeni sinyal olarak geri doner ("N kez tekrar = rutin").
            cursor.execute(
                "UPDATE events SET occurrence_count = occurrence_count + 1, last_seen = ?, "
                "ttl_expiry = MAX(ttl_expiry, ?), distilled = 0 WHERE id = ?",
                (now, ttl_expiry, dup["id"]))
            conn.commit()
            self.audit_chain.record(self.agent_id, action,
                                    {**details, "result": "success", "event_id": dup["id"],
                                     "deduplicated": True})
            return {"status": "success", "event_id": dup["id"], "deduplicated": True}

        # L2: content at-rest AES-GCM sifrelenir (AAD = events|content). Metadata (source/type/ttl) plaintext.
        enc_content = cell_crypt.encrypt_cell(json.dumps(content), self._key(), cell_crypt.aad_event())
        cursor.execute(
            "INSERT INTO events (timestamp, session_id, source, type, content, ttl_expiry, "
            "content_hash, occurrence_count, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (now, self.agent_id, source, type, enc_content, ttl_expiry, content_hash, now)
        )
        event_id = cursor.lastrowid
        
        # Kör İndeks oluşturma (Blind Indexing)
        text_content = json.dumps(content)
        words = set(re.findall(r'\b\w{3,}\b', text_content.lower()))
        if words:
            word_params = []
            for w in words:
                whash = hmac.new(self._key(), w.encode('utf-8'), hashlib.sha256).hexdigest()
                word_params.append((event_id, whash))
            cursor.executemany("INSERT INTO search_index (event_id, word_hash) VALUES (?, ?)", word_params)
            
        conn.commit()

        self.audit_chain.record(self.agent_id, action, {**details, "result": "success", "event_id": event_id})
        return {"status": "success", "event_id": event_id, "deduplicated": False}
