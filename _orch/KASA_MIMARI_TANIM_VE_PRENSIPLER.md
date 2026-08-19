# KASA Mimari Tanım, Yaşam Döngüsü ve Çalışma Prensipleri

Bu belge, KASA'nın (Yerel-Öncelikli Ajan Hafıza ve Güvenlik Kasası) kavramsal mimarisini, yaşam döngüsünü ve sektördeki diğer sistemlerden ayrılan 5 temel çalışma prensibini açıklar.

---

## 1. KASA Nedir? (Tek Cümlelik Konumlandırma)

**KASA:** Windows üzerinde yerel (cihaz-üstü) çalışan, yapay zeka ajanları ile kullanıcı verileri/araçları arasına deterministik bir sınır koyan, hafızayı hücre bazlı şifreleyen ve tüm eylemleri kriptografik olarak denetleyen bir **Reference Monitor (Güvenlik Kapısı) ve Hafıza Kasasıdır.**

---

## 2. KASA Nasıl Çalışır? (Yaşam Döngüsü / Lifecycle)

KASA bulut servisi değildir; bilgisayarınızda bir yerel arka plan servisi (daemon) olarak yaşar:

```
+-------------------------------------------------------------------------+
|                              WINDOWS OS                                 |
|                                                                         |
|  [1. Başlatma]                                                          |
|  python run.py  ---> Sistem Tepsisi (System Tray) & 127.0.0.1:8000     |
|                      (Windows DPAPI anahtarı çözülür, KASA hazır)       |
|                                                                         |
|  [2. Boşta Bekleme (Idle)]                                              |
|  Sıfır CPU tüketimi; sadece yerel MCP isteklerini dinler.               |
|                                                                         |
|  [3. İstek & Müdahale (Intercept)]                                      |
|  Dış Ajan / Extension ---> HTTP POST /v1/execute_tool                  |
|                             |                                           |
|                             v                                           |
|             +-------------------------------+                           |
|             |     KASA REFERENCE MONITOR    |                           |
|             |  - Token'dan kimlik çözümü    |                           |
|             |  - gate.py parametre denetimi |                           |
|             |  - permissions tablosu        |                           |
|             +---------------+---------------+                           |
|                             |                                           |
|               +-------------+-------------+                             |
|               | (Yetkisiz/Zararlı)        | (İzinli/Zararsız)           |
|               v                           v                             |
|        [HTTP 403 / Karantina]       [Vault İşlemi]                      |
|                                    - AES-256-GCM Şifreleme              |
|                                    - HMAC Kör İndeks                    |
|                                                                         |
|  [4. Adli Mühürleme (Audit & Seal)]                                     |
|  Tüm eylemler Ed25519 imzalı zincire ve Merkle köklerine mühürlenir.    |
|                                                                         |
|  [5. Otomatik Damıtma & Bakım (Distillation & Pruning)]                 |
|  Arka planda periyodik olarak ham olayları damıtır, süresi dolan        |
|  verileri 'tombstone' mezar taşına çevirir.                             |
+-------------------------------------------------------------------------+
```

---

## 3. KASA'nın 5 Değişmez Güvenlik ve Çalışma Prensibi

### Prensip 1: Model Sınır Değildir ("Model Proposes, Boundary Disposes")
* **Kural:** Güvenlik ve erişim kararları asla modelin (LLM) vicdanına, prompt'a veya sistem talimatına bırakılmaz.
* **Uygulama:** Model yalnızca bir araç çağırmayı *önerir*. Kararı veren KASA'nın el yazısı deterministik `gate.py` kodu ve `permissions` tablosudur (`deny-by-default`).

### Prensip 2: İki Kademeli Hafıza (Raw Events vs. Distilled Profile)
* **Tier 1 (Ham Olaylar - Events):** `event_ingest` ile kaydedilen günlük aktivitelerdir. TTL (ömür) süresi vardır. Tekrarlayan rutinler HMAC ile tek satırda birleştirilir (`DEBI-1 Dedup`).
* **Tier 2 (Kalıcı Profil - Profile):** `DistillEngine` ve `sensory_filter` tarafından ham olaylardan damıtılan doğrulanmış bilgilerdir.
* **Karantina Koruması:** Web'den veya serbest metinden gelen enjeksiyon kalıpları (`system:`, `ignore previous`) canlı profile giremez; `profile_quarantine` tablosuna hapsedilir.

### Prensip 3: Hücre Bazlı Şifreleme ve AAD Bütünlüğü (L2 Cell Crypt)
* **Kural:** Veritabanı (`kasa.db`) çalınsa dahi kullanıcı sırları güvendedir.
* **Uygulama:** Hassas sütunlar AES-256-GCM ile şifrelenir. AAD (Authenticated Additional Data) bağlamı sayesinde hücrelerin yeri değiştirilemez (Cut-and-paste saldırısı imkansızdır).

### Prensip 4: Kör İndeksleme ve Unutulma Hakkı (Blind Index & Tombstone)
* **Kör İndeks:** `search_index` kelimeleri HMAC-SHA256 ile saklar. Diski okuyan biri arama geçmişini çözemez.
* **Unutulma Hakkı:** Kullanıcı `forget(topic)` dediğinde içerik yok edilir; ancak profilin türediği olaylar mezar taşına (`tombstone:`) dönüştürülerek adli köken zincirinin (provenance) kopması engellenir.

### Prensip 5: Değiştirilemez Adli İz (Ed25519 & Merkle Audit Trail)
* **Kural:** Bir ajan yaptığı işlemi inkar edemez; geçmiş kayıtlar sonradan değiştirilemez veya silinemez.
* **Uygulama:** Tüm kayıtlar `previous_hash` zinciriyle birbirine bağlanır, Ed25519 ile imzalanır ve `audit_checkpoint` ile Merkle ağacı köklerine mühürlenir.

---

## 4. Tehdit Modeli ve Kapsam Sınırları (Honest Framing)

| Aktör | Tehdit Tanımı | KASA Savunması | Kapsam Durumu |
| :--- | :--- | :--- | :--- |
| **A1** | Prompt-Zehirli Model / Halüsinasyon | Deterministik `gate.py` ve `Namespace Allowlist` | ✅ Tam Kapsam |
| **A2** | Kötücül / Yetkisiz Araç Çağrısı | `deny-by-default` İzin Tablosu ve Token Kimlik Bağlama | ✅ Tam Kapsam |
| **A3** | Ziyaret Edilen Sayfadan Enjeksiyon | Yapısal Karantina (`_QUARANTINE_PATTERNS`) & Nötrleme | ✅ Tam Kapsam |
| **A4** | Aynı İşletim Sistemindeki Yetkisiz Kullanıcı | Windows DPAPI Anahtar Koruması + Hücre Şifreleme | ⚠️ Kısmi (OS Admin Kapsam Dışı) |
