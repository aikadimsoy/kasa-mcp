# KASA Yol Haritası — "geride" alanları kapatma sırası (2026-08-04)

> **Karar sahibi:** plan (sıralama + öncelik + gerekçe) elle yazıldı; yerel model yalnız düzyazı-taslak
> için KASA kapısından kullanıldı (dogfood) ve **kararı değiştirmedi**. Yerel taslağın "neden bu sırada"
> gerekçeleri jenerik çıktı → sıralama muhakemesi bu belgede elle konuldu ([[dont-delegate-or-predecide]]).
>
> **Kuzey yıldızı:** NLnet başvurusu — "bul→kanıtla→kapat" + "Anthropic'in Mayıs 2026'da adını koyduğu
> Zero-Trust-for-Agents duruşunu zaten uyguluyoruz; **kripto-implementasyon boşluğunu kapatıyoruz**."
> **Sınır:** güvenlik-kritik yolu Claude yazar, **sahip mühürler**, push yok.

| Faz | İş | Efor | Bağımlılık | Güvenlik-kritik |
|---|---|---|---|---|
| 0 | G2 Host-guard (TrustedHostMiddleware) | düşük | yok | evet (mühür) |
| 1 | Ed25519 imzalı audit + Merkle | orta | Faz-0 | evet (mühür) |
| 2 | G3 türetme-DAG + karantina + bayrak-değerlendirici | orta | Faz-1 faydalı | evet (mühür) |
| 3 | Dual/Quarantined-LLM | orta | Faz-2 ile anlamlı | evet (mühür) |
| 4 | Egemenlik: kısa-ömürlü token + CPU-TEE spike | büyük | spike-önce | spike salt-okur |

---

## Faz 0 — G2 Host-guard (TrustedHostMiddleware) — ✅ TAMAM (2026-08-04, sahip mührü bekliyor)
> **Durum:** uygulandı + **canlı-doğrulandı** (loopback→200, attacker/`127.0.0.1.evil.example` Host→400);
> 281 test geçti/1 xfailed (regresyon yok). Dosyalar: `src/mcp_server/server.py` (`_host_guard`),
> `tests/test_host_guard.py`, `tests/conftest.py`. **Push yok — sahip mührü bekliyor.**

- **Amaç:** DNS-rebinding savunma-derinliği boşluğunu (bu oturumda bulundu, HEAD'de yamasız) kapatmak.
- **Ne yapılır:** FastAPI `TrustedHostMiddleware(allowed_hosts=["127.0.0.1","localhost","::1"])`; Host ∉ liste → red; wildcard yok.
- **Neden BU sırada (ilk):** Tek gerçek *bulunmuş + standart-fix'i olan* açık; düşük efor, sıfır bağımlılık, hemen
  kapanır ve MCP-spec uyumu getirir. NLnet anlatısını en hızlı güçlendiren adım: "bulduk, kanıtladık, **kapattık**."
- **Kabul:** loopback-dışı Host → 421/403; loopback → geçer; batarya testi tekrar koşulur; testler yeşil.

## Faz 1 — Ed25519 imzalı audit + Merkle — ✅ TAMAM (2026-08-04, sahip mührü bekliyor)
> **Durum:** uygulandı + testlerle kanıtlandı (imzalı doğrulama, kurcalama tespiti, **bağımsız
> public-key doğrulama**, legacy geriye-uyum, Merkle kökü). 285 test geçti/1 xfailed. Dosyalar:
> `src/vault/audit.py` (imza+Merkle+`verify_entry_signature`), `src/vault/database.py`
> (`_get_or_create_audit_signing_key` DPAPI, `audit_public_key_hex`), `src/vault/schema.py`
> (`signature`, `merkle_root` kolonları + migration), `tests/test_audit_signing.py`.
> Yeni dosya diskte KALIR: `.auditsignkey` (silinirse eski imzalar doğrulanamaz). **Push yok.**

- **Amaç:** audit'i "depo-içi tamper-evident"ten "**bağımsız doğrulanabilir**"e taşımak (KASA'nın Notarized-Agents/MemLineage karşısında geride olduğu tam nokta).
- **Ne yapılır:** mevcut audit hash-zincirine per-entry **Ed25519 imza** + checkpoint'e **Merkle kök**.
- **Neden BU sırada (2.):** Mevcut `audit.py` hash-zinciri + checkpoint'i **genişletir** — en az yeni yüzey, en yüksek
  hiza. Ayrıca Faz-2'nin türetme-lineage'ının **güvenilir** olması için girdilerin imzalı olması gerekir → Faz-2'den önce.
- **Kabul:** her audit satırı public key ile **üreticiden bağımsız** doğrulanır; imza-anahtarı yönetimi sahip kararı.
- **Not:** post-quantum (ML-DSA-65) opsiyonel; Notarized Agents referans.

## Faz 2 — G3: türetme-DAG + karantina + bayrak-değerlendirici (ASI06) — ✅ ÇEKİRDEK TAMAM (2026-08-04)
> **Durum:** uygulandı + testlerle kanıtlandı (291 test geçti/1 xfailed). Karantina mekanizması **hem
> ajan-yazımını (`profile_write`) hem damıtma motorunu** kapsıyor: yapısal olarak ajana-emir görünümündeki
> yazım canlıya girmez, `profile_quarantine`'a atıf (`agent_id`) + neden ile konur; sahip `release_quarantined`
> (admin:grant) ile serbest bırakır. Deterministik yapısal bayrak (model-yargısı değil → adaptif-atlatmaya
> kapalı). Dosyalar: `src/vault/quarantine.py` (paylaşılan bayrak), `src/vault/schema.py`
> (`profile_quarantine` tablosu), `src/mcp_server/tools.py` (karantina dalı + list/release),
> `src/distill/engine.py` (damıtma yönlendirmesi), `tests/test_quarantine.py` + `test_distill_quarantine.py`.
> **Ertelenen (Faz 2b+):** izole LLM "ikinci değerlendirici" (ek yumuşak sinyal — deterministik bayrak zaten
> birincil), tam türetme-DAG sorgu API'si + Merkle-tarzı lineage attestation (MemLineage). **Push yok.**

- **Amaç:** scope-geçerli-ama-enjekte bir ajanın hafızaya zehir yazmasını **tespit + karantina + atıf** (önleme değil).
- **Ne yapılır:** `provenance`'ı **türetme-DAG**'a genişlet (hangi olay hangi damıtmayı besledi); düşük-provenance /
  damıtma yazımlarını **karantinaya**; **izole, araçsız** bir değerlendirici **risk bayrağı** koyar (kapı DEĞİL).
- **Neden BU sırada (3.):** En derin boşluk (endüstri-açık) ve en zor; Faz-1'in imzalı zinciri lineage-atıfını
  güvenilir kılar. Karantina, belgelenmiş "damıtma denetimsiz yazım" boşluğunu kapatır.
- **Kabul:** enjekte scope-geçerli yazım karantinaya düşer + kaynağa atfedilir. **Dürüst sınır:** semantik-geçerli
  zehri *önlemez*; iddia "tespit + karantina + atıf".

## Faz 3 — Dual / Quarantined-LLM — ✅ TAMAM (2026-08-04, sahip mührü bekliyor) — DÜRÜST YENİDEN-KAPSAMLAMA
> **Kurmadan önce kod okundu → izolasyonun büyük kısmı ZATEN yapısal.** KASA'daki tek araç-yetkili
> LLM yolu `src/agent/harness.py` (`run_chat`) ve şunlar hâlihazırda var: (1) **sabit, salt-okunur,
> maskeli** araç allow-list'i (`gate.TOOLS`); (2) her çağrıda deterministik `gate.validate_call`
> (ad-listesi + kredensiyel içerik-kapısı); (3) tek yazıcı `kasa_note` **modele gösterilen şemaya bile
> girmiyor** (`allow_notes=False` → `chat_tool_schemas` atlar), izni seed edilmemiş, handler `disabled`;
> (4) her araç sonucu modele dönmeden `sanitize_untrusted_text`. **Bu, CaMeL Action-Selector +
> Quarantined-LLM deseninin ta kendisi.** → Faz-3 sıfırdan "çift-LLM kurmak" DEĞİL; **kanıtlamak +
> dar kalıntıyı kapatmak.**
>
> **Yapılan (uygulandı + testlerle kanıtlandı; 297 test/1 xfailed):**
> - **(A) Read-time deterministik nötrleme** — `src/vault/quarantine.py::neutralize` (Faz-2'nin
>   paylaşılan yapısal paterni; model-yargısı değil): vault serbest-metni (yalnız `profile` değeri;
>   `recent_events` zaten `content` döndürmüyor) araç-yetkili modele **dönmeden** enjeksiyon-kalıplı
>   span yer-tutucuya indirilir (`harness._prepare_result`). → enjeksiyon-metni modelin **cevabını**
>   kelimesi kelimesine yönlendiremez.
> - **(C) Negatif kontrol** — `tests/test_agent_isolation.py`: enjekte profil değeri gören model bir
>   yazma (`kasa_note`) + exfil (`vault_dump_raw`) çağrısı üretse bile **ikisi de gate-reddedilir,
>   hiçbir araç çalışmaz** → vault'a yazım ulaşmaz. Pozitif kontrol: zararsız metin nötrlenmez.
> - **Dosyalar:** `src/vault/quarantine.py` (`neutralize`), `src/agent/harness.py` (`_prepare_result`
>   + import), `tests/test_agent_isolation.py` (6 test: birim + e2e, pozitif+negatif). **Push yok.**
>
> **Dürüst kalıntı/sınır (önleme DEĞİL, çevreleme):**
> - Nötrleme paterni Faz-2 ile **aynı** → Faz-2'den sonra yazılan değerler zaten aktif profile
>   girmez (karantina); (A)'nın gerçek hedefi **legacy / kapı-öncesi** ya da `quarantine=False` ile
>   zorlanmış değerlerdir — savunma-derinliği.
> - **Semantik-geçerli** (patern-dışı) enjeksiyon modele hâlâ ulaşabilir; ama **yalnız cevabı**
>   bozabilir, **hiçbir yetkili eylemi** tetikleyemez (gate deterministik keser). Bu ayrımın kanıtı
>   testtedir. İddia: **"tespit + çevreleme"**, "önleme" değil.
> - Muhafazakâr patern kullanıcının **kendi** notundaki mesru "you must ..." gibi ifadeyi de
>   maskeleyebilir (aşırı-çevreleme) → modelin cevabı bağlamdan biraz yoksun kalabilir. **Depoda
>   saklanan veri DEĞİŞMEZ**; yalnız modele-beslenen kopya nötrlenir.
> - **Ertelenen:** ayrı bir araçsız-LLM "ikinci özetleyici" (ek yumuşak sinyal). Deterministik nötrleme
>   birincil; ikinci-LLM'e güven, tüm modeller enjekte-edilebilir olduğu için bilinçli olarak ertelendi.

- **Amaç:** güvenilmez içeriğin (A1) araç-yetkili akıl yürütmeye ulaşmasını yapısal olarak kesmek (CaMeL deseni).
- **Kabul (KARŞILANDI):** güvenilmez içerik **hiçbir araç tetikleyemez** — negatif kontrolle kanıtlandı.

## Faz 4 — Egemenlik-derinliği (spike-önce)
- **Amaç:** A4/G1'i kısmen kapatmak + Zero-Trust'ın "kısa-ömürlü token" ilkesini eklemek.
- **Ne yapılır:** (a) kısa-ömürlü/rotasyonlu ajan token'ları; (b) sub-7B için **CPU-TEE (Intel SGX)** fizibilite spike'ı.
- **Neden BU sırada (son):** En büyük/en spekülatif; TEE enjeksiyonu çözmez (yalnız kullanımdaki-veri) → NLnet
  anlatısı için bloklayıcı değil. **Önce salt-okur fizibilite raporu**, sonra karar.
- **Kabul:** spike raporu (fizibil mi, perf, karmaşıklık) → sahip kararı.

---

## Yerel-model dogfood değerlendirmesi (bu belgenin üretim notu)
- Yerel `qwen2.5:7b`, KASA kapısından (`/v1/agent/chat`, owner+gate) planı düzyazıya genişletti — **kararı korudu** (sıra/öncelik değişmedi). ✓ dogfood çalışıyor.
- **Ama "neden bu sırada" gerekçeleri jenerik/vakum** çıktı (her fazda aynı cümle) ve bir anahtar kelimeyi bozdu.
  → Sıralama muhakemesi elle konuldu. Ders (tekrar): yerel = düzyazı-iskelet; **planlama-kararı = Claude**.

## Dürüstlük iddiaları
- `local_model_via_kasa_gate: true` (qwen2.5:7b, owner+gate); `plan_decision_by: claude` (elle)
- `scores_or_probabilities_invented: false` · efor/sıra gerekçeleri argüman-bağlı, sayı uydurulmadı
