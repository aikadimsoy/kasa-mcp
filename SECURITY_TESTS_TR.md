# Kasa - Güvenlik Testleri ve Mimari Savunma Raporu

Bu belge, Kasa (Vault) sistemi üzerinde uygulanan ampirik güvenlik testlerinin, test yöntemlerinin ve ulaşılmak istenen hedeflerin listesini içermektedir. Kasa projesi sadece otonom ajan (LLM) güvenliğini değil, katmanlı bir savunma (Defense-in-Depth) yaklaşımını hedefler.

> **Ölçüm damgası (2026-08-05).** Bu projenin kuralı: *ölçülene kadar mühürlenmez.* Aşağıdaki her
> madde, dayandığı ölçümü (dosya:satır veya `docs/` damgası) yanında taşır; dayanağı olmayan iddia
> yazılmaz. Güncel güvenlik tezgahı 21 kalemde **21 PASS · 0 FAIL · 0 WARN** okuyor
> (`docs/SECURITY_BENCHMARK.md`, commit `fc40b10`) ve *yayın-adayı* damgası basıyor. **Bu kelime
> tezgâhın, projenin değil** — dar bir takımda hiçbir kontrolün kalmadığı anlamına gelir, oysa
> F-POISON bulgusu açık ve o takımda onu ölçen kontrol yok (`docs/SECURITY_BENCH_LIMITS.md`).
> Açık bulgular ve
> bilinen sınırlar `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4 ve §7'de listelidir.
> Bu belgedeki hiçbir madde "kanıtlanmış / kırılamaz / %100 güvenli" anlamına gelmez.

## 1. Entropi Eşiği Doğrulaması (Entropy Backstop)
- **Nasıl Yapıldı:** Hem sentetik veri setleri hem de canlı `kasa.db` üzerinde Shannon entropisi (4.3 eşiği) test edildi. Canlı taramalar (Dry-Run) sonucunda elde edilen veriler karşılaştırıldı.
- **Amaç / Hedef:** Sırları (secrets) zararsız metinlerden (benign) sadece entropi ile ayırmanın mümkün olup olmadığını ölçmek.
- **Not:** Gerçek sırlar (ör. AKIA) ile URL/dosya yollarının entropi uzayında kesiştiği ölçümle gösterildi. Entropi ana kalkan değil, sadece bir "Son Savunma Ağı" (Backstop) olarak bırakıldı.

## 2. Base64 Gürültü Azaltma (Base64 Floor)
- **Nasıl Yapıldı:** Base64 tespit regex'ine `H >= 4.0` entropi tabanı (floor) şartı eklendi.
- **Amaç / Hedef:** `run/this/path` gibi zararsız dosya yollarının Base64 kuralına takılıp maskelenmesini (False Positive) önlemek.
- **Not:** Bu sayede gerçek Base64 sırları kaçırılmadan, sistemin kendi kendine "Veri Karartma (DoS)" yapmasının önüne geçildi. Ayırıcı pencere ölçüldü: zararsız dosya yolu H~3.92, gerçek base64 sır H>=4.66 (`src/vault/redact.py:23-26`).

## 3. Yapısal Prefix (Ön Ek) Kalkanı
- **Nasıl Yapıldı:** `AKIA...`, `ghp_...`, `sk_live_...` gibi bilinen düşük entropili anahtarlar için doğrudan Regex desenleri eklendi.
- **Amaç / Hedef:** Entropi eşiğine takılmayan (H < 4.3) bulut servis kimlik bilgilerini, entropiden **bağımsız** deterministik desenlerle yakalamak.
- **Ölçülen kapsam:** `src/vault/redact.py:49-60` içinde **10 sağlayıcı ailesi** için prefix deseni tanımlı (AWS erişim anahtarı, GitHub klasik token, GitHub fine-grained PAT, Stripe secret, Stripe restricted, OpenAI, Google API key, Slack, Google OAuth, npm). Bu desenlere uyan anahtar, entropi kapısına hiç girmeden maskelenir — gerekçesi ölçülmüştür: `AKIA` önekli anahtarın Shannon entropisi **H = 3.68**, yani hex'in bile altında (`src/vault/redact.py:46`).
- **Not (dürüst sınır):** "%100 doğruluk" iddiası **edilmez**. Kapsam listelenen ailelerle sınırlıdır; listede olmayan bir sağlayıcı formatı bu kuralla yakalanmaz, entropi ağına (§1) düşer. Ayrıca depo geneli bağımsız tarama kalemi `SCAN-SECRETS` (detect-secrets) şu an **FAIL** durumdadır — `docs/SECURITY_BENCHMARK.md` ve triyaj için `docs/SECRET_SCAN_CORPUS.md`. TruffleHog ve GitLeaks gibi endüstri standartlarının prefix yaklaşımı referans alınmıştır.

## 4. Delimiter Breakout (Yapısal Kaçış) Koruması
- **Nasıl Yapıldı:** Dış dünyadan (untrusted) gelen verilerdeki `<<<` ve `>>>` gibi yapısal işaretleyiciler Sıfır Genişlikli Boşluk (Zero-Width Space - ZWSP) ile nötralize edildi.
- **Amaç / Hedef:** Saldırganların veri bloklarından kaçarak "Semantic Prompt Injection" (Semantik İstem Enjeksiyonu) yapmasını engellemek.
- **Not:** Bu önlem **tek bir somut vektörü** (yapısal ayraç kaçışı) hedefler; komut enjeksiyonunun tamamına çözüm değildir — enjeksiyon tüm sektörde açık bir problem sınıfı olarak durmaktadır.

## 5. Okuma Zamanı Sansürü (Read-Time Redaction)
- **Nasıl Yapıldı:** Hassas hücreler veritabanına (SQLite) AES-GCM ile şifreli yazıldı (kapsamın tam sınırı için bkz. §11). Maskeleme işlemi yalnızca okuma anında (LLM veya dış API erişirken) `redact.scan` üzerinden yapıldı.
- **Amaç / Hedef:** Kasa verisi ile Yapay Zeka arasına bir "Zero-Trust" (Sıfır Güven) hava boşluğu (air-gap) koymak.
- **Not:** Yapay zekaya (LLM) asla güvenilmemesi gerektiği (Topluluk tabiriyle: "maximally evil") ilkesiyle tasarlandı.

## 6. Kaynak Kodu Koruması (Native Derleme)
- **Nasıl Yapıldı:** `redact.py` ve `cell_crypt.py` gibi güvenlik kritik dosyalar, Nuitka kullanılarak native makine koduna (C derleyici üzerinden) derlendi.
- **Amaç / Hedef:** Kötü niyetli aktörlerin IP (Fikri Mülkiyet) ve şifreleme/maskeleme algoritmalarını tersine mühendislikle (Decompile) elde etmesinin **çıtasını yükseltmek**.
- **Ölçüm (2026-07-10, `docs/EXE_PACKAGING_LOG.md`):** Derlenmiş dağıtımda ve onefile'ın `%LOCALAPPDATA%\KASA\0.1.0` açılım dizininde `src/*.py` sayısı **0**; `redact.py`, `cell_crypt.py`, `server.py`, `routes.py` dosya olarak **yok**; okunabilir `.pyc` **yok**. Yani klasik `pyinstxtractor` + geri-derleyici zinciri bu ikilide **uygulanacak bir hedef bulamaz**.
- **Not (dürüst sınır):** Nuitka ile Python → C derleme, `.pyc` çıkarımını ve geri-derlemeyi **önemli ölçüde** zorlaştırır; **%100 koruma mümkün değildir.** String sabitleri ve mantık izleri ikilide kalır, disassembly ile analiz edilebilir — `docs/SOURCE_PROTECTION_NOTES.md` §2 ve §5 ("%100 koruma imkânsızdır"). Kerckhoffs ilkesi gereği KASA'nın **güvenliği zaten kaynak gizliliğine dayanmaz**: sır = DPAPI ile korunan vault anahtarı, kod değil. Kaynak koruma burada bir **fikri mülkiyet** önlemidir, bir güvenlik sınırı değil. UI dosyaları (`dashboard_ui/`) bilerek düz metin kalır.

## 7. Veri Bütünlüğü (Audit Hash-Chaining)
- **Nasıl Yapıldı:** Veritabanındaki `audit` (denetim) tablosundaki her kayıt, bir önceki kaydın kriptografik özetini (SHA-256) içerecek şekilde zincirlendi — `src/vault/audit.py:71-93`, şifrele-sonra-hashle sırasıyla.
- **Amaç / Hedef:** Geçmişe dönük log silinmesi veya veri değiştirilmesi (Tampering) girişimlerini **tespit etmek**.
- **Ölçüm:** `AUDIT-VERIFY` PASS ("3-record chain verified"), `AUDIT-TAMPER-MODIFY` PASS ("Tampering detected in row 2"), `AUDIT-TAMPER-DELETE` PASS ("Deletion detected in row 2") — `docs/SECURITY_BENCHMARK.md`. Şifreli hücrenin tek karakteri değişse bile zincir bozulur.
- **Not (zincirin kanıtlaMAdığı şey):** Zincir bir kaydın **değişmediğini** kanıtlar; **"bu kaydı şu ajan yaptı"yı kanıtlamaz.** `agent_id` istek gövdesinden gelir ve doğrulanmaz, dolayısıyla **denetim atfı sahtelenebilir**. Ölçüm: `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.1 — dönen `agent_id` ile 300 istek gönderildi, hız freni **0 kez** devreye girdi, zincire **300 kalıcı satır** yazıldı. Bu yüzden "hiçbir aktivite sessizce silinemez" gibi bir garanti **yazılmaz**. Doğru ifade: *silme ve değiştirme tespit edilebilir; kimlik atfı güvence altında değildir* (kapatma planı: aynı belgede P1, "kimlik bağlama").

## 8. XSS (Cross-Site Scripting) Koruması
- **Nasıl Yapıldı:** Pano (dashboard) arayüzü DOM'u yalnızca `textContent` ve `createElement` ile kurar; `dashboard_ui/` içinde veri gösteren hiçbir yolda `innerHTML` veya `eval()` kullanılmaz.
- **Amaç / Hedef:** Kasa içine sızabilecek zararlı HTML veya JavaScript kodlarının kullanıcı arayüzünde çalışmasını engellemek.
- **Ölçüm (statik, 2026-08-03):** `dashboard_ui/app.js` içinde **71 `textContent` ataması, 0 `innerHTML` ataması, 0 `eval(` çağrısı**. (`textContent` kelimesi dosyada 73 kez geçer; 2'si yorum satırıdır. `innerHTML` kelimesi 5 kez geçer; **beşi de** yorum satırıdır.) `dashboard_ui/` içindeki tek `innerHTML` ataması `dashboard_ui/terms.html:130`'dadır ve **sabit bir metin literali** yazar — hiçbir vault/olay verisi enterpole edilmez.
- **Kapsam (ölçümün DIŞINDA kalan yüzey — dürüst sınır):** Yukarıdaki ölçüm **yalnızca `dashboard_ui/` içindir**. Tepsi menüsünden açılan tarayıcı penceresinin gömülü JS kabuğu (`src/browser/browser_window.py`, `src/tray/app.py:116` üzerinden çağrılır) `innerHTML` **kullanır**: 13 atama. Bunların 12'si sabit literal veya sabit SVG/ikon yazar (`:204, :208, :212, :634, :683, :702, :744, :784, :842, :857, :907, :1459`), ancak **`:152` adres çubuğunu kurarken `window.location.href` değerini enterpole eder** — yalnızca `"` karakteri `&quot;` ile kaçırılır, `<`, `>` ve `&` kaçırılmaz. Bu yol triyaj **edilmemiştir**. Bu yüzden "arayüzün tamamında `innerHTML` yok" **denemez**; ölçülmüş doğru ifade: *panonun veri yolunda `innerHTML` yoktur; tarayıcı penceresi kabuğunda vardır ve bir tanesi ziyaret edilen sayfanın URL'sini enterpole eder.*
- **Not (dürüst sınır):** Bu bir **kod disiplini ölçümüdür**, bir saldırı ölçümü değil. Güvenlik tezgahının 21 kaleminde XSS kalemi **yoktur**; bağımsız bir XSS penetrasyon testi **koşulmamıştır** (`docs/SECURITY_BENCHMARK.md`). Bu yüzden "sıfır risk" denmez — söylenebilecek olan, bilinen XSS taşıyıcısının (veri yolunda `innerHTML`) **panoda** ölçülebilir biçimde kullanılmadığıdır.

## 9. Ağ İzolasyonu (Air-Gap & Local-First)
- **Nasıl Yapıldı:** Sistem mimarisinde bulut bileşeni yoktur; API varsayılan olarak yalnızca `127.0.0.1`'e bağlanır ve CORS izin listesi yapılandırmadan okunur (`src/mcp_server/server.py:57`, `:109-114`).
- **CORS'un ölçülen tam hâli (dürüst sınır):** Kod içi varsayılan `["http://localhost", "http://127.0.0.1"]`'dir (`src/config.py:11`), ama README'nin kopyalamanızı söylediği `kasa.toml.example:8` bu listeye **`"null"` origin'ini de ekler**. `null` origin'i sandbox'lı iframe'ler, `data:` ve `file://` bağlamları gönderir; yani taze kurulumda CORS "yalnızca localhost" **değildir**. Bu yüzden CORS burada tek başına bir sınır sayılmaz — asıl kapı §10'daki bearer token'dır (`FUZZ-NOAUTH` / `AUTHZ-TOKEN-*` PASS).
- **Amaç / Hedef:** Vault verisinin kullanıcı makinesinden çıkmasını **gerektiren** her yolu mimariden çıkarmak.
- **Ölçüm:** `AUTHZ-BIND` PASS — `Default host: 127.0.0.1` (`docs/SECURITY_BENCHMARK.md`). KASA kendi başına dışarıya bağlanmaz; damıtma da yerel Ollama'ya (`localhost:11434`) gider.
- **Not (ölçülMEyen kısım — önemli):** KASA, makinedeki giden ağ trafiğini **kısıtlamaz ve ölçmez.** Çıkış (egress) kontrolü `docs/GUVENLIK_CIKIS_PLANI.md` Faz 1-4'te planlıdır ve **hiçbiri kurulmamıştır** (`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.4 ve E3). Bu yüzden veri sızdırmanın "kökten imkânsız" olduğu **söylenemez**: aynı makinede çalışan ve bearer token'ı okuyabilen bir süreç için dışarı konuşma yolu ölçülmemiş durumdadır. Doğru ifade: *vault erişimi izin aracısıyla dar tutulur, okunan her şey redact kapısından geçer, KASA kendisi dışarıya bağlanmaz — ancak egress kanıtla kapatılmış değildir.*

## 10. Yetkisiz API Erişimi (Bearer Token)
- **Nasıl Yapıldı:** Arayüzün haberleştiği yerel API (FastAPI), her istekte `KASA_TOKEN` Bearer Token doğrulaması arar; token ilk çalıştırmada üretilir ve `kasa.toml` içinde tutulur.
- **Amaç / Hedef:** Bir web sitesinin veya farklı OS kullanıcısı altında çalışan bir sürecin Kasa API'sine sahte istek (SSRF/CSRF) atmasını engellemek.
- **Ölçüm:** `AUTHZ-TOKEN-MISSING` PASS (401), `AUTHZ-TOKEN-WRONG` PASS (401), `FUZZ-NOAUTH` PASS (401) — `docs/SECURITY_BENCHMARK.md`.
- **Not (dürüst sınır):** Token **tek kullanımlık değildir**; kalıcı ve paylaşılan bir sırdır ve `kasa.toml` içinde **düz metin** durur — bu, tezgahın `SCAN-SECRETS` bulgusunun bir parçasıdır. Uygulanan azaltma: dosya ACL'i sahip + SYSTEM + Administrators ile sınırlı; rotasyon ve DPAPI-wrap sahip kararı bekliyor (`docs/SECRET_SCAN_CORPUS.md` §6, `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.3). Pratik anlamı: token **farklı OS kullanıcıları ve web sayfalarına** karşı bir sınırdır, aynı kullanıcı bağlamında çalışan kod ile Kasa arasında değil — MCP ile bağlanan her ajan da bu token'ı bilir.

## 11. Hücre Bazlı Şifreleme (Data at Rest - AES-GCM)
- **Nasıl Yapıldı:** Veritabanına (SQLite) yazılan hassas hücreler düz metin olarak değil, Kimliği Doğrulanmış Şifreleme (AES-256-GCM) ile — hücre başına rastgele nonce ve AAD (bağlama bağlama) eklenerek — kaydedildi.
- **Amaç / Hedef:** Kötü amaçlı bir yazılım diske erişip `kasa.db` dosyasını fiziksel olarak çalsa bile **şifreli kolonların içeriğini** okuyamamasını sağlamak.
- **Ölçüm:** `CRYPTO-ATREST` PASS (canary `kasa.db` ve yan dosyalarında bulunamadı), `CRYPTO-KDF` PASS (scrypt), `CRYPTO-DPAPI` PASS, `CRYPTO-EXPORT` PASS (yanlış parola reddedildi) — `docs/SECURITY_BENCHMARK.md`. Canlı vault'ta **175 şifreli hücre** sayıldı; satır/kolon takası AAD sayesinde `InvalidTag` ile başarısız oluyor (`test_aad_swap_breaks_decrypt`).
- **Kapsam (dürüst sınır — bu maddedeki en önemli satır):** `kasa.db` **şifreli bir dosya değildir**; başlığı `SQLite format 3` olan düz bir SQLite veritabanıdır. Şifreleme **hücre bazlıdır ve yalnızca üç kolonu** kapsar: `events.content`, `profile.value`, `audit.details`. Diğer tüm kolonlar — `timestamp`, `session_id`, `source`, `type`, `ttl_expiry`, `distilled`, `profile.key`, `provenance`, `profile.created_at`, `profile.updated_at`, `agent_id`, `action`, hash'ler ve `permissions.*` — **düz metindir**; sorgulanabilirlik, TTL taraması ve hash zinciri bunlara bağlı olduğu için bilinçli olarak şifrelenmemiştir. Kolon kolon ölçüm: `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §1. Tam-DB at-rest şifreleme (SQLCipher) **mühürlü değildir** — `docs/adr/0003-at-rest-sifreleme-boslugu.md`.
- **Sonuç (ölçülmüş):** Dosyayı ele geçiren biri **içeriği** okuyamaz, ama **deseni** okuyabilir: hangi profil anahtarlarının var olduğu, kaç olay bulunduğu ve hangi saat aralığında gezinildiği düz metin metadata'dan çıkarılabilir (aynı belge §1'de örneklendi). Bu, kapatılmış bir açık değil, **belgelenmiş bir takastır**; kullanıcı tarafında azaltma yolu vault dizinini BitLocker gibi şifreli bir birime koymaktır.
- **Not:** Şifre çözme anahtarı (`.vaultkey`) veritabanından ayrı tutulur ve Windows DPAPI ile korunur. Aynı kullanıcı bağlamında çalışan bir zararlı yazılım DPAPI'yi çağırabilir; bu, kapatılamayan ve belgelenmiş bir sınırdır (`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.5).
