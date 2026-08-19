# KASA Workcell "Deep Research" Raporu — Nihai Değerlendirme

**Tarih:** 2026-08-05
**Değerlendirilen belge:** `deep-research-report.md` (2201 satır)
**Değerlendirmeyi yapan:** ana ajan + 9 alt-ajanlık iş akışı (ham çıktılar: `wf_results.json`)
**Ölçüm seviyeleri:** `RAN-LIVE` (bugün gerçekten koşuldu) · `CODE-STRUCTURE` (kaynak okundu, koşulmadı) · `DOCUMENTED` (yalnız belgede yazılı)

---

## 1. Yönetici özeti

**Rapor mimari fikir kaynağı olarak değerli, kanıt kaynağı olarak kullanılamaz — ve merkezindeki sayı ölçülmüş bir sonuç değil, kendi tablosuyla çelişen bir varsayım çıktısıdır.**

Üç şey bugün ölçülerek kanıtlandı. Birincisi: raporun manşeti olan "%93,7 bileşik başarı", raporun kendi sınıf-başına tablosuyla aritmetik olarak bağdaşmıyor. On sınıfın çarpımı %55,77 eder (fark 37,9 puan); bölüşme okumasında sınıf ortalaması tanımı gereği bileşik değere eşit olmak zorundadır ve %94,35 çıkar, %93,7 değil. Üç manşeti (33,9 / 82,8 / 93,7) ve sınıf tablosunu aynı anda tutarlı kılan hiçbir parametre seti yok. Ayrıca %90,3 ve %93,7 gibi değerler beyan edilen 500 koşu/sınıf bütçesiyle hiçbir tamsayı sayımdan çıkamaz. İkincisi: raporun bütünlük mekanizmasının merkezindeki `canonical_hash()` deterministik değil — aynı kanıt kartını 8 ayrı süreçte mühürledim, 8 farklı hash çıktı. Yani `card_hash → package_hash → Ed25519 imza → Cortex import doğrulaması` zinciri üretimde ve doğrulamada farklı sonuç verir. Düzeltmesi tek satır (`sorted(...)`), ki bu da bu fonksiyonun hiç koşulmadığını gösteriyor. Üçüncüsü: rapor kendi sentetik sayısını `trust=verified_tool_result, confidence=1.0` etiketiyle Cortex paketine gömüp kendi terfi kapısından geçiriyor — bu, KASA'nın ölçtüğü F-POISON'un aynı deseni: kapı **yetkiyi** aracılar, **doğruluğu** değil.

Raporun teşhisi ise büyük ölçüde doğru: LLM kontrol otoritesi olmamalı, MCP annotation'ları güvenlik kararı için kullanılmamalı, karar defteri append-only olmalı, idempotency ile "bilinmeyen durum" ayrı ele alınmalı, vektör indeks otorite değildir. Bunların hiçbiri için rapora ihtiyaç yok — hepsi KASA'nın kendi ölçümleriyle zaten uyumlu — ama derli toplu bir kontrol listesi olarak işe yarar.

Önerdiği yığın KASA için yanlış. Ölçüldü: bugünkü 36 paketlik bağımlılık kapanışı 133'e çıkıyor (+97 paket) ve üstüne 7-8 uzun ömürlü servis geliyor; bu, "tek exe, kullanıcıda Python bile gerekmez" kararının tersi. Daha kötüsü, en yüksek eforlu bu seçenek KASA'nın ölçülmüş tek açık kusurunu (F-POISON) **kapatmıyor**: raporun kendi Rego politikasında `taint` girdisi hiç yok.

**Karar:** fikirleri al, sayıları alma, yığını alma. Bu hafta yapılacak iş rapordan değil, aşağıdaki 10. bölümden çıkıyor.

---

## 2. Ölçülen kusurlar

Bu bölümdeki her madde ya bugün koşuldu ya da kaynak metin/koddan okundu. Hiçbiri "muhtemelen" değil.

### 2.1 Manşet sayı, raporun kendi tablosuyla aritmetik olarak tutarsız — `RAN-LIVE`

Betik: `…/scratchpad/arith_check.py`, bugün koşuldu. Raporun V2 sınıf-başına tablosu (satır 1851-1862: %90,3 … %97,2, 10 sınıf) üzerinde:

| Okuma | Değer | Manşetle fark |
|---|---:|---:|
| Bağımsız çarpım ("tüm sınıflarda güvenli") | 0,5577 | −37,93 puan |
| Sınıf ortalaması ("her koşu tek sınıfa maruz") | 0,9435 | +0,65 puan |
| Raporun manşeti | 0,9370 | — |

Çarpım okumasında %93,7'yi üretmek için sınıf-başına **0,99351** gerekir; raporun kendi tablosunun tavanı 0,972'dir. Yani hiçbir sınıf bu eşiği karşılamıyor.

Ortalama okuması manşete çok daha yakın, ama **bu okumada fark gürültü olamaz**: sınıf başına eşit koşu varsayıldığında bileşik oran, tanım gereği sınıf oranlarının ortalamasıdır (toplam başarı / 5000 = ortalama(p_i)). 0,65 puanlık sapma için ya eşitsiz koşu dağılımı ya tabloda görünmeyen ek bir kayıp kaynağı gerekir; rapor ikisini de belirtmiyor.

Ayrıca `,7` hanesi anlamsız: 5000 koşuda p=0,937 için standart hata 0,00344, %95 güven aralığı **[0,9303 ; 0,9437]**. Rapor 0,1 puan çözünürlükle 10 sınıfı sıralıyor; o çözünürlüğü %95 güvenle çözmek için ~907.000 koşu gerekirdi.

### 2.2 Simülasyonun bağımsız yeniden üretimi — `RAN-LIVE` (alt-ajan koştu)

Betik ve çıktı diskte: `…/scratchpad/sim_repro.py`, `…/scratchpad/sim_repro_result.json` (Python 3.14.5, yalnız stdlib, tohum 20260805, 5000 koşu).

- **Rapor simülasyon kodunu yayımlamıyor.** Metinde 7 python bloğu var; hiçbiri simülasyon değil. `random.seed`, `numpy`, `def simulate` hiç geçmiyor; `tests/run_simulation.py` yalnız bir dizin ağacında **isim** olarak geçiyor. Kapı olasılıkları, RNG modeli, 5000 koşunun sınıflara dağılımı ve "bileşik"in hangi kompozisyon kuralıyla hesaplandığı hiçbir yerde yazmıyor. **Sabit tohum, kod olmadan yeniden üretilebilirlik sağlamaz — yalnızca görüntüsünü verir.**
- **Üç kompozisyon modeli koşuldu.** Kesişim (A), bölüşme (B), görülme sıklığı (C). Raporun tablosuyla manşetini uzlaştıran tek model C'dir ve q = 0,11475 gerektirir; aynı q taban için zorlandığında tabanın sınıf-başı güvenli oranı **%10,6** çıkar, yani tek ajan bir hata sınıfıyla karşılaştığında 10 kezden ~9'unda başarısız olur. Bu, raporun "%33,9 makul bir taban" çerçevesini yıkar.
- **Duyarlılık, sayının mimariyi değil varsayımları ölçtüğünün ampirik kanıtı.** Kapı yakalama olasılıklarını yalnızca −%20 oynattığımda V2'nin kesişim bileşiği 0,6868 → **0,3386** oldu; bu, raporun "temel tek ajan" diye sunduğu 0,339 sayısının kendisi. Aynı mimari, sadece varsayım kaymasıyla tabana düşüyor.
- **Tohum yayılımı (20 tohum × 5000 koşu):** bölüşme modelinde 0,9352 – 0,9502 (yayılım 1,50 puan, sd 0,396 puan).
- **Sayılabilirlik (granülarite) bulgusu.** Bir oran n koşuda ancak k/n olabilir. 500 koşu/sınıf ile **%90,3 · %93,7 · %95,9 değerleri hiçbir tamsayı sayımdan çıkmaz**; tablo ancak sınıf başına ≥1000 koşu (≥10.000 toplam) ile üretilebilir. Rapor "toplam beş bin run" diyor. Manşet değerler (1695 / 4140 / 4685) ise n=5000'de tamsayı — yani manşetler tablodan ayrı bir hesaptan geliyor gibi görünüyor.
- **Homojenlik testi:** 10 sınıfın tek bir gerçek orana sahip olduğu H0 altında 500 koşu/sınıfta beklenen yayılım 3,17 puan; raporda gözlenen 6,9 puan. 45 sınıf çiftinin **27'si (%60)** bu örneklem büyüklüğünde istatistiksel olarak ayırt edilemez; özellikle injection %93,6 / compaction %93,7 / memory-poisoning %93,8 üçlüsü tümüyle gürültünün içinde ve sıralaması yorumlanamaz.

**Hüküm:** %93,7 KASA disiplininde `RAN-LIVE` değil, en fazla `DOCUMENTED` seviyesindedir ve yayımlandığı haliyle yeniden üretilemez. Bu bir "rapor uyduruyor" iddiası değildir — kanıtlanan şey iç tutarsızlık ve varsayım duyarlılığıdır.

### 2.3 Bütünlük mekanizması ölçülerek kırıldı — `RAN-LIVE`

Betik: `…/scratchpad/hash_stability_check.py`, bugün koşuldu.

Raporun `EvidenceCard` sınıfında `taint_labels` bir `set[str]` (satır 986) ve `canonical_hash()` bunu `json.dumps(..., default=str)` ile serileştiriyor (satır 953-961). `json` bir set'i serileştiremez, dolayısıyla `default=str` devreye girip `str(set)` kullanılır — ve Python'da string elemanlı set'in yineleme sırası süreçler arası rastgeledir (hash randomizasyonu, 3.3'ten beri varsayılan açık).

Aynı kanıt kartı 8 ayrı süreçte mühürlendi: **8 farklı sha256**. (Aynı süreç içinde kararlı; kontrol koşusu bunu gösteriyor. Daha önceki bir koşumda 8 süreçte 7 farklı hash çıkmıştı — sayı koşudan koşuya değişir, kararsızlık değişmez.)

Sonuç: `seal() → card_hash → package_hash → Ed25519 imza → Cortex import doğrulaması` (satır 2127-2152) zincirinin tamamı kullanılamaz. Üretimde mühürlenen kart, doğrulamada farklı hash verir; doğrulama **yanlış-negatif** üretir.

Düzeltme tek satır ve test edildi:

```python
# EvidenceCard.seal() — before: unordered set leaks into the digest
"taint_labels": self.taint_labels,          # set[str] -> str(set) via default=str
# after: deterministic across processes
"taint_labels": sorted(self.taint_labels),  # list[str], canonical order
```

*Türkçe açıklama: `set` bir sıra taşımaz; onu doğrudan özete sokmak, özetin sıraya bağlı olmasına yol açar. `sorted(...)` ile listeye çevirmek sırayı deterministik kılar. Kontrol koşusunda `sorted(...)` ile aynı içerik her seferinde aynı hash'i verdi. Bu kadar küçük bir düzeltmenin gerekmesi, "content-addressed, imzalı, doğrulanabilir" iddiasının merkezindeki fonksiyonun hiç çalıştırılmadığının kanıtıdır.*

### 2.4 Raporun kendi kodundaki diğer kusurlar — `CODE-STRUCTURE` (aksi belirtilmedikçe)

- **`score()` güven hiyerarşisini tersine çeviriyor — `RAN-LIVE` (alt-ajan yeniden kodlayıp koştu).** Alakalı ve taze bir `untrusted_external` parça, taint cezası uygulansa bile **0,5875** alıyor; daha az alakalı ama `human_approved` bir proje kararı **0,495** alıyor. Enjekte içerik kazanıyor. Yapısal neden: alaka bandı 0,50 ağırlık taşırken güven bandı yalnızca 0,1275 taşıyor.
- **Taint cezası ölü kod.** Ceza tam olarak `may_contain_instructions` etiketini arıyor (satır 1080-1082); `web.fetch` çıktı şeması `untrusted_external` üretiyor (satır 875); Cortex paketindeki gerçek kartların hepsi `external_data` kullanıyor. Yani raporun P0 saydığı prompt-injection kontrolü, raporun **kendi verisi üzerinde hiç tetiklenmiyor**. Pozitif kontrol hiç yapılmamış.
- **Mutlak değişmez, yumuşak cezaya çevrilmiş.** Cortex paketi "Untrusted content cannot authorize tools" diye mutlak bir kural yazıyor (satır 1910); uygulama bunu 0,20'lik bir çıkarma olarak modelliyor. Deny-by-default gereken yerde ağırlıklı toplam kullanılmış; güvenlik özelliği tek bir skalere karıştırıldığında artık değişmez değil, tercihtir.
- **`freshness_score()` determinizmi kırıyor.** Her çağrıda `datetime.now(timezone.utc)` okunuyor (satır 1070) ve `score()` hem `sorted()` anahtarı olarak (satır 1102) hem çıktı sözlüğü kurulurken (satır 1130) **yeniden** hesaplanıyor. Yayımlanan `score` değeri, sıralamayı üreten değer değildir; aynı girdi aynı çıktıyı vermez. Replay ve Temporal determinizmi üzerine kurulu bir mimaride, bağlam derleyicisinin kendisi yeniden üretilemez.
- **ContextCompiler çelişkileri "birlikte taşı" diyor, kod taşımıyor.** Yorum satırı (1114) çelişen kayıtların birlikte taşınmasını söylüyor; kod yalnızca `contradiction_set` **adını** ekliyor. Karşı kayıt token bütçesinin altında kalırsa düşüyor; üstelik skor sıralı seçim, çelişen çiftlerden daha alakalı görünen tarafı sistematik olarak seçer — yani çelişki gizlenmeye yatkın. Skill manifestinin çıkış şartı `contradictions_listed` kodla karşılanmıyor.
- **`manifest_verified` kendi kendini onaylıyor ve hiçbir yerde üretilmiyor.** Rego bu alanı arıyor (satır 1243); ToolGateway `tool.metadata`yı, yani manifestin kendisini gönderiyor (satır 1394). Metinde `manifest_verified` **toplam 1 kez** geçiyor — yalnız Rego'da. İki sonuç var, ikisi de kötü: ya alan hiç üretilmez (her çağrı `default_deny`, ve raporda tek bir pozitif kontrol yok), ya da manifestten okunur (kötü niyetli sunucu `manifest_verified: true` yazıp kapıyı açar).
- **Rapor "manifest `idempotent: true`'ya güvenme" diyor, kendi politikası tam da ona güveniyor** (ilke satır 913, uygulama satır 1252-1260 + 1394).
- **Alan adı uyumsuzluğu.** Araç kataloğu `risk.readOnly` / `risk.destructive` (iç içe, camelCase); Rego `input.tool.read_only` (düz, snake_case); gateway `tool.metadata.get('read_only')`. Üç bileşen hiç birlikte koşulmamış — bu, kodun `DOCUMENTED` seviyede olduğunun doğrudan kanıtı.
- **Rego `decision` kuralı üç kez complete rule olarak tanımlanmış** (satır 1271-1293) ve `read_only_allowed` ile `human_required`'ın ikinci gövdesi birbirini dışlamıyor. `web.fetch` tam olarak `readOnly:true + openWorld:true`; yüksek riskli bir görevde her iki gövde de doğru olursa OPA "complete rule farklı değerler üretti" hatası verir. Yön olarak fail-closed, yani bypass değil olgunluk kusuru — ama bu kombinasyonların hiç test edilmediğini gösterir.
- **Gateway salt-okunur çağrılarda girdi hash'ini idempotency anahtarı yapıp bayat sonuç dönüyor** (satır 1407-1423). TTL veya geçersiz kılma yok; `repo.search` ile değişen dosyalar hiç görünmez. Tazelik raporun kendi P1 kontrollerinden biri.
- **Cortex örnek paketi kendi import prosedürünü geçemez — `RAN-LIVE` (metin sayımı).** `package_hash: "sha256:example_cortex_package_hash"`, imza `"base64:example-signature"`, 11 adet `sha256:example_*` yer tutucusu var. Daha ciddisi: dört doğrulama kaydı `"status": "passed"` taşıyor ve çözülemeyen CAS referanslarına işaret ediyor. **Koşulmamış testler GEÇTİ olarak kayda geçirilmiş**; yer tutucu bir örnekte bile `not_run` yazılmalıydı.
- **42 atıf hedefinin tamamı çözülemez — `RAN-LIVE` (metin sayımı).** 21 atıf bloğu, U+E200/E201/E202 özel-kullanım ayırıcılarıyla birleştirilmiş 42 hedef (29 benzersiz): `turn6academia0`, `turn11view1` … Hiçbiri bir URL'ye, başlığa veya sayfaya çözülmüyor; kaynakça tablosuyla eşleşme mekanizması yok. Ayrıca raporun temel önermesi (satır 24) `fileciteturn0file0` ile, yani sohbete yüklenmiş isimsiz bir dosyaya atıfla dayandırılıyor — üçüncü taraf erişemez.
- **Ölçüm seviyesi etiketi hiç yok, dil ise RAN-LIVE.** Raporda tek satır kod çalıştırılmamış; buna karşın V1→V2 tablosunun tüm Etki sütunu geçmiş zaman kipiyle tamamlanmış eylem bildiriyor ("engellendi", "durdu", "azaldı"). Ayrıca **önleme** dili kullanılmış, KASA'nın tercih ettiği "tespit + çevreleme" dili değil.
- **Negatif kontrol yok.** Bütün metrikler tek yönlü (yakalama, önleme, kapsam). "Kapı zararsız işi ne sıklıkta blokladı", "kaç meşru yazma insan onayına takıldı" hiç ölçülmüyor. Her şeyi reddeden bir sistem bu tablonun tamamında %100 alırdı — yani tablo, işe yaramaz bir sistemi mükemmel gösterecek şekilde kurulmuş.
- **Döngüsellik.** Rapor satır 161'de "aynı modelin öz-eleştirisi kanıt değil, hipotez kaynağıdır" diyor; sonra V1'in zayıflıklarını kendi tespit ediyor, V2 düzeltmelerini kendi öneriyor ve etkilerini yine kendi varsayım parametreleriyle kurduğu simülasyonla "doğruluyor".
- **Seçici çekince.** WebArena/AgentBench/SWE-bench sayılarına "bunlar güncel modelleri temsil etmez" çekincesi konuyor (satır 71, doğru ve dürüst); aynı dönemin (2023) bulgusu olan Lost-in-the-Middle'a aynı çekince konmuyor, tersine somut bir tasarım kuralı üretiliyor. Çekince, tezi zayıflatan kaynaklara uygulanmış, destekleyenlere uygulanmamış.
- **Sentetik sayı, `verified_tool_result` olarak paketleniyor.** `evd_sim_002` (satır 2011-2020) %93,7'yi `source_type='test'`, `trust='verified_tool_result'`, `confidence=1.0`, `taint_labels=[]` ile taşıyor ve raporun **kendi** terfi politikasından (satır 385-402, `minimum_confidence: 0.85`) geçiyor; `prom_041` bu kartı kanıt göstererek "approved" olmuş. Raporun kendi `TrustLevel` enum'una göre simülasyon çıktısı `MODEL_GENERATED` (0.25) olmalıydı. Nesirdeki çekince (satır 46, 1830, 1866) Cortex paketine **binmiyor**; devralan model yalnız kartı görür ve kartta fiil "produced"dır. **Bu, KASA'nın ölçtüğü F-POISON deseninin birebir aynısıdır: kapı yetkiyi aracılar, doğruluğu değil.**

---

## 3. Raporun haklı olduğu yerler

Tek yanlı olmamak için: raporun teşhis kısmı büyük ölçüde doğru ve KASA'nın kendi ölçümleriyle uyumlu.

**Kontrol otoritesi ayrımı.** "LLM kontrol otoritesi olmamalıdır; yorumlar, ilişkilendirir, alternatif üretir — ama hangi yüksek riskli aracı kullanacağına, üretime yazıp yazmayacağına, bir kaydın kalıcı gerçek sayılıp sayılmayacağına tek başına karar veremez" (satır 52-69). Bu, KASA'nın deterministik kapı doktrininin doğru ifadesidir.

**MCP annotation'larına güvenilmemesi.** Rapor açıkça "Tool Gateway, manifestte `idempotent: true` yazdığı için buna güvenmemelidir" diyor (satır 913). İlke doğru — kendi referans uygulaması bu ilkeyi çiğnese de.

**Temporal sandbox'ının güvenlik sandbox'ı olmadığı uyarısı** (satır 1654) ve **handoff talimatlarının hedef sistemde yeniden politika hesabına tabi olması** (satır 2154) — ikisi de doğru ve sık atlanan noktalar.

**Idempotency + "unknown state" + reconciliation ayrımı.** Yan etkili çağrılarda "başarılı/başarısız" ikilisinin yetmediği, üçüncü bir "bilinmiyor" halinin ve mutabakat yolunun gerektiği doğru. KASA bu üç-hal disiplinini ölçüm katmanında zaten uyguluyor (`bulundu / bulunamadı / BAKILAMADI`), işlem katmanında uygulamıyor. Rapor bu boşluğu doğru işaret ediyor.

**Vektör indeksin otorite olmaması, append-only karar defteri, kaynak tazeliği, kaynak otoritesi.** Hepsi savunulabilir ve KASA'da eksik.

**Akademik içerik doğru.** WebArena'nın %14,41 / %78,24 sayıları, Lost in the Middle, MemGPT, Generative Agents, Reflexion, Self-Refine, ReAct, AgentBench, SWE-bench eşlemeleri doğru kullanılmış (`DOCUMENTED` — bu doğrulama model bilgisiyle yapıldı, birincil kaynaklar açılmadı). **Sorun bilgi değil, ispat rejimi.**

**Dürüst bir hamle de kayda geçirilmeli:** rapor satır 137'de önceliklendirmesinin ölçülmüş pazar sıklığı olmadığını kendiliğinden belirtiyor ve satır 1866'da "production kabul kriteri %93,7 olmamalıdır" diyor. Bunlar doğru refleksler; sorun, aynı çekincelerin makine-okunur yüke taşınmamış olması.

---

## 4. KASA'da zaten ne var

Raporun 17 bileşeninin depodaki karşılığı. Ölçüm seviyesi: `CODE-STRUCTURE` (kaynak okuması; "ZATEN VAR" hükmü o işlevi gören kodun bulunduğunu söyler, doğru veya güvenli çalıştığını **değil**).

| Bileşen | Durum | Dosya:satır / kanıt |
|---|---|---|
| Receipt / attestation | **VAR** (kripto olarak öneriden ileri) | `src/vault/audit.py:81-133` (hash zinciri + Ed25519), `:14-30` (Merkle), `:51-60` (bağımsız doğrulama) |
| Tool Gateway | **VAR** (deny-by-default broker) | `src/mcp_server/server.py:336-399`, `:77` (PUBLIC_TOOLS), `src/agent/gate.py:85-131` |
| Risk Router | **KISMEN** (statik kademe, dinamik yönlendirici yok) | `server.py:77`, `:79-81`, `:274/:285` (verify_token vs require_owner) |
| Promotion gate | **KISMEN** (karantina; ekseni farklı) | `src/vault/quarantine.py:17-35`, `src/vault/schema.py:56-65`, `tools.py:160-170/:203-223` |
| Semantic memory | **KISMEN** (profile tablosu; claim record değil) | `src/vault/schema.py:35-49`, `src/distill/engine.py:223-231` |
| Episodic memory | **KISMEN** (events; "episode" kavramı yok) | `src/vault/schema.py:9-32`, `tools.py:438-484` |
| Decision memory | **KISMEN** (3 insan-okunur ADR; makine-okunur defter yok) | `docs/adr/0001…0003` |
| Evidence card | **KISMEN** (provenance + `measurements.json`) | `schema.py:40`, `engine.py:51/:233-245`, `_orch/archive/measurements.json` |
| External Verifier | **KISMEN** (depo-güvenlik tezgahı; görev-başı değil) | `tools/security_bench/run.py:82-89`, `src/dashboard/auditor.py` |
| Blind Critic | **KISMEN** (geliştirme hattı + Yarış Modu; körleştirme yok) | `src/agent/harness.py:213-226`, `docs/adr/0001` |
| Policy ayrımı (OPA yerine) | **KISMEN** (veri düzeyinde: `permissions` tablosu) | `tools.py:45-57/:59-73`, `tools/grant_agent_scope.py` |
| Cortex export/import | **KISMEN** (elle, imzasız, şemasız) | `_orch/KORTEX.md` |
| Context Compiler | **YOK** (en yakın: düz karakter kırpma) | `engine.py:165` (`[:2000]`), `harness.py:109-123` (8000 kırpma) |
| Specification Gate | **YOK** (embriyo: zorunlu `reason` bileti) | `tools.py:75`, `:90-92` |
| Working memory | **YOK** (tamamen) | `run_id / state_version / expected_version` → 0 eşleşme |
| Contradiction set | **YOK** | `INSERT OR REPLACE` = last-write-wins; rapor bunu açıkça yasaklıyor |
| Idempotency ledger | **YOK** (embriyo: HMAC olay dedup'u) | `tools.py:444-463` |
| Taint tracking | **YOK** (ve **ölçülerek** gerekçelendirilmiş) | `docs/KASA_SAVUNMA_ARASTIRMA_2026-08-04.md:42`, `docs/KNOWLEDGE_ARCHIVE.md:573` |
| CAS / artifact store | **YOK** (hash kimlik var, hash adresleme yok) | `cas:` referansı hiçbir yerde geçmiyor |
| OpenTelemetry | **YOK** | bağımlılık yok; `harness.py` bellek-içi trace |
| LangGraph / Temporal | **YOK** (embriyo: sınırlı döngü) | `harness.py:170-207`, `gate.py:25-31` |

**Raporda karşılığı olmayan KASA üstünlükleri (üçü de kayda değer):**

1. **Ölçüm dürüstlüğü disiplini.** Uydurulmuş skor yok, her iddiaya seviye, her iddianın yanına "bunun göstermediği ne". Rapor bu kuralların üçünü de ihlal ediyor.
2. **Gizlilik / at-rest / unutulma hakkı.** Raporun memory mimarisinde gizlilik katmanı **hiç yok**. KASA'da hücre-başı AES-GCM (AAD ile satır takası engellenir), yazım öncesi redaksiyon, audit'e ham değer yerine digest, HMAC kör-indeks, gerçek silme + "sessiz-sıfır" koruyucusu, prune'da tombstone var. Dürüst sınır: `F-DISTILL-PLAINTEXT` açık — damıtıcı yolundan yazılan `profile.value` düz metin düşüyor, broker yolu şifreliyor (pozitif kontrol).
3. **Kanıt kartında "bunun göstermediği ne" alanı.** `docs/REPRODUCE.md` tablo başlığı: `Claim | Level | Command | What it does NOT show`. Raporun kartlarında böyle bir alan yok.

**Bulunan gerçek kusur (raporun değil, KASA'nın):** `supersedes` alanı var ama önceki sürümü saklamıyor. Broker yolu eski satırın id'sini okuyup `INSERT OR REPLACE` ile **aynı id'ye** yazıyor (`tools.py:150-176`), yani yeni satırın `supersedes` değeri kendi id'sidir; damıtıcı yolu `supersedes`'i hiç yazmıyor (`engine.py:266`). Aynı tabloya iki farklı semantikle yazan iki yol var.

**Ürün yolunda ölçülen bir kırık — `RAN-LIVE`, gerçek HTTP isteğiyle doğrulandı.** `src/mcp_server/tools.py:75` `profile_read(self, scope, reason)` tanımlıyor ve `:90-92` `reason` boşsa `ValueError` atıyor. `src/mcp_adapter/__main__.py:111` ise yalnızca `{"scope": scope}` gönderiyor. `server.py:377` `method(**params)` ile çağırdığı için eksik argüman `TypeError` → `server.py:383-388` → **422**.

Bu bulgu ana ajan tarafından koşularak doğrulandı (betik: `…/scratchpad/verify_profile_read.py`); TestClient üzerinden gerçek istek şu cevabı verdi:

```
HTTP 422
{'detail': "'profile_read' aracı için geçersiz parametreler:
            VaultTools.profile_read() missing 1 required positional argument: 'reason'"}
```

*Türkçe açıklama: bu, sevk edilen adaptörle `profile_read` çağıran her MCP istemcisinin aldığı cevaptır — ve bu MVP'nin birincil okuma yoludur. Yani "ajan hafızayı okur" senaryosu bugün hiç çalışmıyor.*

**Sözleşme taraması (`RAN-LIVE`, betik: `…/scratchpad/adapter_contract_scan.py`):** adaptörün sunduğu 6 aracın parametre kümeleri sunucu imzalarına AST ile karşılaştırıldı. **6'dan 1'i kırık** (`profile_read`); `audit_read`, `event_ingest`, `forget`, `profile_write`, `prune_expired_events` bağlanıyor. Bu, tek noktalık bir hata olduğunu gösterir — sistematik bir sözleşme çürümesi değil; ama sınırın nerede olduğunu da ölçmüş olur.

Mevcut test setinin hiçbiri yakalamadı. Nedeni testlerde görünüyor: `tests/test_l4_error_mapping.py:46` `profile_read`'i `lambda self, scope` ile monkeypatch'liyor — yani test, **sunucunun gerçek imzasını değil, adaptörün varsaydığı imzayı** taklit ediyor. Test ile ürün aynı yanlış varsayımı paylaşınca uyuşmazlık görünmez olur. Testler bileşenleri ölçüyor, ürünü değil.

---

## 5. Teknoloji yığını hükmü

Ölçülen bağlam (`RAN-LIVE`, `pip install --dry-run --report`, 2026-08-05, py3.14/win_amd64): KASA'nın bugünkü transitif Python kapanışı **36 paket**; önerilen yığın **133 pakete** çıkarıyor — **97 yeni üçüncü-taraf paket (+%269)** ve üstüne 7-8 uzun ömürlü servis. Bu sayı bir **alt sınırdır**: OPA, Temporal sunucusu, PostgreSQL, MinIO, Kafka ve Vault ikilileri pip kapanışına girmiyor.

Ayrıca ölçüldü (`RAN-LIVE`, metin sayımı): 2200 satırlık raporda **Windows = 0, Ollama = 0, SQLite = 0, DPAPI = 0, PyQt = 0, local-first = 0, sovereign/egemen = 0**. Bir yığın önerisi, değiştirmeyi önerdiği yığını adlandırmıyorsa gerçeklik denetimini geçemez.

| Bileşen | Damga | Yerel alternatif / gerekçe |
|---|---|---|
| FastAPI + Pydantic | **GEREKLİ** | Zaten var; değişiklik gerekmiyor |
| pytest | **GEREKLİ** | Zaten var |
| Hypothesis (property-based test) | **GEREKLİ** | 2 paket, daemon yok; `gate.py`/`proxy.py`/`redact.py` ideal hedef; "pozitif+negatif kontrol" kuralıyla birebir örtüşür |
| Temporal | **BU PROJE İÇİN YANLIŞ** | Döngü zaten 5 tur / 120 s / 300 s ile sınırlı. Alternatif: SQLite'ta `job` + `job_step` tabloları + idempotency anahtarı; ~30-50 satır, sıfır yeni bağımlılık |
| PostgreSQL | **BU PROJE İÇİN YANLIŞ** | Tek kullanıcı, tek yazıcı. Doğru yapılandırılmış SQLite yeter — ama bugün yapılandırılmamış (aşağıya bakınız) |
| pgvector | **ERTELENEBİLİR** | Önce semantik aramaya ihtiyaç kanıtlanmalı; sonra sqlite-vec veya FTS5 |
| S3 / MinIO | **BU PROJE İÇİN YANLIŞ** | `~/.kasa/cas/<sha256[:2]>/<sha256>` içerik-adresli dizin + SQLite meta + okuma anında hash doğrulaması aynı değişmezliği verir |
| Kafka / NATS | **BU PROJE İÇİN YANLIŞ** | Raporun kendisi alternatifini yazıyor ("PostgreSQL outbox"); KASA karşılığı SQLite outbox + tek tüketici thread |
| OPA / Rego | **BU PROJE İÇİN YANLIŞ** (fikir doğru) | Aşağıda ayrıca ele alınıyor. Yerel karşılık: imzalı `policy.json` + `gate.py` içinde ağsız değerlendirici + audit'e `policy_hash` |
| OpenTelemetry | **ERTELENEBİLİR** | Korelasyon kimliği eksikliği gerçek bir boşluk; ama Collector daemon'u değil, audit zincirine bir `trace_id` alanı yeter |
| in-toto | **ERTELENEBİLİR (format olarak)** | Kripto katmanı zaten var; kazanç yalnız FORMAT'ta. Kütüphaneyi zorunlu bağımlılık yapmaya gerek yok |
| HashiCorp Vault | **BU PROJE İÇİN YANLIŞ** | Amaç zaten DPAPI + ajana-bağlı token ile karşılanmış; Vault = ağ dinleyen daemon + "unseal anahtarı nerede duracak" |
| LangGraph | **BU PROJE İÇİN YANLIŞ** | `langgraph → langchain-core → langsmith` zinciri koşulsuz. **Dürüst sınır:** langsmith'in varsayılan olarak veri gönderdiğini iddia etmiyorum; ölçülen tek şey koşulsuz kurulduğu. Egemenlik iddiası taşıyan bir üründe bulut telemetri istemcisinin süreç içinde olması latent bir çıkış yolu ve "yanlışlıkla açık kalma" arıza modudur |
| Container / gVisor / mikro-VM | **BU PROJE İÇİN YANLIŞ (bu haliyle)** | gVisor ve Firecracker Linux/KVM ister, Windows'ta çalışmaz (`DOCUMENTED`). Docker Desktop = WSL2 + ayrı VM = "bootstrapper YOK" kararının tersi. **Ama izolasyon ihtiyacı gerçek ve KASA'da açık.** Yerel karşılık: AppContainer / düşük-bütünlük seviyesi, Job Object ile CPU/bellek tavanı, ayrı düşük-ayrıcalıklı kullanıcı, WFP ile süreç-bazlı egress reddi, Windows Sandbox. **Hiçbiri ölçülmedi; öneridir** |
| Semgrep | **ERTELENEBİLİR (CI'ya, yerele değil)** | `RAN-LIVE`: birleşik kurulum bu makinede başarısız oldu (tekerlek yok, kaynak derlemesi kırıldı); tek başına 67 paket getiriyor. Yerelde `bandit` + `ruff` zaten kurulu |
| Playwright | **ERTELENEBİLİR** | Tarayıcı bilinen köprü-izolasyon kusuru nedeniyle devre dışı sevk ediliyor; ~300 MB ikili indirmenin karşılığı yok |

**OPA hakkında en sert bulgu.** Rapor "gerçek yetkilendirme OPA'da yapılmalı" diyor, ama sunduğu Rego politikasının girdileri (`manifest_verified`, `read_only`, `destructive`, `actor.scopes`) **çağıran kod tarafından hesaplanıp OPA'ya veriliyor**. Güven kökü yer değiştirmiyor, sadece uzuyor. Dahası: **rapordaki Rego'da `taint` girdisi hiç yok** (`taint` yalnızca EvidenceCard alanı ve skorlamada −0,20 ceza olarak var). Yani KASA'nın ölçtüğü F-POISON, önerilen OPA katmanından da geçerdi — doğru kapsamla gelen, zehirli içerikten türetilmiş bir çağrı `allow` alırdı. Ek olarak OPA sunucu kipinde HTTP dinler ve kimlik doğrulaması varsayılan kapalıdır (`DOCUMENTED`, bu oturumda koşulmadı); raporun kendi `OPAClient` örneği hiçbir `Authorization` başlığı göndermiyor ve "OPA erişilemezse ne olur" sorusu cevapsız — fail-open riski kod düzeyinde açıkta.

**Policy-as-code ayrımının gerçek kazancı var ama OPA gerektirmiyor:** politikanın diff'lenebilir, versiyonlanabilir ve **imzalanabilir** ayrı bir eser olması; her kararın audit'e `policy_hash` ile yazılması ("hangi kural sürümü bu çağrıya izin verdi"); aynı politikanın broker, adaptör ve panoda tek kaynaktan gelmesi. `gate.py:44-72`'deki `TOOLS` sözlüğü bunun ilkel hali — veri zaten koddan ayrı; eksik olan dışa alınması ve imzalanması.

**Bu incelemenin yan ürünü olan gerçek bir KASA eksiği (`CODE-STRUCTURE`):** bugün tüm depoda tek bir PRAGMA var, `secure_delete=ON`. Yani `journal_mode` WAL **değil**, `busy_timeout` ayarlı değil, `foreign_keys` **açık değil** (SQLite'ta varsayılan kapalı — şemadaki yabancı anahtarlar uygulanmıyor olabilir). "SQLite Postgres'in yerini tutar" cümlesinin dürüst hali: **doğru yapılandırılmış** SQLite tutar. Öneri sırası: `journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`, `synchronous=NORMAL`. Eşzamanlılık altında kilit hatası canlı ölçülmedi.

---

## 6. Nörobilim sentezi

**Baştan söylenmesi gereken:** beyin metaforu tasarım **kanıtı** değil, **hipotez kaynağıdır**. Bu bölümdeki hiçbir bulgu KASA'da bir savunmanın çalıştığını göstermez; hepsi "ölçülecek hipotez" seviyesindedir ve koşulmadan `SECURITY.md`'ye yazılamaz. İkinci uyarı daha önemli: **literatürde düşman yok.** Konsolidasyon, transience ve tahmin-hatası çerçevelerinin hepsi gürültülü ama düşmanca **olmayan** bir çevre varsayar. Optimize eden bir saldırgan varken "unutma işlevseldir" önermesi otomatik olarak geçerli kalmaz; hatta tersine döner.

### Tezin doğrudan cevabı: "tek gözlemle kalıcı gerçek olmaz" kuralı F-POISON'u kapatır mıydı?

**Hayır, kapatmazdı.** Ama sessiz başarıyı görünür çelişkiye çevirebilirdi — ki bu KASA'nın kendi doktrinine ("önleme değil, tespit + çevreleme") tam oturur.

Gerekçe üç ayrı dayanaktan geliyor:

**(a) Tekrar sayısı saldırganın yazabildiği bir sayıdır.** `src/vault/schema.py:18-20`'deki `content_hash` dedup'u aynı içeriği tek satırda `occurrence_count = k` olarak topluyor. Yani "k kez görülmüş" alanı, sayfayı kontrol eden saldırganın doğrudan sürdüğü bir sayaçtır. Sayacı eşik yapmak, saldırgana eşiğin kendisini vermektir.

**(b) Tse ve ark. (2007, Science 316:76-82) öneriyi doğrudan çürütüyor.** Mevcut bir şemaya uyan bilgi **tek denemede** kalıcılaşabiliyor. Ölçülmüş A8 saldırısında `hermes3:8b`'nin sahte kaydı gerçek bir kaydın yanına koyması tam olarak şema-uyumluluğudur. `user.profile.occupation = "verified diamond dealer"` gibi inandırıcı, mevcut kalıba oturan bir zehir tekrar eşiğini geçmek zorunda bile kalmaz.

**(c) O halde kazanç sayıda değil, saldırganın kontrol etmediği bir boyuttadır.** KASA'da bu boyut şemada zaten duruyor: `events.source` ve `session_id`. Somut kural: bir claim ancak **≥2 farklı source** ve farklı oturumlardan desteklenirse `consolidated` olur. Tek bir web origin'ini kontrol eden saldırgan bunu tek başına üretemez; üretmek için sahibin manuel kanalına veya ikinci bir kanala erişmesi gerekir — tehdit modelinde A2/A3'ten A4'e tırmanıştır. **Dürüst sınır:** birden fazla domain'e içerik serpebilen bir saldırgan için açık web'de bu ucuzdur. Yani bu bir **maliyet çarpanıdır**, yapısal bir kapı değil.

**Yazılabilecek cümle:** "sessiz kalıcı gerçek → sahibin gördüğü çözülmemiş çelişki". Yazılamayacak cümle: "F-POISON kapandı".

### Reconsolidation'ın güvenlik anlamı: cazip, ama saf haliyle bir gerileme

Nader, Schafe & LeDoux (2000, Nature 406:722-726) konsolide bir hafızanın geri çağrıldığında yeniden labil hale geldiğini gösteriyor. Hupbach ve ark. (2007) insanda tamamlıyor: kısa bir hatırlatıcının ardından sunulan yeni içerik, **eski kaydın içine karışıyor** — ve etki tek yönlü. Sinclair & Barense (2019) pencereyi açan şeyin hatırlatmanın kendisi değil, **kısmi/eksik** hatırlatıcının yarattığı tahmin hatası olduğunu söylüyor.

Bunu KASA'ya olduğu gibi taşımak **her `profile_read`'i yeni bir zehirlenme penceresine çevirir** ve mevcut `ALLOWED_KEY_PREFIXES` + karantina savunmalarını tamamen atlatır: yeni anahtar yazılmaz, mevcut anahtarın içeriği kayar. Bugün okuma yolunun tamamen pasif olması (okumak hafızayı değiştirmez) bir **güvenlik avantajıdır**; Anderson-Bjork-Bjork'un retrieval-induced forgetting bulgusu bunu ayrıca destekliyor: "sık sorulan claim güçlensin" gibi bir mekanizma eklenirse saldırgan yalnızca kendi claim'ini sorgulayarak rakip doğru claim'leri bastırabilir — sorgu hacmi saldırganın kontrolündedir.

**Bu yüzden öneri asimetriktir:** yeniden-doğrulama yalnızca güveni **düşürüp** karantinaya alabilmeli, **asla içerik yazamamalıdır**. Ve tetikleyici bulanık eşleşme üzerine kurulmamalı — deterministik ikili kontrol (kaynak olay id'si çözülüyor mu / çözülmüyor mu). Bulanık eşleşme, saldırgana ayarlanabilir bir kadran vermektir.

### Somut tasarım önerileri (hepsi hipotez)

- **O1 — İki hız sistemi, gerçekten.** `profile` tablosuna `status` (`candidate`/`consolidated`), `support_count`, `distinct_source_count`, `first_seen`, `last_confirmed`, `stability_level`. Damıtma yalnız `candidate` yazar. Terfi: ≥2 farklı source **ve** zamansal olarak ayrık ≥2 gözlem (Cepeda ve ark. 2006: aralık önemli, sayı değil) **ve** ≥2 ayrı damıtma koşusunda bağımsız yeniden türetilmiş olmak. `stability_level` her bağımsız doğrulamada +1, her çelişkide −1 (Fusi, Drew & Abbott 2005 kaskadı: derinleştikçe değiştirmesi zorlaşır). Bugünkü tabloda kalıcılığın tek seviyesi var: satır ya var ya yok.
- **O2 — Sessiz üzerine yazmayı kaldır.** `src/distill/engine.py:266`'daki `INSERT OR REPLACE INTO profile` bu projenin en zayıf tek satırı. Çelişen değer eskisini silmesin; ikisi de yaşasın, satırlar `contested` işaretlensin, okuma yolu çelişkiyi görünür döndürsün. Bu, EWC'nin (Kirkpatrick ve ark. 2017) "önemli parametreyi değiştirmek pahalı olmalı" fikrinin sembolik karşılığıdır ve ölçülmüş saldırının en sinsi özelliğini (meşru kaydın yanına sızıp göze batmamak) etkisiz kılar — artık yan yana değil, karşı karşıya dururlar.
- **O3 — Yeniden doğrulama, ama tek yönlü.** Yukarıda gerekçelendirildi: yalnız düşürür ve karantinaya alır, asla yazmaz.
- **O4 — Transitif silme.** `src/distill/scheduler.py` `prune_expired_events()` olayları siliyor, onlara dayanan `profile` satırlarına dokunmuyor. Sonuç: kaynağı silinmiş, doğrulanamaz, ama tam güvenle yaşayan claim'ler. Prune, dayanağı silinen her claim'in `support_count`'unu düşürmeli. KASA'nın sembolik hafızası burada sinir ağına göre avantajlıdır (Cao & Yang 2015; Bourtoule ve ark. 2021 / SISA): kesin silme ucuzdur, yeniden eğitim gerekmez.
- **O5 — Modelin kendi `confidence`'ını kanıt saymayı bırak.** Ölçüldü: saldırganın anahtarı `confidence: 1.0` ile geldi. Depolanan güven deterministik olarak yeniden türetilmeli: f(support_count, distinct_source_count, tazelik, çelişki durumu, verbatim çapa var mı). Model beyanı en fazla ipucu olarak loglanır.
- **O6 — Verbatim çapa.** Damıtma bir *gist* üretecidir; DRM literatürü (Roediger & McDermott 1995) gist katmanının **girdi tamamen temiz olsa bile** kaynakta bulunmayan öğe ürettiğini gösterir. Provenance bunu yakalamaz — "hangi olaylardan" der, "olayda gerçekten var mıydı" demez. Ölçülmüş vakada zehirli fact gerçek bir olayı (bir kahve değirmeni incelemesi) gösteriyordu: **türetme zinciri tam doğrulanabilir, içerik yanlış.** Her claim, dayandığı olay metninden doğrulanabilir bir alıntı/hash taşımalı.
- **O7 — Sürprizi tersine kullan.** Yüksek şaşırtıcılık terfi sinyali değil, karantina tetikleyicisi olsun. Tek cümlelik gerekçe: saldırganın bedavaya maksimize edebildiği hiçbir büyüklük terfi kriteri olamaz. (Schultz, Dayan & Montague 1997 çerçevesinde sürpriz **doğadan** gelir, düşmandan değil.)
- **O8 — Offline konsolidasyonu gerçekten konsolidasyon yap.** Biyolojik replay tekrarlı ve karıştırılmıştır (Girardeau ve ark. 2009 nedensel kanıt); KASA'nınki tek geçişlidir (`distilled=0` → işlenir → `distilled=1`; her olay hayatı boyunca tam bir kez etki eder). Öneri: bir pencere boyunca (ör. 3 gece) karıştırılmış sırayla tekrar damıtma; yalnız bağımsız koşularda yeniden üretilen claim'ler terfi eder. **Uyarı:** bu, iş-kuyruğu baskısı yaratan tek öneridir ve local-first sınırını zorlayabilir — bu yüzden en sona bırakılmalı.
- **O9 — Çürüme, dikkatli.** Sabit TTL değil, yasa-biçimli decay (Ebbinghaus eğrisi ile Fusi kaskadı aynı yöne işaret ediyor): tek-kanıtlı claim hızla güven kaybeder, çok-doğrulanmış claim neredeyse hiç kaybetmez. Decay **silmez**, yalnız güveni düşürür ve her decay olayı audit'e yazılır. **Uyarı:** kullanım-tabanlı decay bir starvation/eviction saldırı yüzeyidir ve hafıza durumunu sorgu desenine bağladığı için yan kanal açar. Ölçülmeden canlıya alınmamalı.
- **O10 — Ölçüm planı.** Bunlar olmadan yukarısı hikâyedir. `_orch/redteam/indirect_variant_probe.py` üç kolla koşulur: (i) tek atışlı zehir → beklenti: `consolidated`'a giremez; (ii) k kez tekrarlanan **aynı kaynak** zehir → hipotez: hâlâ geçer; (iii) şema-uyumlu, inandırıcı zehir → hipotez: geçer. **Negatif kontrol şart:** iyi niyetli yazımlar hâlâ geçiyor mu (mevcut taban 5/5). Geçmiyorsa üretilen şey savunma değil, çalışmaz hale getirilmiş bir sistemdir. Sonuç ne çıkarsa o yazılır; beklenen sonuç yazılmaz.

### Bir uyarı daha: TMR

Rudoy ve ark. (2009) konsolidasyonun körü körüne bir toplu iş değil, dışarıdan **ipucuyla yönlendirilebilir** bir süreç olduğunu gösteriyor. Güvenlik karşılığı: eğer "hangi olayların öncelikli damıtılacağı" güvenilmez içerikten etkilenebilir hale gelirse, saldırgan konsolidasyon önceliklendirmesini ele geçirir. Bugün `engine.py` sabit `LIMIT ?` ile sırasız çekiyor — **yönlendirilemez olması kazara bir savunmadır** ve O8 uygulanırken korunmalıdır.

---

## 7. Denenebilir, az bilinen yaklaşımlar

Hiçbiri KASA üzerinde koşulmadı. Bu "denenebilir" listesidir, "denenmiş" listesi değildir.

| Yaklaşım | Ne kazandırır | Maliyet | Durum |
|---|---|---|---|
| **Mutasyon testi** (DeMillo 1978; mutmut/cosmic-ray) | "Kendi ölçüm aletimiz yalan söylüyor" problemini doğrudan ölçer: öldürülemeyen mutant, testin o davranışı hiç sınamadığının **ispatıdır** | 1-2 gün, sıfır yeni servis; eşdeğer mutantlar elle elenir | **Yerleşik teknik, KASA'da denenmemiş.** Fit×efor oranı en yüksek madde |
| **Metamorfik test** (Chen 1998; Bayati Chaleshtari ve ark., IEEE TSE 2023) | Oracle olmadan sınama: "aynı görev farklı sunumda aynı **kapı kararını** vermeli". MR1 parafraz, MR2 **dil (TR/EN)**, MR3 dolgu, MR4 kodlama | Düşük; tek test dosyası | **Yerleşik, denenmemiş.** MR2 hemen somut açık veriyor (aşağıya bakınız) |
| **Property-based test** (Hypothesis) | `gate.validate_call` invariantları binlerce girdide sınanır, karşı-örnek küçültülür | 2 paket | Yerleşik, denenmemiş |
| **Diferansiyel test** (McKeeman 1998) | KASA'da bağımsız gelişmiş **iki** yetki yolu var (`gate.py` ve mcp_server bearer+allow-list+scope); aynı girdide ayrışırlarsa en az biri yanlıştır — hangisinin doğru olduğunu bilmeye gerek yok | Düşük | Yerleşik; "tam aracılık" ölçümünün otomatikleştirilmiş hali |
| **FIDES / tip-tabanlı deklasifikasyon** (arXiv:2505.23643) | Dual-LLM'in nasıl **yanlış** yapılacağını gösteriyor: karantina-LLM'in serbest metin özeti yeni bir enjeksiyon kanalıdır. Doğrusu güvenilmez metinden yalnız düşük-kapasiteli tip (bool/enum) çıkarmak | Orta | Yerleşik değil, yeni; KASA'da yok |
| **Permissive IFC** (arXiv:2410.03055) | Naif taint yayılımının her şeyi "güvenilmez" yapma sorununa (over-tainting) literatürdeki cevap | Orta | KASA taint'e geçerse ön koşul |
| **Object-capability / attenuation** (Miller 2006; ChainCaps) | Ambient authority'yi kaldırır. `F-MCP-OWNER-BEARER` ders kitabı confused-deputy'siydi; düzeltme doğru yönde ama hâlâ kimlik-tabanlı | Yüksek | ocap yerleşik; ChainCaps **tek ekip sonucu, bağımsız tekrar yok, atıf doğrulanamadı** |
| **Security / edit automata** (Schneider 2000; Ligatti ve ark. 2005) | `gate.py` durumsuz bir truncation automaton; "ard arda 3 red sonrası oturum kapanır" gibi **dizisel** invariantlar bugün ifade edilemez | Orta | Yerleşik teori, KASA'da yok |
| **LTL monitörü** (Safety Chip, arXiv:2309.09919) | `harness` zaten bir eylem izi üretiyor; besleyecek veri var, eksik olan otomat | Orta | Yerleşik |
| **Transparency log tanığı** (RFC 6962/9162) | KASA'da Merkle + Ed25519 + mühür **zaten var**. Gerçek eksik iki tane ve raporda hiç geçmiyor: **tanık yok** (imzalayan ile tutan aynı taraf → makine ele geçerse zincir baştan sona tutarlı yeniden yazılabilir) ve **consistency proof yok** | Orta; yeni kripto değil, bir **dağıtım** adımı | Yerleşik; en yüksek oranlı orta-efor maddesi |
| **in-toto / SLSA** (USENIX Security 2019) | `event → distill → profile` bir tedarik zinciridir; bugün artefakt bağlantısı var, **adım yetkilendirmesi** yok | Orta (format olarak düşük) | Yerleşik |
| **Bitemporal model** (Snodgrass 1999; XTDB) | Raporun `valid_from/valid_to`'su modelin **yalnız yarısı**. Eksik yarı adli inceleme için kritik: "sistem T anında neye inanıyordu ve o arada buna dayanarak neler türetildi?" | Orta | Yerleşik |
| **Datomic tarzı retraction** | Silme yerine geri-alma; `profile.supersedes` bu fikrin yarısı ama `key UNIQUE` yüzünden canlı tablo hâlâ tek-değer mantığında | Orta | Yerleşik |
| **CRDT MV-Register** (Shapiro ve ark. 2011) | `profile.key UNIQUE` → yazım mantığı **LWW**. LWW zehirlenme altında yapılabilecek en kötü seçimdir: saldırganın yazımı meşru değeri sessizce siler. MV mantığında çelişkinin kendisi sinyaldir | Orta | CRDT yerleşik; **güvenlik amacıyla bu eşleme alt-ajanın kendi çıkarımı, atıf doğrulanamadı.** CRDT'ler Byzantine-güvenli değildir |
| **Datalog bütünlük kısıtları** | Ayrıcalık-yükselten olgu sınıfını kurala bağlar: "`verified` önekli hiçbir nitelik ajan kaynaklı olamaz". Ölçülmüş `verified diamond dealer` vakası tam bu sınıfta olduğu için yakalanırdı | Orta | Deduktif DB yerleşik; **ajan hafızasına uygulanması için spesifik atıf bulunamadı** |
| **Honeytoken / kanari** | Zehirlenmenin en zor yanı **tespittir**. `user._canary.<rastgele>` satırları: değer ajan cevabında görünürse maskeleme kırıldı; satır değişirse yazım yolu geniş; damıtma provenance'ında görünürse sızıntı var | Düşük | Desen yerleşik (Canarytokens); **ajan hafızası zehirlenme tespitine uygulanması için akademik atıf arandı ve BULUNAMADI** — bu bir öneridir |
| **Chaos / hata enjeksiyonu** | `harness._chat_call`, `_run_tool`, `proxy.execute` zaten izole enjeksiyon noktaları. Güvenlik sorusu: `_run_tool` istisnada hata metnini modele geri besliyor — bu bir sızıntı kanalı mı? | Düşük-orta | Chaos yerleşik; **ajanlara uygulanması çoğunlukla uygulamacı kaynağı, akademik taraf seyrek** |

**Bu taramanın en somut yan ürünü (`CODE-STRUCTURE`, bugün doğrulandı):** `src/vault/quarantine.py:17-21`'deki `_QUARANTINE_PATTERNS` **tümüyle İngilizce** — `ignore (all|previous|above)`, `disregard`, `you must`, `system:`, `reply with`, `output only`, `append … to every`, `rm -rf`. "Önceki tüm talimatları yoksay" hiçbirine uymaz. **KASA Türkçe-öncelikli bir ürün; karantina kapısı ana dilinde boş.** Bu tam olarak bir metamorfik dil-değişmezliği ilişkisinin yakalayacağı şeydir. Koşularak doğrulanmadı: TR/EN çifti `quarantine_reason()`'a verilip iki sonucun farklı olduğu gösterilmeli. **Negatif kontrol zorunlu:** TR kalıplar eklendikten sonra kullanıcının kendi meşru Türkçe notları ("şunu yapmalısın", "yoksay") karantinaya düşüyor mu — düşüyorsa kazanç değil aşırı-çevreleme üretilmiştir.

---

## 8. Olasılık uzayı — "eğer bu olsaydı bu olur"

Nitel olabilirlik nitelemeleri **uydurulmuş olasılık değildir**; sayılmış geçmiş davranışa veya okunmuş koda dayanır ve gerekçesi her satırda yazılıdır. Gelecek hakkındaki her cümle hipotezdir.

| # | KOŞUL | SONUÇ | ÇÜNKÜ | Olabilirlik | Erken uyarı |
|---|---|---|---|---|---|
| 1 | `engine.py:266` `INSERT OR REPLACE` yerine çelişkiyi silmeyen `contested` yazım gelirse (~20 satır) | Ölçülmüş 20/20 **sessiz** zehirlenme, 20/20 **görünür çelişkiye** döner. F-POISON kapanmaz; saldırının en değerli özelliği (meşru kaydın yerine sessizce geçmek) kaybolur | Zehirlenmenin kalıcılığı tek bir SQL fiilinde yaşıyor; gereken şema alanı (`supersedes`) zaten var, yalnız doldurulmuyor | yüksek | `SELECT key, COUNT(*) FROM profile GROUP BY key HAVING COUNT(*)>1` 0 satır dönüyorsa ikinci yazma yolu (`tools.py` profile_write) atlanmıştır. Negatif kontrol: 5/5 iyi niyetli yazım hâlâ geçiyor mu |
| 2 | 1-2 gün mutasyon testine ayrılır ve `gate.validate_call`, `quarantine_reason`, `proxy._is_loopback_url` mutantlanıp tezgah koşulursa | En az bir **öldürülemeyen** mutant çıkması beklenir; tezgahın hangi kapıyı hiç sınamadığı iddia olmaktan çıkıp ölçüm olur | Aynı sınıf kusur zaten kaynak okumayla bulundu: CRYPTO-DPAPI Windows'ta koşulsuz PASS ekliyor; AUTHZ-BIND sevk edilen uygulamanın hiç çağırmadığı varsayılanı inceliyor; AUDIT-VERIFY zinciri kendi hash fonksiyonuyla doğruluyor; AUTHZ-DENY yüklemi `status != 200` olduğu için Host kapısından dönen 400'ü başarı sayıyordu | yüksek | İlk koşuda 21 kontrolün kaçının **hiçbir** mutant tarafından kırmızıya dönmediğini say. >0 ise fark yazılı hale gelir |
| 3 | `kasa_note` yazma aracı, ocap/attenuation ve dizisel kapı kurulmadan `allow_notes=True` ile açılırsa | Bugünkü güvenlik durumu kaybolur: patlama yarıçapı ~sıfırdan vault yazımına çıkar; "vault metni → aynı araç-yetkili model → yazım" döngüsü gerçek bir açığa döner | `harness` araç sonucunu `messages`'a ekleyip aynı modelin sonraki çağrıyı seçmesine izin veriyor; gate durumsuz ve içerik kapısı yalnız kredensiyel ifadesi arıyor. **Bugün güvenli olmanın nedeni mimari değil, yüzeyin üç salt-okunur maskeli fonksiyona inmiş olması** | yüksek | `gate.TOOLS`'ta `readonly=False` bir araç için testlerin `allow_notes=True` ile geçmesi; izin seed'inde `kasa_note` scope'unun belirmesi; `agent_config.json`'da not yazımını açan bayrak |
| 4 | "n≥k tekrar" eşiği kaynak-bağımsızlığı olmadan terfi kriteri yapılırsa | Ölçülmüş 20/20 büyük olasılıkla 20/20 kalır; savunma görünümü artar, ölçüm artmaz | `content_hash` dedup'u aynı içeriği `occurrence_count=k` olarak topluyor → sayaç saldırganın kontrolünde. Tse 2007: şema-uyumlu bilgi tek denemede kalıcılaşır | yüksek | Prob üç kolla koşulur; kol (ii) veya (iii) `consolidated`'a giriyorsa eşiğin yapısal kapı **olmadığı** ölçülmüş olur |
| 5 | Rapordaki yığın (Temporal + PostgreSQL + MinIO + OPA + OTel + Kafka + Vault + konteyner) benimsenirse | local-first iddiası ve tek-exe kararı ölür, saldırı yüzeyi büyür, **F-POISON hayatta kalır**. En yüksek eforlu seçenek, ölçülmüş tek açık kusuru kapatmayan seçenektir | 36 → 133 paket (+97), üstüne 7-8 servis; ve önerilen Rego'da `taint` girdisi hiç yok — OPA da yetkiyi aracılar, doğruluğu değil | yüksek | `requirements.txt`'teki 6 doğrudan bağımlılığın artması; `EXE_PACKAGING_LOG.md`'deki "bootstrapper YOK" kararının revizyon teklifi; depoda `docker-compose.yml` veya dış ikili indiren bir yapı adımının belirmesi |
| 6 | Karantina kalıplarına Türkçe eklenmezse (ya da eklenip metamorfik dil testi yazılmazsa) | Türkçe-öncelikli bir üründe karantina kapısı ana dilinde boş kalır; ayrıca kalıp eklenirse aşırı-çevreleme riski doğar ve bu **ölçülmeden** kapalı sayılamaz | `_QUARANTINE_PATTERNS`'in tamamı İngilizce (bugün okundu). Kapı deterministik regex olduğu için dil bağımlıdır — model-yargısı olmaması gücüdür ama dil sınırını sert yapar | yüksek | Aynı emrin TR/EN çifti `quarantine_reason()`'a verilir; iki sonuç farklıysa açık kanıtlanmış olur. Negatif kontrol: meşru Türkçe notlar karantinaya düşüyor mu |
| 7 | `audit_checkpoint.entry_count` / `merkle_root` `verify_chain`'e bağlanırsa | Kuyruk silme (`DELETE FROM audit WHERE id > N`) tespit edilebilir hale gelir | `verify_chain` ileri yürüyüp halka sürekliliğini kontrol ediyor; genesis'ten temiz bağlanan kısaltılmış bir zincir `True` dönüyor. Malzeme tabloda hazır — eksik olan yeni mekanizma değil, mevcut alanın okunması | yüksek | Kuyruk silindikten sonra `verify_chain()` hâlâ `True` dönüyorsa kusur duruyordur. Pozitif **ve** negatif kontrol gerekir (meşru arşivleme/rotasyon `False` üretmemeli) |
| 8 | Efor `gate.py`'yi zenginleştirmeye (daha çok kural, daha çok denylist) harcanırsa | Ölçülebilir güvenlik kazancı **bugün** düşüktür; aynı efor yüzeyi kapalı tutmaya ve `contested` yazıma harcansa çok daha fazla getirir | `harness`'in gördüğü yüzey üç salt-okunur maskeli pano fonksiyonu; ham `VaultTools` oradan erişilemez. Bir katmanın değeri kendi kalitesine değil, **altındaki katmanın durumuna** koşulludur | orta | Hafta sonunda sor: kural sayısı mı arttı, **düşebilen** test sayısı mı? `gate.py` satır sayısı büyürken test setinin öldürdüğü mutant sayısı sabit kalıyorsa efor yanlış katmana gitmiştir |
| 9 | Ürün yolunun (adaptör → sunucu, uçtan uca) kendi entegrasyon ölçümü kurulmadan tezgah ve red-team arşivi büyümeye devam ederse | Ürünün bir sonraki kırılması da ancak bir red-team betiğinin yan ürünü olarak bulunur; ve bulunana kadar "MVP çalışıyor" ölçülmemiş bir iddia olarak yayında kalır | Bugün `profile_read` üzerinden 422 dönüyor (üç dosya okunarak doğrulandı) ve mevcut test setinin hiçbiri yakalamadı. Testler bileşenleri ölçüyor, ürünü değil | yüksek | (i) `git log -- src/` ile `git log -- docs/ _orch/` oranı (bugün 18/65); (ii) adaptörü gerçek sunucuya karşı koşan uçtan uca test sayısı — bugün **0** |
| 10 | `src/config.py` ve `kasa.toml` tek satırla `kasa-agent:8b`'ye çevrilir ve bu `SECURITY.md`'de "F-POISON azaltıldı" diye kaydedilirse | Ölçülmemiş bir iddia, ölçülmüş bir iddianın yerine geçer — ve geri alınması daha zor olur, çünkü değişiklik gerçek bir iyileşmeye **benziyor** | Ölçüldü: `kasa-agent:8b` zehir 0/25, fayda 8/8 — ama yalnız **kaba-override** stili için. P2b (ince, sistem-notu kılıklı) stilini **her iki model de 0/3 kaybediyor**. Ve savunma modelin **içinde**, yapıda değil | yüksek | `SECURITY.md`'de F-POISON satırından "OPEN" kaybolduğu commit'te `_orch/redteam/` altına yeni bir stil-kapsam ölçüm eseri eklenmiş mi? Eklenmemişse ihlal ölçülmüştür |
| 11 | Yeni bir hafıza kapısı (O1/O2) eklenir ve mevcut zehirlenme probları güncellenmeden koşulursa | Problar "zehir yazılamadı" diye okunur, oysa zehir `candidate` satırında canlı durur; savunma **ölçüm aletini kör eder** ve 20/20'lik gerçek bulgu sahte bir 0/20'ye döner | Tam bu kalıp bu depoda gerçekleşti: kimlik-bağlama kapısı dört AUTHZ kontrolünün dördünü de PASS gösterdi ve dördü de hedef kapıya hiç varmadı (audit satırı 0) | yüksek | Prob çıktısında ayrım var mı: "profile satırı var mı" değil, **"hangi status ile var"**. Yoksa prob artık ölçmüyor |
| 12 | Tezgahı yeşil tutmak (release-candidate damgasını korumak) örtük bir hedef haline gelirse | Altıncı yanlış-hüküm kök nedeni üretilir ve bu kez muhtemelen fark edilmez, çünkü önceki beşi fark edildiği için "artık dürüstüz" güveni oluşmuştur | Tezgah bugüne kadar **peş** ayrı yanlış-hüküm kök nedeni üretti; beşincisi tam olarak buydu — gölge fark edilmiş ama erişim düzeltilecek yerde **yüklem genişletilmiş** | orta | Mekanik kural: bir kontrolün **yüklemi** değişen her commit, aynı commit'te ya bir üçüncü hal (ERROR = ölçülemedi) ya bir negatif kontrol eklemek zorunda. İkinci sinyal: PASS sayısı artarken bağımsız yan-kanıt sayacı (audit satırı) artmıyorsa yeşil sahtedir |
| 13 | Bir sonraki çalışma bloğu O1-O10'un tamamını (ya da raporun yığınını) sırayla uygulamayı hedeflerse | Hiçbiri ölçülmeden yarım kalır; depo çalışan bir üründen çok bir tasarım arşivine döner ve F-POISON hem kapanmaz hem **ölçülemez** hale gelir, çünkü ölçtüğü sistem sürekli değişiyordur | Ölçülmüş kapasite: 6 çalışma günü / 75 commit / 7150 satır src. O1-O10 yedi yeni kolon, terfi mantığı, transitif silme, verbatim çapa ve çok geçişli damıtma demek — bugünkü damıtma katmanının birkaç katı | orta | "Şema değişikliği içeren ama ölçüm betiği içermeyen" commit — tanım gereği ölçülemez bir değişikliktir ve tek başına yeterli bir durdurma sinyalidir |
| 14 | Bugünkü tempo (tek gün 32 commit, aralarda 17 güne varan boşluklar) devam ederse | Proje bir sonraki boşluktan dönmez; geride kalan şey yarısı "OPEN" işaretli bulgular içeren, devredilemez bir güvenlik arşivi olur | Tüm depo tarihi 6 çalışma gününe sıkışmış (07-09, 07-15, 08-01, 08-03, 08-04, 08-05); son gün tek başına 32 commit ve içlerinde geri alma/kayıt düzeltme commit'leri var. Yoğunluk arttıkça düzeltme commit'i belirmesi hız değil yorgunluk göstergesidir | yüksek | (i) Son commit'ten bu yana geçen günün 17'yi aşması; (ii) düzeltme/geri alma commit'lerinin oranının bir çalışma günü içinde artması; (iii) "yarın sıfırdan gelen biri nereden başlar" satırının `IS_HATTI.md`'de güncel olup olmadığı |
| 15 | Hafıza katmanı büyürken (O8 gibi) iş SQLite + tek süreç sınırının dışına taşarsa | "Tek exe, bootstrapper YOK" kararı hiç tartışılmadan ölür ve local-first iddiası, iddia geri çekilmeden içi boşalır — ki bu, açıkça yanlış bir iddiadan daha kötüdür | Risk raporun bulut yığınından değil, **kendi O8 önerimizden** geliyor: "olaylar bir pencere boyunca karıştırılmış sırayla damıtılsın" bir zamanlayıcı baskısı yaratır ve en kolay çözüm hep bir servis eklemektir | düşük | `pip --dry-run --report` kapanışının 36'yı aşması; `scheduler.py`'nin süreç-içi zamanlayıcı olmaktan çıkıp dış bir tetikleyiciye bağlanması |
| 16 | Okuma yoluna "hatırlama anında yeniden doğrulama" **yazma yetkisiyle** eklenirse | Her `profile_read` yeni bir zehirlenme penceresine döner; yeni içerik **mevcut** claim'in içine sızar ve `ALLOWED_KEY_PREFIXES` ile karantina savunmaları tümüyle atlanır (yeni anahtar yazılmaz) | Nader 2000 + Hupbach 2007 birlikte: geri çağırma kaydı labilleştirir ve yeni içerik eski kaydın içine karışır. Sinclair & Barense 2019: pencereyi açan şey **kısmi** eşleşmedir | orta | Kod incelemesinde `profile_read` yolunda herhangi bir `UPDATE`/`INSERT` belirmesi. Kural: yeniden doğrulama yalnız düşürür ve karantinaya alır |
| 17 | Kullanım-tabanlı decay (O9) ölçülmeden canlıya alınırsa | Sorgu hacmini etkileyebilen bir saldırgan **doğru** claim'leri soldurabilir (starvation/eviction) ve kendi claim'ini göreli olarak öne çıkarır; ayrıca hafıza durumu sorgu desenine bağlandığı için yan kanal açılır | Anderson-Bjork-Bjork: geri çağırma rakip izleri bastırır. Sorgu hacmi saldırganın kontrolündedir | orta | Decay canlıya alınmadan önce: sorgu hacmiyle güven skoru arasındaki ilişkiyi ölçen tek bir test. Yoksa özellik açılmamalı |
| 18 | `_orch/` arşivi (3,5 MB, yalnız redteam altında ~90 dosya) elle tutulan bir indeksle yönetilmeye devam ederse | Yayımlanan kayıt tekrar gerçeğin gerisine düşer — ve bir sonraki sefer projenin **lehine** yanlış olur, yani kapanmamış bir bulgu kapanmış görünür | Bu tam olarak iki kez oldu; birinde yayımlanan kayıt koddan daha kötümserdi (güvenli yön). Simetri yok: aynı elle-senkronizasyon ters yönde de sapabilir | orta | `SECURITY.md`'deki her OPEN/CLOSED işaretinin `_orch/archive/measurements.json` karşılığıyla eşleştiğini doğrulayan bir betik — bugün **yok**. Eşleşmeyen tek satır CI'ı kırmalı |

---

## 9. Kullanım paneli tasarımı

**Temel karar: yeni servis yok.** Mevcut FastAPI uygulamasına, dashboard'un birebir aynı deseniyle owner-kapılı route'lar + tek statik HTML sayfası eklenir (`/review`). Gerekçe: dashboard deseni `F-DASH` ve `F-OWNER-SCOPE`'tan sonra zaten sertleştirilmiş ve testlenmiş; ikinci bir süreç/port açmak üçüncü bir kimlik kapısı icat etmek demektir ve tam-aracılık iddiasını bozar.

Devralınan beş mekanizma (hiçbiri yeniden yazılmaz): `server.py:305` süreç-başına `_LAUNCH_NONCE` (diske yazılmaz) · `server.py:285` `require_owner()` (sabit zamanlı) · `routes.py:59` `_nonce_ok(k)` (fail-closed; token HTML'e yalnız geçerli nonce ile gömülür) · `routes.py:80` `add_api_route` deseni (bu ortamda `include_router` route düşürüyor) · `dashboard_ui/app.js`'in `createElement + textContent` disiplini.

**Panelin çıktı birimi ekran değil, karardır.** Karar veremeyeceğin ekran panele girmez.

### Ekranlar

| Ekran | Verdiği karar |
|---|---|
| **S1 — Oturum listesi** | Hangi konuşmayı inceleyeceğim? |
| **S2 — Oturum içgörü** (Bağlam / Kanıt / Karar şeritleri) | Bu çalışma kabul edilebilir miydi? Modelin kararını hangi kanıt destekliyordu, hangisi desteklemiyordu? |
| **S3 — Ölçüm panosu** (iddia → kanıt seviyesi + "bayat" bayrağı) | Bu iddiayı README/PR'a yazabilir miyim, yoksa önce yeniden mi koşmalıyım? |
| **S4 — Karantina kuyruğu** | Bu bilgi kalıcı hafızama girsin mi, silinsin mi, beklesin mi? |
| **S5 — Çelişki / supersession görünümü** | Yeni değer doğru mu, yoksa eskisine mi dönmeliyim? |
| **S6 — Zincir doğrulama** (Ed25519 + Merkle, en üstte global bayrak) | Kayıtlarıma güvenebilir miyim? Güvenemiyorsam bu panelin gösterdiği hiçbir şeye de güvenmemeliyim |
| **S7 — Karar kaydı** (KABUL / RED / BEKLET + zorunlu gerekçe) | Bu çıktıyı kabul ediyorum / reddediyorum, ve neden |

S4 bugün hiçbir dashboard route'unun dışarı açmadığı bir yetenektir (`list_quarantined` `tools.py:184`, `release_quarantined` `:203`) — **panelin gerçek yeni katma değeri burasıdır.**

### Veri kaynağı: geçmiş konuşma kayıtlarının gerçek konumu ve formatı

`RAN-LIVE` (dosya sistemi taraması + JSONL ayrıştırma, bugün):

- **Konum:** `~/.claude/projects/<cwd-slug>/<session-uuid>.jsonl`. `cwd-slug`, çalışma dizininin `:` ve `\` karakterleri `-` yapılmış hali. **Sürücü harfi büyük/küçük tutarsız** (hem `D--kasa` hem `d--WebAjans`) → eşleştirme büyük/küçük harf duyarsız olmalı.
- **Alt-ajan kayıtları ayrı:** `<session-uuid>\subagents\*.jsonl` ve `…\subagents\workflows\wf_<id>\*.jsonl`. 439 jsonl dosyasının ~417'si bu alt dizinlerde.
- **Boyut (ölçüldü):** 439 dosya / **543,7 MB**. En büyük tek oturum **82,5 MB** → tam dosya yükleme yasak, akıtma zorunlu.
- **Format:** JSONL; her satır bağımsız JSON. Ortak zarf: `type, uuid, parentUuid, timestamp, sessionId, cwd, gitBranch, version, isSidechain`. Ölçülen `type` değerleri: `user`, `assistant`, `attachment`, `system`, `file-history-snapshot`, `ai-title`, `last-prompt`, `mode`, `queue-operation`.
- **Ayrıştırıcı savunmacı olmalı:** tanınmayan `type` hata değil, "bilinmeyen kayıt" satırı olarak çizilir. Bu format belgelenmemiştir ve sürüm atladığında alan adları değişebilir; arayüz her oturumun `version`'ını göstermeli.

### Güvenlik

1. **Uçlarda `require_owner`, `verify_token` değil.** `F-OWNER-SCOPE`'un dersi: "geçerli bir bearer" ile "sahip" aynı şey değildir. `tests/test_owner_surface_authz.py`'deki owner-yüzey listesine yeni yollar eklenir — bağlı düşük-yetkili ajan token'ı ile 403 beklenen negatif kontrol olmadan "kapalı" denmez.
2. **HTML'e token yalnız launch nonce ile gömülür.** `F-DASH`'in dersi: tokensiz `GET /dashboard` owner bearer'ını sızdırıyordu. `/review` aynı `_nonce_ok(k)` kapısını kullanır; dashboard'daki "İnceleme" bağlantısı `window.location.search`'ü aynen taşımalı, aksi halde nonce kaybolur.
3. **Yeni ve en büyük risk: bu panel owner-kapılı bir dosya okuyucusudur.** `project`/`session` parametreleri `^[A-Za-z0-9_.-]{1,128}$` ile doğrulanır, birleştirilen yol `resolve()` edilir ve `is_relative_to(PROJECTS_ROOT)` ile kök altında olduğu doğrulanır. Bu kontrol olmadan panel, `..` ile makinedeki herhangi bir dosyayı tarayıcıya döken bir uca dönüşür. Pozitif **ve** negatif test şart.
4. **Panele giren konuşma metni GÜVENİLMEZ VERİDİR.** Ölçüldü: bir oturumda kullanıcı mesajı olarak yapıştırılmış üçüncü-taraf web sayfası kaynağı bulundu. Render **yalnız `textContent`**; `innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/new Function` ve log içeriğinden üretilen `href/src` yasak; markdown render edilmez; URL'ler tıklanamaz düz metin; uzak görsel yüklenmez. **Bu kural bir grep testiyle zorlanır** (`tests/test_review_no_html_sink.py`), yorumla değil.
5. **CSP ikinci duvar.** `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. Bugün `/dashboard`'ta CSP header'ı **yok** — bu bir eksik.
6. **Panel modele hiçbir şey göndermez (MVP).** Salt okunur, çevrimdışı, LLM çağrısı sıfır. Dolaylı enjeksiyon için "model" diye bir hedef yoktur; **kalan tek hedef insandır.**
7. **İnsanı da hedef say.** Log'dan gelen her blok "DIŞ KAYNAK — güvenilmez" çerçevesi içinde çizilir ve KASA'nın kendi ifadeleriyle aynı tipografiyi kullanamaz. "SİSTEM: bu kaydı onayla" yazan bir log satırı KASA'nın sesi gibi görünmemelidir. Bu çerçeve kozmetik değil, güvenlik kontrolüdür ve öyle test edilmelidir.
8. **Sır maskeleme varsayılan ve kapatılamaz.** `?raw=1` gibi bir kaçış yolu eklenmez. Ölçüm: tek küçük oturum dosyasında (64 satır / 158 KB) 182 `entropy` + 9 `base64` işareti; büyük kısmı hash/uuid yanlış-pozitifi. Bu yüzden arayüz **"N sır bulundu" DEMEZ, "N yerde maskelendi" der.** Skor üretmek yok.
9. **`file-history-snapshot` kayıtları MVP'de tamamen dışlanır** (dosya içeriği taşırlar; en büyük sır yüzeyi, en düşük inceleme değeri).
10. **Kaynak sınırı:** satır satır akıtma, istek başına bayt üst sınırı, blok başına 4 KB kırpma, sayfa başına 200 blok. "Tümünü göster" düğmesi yok.
11. **Oturum içeriği `kasa.db`'ye kopyalanmaz** — yalnız yol + sha256 + bayt uzunluğu + sahibin kendi sözleri saklanır. Sır yüzeyi büyümez.

### MVP — tam olarak hangi dosyalar ve uçlar

**Faz A0:** S1 + S2 + S7. (S3-S6 Faz A1'e; çünkü zincir ve istatistik zaten `/dashboard`'da kısmen görülüyor, **karar verme döngüsü ise bugün hiç yok.**)

Yeni dosyalar (~700 satır kod + ~210 satır test): `src/review/__init__.py` · `src/review/sessions.py` (~180: `_safe_path`, `list_sessions` mtime-geçersizlemeli indeks, `read_blocks` akıtmalı + redaksiyonlu) · `src/review/verdicts.py` (~90: `review_verdict` tablosu, boş gerekçe → `ValueError`, her yazım `AuditChain.record`) · `src/review/routes.py` (~140) · `dashboard_ui/review.html` (~260) · `dashboard_ui/review.js` (~380) · `tests/test_review_authz.py` + `test_review_sessions.py` + `test_review_no_html_sink.py`.

Değişen mevcut dosyalar (toplam ≤15 satır): `src/mcp_server/server.py` satır 326'nın altına iki satır (`_register_review(app, get_vault, _BEARER_TOKEN, require_owner, _LAUNCH_NONCE)`) · `dashboard_ui/index.html` rail'e "İnceleme" bağlantısı (3 satır) · `tests/test_owner_surface_authz.py` owner-yüzey listesine `/v1/review/*` (~6 satır).

Uçlar (hepsi `Security(require_owner)`): `GET /v1/review/sessions` · `GET /v1/review/session` · `GET /v1/review/verdicts` · `POST /v1/review/verdict` (gerekçe boşsa 400) · `GET /review` (HTML, token yalnız `?k=<nonce>` ile) · `GET /review/review.js`.

**Faz A1:** `/v1/review/chain`, `/v1/review/quarantine` (+ release/reject, gerekçe zorunlu), `/v1/review/profile/history`, `/v1/review/measurements`.
**Faz B (ayrı karar, sessizce eklenmez):** benchmark yeniden koşumu ve "oturumu yerel modele özetlet". İkisi de salt-okunurluğu bozar; her biri kendi tehdit değerlendirmesini ister.

**Dürüst sınır:** bu panel KASA'yı daha güvenli **yapmaz**. Yeni bir sahip-kapılı okuma yüzeyidir; net etkisi saldırı yüzeyini büyütmektir. Gerekçesi güvenlik değil, görünürlük ve karar verebilirliktir; öyle sunulmalıdır.

---

## 10. Tavsiye: ne yapılmalı

Sıra tesadüfi değil. KASA'nın kendi bağımlılık sürüşü: **saldırı yüzeyi → kriptografik bütünlük → güvenilmez-veri izolasyonu → kontrollü işleme.** Sonraki her katmanın değeri, öncekinin kapalı olmasına koşulludur.

### Bu hafta

**1. Ürünü ölçümün kapsamına al** — *bir oturum.*
`src/mcp_adapter/__main__.py:111` ile `src/mcp_server/tools.py:75` arasındaki `reason` uyuşmazlığını düzelt ve düzeltmeyi bir uçtan uca testle kilitle (adaptör → gerçek sunucu → 200).
*Bu neyi kanıtlar:* MVP'nin birincil okuma yolunun çalıştığını. *Neyi kanıtlamaz:* diğer araç yollarının çalıştığını — uçtan uca test sayısı bugün 0, bu onu 1 yapar.

**2. `contested` yazım (O2)** — *~20 satır.*
`engine.py:266`'daki `INSERT OR REPLACE INTO profile` yerine çelişkiyi görünür bırakan yazım.

```sql
-- before: the new claim silently overwrites the old one (last-write-wins)
INSERT OR REPLACE INTO profile (id, key, value, provenance, created_at, updated_at)
VALUES (NULL, ?, ?, ?, ?, ?);

-- after (sketch): keep both, mark the conflict, let the owner resolve it
INSERT INTO profile (key, value, provenance, supersedes, status, created_at, updated_at)
VALUES (?, ?, ?, (SELECT id FROM profile WHERE key = ? AND status = 'active'), 'contested', ?, ?);
UPDATE profile SET status = 'contested' WHERE key = ? AND status = 'active';
```

*Türkçe açıklama: bugünkü tek satırlık fiil, yeni bir değerin eskisini koşulsuz ezmesine izin veriyor — ve zehirlenmenin "sessiz" olmasının tek nedeni bu. İkinci biçimde eski satır silinmez; ikisi de `contested` işaretlenir ve okuma yolu çelişkiyi döndürür. `key UNIQUE` kısıtının kaldırılması gerekir; şemadaki `supersedes` kolonu zaten var, yalnız doldurulmuyor.*
*Bu neyi kanıtlar:* zehirli yazımın meşru değeri artık sessizce silemediğini. *Neyi kanıtlamaz:* zehrin yazılmadığını — **F-POISON kapanmaz.** Yazılacak cümle: "sessiz kalıcı gerçek → sahibin gördüğü çözülmemiş çelişki".

**3. Mutasyon testi** — *1-2 gün.*
`gate.validate_call`, `quarantine_reason`, `proxy._is_loopback_url`'e kasıtlı mutantlar; `tools/security_bench/run.py` koşulur. Özellikle `_is_loopback_url`'ü eski `startswith` haline döndür.
*Bu neyi kanıtlar:* tezgahın hangi kapıyı hiç sınamadığını — iddia olarak değil, ölçüm olarak. Bench yeşil kalıyorsa gerçekten yaşanmış `127.0.0.1.evil.example` bypass'ının bugün de kaçırıldığı ispatlanmış olur. *Neyi kanıtlamaz:* öldürülen mutantların olduğu yerde savunmanın **doğru** olduğunu — yalnızca testin oraya baktığını.

**4. Karantina kalıplarına Türkçe + metamorfik dil-değişmezliği testi** — *yarım gün.*
*Bu neyi kanıtlar:* dil sınırının varlığını (TR/EN çifti farklı sonuç veriyorsa açık kanıtlanmış olur). *Neyi kanıtlamaz:* Türkçe kalıpların işe yaradığını — **negatif kontrol zorunlu:** meşru Türkçe notlar karantinaya düşüyorsa kazanç değil aşırı-çevreleme üretilmiştir.

**5. SQLite PRAGMA'ları** — *bir saat.*
`journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`, `synchronous=NORMAL`.
*Bu neyi kanıtlar:* hiçbir şeyi — bir yapılandırma düzeltmesidir. *Neyi kanıtlamaz:* eşzamanlılık altında kilit davranışını; o ayrıca ölçülmeli. Ama "Postgres yerine SQLite yeter" cümlesinin dürüst olabilmesi için ön koşuldur.

### Bu ay

**6. `audit_checkpoint.entry_count` → `verify_chain`** — *yarım gün.* Kuyruk silme tespiti. Malzeme tabloda hazır. Pozitif ve negatif kontrol şart.
**7. Transparency-log tanığı** — *1-2 gün.* Periyodik Signed Tree Head'i sahibin ikinci bir cihazına/dosyasına yaz. *Bu neyi kanıtlar:* denetim iddiasını "makine ele geçmediyse doğru"dan "makine ele geçse bile split-view tespit edilir"e yükseltir. *Neyi kanıtlamaz:* zincirin içeriğinin doğru olduğunu — imza kökeni doğrular, doğruluğu değil.
**8. F-POISON'un kapsamını ölç, kapatma** — *1-2 gün.* `config`'i `kasa-agent:8b`'ye çevirmek tek satır ve cazip; şu haliyle yapılırsa ölçülmüş bir iddia (20/20) ölçülmemiş bir iddiayla (0/25, tek stil) değiştirilmiş olur. Önce parafraz + çok-turlu + kodlanmış varyantları koş, negatif kontrolü esere gömülü tut. Yazılacak en iyi cümle: **"ölçülen stiller kapandı"** — "F-POISON azaltıldı" değil.
**9. O1 (candidate/consolidated + distinct_source_count) ve O4 (prune'da transitif düşürme)** — *3-5 gün.* O11 kuralı: prob "satır var mı" değil "hangi status ile var" sormalı, yoksa yeni savunma eski ölçümü kör eder.
**10. O5 — model beyanı `confidence`'ı kanıt saymayı bırak** — *yarım gün.*
**11. İnceleme Panosu Faz A0** — *2-3 gün.* Yukarıdaki 9. bölüm.
**12. Ölçüm betiği standardı** — *yarım gün.* Sonuç yazan her betik bir fayda/negatif kontrol alanı içermeli; fayda sıfırsa hüküm yazmadan `exit 1`. Bu çözüm `hardening_prompt_ab.py`'de **var** ama standart değil. Ek olarak: `SECURITY.md`'deki her OPEN/CLOSED işaretini `measurements.json` ile eşleştiren bir CI kontrolü.

### Sonra (3 ay ve ötesi)

**13. O6 verbatim çapa** · **14. bitemporal + retraction** · **15. tiple daraltılmış deklasifikasyon kanalı (FIDES deseni)** · **16. O8 çok geçişli karıştırılmış damıtma — en sona**, çünkü zamanlayıcı baskısı yaratan tek öneri odur ve local-first sınırını zorlar.
**17. `kasa_note` ANCAK bunlardan sonra** ve ocap/attenuation + dizisel (edit-automata tarzı) kapı ile. Yazma yetkisi gate'e kural **eklenerek** değil, veri akışına **bütçe bağlanarak** verilmelidir.

### Yapılmayacak

Rapordaki yığın. En yüksek eforlu seçenek olmasının yanında, ölçülmüş tek açık kusuru kapatmıyor. Fikirler (evidence card, taint, idempotency, kör eleştiri, dış doğrulayıcı) sağlam; sorun taşıma biçimi.

Ve bir insan-faktörü kısıtı: **tempoyu bir kısıt olarak yaz.** Altı çalışma günü, 17 güne varan boşluklar, tek günde 32 commit — bu veri, yukarıdaki teknik risklerin hiçbirinden daha yüksek bir başarısızlık olasılığı taşıyor. Somut karşı önlem tek satırlık: her çalışma bloğunu "yarın sıfırdan gelen biri nereden başlar" cümlesini `IS_HATTI.md`'ye yazarak bitir. Bu, tükenmeyi önlemez — devredilebilirliği korur, ki tek kişilik projede korunabilecek olan budur.

---

## 11. Bu değerlendirmenin sınırları

**Neyi ölçmedik**

- Raporun önerdiği mimarinin **gerçek dünyada işe yarayıp yaramayacağını** ölçmedik. Bu inceleme yalnız **iddia rejimini** denetler: neyin ölçüldüğü, neyin varsayıldığı, neyin kanıt gibi paketlendiği. Mimarinin performansı hakkında olumlu ya da olumsuz hiçbir hüküm içermez.
- Raporun Python kodu bir bütün olarak çalıştırılmadı (bağımlılıklar kurulu değil). `score()`, `canonical_hash()` ve freshness mantığı raporda yazıldığı gibi elden yeniden kodlanıp koşuldu; bulgular bu yeniden kodlamaya dayanır. **Rego politikası OPA ile hiç değerlendirilmedi** — complete-rule çakışması bulgusu `CODE-STRUCTURE` seviyesindedir.
- Bu oturumda **hiçbir KASA testi, tezgahı veya red-team probu koşulmadı.** `342 test toplandı` bir önceki oturumda `RAN-LIVE` alındı; `323 passed`, `20/20 F-POISON`, `23/25 vs 0/25`, `7/10 e2e` ve tüm F-* bulgu sayıları bu belgede `DOCUMENTED` seviyesindedir. Bağımsız doğrulanmadı, kayıttan alındı.
- Gerçek vault'a dokunulmadı, sunucu başlatılmadı, hiçbir HTTP çağrısı yapılmadı. 401/403/422/429 davranışları yalnız koddan okundu.
- `src/browser/browser_window.py` (1699 satır, src'nin ~%24'ü) okunmadı. Tarayıcı yüzeyi bu incelemenin dışında.
- Performans, gecikme, kaynak tüketimi hiç ölçülmedi. "İşletme maliyeti" argümanı süreç/bağımlılık sayımına dayanır, profil ölçümüne değil.
- Önerilen yerel alternatiflerin (SQLite outbox, dizin-CAS, imzalı `policy.json`, AppContainer/Job Object izolasyonu) **hiçbiri uygulanmadı ve ölçülmedi.** Bunlar önerilerdir; "daha güvenli olduğu kanıtlandı" iddiası taşımazlar.
- 7. bölümdeki 19 yaklaşımın **hiçbiri KASA üzerinde koşulmadı.** "Denenebilir" listesi, "denenmiş" listesi değildir.
- 6. bölümdeki nörobilim önerilerinin hiçbiri ölçülmedi. Ayrıca **ölçülmemiş bir varsayım:** "çelişkiyi görünür bırakmak" önerisinin kullanılabilirlik bedeli bilinmiyor. Sahibin inceleme kuyruğu dolduğunda (alarm yorgunluğu) görünür çelişki pratikte sessiz kabule döner. "Tespit + karantina + atıf" doktrini ancak inceleme kapasitesi kadar gerçektir.

**Hangi iddia doğrulanmadı**

- Simülasyonun **gerçekte hangi formülle üretildiğini bilemeyiz.** Kanıtlanan şey sayıların iç tutarsızlığı ve varsayım duyarlılığıdır; üretim formülünün ispatı değildir. Üretici kod ortaya çıkarsa bu bulgular yeniden değerlendirilmelidir.
- Sayılabilirlik testi, raporun değerlerinin ham koşu sayımlarından geldiğini varsayar. Değerler ağırlıklı/yumuşatılmış oranlarsa test uygulanmaz — ama rapor böyle bir işlem belirtmiyor.
- "Bileşik görev başarısı"nın hangi kompozisyon kuralı olduğunu rapor söylemiyor; üç makul okuma test edildi, dördüncü bir okuma tanımlanmış olabilir. O durumda dahi **yeniden üretilemezlik bulgusu geçerli kalır.**
- `langsmith`'in varsayılan olarak dışarı veri gönderdiği **iddia edilmedi.** Ölçülen tek şey koşulsuz bir bağımlılık olarak kurulduğu.
- OPA'nın varsayılan bind adresi ve kimlik doğrulamasının varsayılan kapalı olduğu `DOCUMENTED`; bu oturumda bir OPA daemon'u çalıştırılıp taranmadı. gVisor/Firecracker'ın Windows'ta çalışmadığı da `DOCUMENTED`.
- Bağımlılık sayımları 2026-08-05'te, py3.14/win_amd64 üzerinde alındı; sürüm çözümlemesi zamana göre değişir. Sayılar mutlak değil, **büyüklük mertebesi kanıtıdır** — ve ölçülen 97 yeni paket gerçek maliyetin **alt sınırıdır** (OPA, Temporal, PostgreSQL, MinIO, Kafka, Vault ikilileri dahil değil).

**Hangi atıf teyit edilmedi**

Bu oturumda internet erişimi kullanılmadı. Aşağıdakiler açıkça **"atıf doğrulanamadı"** olarak işaretlenir ve sessizce aktarılmaz:

- Richards & Frankland (2017) cilt/sayfa numaraları; Roediger & McDermott (1995) tam sayfa aralığı; Brainerd & Reyna bulanık-iz kuramı künyesi; Ebbinghaus (1885) künyesi — **web ile doğrulanmadı.** (Doğrulanmış olanlar: McClelland ve ark. 1995 PMID 7624455; Kumaran ve ark. 2016 PMID 27315762; Girardeau ve ark. 2009 PMID 19749750; Rudoy ve ark. 2009 PMID 19965421; Schultz ve ark. 1997 PMID 9054347; Tse ve ark. 2007 doi:10.1126/science.1135935; Nader ve ark. 2000 PMID 10963596 — bazı ikincil kaynaklar "Nature 416" yazıyor, **doğrusu Nature 406:722-726**.)
- **ChainCaps (arXiv:2605.26542)**, **AgentSpec (arXiv:2503.18666)**, **ReliabilityBench (arXiv:2601.06112)**: 2025-2026 tarihli, tek ekip sonuçları; bağımsız tekrar yok. ChainCaps'in etkinliği manifest kalitesine aşırı duyarlı (%100'e karşı %27,3) — yani sonuç teknikten çok kural yazımının kalitesinden geliyor olabilir. Bu belgedeki hiçbir tavsiye bu sayılara dayanmıyor.
- **Honeytoken'ın ajan hafızası zehirlenme tespitine uygulanması** için akademik atıf **arandı ve bulunamadı.** Desenin kendisi yerleşiktir; bu alana taşınması bir öneridir, literatür desteği değil.
- **CRDT MV-Register ve Datalog kısıtlarının güvenlik amacıyla zehirlenmeye karşı kullanımı** alt-ajanın kendi çıkarımıdır; atıf doğrulanamadı. Her iki teknik de yerleşiktir ama **düşmanlık modeli için tasarlanmadı** — CRDT'ler Byzantine-güvenli değildir.
- Raporun kendi atıfları hakkında: **42 atıf hedefinin tamamı çözülemez** (`RAN-LIVE` sayım). Rapordaki MCP blog URL'leri (2026-03-16, 2026-07-28), "OWASP Agentic Top 10 2026 / ASI06" çerçevesi, A-MEM (2502.12110) ve SWE-bench-Live (2505.23419) arXiv kimlikleri **doğrulanamadı**. Kritik nokta: `evd_mcp_001` doğrulanmamış bir blog URL'sini `trust='verified_primary', confidence=0.99` ile taşıyor.
- Raporun **SCoRe (2409.12917) atfı yanlış amaçla kullanılmış** görünüyor: SCoRe'un tezi self-correction'ın RL ile **öğretilebildiğidir**; "harici gözetim olmadan güvenilmez" iddiasının asıl kaynakları Huang ve ark. (2310.01798) ve Tyen ve ark. (2311.08516) olup ikisi de raporun kaynakçasında yok. Bu değerlendirme `DOCUMENTED` seviyesindedir (model bilgisi, canlı teyit değil).

**İş akışının kendi eksikleri**

- Planlanan 12 alt-ajandan **9'u sonuç döndürdü.** Dönmeyen üçü: **saldırı lensi** (`uzay:saldiri`) ve **iki eleştiri ajanı** (`adversaryal-dogrulama`, `eksiklik-kritigi`). Pratik sonuçları: (i) 8. bölümdeki olasılık uzayı **inşaat ve başarısızlık** lenslerinden beslendi; saldırgan-öncelikli dallar (16, 17) nörobilim ve yaklaşım taramalarından türetildi, ayrı bir saldırı lensinden değil. (ii) **Alt-ajan çıktıları bağımsız bir adversaryal doğrulamadan geçmedi** — atıf teyidi bu bölümde elle yapıldı, otomatik değil.
- **İşaretlenen çelişki:** bir alt-ajan `harness.py`'nin "CaMeL deseninin yarısını uyguladığını" (kontrol-akışı bütünlüğü) söylüyor; başka bir alt-ajan "KASA'nın harness'i CaMeL varyantı **değildir**" diyor, çünkü araç sonucu `messages`'a eklenip aynı araç-yetkili model bir sonraki çağrıyı seçiyor. **Zayıf olanı elendi:** CaMeL'in tanımlayıcı özelliği P-LLM'in kontrol akışını güvenilmez veriyi **görmeden** sabitlemesidir ve bu KASA'da yok. Bu belgede geçerli okuma ikincisidir; "CaMeL'in yarısı var" ifadesi abartılıdır.
- **İşaretlenen ikinci fark:** hash kararsızlığı ölçümü koşuya göre 6/6, 7/8 ve bugün 8/8 farklı hash verdi. Sayı değişkendir (rastgele tohum etkisi); **kararsızlığın kendisi her koşuda doğrulandı.**

---

*Bu belge bir değerlendirmedir, bir kapanış kaydı değildir. İçindeki hiçbir madde "düzeltildi" demiyor. Ölçülen kusurlar `bulundu → kanıtlandı` aşamasındadır; `kapatıldı` aşaması, karşılık gelen düzeltme koşulup pozitif ve negatif kontrolüyle birlikte yayımlandığında yazılabilir.*
