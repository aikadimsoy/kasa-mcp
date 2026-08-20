# Proje KASA

Windows'ta Ajan Tabanlı Tarama için Egemen, Yerel-Öncelikli bir Hafıza Kasası

> ## ⚠️ v0.1 — Araştırma Önizlemesi / Güvenlik Mimarisi Gösterimi
>
> **Bu deneysel bir prototiptir. Üretimde veya hassas veriyle kullanmayın.**
>
> Amacı bir mimariyi — yerel yapay zekâ ajanları için izin, şifreleme ve denetim — göstermek
> ve *ölçmektir*; bitmiş bir ürün olmak değil. Gözden çıkarabileceğiniz veriyle çalıştırın.
>
> **Bugün gerçekten doğru olanlar**, her biri bir özelliği iddia etmek yerine dayandığı
> kanıtı göstererek:
>
> | | |
> |---|---|
> | Tümüyle yerel çalışır | kasa dosyası, anahtar ve izin kararları makineden hiç çıkmaz |
> | *Belirli* alanları şifreler — **broker yazma yolunda** | 3 kolon, AES-256-GCM, AAD-bağlı — veritabanının tamamı değil, **ve damıtıcı yolunda değil**: 2026-08-05 ölçüldü, damıtıcının yazdığı `profile.value` **düz metin** kalıyor (`_orch/redteam/distill_crypto_bypass.py`) |
> | Araç yetkisini sıradan kodla sınırlar | deterministik aracı; model asla sınır değildir |
> | Hash-zincirli denetim defteri tutar | kurcalama ve silme tespiti ölçümle PASS |
> | Ajan kimliğini token'a bağlar | gerçek sunucuya karşı 7/7 kontrol, pozitif **ve** negatif — `_orch/redteam/fimp_live_verify.py` |
> | 451 test geçiyor | 2026-08-20 koşusu (+1 xfail — xfail bir geçiş değil, beklenen başarısızlıktır; bu yüzden "%100 geçti" denmez). Önceki sayılar da gerçek koşulardı: 2026-08-05'te 323, tarayıcının üç mock testi on dört gerçek-sunucu testiyle değiştirilmeden önce 357, 2026-08-19'da 384, 19 kırık test silinmek yerine düzeltilince 428. **Test sayısı bir güvenlik iddiası değildir** — aynı koşu, bu projenin daha önce "doğrulandı" dediği kodda kusur kanıtlayan testler de ekledi |
>
> **İddia EDİLMEYENLER** — bunlar açık, yazılı, ve bir kısmı ölçülmüş başarısızlıktır:
> tam at-rest şifreleme, egress kontrolü, bağımsız güvenlik denetimi. Ağdan gelen bir çağıran
> artık denetim *atfını* sahteleyemez (yukarı bkz.), ama **doğru** bir atıf, atfedilen iddiayı
> doğru yapmaz — bkz. F-POISON bulgusu. KASA tarayıcısı, bilinen bir köprü izolasyon kusuru
> nedeniyle **kapalı** geliyor. Projenin kendi tezgâhı artık *yayın-adayı* damgası basıyor —
> **bu kelime tezgâhın, projenin değil**: dar bir takımda hiçbir kontrolün kalmadığı anlamına
> gelir, ve o takımda KASA'nın karşısına kurulduğu düşmanı ölçen tek bir kontrol yoktur.
>
> Kendi negatif sonuçlarımızı yayımlarız ve yukarıdaki her iddianın arkasında bir komut var.
> **[`docs/REPRODUCE.md`](docs/REPRODUCE.md)** dizindir: her iddia için onu üreten komut ve o
> komutun neyi *göstermediği*. Açık bulgular [`SECURITY.md`](SECURITY.md)'de.
> Buradan değil, oradan başlayın.

## Sorun

Bugünkü ajan tabanlı tarayıcılar, kalıcı kullanıcı hafızasını satıcı bulutlarında saklıyor; bu da ciddi gizlilik ve kontrol sorunları doğuruyor. Kullanıcılar tarama verilerine sahip olamıyor ve yapay zekâ ajanlarına izin vermenin yasal sonuçları net biçimde tanımlanmış değil. Bu proje, herhangi bir ajanın izin-aracılı bir MCP (Model Context Protocol) sunucusu üzerinden erişebileceği; yerel-öncelikli, şifreli ve kullanıcıya ait bir hafıza kasası sağlayarak bu eksiklikleri gidermeyi amaçlıyor.

## KASA Ne Yapar

KASA, Windows kullanıcıları için egemen bir hafıza kasası olarak tasarlanmıştır: kasa dosyası, şifreleme anahtarı ve izin kararları kullanıcının makinesinde kalır. *Tam kontrol* iddia **edilmez** — ölçülmüş sınırlar (istemci beyanlı `agent_id`, ölçülmeyen egress, düz metin metadata kolonları) aşağıdaki Proje Durumu'nda adıyla yazılıdır. "Ajanlar gelip gider; hafızanız sizindir" ilkesine dayanır. Sistem şunları içerir:

- Hassas hücreleri diskte hücre başına AES-256-GCM ile şifreleyen yerel bir Hafıza Kasası. Dürüst kapsam: şifreleme üç kolonu kapsayan hücre bazlı şifrelemedir, tam-veritabanı değil — aşağıdaki Proje Durumu'na bakın.
- Bu kasayı, aracılı bir protokol üzerinden izin sahibi her ajana açan bir MCP Sunucusu.
- Yalnızca yetkili ajanların veriye erişmesini sağlayan, kullanıcı bilgisi üzerinde sıkı denetim kuran bir izin hesabı (permission calculus).

## Mimari

KASA'nın mimarisi beş ana bileşenden oluşur:

| Bileşen | Rol | MVP Durumu |
|---------|-----|------------|
| Hafıza Kasası | Yerel depo; hassas hücreler şifreli (AES-256-GCM), metadata kolonları düz metin | ✅ |
| MCP Sunucusu | Kasayı ajanlara açan localhost sunucusu | ✅ |
| Ajan Çekirdeği | Yerel model ve planlayıcı | ✅ (yalnızca damıtma) |
| İzin Aracısı | Dış erişim için deterministik geçit | ✅ (kapsam denetimleri) |
| Tarayıcı Uzantısı | Sayfaları okur, ileride eylem yürütür | Ertelendi |

### Tasarım Değişmezleri

1. **İnce Kenarlar, Kalın Çekirdek**: Uzantı hiçbir zekâ ve veri içermemeli; tüm durum yardımcı uygulamada tutulur.
2. **Model Güvenlik Sınırı Değildir**: Yetkilendirme kararları, sıradan kod içindeki İzin Aracısı tarafından verilir.
3. **Sayfa İçeriği Veridir, Komut Değildir**: Web'den gelen her metin alıntı verisi olarak etiketlenir. Hedefler yalnızca kullanıcının kendi komutlarından türetilebilir.

## Güvenlik

Bu depodaki her güvenlik iddiasının, dayandığı ölçümü adıyla göstermesi beklenir.

**[`docs/REPRODUCE.md`](docs/REPRODUCE.md) ile başlayın** — her iddiayı, onu kendi makinenizde
yeniden üreten komutu ve o komutun neyi *göstermediğini* listeler. Ayrıca **ölçmediklerimizi** de
adıyla yazar; bir kanıt dizininin genelde atladığı kısım tam olarak budur.

Destekleyici belgeler: kanıt raporu
[`docs/SECURITY_BENCHMARK.md`](docs/SECURITY_BENCHMARK.md) (21 kalem, her kalem için kanıt dizesi)
— ondan bir sayı alıntılamadan önce
[`docs/SECURITY_BENCH_LIMITS.md`](docs/SECURITY_BENCH_LIMITS.md) okunmalı; sınırları açıkça
yazılmış test-test ayrıntı [`SECURITY_TESTS_TR.md`](SECURITY_TESTS_TR.md); açık bulguları içeren
denetim [`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md`](docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md).

- **Kırmızı takım bulguları — ne ölçüldü, ne hâlâ açık.** Her satır dayandığı kanıtı adıyla
  gösterir; hiçbiri "bu saldırı sınıfı çözüldü" demez.
  - *Damıtma zincirine dolaylı komut enjeksiyonu* — güvenilmeyen olay metni açık sınırlayıcılarla
    sarılır ve QC köken (provenance) geçidi, modelin kaynak gösteremediği fact'i reddeder. Ölçüm:
    `tests/test_distill_injection.py`, `tests/test_delimiter_breakout.py`,
    `tests/test_semantic_injection.py`. **Sınır:** komut enjeksiyonu sektör genelinde **açık** bir
    problemdir; buradaki savunma *yapısaldır* (model asla güvenlik sınırı değildir), bağışıklık
    iddiası değildir.
  - *MCP yetkilendirme* — izin-listesi (`PUBLIC_TOOLS`), rezerve-ajan bloğu ve kapsam başına
    varsayılan-red kontrolleri ölçümlerini geçiyor (`AUTHZ-*` kalemleri:
    [`docs/SECURITY_BENCHMARK.md`](docs/SECURITY_BENCHMARK.md); `tests/test_agent_gate.py`).
    **Kapatıldı (F-IMP bulgusu).** `agent_id` eskiden gövdeden doğrulanmadan geliyordu; token
    sahibi başka bir ajanın kimliğine bürünebiliyor ve denetim atfı sahtelenebiliyordu. Kimlik
    artık token'dan çözülüyor; gövdedeki beyan yalnızca bir iddiadır ve çelişirse reddedilir.
    2026-08-05'te **gerçek** bir sunucuya karşı ölçüldü, 7/7 kontrol — ve önemli olan ikisinin
    birlikte olması: ölçülmüş saldırı (sahip token'ı `browser` kimliğini beyan ediyor → eskiden
    200, şimdi **403**) *ve* kapının kör bir ret olmadığını gösteren pozitif kontrol (bağlı token
    kendisi olarak gerçek bir yazmayı tamamlıyor → **200**). Aynı kök nedenden doğan hız-sınırı
    bypass'ı da onunla gitti: dönen kimlikle 300 istek artık **240 adet HTTP 429** üretiyor;
    eskiden 150 istek **sıfır** üretiyordu. Kanıt: `_orch/redteam/fimp_live_verify.py`,
    `_orch/redteam/fimp_live_result.json`, `tests/test_identity_binding.py` (15 test).
    **Sınır:** kimlik bir *token*'a bağlıdır; gücü token gizliliği kadardır — vault'u okuyabilen
    aynı-OS saldırganı token üretebilir ve o düşman sınıfı tasarımla kapsam dışıdır. Ayrıca doğru
    bir atıf, atfedilen iddiayı doğru yapmaz (F-POISON).
  - *KASA tarayıcısı köprü izolasyonu* — **açık, ve tarayıcının kapalı gelmesinin sebebi.**
    pywebview `js_api` köprüsü ziyaret edilen sayfanın JS bağlamında bulunuyor ve sayfa
    betikleri origin denetimi olmadan enjekte ediliyor; dolayısıyla ziyaret edilen her site
    `window.pywebview.api.*`'a — `set_proxy()` ve `ingest()` dâhil — erişebiliyor.
    `open_browser()` artık `KASA_ENABLE_BROWSER=1` olmadan başlamıyor ve hiçbir yan etki
    oluşmadan kapanıyor (`tests/test_browser_optin_gate.py`, negatif ve pozitif kontrolüyle).
    **Sınır:** bulgu kod yapısından ve ingest özelliğinin kendi çalışmasından kuruldu;
    **çalışan bir sömürü yazılmadı ve koşulmadı.** Tam yazım: [`SECURITY.md`](SECURITY.md),
    "Known-unsafe surfaces". Aynı yüzeydeki daha küçük bir kusur *düzeltildi*: adres çubuğu
    artık URL'yi HTML'e gömmüyor.
  - *Otomatik test→düzelt döngüleri* — sıfır-maliyetli yerel-model döngüsü ve tarayıcı sağlık
    kapıları kontrolleri tekrar tekrar koşar (`_orch/loop/`, `tools/security_bench/`). Bunlar
    regresyon kapsamını artırır; tek başlarına güvenlik kanıtı **değildir**.

### Yol Haritası

Sıralama efora göre değil, **bir sonraki dürüst iddianın önünü neyin tıkadığına** göre. Her
madde bugün ölçümle açık olan bir boşluğu kapatır; kanıtlar [`SECURITY.md`](SECURITY.md)'de.

| Sürüm | Hedef | Kapattığı |
|---|---|---|
| **v0.1** *(bu sürüm)* | Temiz public depo, güvenli örnek yapılandırma, açıkça yazılmış sınırlar | — |
| **v0.2** ✅ *(bitti, 2026-08-05 ölçüldü)* | **Doğrulanmış ajan kimliği** — `agent_id` token'dan çözülür, uyuşmazlık reddedilir | F-IMP; denetim *atfını* anlamlı kılar ve aynı kök nedenden doğan hız-sınırı bypass'ını da kapatır. 7/7 canlı kontrol: `_orch/redteam/fimp_live_verify.py`. **Süreç** kimliği (isimli-boru üzerinden OS düzeyi) hâlâ bir fizibilite denemesi, kurulmuş değil |
| **v0.3** | **Varsayılan-red egress + capability izinleri** | "egress kontrolü yok" |
| **v0.3** | **Ayrıcalıklı arayüzü sayfa bağlamının dışına alma** | yukarıdaki tarayıcı köprü izolasyonu kusuru |
| **v0.4** | Saldırı testleri, frenler ve bütçeler | kırmızı-takım betiklerini kapıya dönüştürür |
| **v1.0** | Üretim adayı — *bağımsız güvenlik incelemesinden sonra* | "bağımsız denetim yok" |

## Kurulum ve Çalıştırma

### Gereksinimler

- **Yalnızca Windows.** KASA bugün çapraz-platform değildir: tepsi uygulaması Windows'ta PyQt5 kullanır ve kasa anahtarı **Windows DPAPI** ile korunur. macOS/Linux'ta DPAPI katmanı bir no-op'tur, yani KASA'nın dayandığı anahtar koruması orada mevcut değildir (ölçülmüş sınır: `docs/SECURITY_BENCHMARK.md` → "Bilinen Sınırlar", *non-Windows DPAPI no-op*).
- **Python 3.12 — her zaman bunu kullanın.** Masaüstü yolu 3.12'ye sabitlenmiştir: Nuitka ile derlenmiş ikili, Python 3.14 altında pywebview penceresini açarken **segfault** veriyor. Bu varsayım değil, ölçüm — `docs/EXE_PACKAGING_LOG.md`, "Spike-2 Py3.14: SEGFAULT (exit 3)"; derleme script'i başka sürümü `build_kasa.ps1:29-32`'de reddediyor. Ölçümün dürüst kapsamı: bu, masaüstü/exe yolunda gözlendi; test paketi ve güvenlik tezgahının kendisi en son 3.14.5 altında koşturuldu (`docs/SECURITY_BENCHMARK.md` başlığı). 3.12 kullanmak bu soruyu tamamen ortadan kaldırır.
- **Ollama ayrıca kurulur.** KASA bir model çalışma zamanı paketlemez veya kurmaz. Damıtma çalışma zamanında isteğe bağlıdır; kasa ve pano o olmadan da çalışır.

### Adımlar

1. **Sanal ortam oluşturun** (önerilir; 3.12 sabitini de açıkça görünür kılar):
   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. **Bağımlılıklar**: Gerekli Python paketlerini şu komutla yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. **Yerel Ollama Çalışma Zamanı** (isteğe bağlı, yalnız damıtma için gerekir): Ollama'yı https://ollama.com adresinden ayrıca kurun, ardından modeli çekin ve http://localhost:11434 adresinde servis verdiğinden emin olun:
   ```bash
   ollama pull qwen2.5:7b
   ```
4. **Yapılandırma**: `kasa.toml.example` dosyasını `kasa.toml` olarak kopyalayın ve sunucu host/port, kasa yolu gibi ayarları isteğinize göre düzenleyin. Bearer token ilk çalıştırmada üretilir.
5. **Sistem Tepsisi Uygulamasını Başlatma**: Uygulamayı şu komutla çalıştırın:
   ```bash
   python run.py
   ```
6. **Yalnızca MCP Sunucusu (Tepsisiz Mod)**: Tepsi simgesi olmadan yalnızca MCP sunucusunu çalıştırmak için:
   ```bash
   python run.py --no-tray
   ```
7. **Tek Bir Damıtma Turu Çalıştır ve Çık**: Tek bir damıtma turu çalıştırıp çıkmak için:
   ```bash
   python run.py --distill-now
   ```
8. **Şifreli Taşınabilir Dışa Aktarım**: Kasanızı şifreli bir dosya olarak dışa aktarmak için:
   ```bash
   python run.py export --output my_vault.kasa --verify
   ```

## MCP Araçları

KASA, yerel kullanım için şu MCP araçlarını sunar:

- `profile_read(scope)`, `profile_write(fact)`, `forget(topic)`, `audit_read(range)`, `event_ingest`, `prune_expired_events`.

## Test Etme

KASA test için pytest kullanır. Testleri çalıştırmak için:
```bash
pytest -q
```

## Proje Durumu

**Hâlâ yayına hazır değil — ama sebebi artık kalan bir kontrol değil.** Tezgah artık 21 kalemde
**21 PASS · 0 FAIL · 0 WARN** kaydediyor (`docs/SECURITY_BENCHMARK.md`, commit `5a703cd`,
2026-08-05) ve *yayın-adayı* damgası basıyor. **Bu kelime tezgâhın, projenin değil.** Anlamı şu:
dar bir takımda hiçbir kontrol kalmıyor — oysa aşağıdaki F-POISON bulgusu açık ve o takımda
KASA'nın karşısına kurulduğu düşmanı ölçen **tek bir kontrol yok**. Tezgahtan bir sayı
alıntılamadan önce [`docs/SECURITY_BENCH_LIMITS.md`](docs/SECURITY_BENCH_LIMITS.md) okunmalı.
Evin kuralı *ölçülene kadar mühürlenmez*; bu yüzden "sertleştirilmiş", "kurumsal düzey" veya
"üretime hazır" gibi etiketler burada kullanılmaz — `docs/UI_UX_STANDARD.md` §2.6 bunları ampirik
olarak ölçülene kadar yasaklar.

- **Uygulanan ve yeşil ölçülen:** MVP-0 güvenlik çekirdeği — kasa + MCP sunucusu + aracılı izinler
  + damıtma + denetim hash-zinciri. 7 `AUTHZ-*` kaleminin tamamı PASS (C5/C7/C8 ve `127.0.0.1`
  bağlanma denetimi dahil), 3 `AUDIT-*` zincir/kurcalama kalemi PASS, 5 `CRYPTO-*` kalemi PASS,
  2 `FUZZ-*` kalemi PASS, bağımlılık denetimi 0 açıklı bağımlılık raporluyor.
- **Takım artık tamamen yeşil, ve asıl dikkatli olunacak an burası.** Sarı hiçbir şey kalmadı:
  13 Bandit MEDIUM bulgusu kaynak okunarak tek tek incelendi, her birinin gerekçesi
  `tools/security_bench/bandit_triage.json` içinde yazılı. Dördü SQL enjeksiyonu diye
  işaretlenmişti; enterpole edilen tek şey `?` yer tutucuları olduğu için gerçek `forget()`
  yolunu dört SQL yüküyle süren bir **negatif kontrol** yazıldı — tablolar ayakta kalıyor; ve
  `forget()`'in kör bir no-op olmadığını gösteren pozitif kontrol de yanında
  (`tests/test_bandit_triage.py`). Beşi ise URL'si config/env'den gelen `urlopen` çağrıları;
  bu **"güvenli" değil** — düşman sınıfı A4, tasarımla kapsam dışı, ve temiz kâğıt olarak
  değil **kabul edilen kalıntı** olarak kayda geçti.
- **O takımdaki bir sayı yazı-turaydı ve bunu açıkça söylemek gerekiyor.** `SCAN-SECRETS`,
  tezgâhın *kendi* bir önceki raporunu tarıyor; o raporun `config_hash` parmak izi yapılandırma
  her değiştiğinde değişiyor. 2026-08-05'te ölçüldü: kod ve depo birebir aynıyken yalnızca bu
  değer `f8b97a921348` → `7ec93e4833a5` olduğunda hüküm **1 FAIL** → **0 FAIL**'e döndü; biri
  entropi eşiğini geçiyor, öteki geçmiyor. Artık deterministik olarak sabitlendi ve iki yönü
  birden tutan bir test var (`tests/test_secret_scan_allowlist.py`). Rengi rastgele bir parmak
  izine bağlı olan yeşil bir kontrol zaten ölçüm değildi.
- **Adı konmuş açık boşluklar**, ölçümü `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` içinde:
  (a) *2026-08-05'te kapatıldı* — kimlik artık token'a bağlı ve aynı kök nedenden doğan
  hız-sınırı baypası da onunla gitti (§4.1 geçersizleşti; kanıt
  `_orch/redteam/fimp_live_verify.py`); (b) **çıkış (egress) ne kısıtlanıyor ne ölçülüyor** —
  `docs/GUVENLIK_CIKIS_PLANI.md` planı kurulmadı (§4.4); (c) at-rest şifreleme **üç kolonu kapsayan
  hücre bazlı** şifrelemedir, tam-veritabanı değil — metadata kolonları düz metin kalır (§1 ve
  `docs/adr/0003-at-rest-sifreleme-boslugu.md`).
- **Komut enjeksiyonu — dürüst çerçeve:** tüm sektörde hâlâ açık bir problem sınıfıdır.
  KASA'nın savunması *yapısaldır* (model asla güvenlik sınırı değildir; izin kapısı sıradan,
  deterministik koddur), bir dokunulmazlık iddiası değil.
- Tarayıcı uzantısı, web eylemleri (A1-A3), bulut maskeleme/yükseltme ve parmak izi sahteleme
  katmanı ertelendi / park edildi (MVP-0 kapsamı dışında).

Test test ayrıntı — ve her iddianın neyi kanıtlaMAdığı — burada:
[`SECURITY_TESTS_TR.md`](SECURITY_TESTS_TR.md).

## Lisans

KASA **çift lisanslıdır**:

- **AGPL-3.0** — bireysel, eğitim ve araştırma kullanımı için, ayrıca türev çalışmayı aynı koşullarla
  açık tutan her kullanım için serbesttir. Kanonik lisans metni: [`LICENSE`](LICENSE).
- **Ticari lisans** — türev çalışmasını AGPL altında yayımlamak istemeyen kurumlar içindir.
  Koşullar: [`COMMERCIAL.md`](COMMERCIAL.md).

Yazara atıf, her iki seçenekte de projede kalır.
