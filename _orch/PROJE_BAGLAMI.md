# KASA — Proje Bağlamı (tek girişli devralma belgesi)

**Amaç:** Bağlamı sıfırlanmış bir kişi (ya da model) bu **tek** dosyayı okuyup projeyi devralabilsin.
"Neyi biliyorum, neyi bilmiyorum, nereye bakarım, ne bekliyor" sorularının cevabı.

> **Bu belge bir HARİTA, ikinci bir kopya değil.** Ayrıntıyı burada tutmuyorum — kanonik kaynağı
> adıyla gösteriyorum. Bu projede tam da bunun tersi bir gün boyunca yanlış hüküm yaydı: aynı olgu
> iki yerde tutuldu, biri bayatladı. Bir sayı ya da hüküm gördüğünde **işaret ettiğim dosyaya git**,
> bana güvenme.

**Kanonik kaynaklar (tek doğruluk yeri):**

| Konu | Kaynak |
|---|---|
| 30 ölçüm, her biri seviye/kontrol/sınır ile | [`archive/measurements.json`](archive/measurements.json) |
| Her iddia için komut + "neyi GÖSTERMEDİĞİ" | [`../docs/REPRODUCE.md`](../docs/REPRODUCE.md) |
| Aşama panosu + "Geri dönüp bakma" | [`IS_HATTI.md`](IS_HATTI.md) |
| Açık/kapalı bulgular, tehdit modeli, bildirim politikası | [`../SECURITY.md`](../SECURITY.md) |
| Çalışma kuralları (ölçüm disiplini dahil) | [`../CLAUDE.md`](../CLAUDE.md) |
| Tezgahın göremedikleri | [`../docs/SECURITY_BENCH_LIMITS.md`](../docs/SECURITY_BENCH_LIMITS.md) |
| Düşman sınıfları, at-rest kararı | [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) |
| Çalışma tarzı hafızası (proje değil, tarz) | [`KORTEX.md`](KORTEX.md) |

---

## 1. Bir cümlede ne

**KASA**, Windows'ta çalışan, yerel-öncelikli, şifreli, kullanıcıya ait bir **ajan hafıza kasası**;
bu kasayı herhangi bir ajana **izin-brokerli MCP sunucusu** (loopback) üzerinden açar. İlke:
*"Ajanlar gelir gider; hafızan senindir."*

**Ne DEĞİLDİR:** üretime hazır bir ürün değil — **v0.1 araştırma önizlemesi / güvenlik mimarisi
gösterimi** ([`../README.md`](../README.md) başlık uyarısı). Tam-dosya şifreleme, egress kontrolü,
bağımsız güvenlik denetimi **yok** ve bunlar açıkça yazılı. Asıl IP ürün değil, **ölçüm
disiplini**: yayımlanan her iddianın arkasında koşan bir komut var.

---

## 2. Bugünkü ölçülmüş durum

| Kalem | Değer | Kaynak / seviye |
|---|---|---|
| Dal | `security/faz-0-3-owner-scope-hardening` | `git branch` (RAN-LIVE) |
| HEAD | `9902ac8` (F-DISTILL-PLAINTEXT commit'i) | `git log` (RAN-LIVE) |
| Çalışma ağacı | 2 değişik (`src/mcp_server/tools.py`, `src/vault/schema.py`), 2 takipsiz (`_orch/KORTEX.md`, `src/distill/sensory_filter.py`) | `git status` (RAN-LIVE) |
| Test paketi | **323 passed, 1 xfailed** (2026-08-05) | [`../docs/REPRODUCE.md`](../docs/REPRODUCE.md) — **DOCUMENTED**, bu belgede koşulmadı; depoda 51 test dosyası var |
| Güvenlik tezgahı | **21 kontrol · 21 PASS / 0 FAIL / 0 WARN**, damga *YAYIN-ADAYI*, commit `5a703cd`, 2026-08-05 17:51 | [`../docs/security_bench_result.json`](../docs/security_bench_result.json) (makine kaydı) |
| PR durumu | PR #2, ~78 dosya, sahip birleştirme kararı bekliyor | [`KORTEX.md`](KORTEX.md) — **DOCUMENTED**; GitHub'a canlı sorulmadı |

**İki uyarı — bunları saklamıyorum:**

1. ~~**Tezgah sayısı belgeler arası ÇELİŞİYOR.**~~ — **ÇÖZÜLDÜ 2026-08-05 18:40, aynı gün.**
   Bu belge yazılırken makine kaydı (`security_bench_result.json`, commit `5a703cd`)
   **21 PASS / 0 WARN** diyordu, ama `docs/REPRODUCE.md` ve `IS_HATTI.md` hâlâ
   **20 PASS / 1 WARN** yazıyordu — Bandit triyajı sonrası ikisi güncellenmemişti. Bu belgenin
   yazımı sırasında yakalandı ve iki dosya da makine kaydına eşitlendi. **Kanonik olan her zaman
   makine JSON'udur**; bir metin onunla çelişiyorsa metin yanlıştır.
2. **"YAYIN-ADAYI" tezgahın kelimesidir, projenin durumu değildir.** Dar bir takımda hiçbir kontrol
   kalmıyor demektir — oysa F-POISON açık ve o takımda onu ölçen **tek bir kontrol yok**
   ([`../docs/SECURITY_BENCH_LIMITS.md`](../docs/SECURITY_BENCH_LIMITS.md)).

---

## 3. Mimari — `src/` altındaki paketler

Her satır bir paket; dosya:satır kanıtı verebildiğim yerde verdim. Ayrıntı için ilgili modülü aç.

| Paket / dosya | Ne yapar |
|---|---|
| `src/vault/database.py` | SQLite bağlantısı + `Vault` sınıfı; **dosya şifrelenmez**, anahtar DPAPI ile korunur |
| `src/vault/cell_crypt.py` | Hücre-başı AES-256-GCM at-rest şifreleme (L2); ciphertext base64 + `K1:` öneki, AAD-bağlı |
| `src/vault/schema.py` | Tablo şeması: `events`, `profile`, `permissions`, `audit`, `profile_quarantine` |
| `src/vault/audit.py` | Hash-zincirli denetim kaydı (her satır öncekinin SHA-256'sı); üretimde Ed25519 imza |
| `src/vault/redact.py` | Okuma yolu içerik kapısı; izinli namespace'e gizlenmiş sır/anahtarı `[REDACTED]` yapar |
| `src/vault/quarantine.py` | Deterministik yapısal karantina bayrağı; **iki yazma yolunca da** paylaşılır |
| `src/mcp_server/server.py` | MCP HTTP sunucusu (loopback), bearer auth, `resolve_agent` (kimlik token'dan çözülür, `:240`), `_bound_identity` (uyuşmazsa 403, `:308`), `require_owner` (`:285`), `PUBLIC_TOOLS` allow-list (`:77`) |
| `src/mcp_server/tools.py` | `VaultTools` — gerçek DB operasyonları; `_check_permission` izin brokeri burada |
| `src/mcp_server/ratelimit.py` | Ajan-başı token-bucket hız sınırı; **bağlı** kimliğe göre anahtarlanır (üst sınır + LRU tahliye) |
| `src/agent/gate.py` | Ajan köprüsünün deterministik kapısı — EL YAZISI güvenlik carve-out'u; yerel model bunu düzenlemez |
| `src/agent/harness.py` | Seçili yerel modeli (127.0.0.1:11434) salt-okunur maskeli dashboard'a karşı sınırlı araç-döngüsünde sürer |
| `src/agent/store.py` · `routes.py` | Ajan model seçimi kalıcılığı + FastAPI ajan uçları (owner-özel) |
| `src/distill/engine.py` | **Damıtma** — ham olayları profile dönüştürür; **süreç-içi, brokersiz** (bkz. §4) |
| `src/distill/profile_enrich.py` | Profil zenginleştirme; model `hermes3:8b` (`:30`) |
| `src/distill/sensory_filter.py` · `scheduler.py` | Duyusal filtre + zamanlama (takipsiz/yeni) |
| `src/dashboard/routes.py` · `stats.py` · `auditor.py` | Salt-okunur pano; bearer korumalı GET uçları; ikinci paralel API kurmaz |
| `src/mcp_adapter/proxy.py` · `__main__.py` | MCP istemcilerini (Claude Code vb.) stdio ile sunucuya bağlar; ayrıcalıklı yol tutmaz |
| `src/browser/browser_window.py` | KASA tarayıcısı (pywebview) — **varsayılan KAPALI** (bkz. §5) |
| `src/tray/app.py` | Sistem tepsisi (PyQt5) |
| `src/desktop/launch.py` · `preflight.py` · `picker.py` | Masaüstü launcher (pywebview pencere) + ön-kontrol |
| `src/export/encrypt.py` | Şifreli taşınabilir `.kasa` dışa aktarımı + doğrulama |
| `src/config.py` · `consent.py` | Config (`kasa.toml`) + bearer çözücü (`resolve_bearer_token`) · kullanım şartları onayı |

---

## 4. Yazma yolları haritası — hafızaya ULAŞAN yollar ve her birinin neyle kapalı olduğu

Kanonik envanter: [`redteam/door_inventory_result.json`](redteam/door_inventory_result.json)
(23 rota, `app.routes`'tan **programatik** çıkarıldı, 3 kimlik-bilgisi profiliyle denendi) ve
[`../docs/REPRODUCE.md`](../docs/REPRODUCE.md) "Door inventory" satırı.

| Yol | Broker'dan geçer mi | Kapı | Kanıt |
|---|---|---|---|
| `POST /v1/execute_tool`, `/v1/ingest` (ağ ajanı) | **Evet** | Token yoksa 401, yetkisiz ajan token'ı 403 (deny-by-default) | vault'a değen **9** rotanın tümü 401/403; `door_inventory_result.json` |
| Owner-özel uçlar (`/v1/dashboard/*`, `/v1/agent/*`, `/v1/terms/*`) | `require_owner` | Ajan token'ı 403, sahip bearer'i 200 | pozitif+negatif kontrol aynı ölçümde |
| **Damıtıcı** (`src/distill/engine.py`) | **HAYIR** | — | **kritik, aşağıda** |

### ⚠️ Damıtıcı izin brokerinden GEÇMEZ ve `profile.value`'yu düz metin yazar

Bu belgenin en önemli tek maddesi. Damıtıcı bir **ağ rotası değildir**: süreç-içi çalışır, kendi
`sqlite3` bağlantısıyla `events` okur ve doğrudan `INSERT OR REPLACE INTO profile ...` yapar
(`src/distill/engine.py:265-268`). Sonuç: brokerli yolun uyguladığı **iki** kontrolü birden atlar.

1. **Yetkilendirme baypası** — `VaultTools._check_permission`'a hiç uğramaz
   (`door_inventory_result.json` → `not_a_network_route`).
2. **At-rest şifreleme baypası (F-DISTILL-PLAINTEXT, AÇIK)** — aynı sır iki yolla yazıldığında:

   | Yol | Diskteki `profile.value` |
   |---|---|
   | `VaultTools.profile_write()` (brokerli) | `K1:+4xIpuvtvr+nlTCo…` — **şifreli** |
   | `DistillEngine.run_batch()` (damıtıcı) | `{"text": "hunter2", …}` — **DÜZ METİN** |

   Yeniden bağlanma şifrelemiyor, `VACUUM`'a dayanıyor → **canlı kolon**, silinmiş-sayfa artığı değil.
   Repro (pozitif kontrol dahil): [`redteam/distill_crypto_bypass.py`](redteam/distill_crypto_bypass.py),
   kayıt [`archive/measurements.json`](archive/measurements.json) → `F-DISTILL-PLAINTEXT`.
   **Aktör:** A1 (prompt-zehirli model) için dolaylı — düz metin içeriği **saldırgan-yazımlı ve
   uzaktan** gelir: ziyaret edilen sayfa neyin şifresiz yazılacağına karar verir.

> Uyarı (bayatlama tuzağı): [`../README.md`](../README.md) ve [`../SECURITY.md`](../SECURITY.md)
> bir süre "üç kolon şifreli" iddiasını **koşulsuz** yazdı. Doğru: bu **yalnız brokerli yolda**
> doğru. Değerlerin çoğu damıtıcıdan geldiği için pratikte önemli bir sızıntıdır.

---

## 5. Bulgular

### Açık (kısa liste — her biri bir satır + nereye bakılacağı)

| Bulgu | Aktör | Seviye | Nereye |
|---|---|---|---|
| **F-POISON** — ad-uzayına uyan uydurma her deterministik kapıyı geçip canlı profile yazılıyor (kasa-agent:8b: uyumlu **7/10**, naif **0/10**). Yapısal çözüm YOK | A1 | RAN-LIVE | [`../SECURITY.md`](../SECURITY.md) §7; `redteam/poison_reproduce.py` |
| **F-DISTILL-PLAINTEXT** — damıtıcı `profile.value`'yu düz metin yazar (bkz. §4) | A1/A3 | RAN-LIVE | `redteam/distill_crypto_bypass.py` |
| **Tarayıcı köprü izolasyonu** — pywebview `js_api` köprüsü ziyaret edilen sayfanın JS bağlamında; tarayıcı bu yüzden KAPALI | A3 | CODE-STRUCTURE | [`../SECURITY.md`](../SECURITY.md) "Known-unsafe surfaces". **Çalışan sömürü yazılmadı** |
| **Egress kontrolü yok** — çıkış ne kontrol ne gözlem | — | DOCUMENTED | `docs/GUVENLIK_CIKIS_PLANI.md` (kurulmadı) |
| **At-rest kısmi** — yalnız 3 kolon şifreli; metadata (timestamp, `profile.key`, `agent_id`, TTL, hash-zinciri) düz metin | B/C | DOCUMENTED | `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §1 |
| **13 Bandit MEDIUM** — triyaj edildi (9 yanlış-pozitif, 5 kabul edilen rezidüel A4), ama açık backlog | A4 | RAN-LIVE | `tools/security_bench/bandit_triage.json` |

### Kapalı (kanıtıyla — ayrı kısa liste)

| Bulgu | Kanıt |
|---|---|
| **F-IMP** — `agent_id` artık token'dan çözülür; ölçülmüş taklit 403 (önce 200), pozitif kontrol de tutuyor (bağlı token kendisi olarak 200). 7/7 canlı | [`redteam/fimp_live_verify.py`](redteam/fimp_live_verify.py) |
| **Hız-sınırı baypası** (aynı kök neden) — dönen kimlikle 300 istek → 240×429 (önce 150'de 0) | aynı script, satır `R1` |
| **F-MCP-OWNER-BEARER** — adaptör artık ajan-bağlı token sunabiliyor (`KASA_MCP_TOKEN`); ajan token'ı owner ucunda 403 | `tests/test_mcp_adapter_wiring.py`; MCP Inspector |
| **Denetim zinciri bütünlüğü** — tahrif + silme tespiti | tezgah `AUDIT-*` |
| **Deny-by-default yetkilendirme** — yetkisiz read/write/forget/audit/prune hepsi reddeder | `redteam/live_mcp_attack.py` |

> **Kapalı ≠ çözüldü:** F-IMP kimliği *token*'a bağlar — gücü token gizliliği kadar; vault dosyasını
> okuyan aynı-OS saldırganı token üretebilir (A4, tasarımla kapsam dışı). Doğru atıf, yazılanın
> **doğru** olduğunu göstermez — oraya F-POISON bakar.

### Tarayıcı — neden KAPALI

`open_browser()`, `KASA_ENABLE_BROWSER=1` yokken **hiçbir yan etki oluşmadan** reddeder
(`tests/test_browser_optin_gate.py`, negatif+pozitif kontrol). Sebep: `js_api=` köprüsü **sayfa
başına**, origin başına değil — sayfanın kendi betikleri `window.pywebview.api.set_proxy()` /
`ingest()` çağırabilir. Kapı yüzeyi kapatır, **kusuru düzeltmez**; düzgün çözüm mimari (ayrıcalıklı
arayüzü sayfa bağlamının dışına almak), yol haritasında.

---

## 6. Ölçüm disiplini (özet — tam metin [`../CLAUDE.md`](../CLAUDE.md), YENİDEN YAZMA)

- **Seviye etiketi zorunlu:** `RAN-LIVE` (koşuldu) / `CODE-STRUCTURE` (okundu) / `DOCUMENTED`
  (birincil kaynaktan). **Yaptığının bir seviye üstünü asla raporlama.**
- **Pozitif VE negatif kontrol her iddiada.** Her şeyi reddeden kapı bütün negatif testleri geçer;
  ayırt ettiğini ancak ikisi birlikte gösterir.
- **`errors` boş değilse hüküm YAZILMAZ.** (HTTP 405 alıp boş profille "savunma tuttu" sanan koşum
  bedelle öğretti.)
- **found → proved → closed:** canlı kanıt olmadan "düzeltildi" yok; repro olmadan "açık" yok.
- **Üç durum ayrıdır: bulundu / bulunamadı / BAKILAMADI.** Üçüncüyü ikinciye katan her satır sahte-PASS üretir.
- **Aktör etiketi zorunlu:** A1 prompt-zehirli model · A2 kötücül araç · A3 ziyaret edilen sayfa ·
  A4 aynı-OS kullanıcı (genelde KAPSAM DIŞI, açıkça belirt).

---

## 7. Bilinen ortam tuzakları (tam liste [`KORTEX.md`](KORTEX.md) §2)

- **Çıplak `python` çalışmaz** → Microsoft Store saplaması, **çıkış kodu 9009**. Gerçek- Python sürümü ve yolu: `pythoncore-3.14-64\python.exe`
- **Test daima izole vault** (`KASA_VAULT_PATH` ayrı dizin); gerçek vault'a dokunma. Alt-ajana bu
  kısıtı **açıkça** yaz — kural kendiliğinden geçmiyor (bir alt-ajan gerçek vault'u sorguladı).
- **PID öldürme yok** — sahibin süreçleri koşuyor (openclaw, streamlit, ComfyUI, uvicorn); komut
  satırını doğrulamadan dokunma.
- **Windows/DPAPI bağımlılığı** — anahtar koruması DPAPI; macOS/Linux'ta DPAPI no-op → o koruma yok.
- **Python 3.12 pini** — `requires-python = ">=3.12,<3.13"`. Alt sınır ölçüldü (3.14'te pywebview
  penceresi SEGFAULT, `docs/EXE_PACKAGING_LOG.md`); **üst sınır bir ÖLÇÜM değil, tercih**. Testler ve
  tezgah **3.14.5** altında koştu; masaüstü/exe yolu 3.12 dayatır.
- Konsol cp1254 → betik başında `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`.

---

## 8. Bekleyen kararlar (kanonik: [`IS_HATTI.md`](IS_HATTI.md) §4 + [`KORTEX.md`](KORTEX.md) §6)

Hepsi **sahip kararı** — yayın düğmesi onda; push/merge/gönderim tek kelime bekler.

1. **PR #2 birleştirme** — ~78 dosya, güvenlik yüzeyi; buton bizde değil.
2. **F-DISTILL-PLAINTEXT düzeltmesi** — damıtıcı yazımını şifrelemek ilkece küçük, ama **mevcut düz
   metin satırlar göç (migration) gerektiriyor** → sahip kararı.
3. **D1 — ad-uzayı politikası** (F-POISON): belgele / destek kontrolü uygula / karantina.
4. **A4** — r/mcp `p0xmazq` yorumu bizim mi (bizse üçüncü taraf öncel sanat diye anılamaz).
5. **APAS yanıtı** gönderilsin mi — metin hazır, savunmanın nasıl aşılacağını tarif ediyor.
6. **`%TEMP%` anahtar setleri** silindi → **token rotasyonu** gerekir mi.
7. **Gerçek vault kopyalandı mı** — **ölçülmedi**, sınıflandırıcı engelledi ("bakamadım", "kopyalanmadı" değil).

---

## 9. `docs/PROJECT_BRIEF.md` BAYAT — düzeltme (brief'i SİLME/DEĞİŞTİRME)

[`../docs/PROJECT_BRIEF.md`](../docs/PROJECT_BRIEF.md) 2026-07-02 tarihli **tasarım devri** belgesidir
ve bugünkü kodla çelişir. Tarihsel niyet olarak değerlidir; **bugünkü gerçek değildir.**

| Brief diyor | Gerçek (kod/ölçüm) | Kanıt |
|---|---|---|
| "SQLCipher ile tam dosya şifrelemesi" (§5) | Hücre-bazlı AES-256-GCM, **3 kolon**; SQLCipher **reddedildi** | `src/vault/cell_crypt.py`; [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) "L2 AT-REST" (bu makinede SQLCipher wheel + C derleyici yok) |
| "PyQt6" (§5) | Tepside **PyQt5**; masaüstü **pywebview** | `src/tray/app.py:3`, `requirements.txt`, `src/desktop/launch.py` |
| "qwen2.5:7b" (§5) | Seçilen ajan modeli **hermes3:8b** (paketlenmiş **kasa-agent:8b**). **Dikkat:** damıtıcı ve config **defaultları hâlâ qwen2.5:7b** (`config.py:18`, `engine.py:19`) ve README kurulumu `qwen2.5:7b` pull der — kod tümüyle taşınmadı | `src/distill/profile_enrich.py:30`; ölçümler `kasa-agent:8b` |
| "MVP-0 kodlamaya başlamadı, T1-T5 bekliyor" (§10) | **Kodlanmış ve ölçülmüş** — 323 test, tezgah, red-team | [`../CHANGELOG.md`](../CHANGELOG.md) [0.1.0] |
| §2 pazar olasılıkları (%2-3, %15-20) | Bunlar **tasarımcının tahminleri**, ölçüm DEĞİL — brief §2 kendisi de "calibrated estimates, not guarantees" der | [`../docs/PROJECT_BRIEF.md`](../docs/PROJECT_BRIEF.md) §2 |

---

## 10. Bu belgenin sınırları

- **Neyi kapsamaz:** tek tek dosyaların iç mantığını, tam test listesini, MCP protokol ayrıntısını,
  öncel-sanat taramasını (F-POISON'un alan bağlamı için `docs/MODEL_BASELINE_REPORT.md` +
  `archive/measurements.json` → `MEMTXN-GAP`).
- **Ne zaman bayatlar:** dal/HEAD değişince (§2), tezgah yeniden koşunca, F-DISTILL-PLAINTEXT ya da
  F-POISON kapanınca, PR #2 birleşince. **Bu bir zaman-anı okumasıdır**; hüküm gördüğün her yerde
  kanonik kaynağa git.
- **Bu belgede hiçbir şey koşulmadı** — dosya okundu (RAN-LIVE olan tek şey `git` durumu ve grep'ler).
  Test/tezgah sayıları **DOCUMENTED** seviyesindedir, ben ölçmedim.

### Emin olamadığım / doğrulayamadığım kalemler (saklamıyorum)

Bu belgeyi yazan ajan beş kalemi doğrulayamadı ve **saklamadı, listeledi**. Beşi de aynı gün
kapatıldı; kapanışlar burada duruyor çünkü *neyin doğrulanmadan yazıldığı* da bir kayıttır.

| # | Belirsizlik | Çözüm (2026-08-05, aynı gün) |
|---|---|---|
| 1 | Tezgah sayısı çelişkisi | **Gerçek çelişkiymiş.** REPRODUCE.md + IS_HATTI.md bayattı, makine JSON'a eşitlendi → **21 PASS / 0 FAIL / 0 WARN** |
| 2 | PR #2 durumu, dosya sayısı ~78 | GitHub'a canlı soruldu: **MERGEABLE / CLEAN**, ve **87 dosya** — 78 değil, gün içindeki commit'lerle büyümüş |
| 3 | Damıtıcı modeli bölünmüş | **Ölçüldü:** `resolve_model()` → `hermes3:8b`. Ama `config.py` ve `kasa.toml` hâlâ `qwen2.5:7b` — *A1 enjeksiyon probunda düşen model*. Ayrıca **bugünkü ölçümlerin model etiketi yanlıştı**: `kasa-agent:8b` yazılmıştı, fiilen çıplak `hermes3:8b` koştu, yani **sertleştirme promptu devrede değildi**. Kayıtlar düzeltildi → `MODEL-CONFIG-GAP` |
| 4 | `origin/main..HEAD` = 29 commit | `ls-remote` ile doğrulandı |
| 5 | Ölçüm sayısı 30 mu 27 mi | JSON ayrıştırılarak sayıldı: **27** (grep iç içe `id` alanlarını da saymış). Bu belgenin yazımından sonra **28** |

**Ders:** 3 numara, kimsenin aramadığı bir bulguya dönüştü. Bir alt-ajanın *"bunu doğrulayamadım"*
demesi, doğrulamış gibi yapmasından kıyasla çok daha değerli çıktı.

---

**Yazan model:** claude-fable-5 (Fable 5) · **Tarih:** 2026-08-05 · **Kaynak dal:** `security/faz-0-3-owner-scope-hardening` @ `9902ac8`
