# KASA — Red-Team Planı (lab + sahip metodolojisi)

**Tarih:** 2026-08-03 · **Yetki:** sahibin kendi makinesi, yalnız loopback, atılabilir instance
· **İlke:** ölçülmeyen bulgu geçersiz; kapsam yazılmayan bulgu geçersiz; skor uydurulmaz.

> Bu plan iki kaynağı birleştirir: (1) diğer AI modelinin kurduğu lab (12 test, 3 açık),
> (2) sahibin saldırı metodolojisi. Sahibin yaklaşımı doğru: brute-force değil, güven
> sınırındaki **en ucuz ve en etkili zincir** önce. O zincirin ilk halkası bu oturumda
> canlı doğrulandı.

## 0. Aktör tanımları (THREAT_MODEL.md ile hizalı)

| | Aktör | Kapsam |
|---|---|---|
| **A1** | Prompt-zehirli model (yalnız araç çağrısı) | İÇERİDE |
| **A2/N** | Ağdan gelen DÜŞÜK-YETKİLİ ağ istemcisi (KASA'nın bilerek kısıtladığı token sahibi) | **İÇERİDE** |
| **A3** | Ziyaret edilen web sayfası (tarayıcı SOP/CORS ardında) | İÇERİDE |
| **A4** | Aynı OS kullanıcısı, keyfi kod (dosya/env/süreç erişimi) | **DIŞARIDA** |

Kritik ayrım: **düşük-yetkili ağ istemcisi A4 DEĞİLDİR.** KASA ona bilerek sınırlı bir
token verdi; onu owner'a yükseltmesi gerçek bir ihlaldir. Buna karşı `.vaultkey`'i okuyabilen
keyfi yerel süreç (A4) kapsam dışıdır ve onun "ihlalleri" bu planda bulgu sayılmaz.

---

## KAPANIŞ NOTU (2026-08-03, aynı gün) — F-DASH + F-OWNER-SCOPE KAPATILDI

Aşağıdaki §1 bulguları **yamandı ve canlı doğrulandı** (repo sunucusu, izole soket):

| Kontrol | Önce | Sonra |
|---|---|---|
| Tokensız `GET /dashboard` token sızdırıyor | evet (200 + token) | **hayır** (nonce'suz → tokensiz sayfa) |
| Geçerli launch nonce ile token | — | **evet** (owner launcher çalışır) |
| Yanlış nonce ile token | — | **hayır** (sabit-zaman) |
| Düşük-yetkili token owner uçları | 200 | **403** (4/4) |
| Owner bearer owner ucu | 200 | **200** (kilitlenmedi) |
| Tam zincir (sıfır kimlik → owner) | tam kontrol | **token çıkarılamıyor → kırık** |

**Nasıl:** (a) owner UI token'ı HTML'e yalnızca `launch.py`'nin ürettiği per-süreç nonce
ile gömülür (`?k=`); (b) owner uçları `verify_token` yerine `require_owner` (sabit-zamanlı
`_BEARER_TOKEN` denetimi) kullanır. Regresyon: `tests/test_owner_surface_authz.py` (7 pin
KIRMIZI→YEŞİL + 3 pozitif kontrol). Defense-in-depth: `proxy.py` loopback kontrolü
`startswith` yerine `urlparse().hostname` tam-eşleşme (`tests/test_loopback_url_guard.py`).

> **Mühür bekliyor:** güvenlik-kritik yol; KURALLAR gereği sahibin incelemesi ve mührü
> gerekiyor. Yerel commit atıldı, public'e itilmedi.

---

## 1. KANITLANMIŞ zincir (ÇALIŞTIRILDI) — en yüksek öncelik

### F-DASH: Tokensız `/dashboard` owner token'ı sızdırıyor
**Ölçüm (2026-08-03, tek GET):**
```
GET http://127.0.0.1:8780/dashboard   (Authorization YOK)
-> HTTP 200,  gövdede: I8E_GnsPeDJuyIUHxX6OSwTMrZT715_UJBfrOIgkq7U
```
`dashboard_index` (`dashboard/routes.py:93`) ve `terms_index` (`:117`) fonksiyonlarında
`Security(verify_token)` **yoktur**. HTML'e owner bearer token gömülüdür (`:95`, `:119`).

**Etki:** 8780'e soket açabilen ve HTTP okuyabilen **her istemci** owner token'ı alır ve
her `verify_token`'lı uca yükselir. Bu, bu turda kurulan kimlik bağlamayı A2/N için
büyük ölçüde **etkisiz** kılar — kapı kilitli ama pencere açık.

**Kapsam ayrımı — dürüst:**
- **A2/N (düşük-yetkili ağ istemcisi):** tarayıcı değil, SOP yok → GET okur, token alır →
  **GERÇEK YÜKSELME, kapsam içi.** Lab bunu ilk aşamada doğruladı.
- **A3 (kötü web sayfası):** `fetch` çapraz-köken **gövdeyi okuyamaz** (CORS allow_origins
  yalnız localhost). Yani tarayıcıdan token çekmek CORS/SOP ile **engelli**. F-DASH esasen
  A2/N bulgusudur, A3 değil.
- **A4:** zaten owner token'a eşdeğer erişimi var; onun için yeni bir şey değil.

**Düzeltme:** `/dashboard` ve `/terms` GET route'larına owner-yetki kapısı. Owner UI'nin
token'a bearer'sız ihtiyacı var (sayfa localhost'ta yükleniyor) — bu bir tavuk-yumurta.
Çözüm seçenekleri (İş F-DASH'te kararlaştırılacak): (a) UI'yi ayrı bir owner-only
loopback porta/sürece taşı; (b) token'ı HTML'e gömmek yerine ilk-yükte tek-kullanımlık
kısa-ömürlü bir el-sıkışma ile ver; (c) UI route'larını yalnız `127.0.0.1` + owner-session
çerezine bağla. **Karar sahibin.**

### F-OWNER-SCOPE: owner uçları kapsam kapısının arkasında değil
**Ölçüm (lab T7/T8/T9):** düşük-yetkili `lab-agent` token'ı ile
`/v1/dashboard/profile`, model-yönetimi (agent bridge), `/v1/terms/status` → beklenen 403,
gelen **200**. Bu uçlar yalnız `verify_token` (herhangi geçerli bearer) istiyor, **kapsam
denetimi yok** (`dashboard/routes.py:58-90` hepsi `Security(verify_token)`, scope yok).

**Etki:** F-DASH olmasa bile, geçerli herhangi bir bearer (legacy dahil) tüm owner
dashboard/audit/terms uçlarına erişir. Kimlik doğru bağlanıyor ama **yetki kapısı bu
uçlarda hiç yok.**

---

## 2. KAPSAM-İÇİ, HENÜZ ÖLÇÜLMEDİ — matris çıkar

### İş M1: Owner-yüzeyi yetki matrisi
Düşük-yetkili token ile **her** owner ucu: dashboard stats/events/profile, audit çalıştır
(`/v1/dashboard/audit/run`), audit rapor/indir (`/v1/dashboard/audit/report`), model
değiştir (agent bridge), chat/race (`agent/routes.py`), terms status/accept. Her uç için
beklenen 403, gelen cevap **birebir** kaydedilir. Çıktı: tarihli matris belgesi.

### İş T1: Token yaşam döngüsü (kapsam içi kısım)
- İptal edilen token tekrar kullanma → 401 olmalı (bugün: `revoked_at IS NULL` filtresi var,
  **test edilmeli**).
- Aynı kimliğe iki etkin token → `cmd_issue_token` öncekini DELETE+revoke ediyor
  (`grant_agent_scope.py:123-127`); "bir kimlik = bir etkin token" değişmezi **test edilmeli**.
- Token sızıntısı: HTML (F-DASH ile **kanıtlandı**), log, hata mesajı/traceback. Log ve
  500-gövdesi sızıntısı ayrıca ölçülür (500-sızıntı testi zaten var; genişlet).
- **Legacy token'ın son-kullanma/kill-switch'i yok** → gerçek tasarım boşluğu. Kapsam içi.

### İş U1: `startswith` loopback bypass (defense-in-depth)
`proxy.py:41` `base_url.startswith(("http://127.0.0.1","http://localhost"))`.
`http://127.0.0.1.evil.example` ve `http://127.0.0.1@evil.example` **geçer**.
`base_url` config/env'den (`KASA_SERVER_URL`) gelir → sömürü A4-kapılı; **ama kontrol
yanlış** ve kod "air-gap" iddia ediyor. Düzeltme: `urllib.parse` ile ayrıştır, `hostname`
tam eşleşme (`in {"127.0.0.1","localhost","::1"}`), userinfo/port ayrı doğrula. İki
satır yukarıdaki `host not in (...)` zaten doğru yöntemi kullanıyor — tutarlılık.

### İş K1: `_lookup_bound_agent` fail-closed
`server.py:184` "no such table" → `None` → legacy yoluna düşer. Güvenlik yolu "emin
olamıyorum"da **fail-closed** olmalı. Düzeltme: tablo-yok halini de 503'e çevir (ya da:
legacy yolu YALNIZ tablo gerçekten hiç kurulmamışsa — bunu başlangıçta bir kez ölç, her
istekte değil). Not: sömürü (tabloyu sildirmek) A4 gerektirir, ama **varsayılan yanlış**.

---

## 3. A4 / KAPSAM DIŞI — belgele, kovalama (bulgu sayma)

Bunlar THREAT_MODEL.md'nin A sınıfıdır: aynı OS kullanıcısı `.vaultkey`'i, config'i, env'i,
süreç tablosunu zaten okur/yazar. "Açık" diye raporlamak sahte-bulgudur. Yine de
**footgun sertleştirmesi** olarak değerlendirilir:

- `agent_tokens` tablosunu boz/kaybet, DB yolunu (`KASA_VAULT_PATH`) yönlendir, yeni/boş
  DB'ye downgrade → hepsi **A4** (DB/env yazımı gerekir). K1 varsayılanı yine de düzeltilir.
- DB kilidi → kodum **zaten fail-closed** (503); yalnız "no such table" düşüyordu (K1).
- Token'ın süreç komut satırı / terminal sızıntısı → **A4** (süreç tablosu okuma).
- `KASA_LEGACY_AGENT_ID=browser` ile ayrıcalık → env yazımı = **A4**; ayrıca legacy kimlik
  varsayılan-red, otomatik-kapsamı yok (auto-grant satırı yalnız "browser"a BAĞLI token
  üretilirse anlamlı). Yine de dokümante edilir.
- **Sunucunun `0.0.0.0`'a bağlanması:** config `host` `0.0.0.0` olursa LAN'a açılır. Config
  A4, ama gerçek footgun → `start_server`/`launch` içinde loopback dışı host'a **başlangıçta
  reddet** guard'ı (ucuz, yüksek değer).

### DNS rebinding / Host başlığı / IPv6 — hızlı ölçüm, muhtemelen düşük
- **DNS rebinding:** tarayıcıyı hedefler; rebound sayfa localhost'a `fetch` atar ama F-DASH
  gövdesini CORS okutmaz. Owner token'ı rebinding ile çekmek A3 → CORS engeli. Yine de
  **Host-başlığı doğrulaması** eklemek ucuz sertleştirme (FastAPI Host'u varsayılan
  doğrulamaz). Ölç: sahte `Host: evil.example` ile owner uçları farklı davranıyor mu (hayır
  beklenir; teyit).
- **CORS'un güvenlik sınırı sanılması:** CORS bir **okuma** sınırıdır, yetki değil. F1
  (evil origin yansıtılmıyor) zaten yeşil; ama planda CORS'a "kapsam kapısı" muamelesi
  yapılmadığı açıkça yazılır. F-OWNER-SCOPE tam da CORS'un yetki olmadığını gösteriyor.

---

## 4. SIRALAMA (etki × kapsam-içilik)

1. **F-DASH** — zincirin ilk halkası; kapatılmadan diğer kimlik işi A2/N için havada.
2. **F-OWNER-SCOPE + M1** — owner uçlarına kapsam kapısı + tam matris.
3. **T1** — token yaşam döngüsü testleri (regresyon zırhı).
4. **U1, K1** — defense-in-depth (sömürü A4-kapılı ama kod yanlış iddia ediyor).
5. **0.0.0.0 guard + Host-header ölçümü** — ucuz footgun sertleştirmeleri.
6. Damıtma güvenlik kalemleri (ayrı belge: CREDENTIAL_DENY anahtar, denetim, n≥20).

## 5. DÜRÜST SINIR

Bu plan A2/N ve A3 için güven sınırını sertleştirir. A4'ü **kapatmaz ve kapatmayı
hedeflemez** — o kapsam dışıdır ve öyle kalır. En büyük tek kazanç F-DASH: onu kapatmak,
bu oturumda kurduğum kimlik bağlamayı gerçekten anlamlı kılan şeydir. Lab ve sahip,
benim tam-aracılık belgemin "owner yüzeyi kapsam kapısının arkasında değil" satırını
bağımsız olarak canlı kanıtladı — bu, belgenin doğru olduğunun kanıtı, ama aynı zamanda
işin bitmediğinin.
