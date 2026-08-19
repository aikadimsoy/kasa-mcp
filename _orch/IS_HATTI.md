# İş hattı / Work Pipeline — 2026-08-05

**Amaç:** hiçbir iş denetimsiz koşmasın, durum bağlamda değil **dosyada** dursun, her aşamanın
arıza planı olsun.
**Purpose:** nothing runs unsupervised, state lives in **files** not in context, every stage has a
failure plan.

---

## 0. Neden bu belge var / Why this exists

Bu oturumda üç ayrı arıza sınıfı yaşandı ve üçü de sessizdi:

| Yaşanan | Nasıl fark edildi | Ders |
|---|---|---|
| Delege edilen ajan API yüklenmesinden düştü (**3 kez**) | Bildirim geldi | Ajan güvenilir bir kanal değil; küçük iş delege edilmez |
| Test koşumu HTTP 405 aldı, profil boş kaldı → **savunma tutmuş gibi göründü** | `errors` alanı okundu | Boş sonuç, başarılı savunmadan ayırt edilemez |
| Ölçtüğüm dosya ölçüm sırasında **büyüdü** (commit `e3211ee`, +6 test) | Sayı tutmadı, git'e bakıldı | Ölçülen şey ölçülürken değişebilir |
| 12 ajanlık sentez "en değerli bulgunuz" dedi, **yanlış okumaydı** | Birincil kaynak açıldı | Sentez birincil kaynağın yerine geçmez |

Hepsinin ortak yanı: **sessiz başarısızlık.** Hiçbiri hata vermedi, hepsi başarı gibi göründü.

---

## 1. Durum panosu / State board

Her aşama şu dördü taşır: **önkoşul · eylem · başarı ölçütü · arıza planı**.

### AŞAMA 0 — Hijyen (yinelenen)

| | |
|---|---|
| **Önkoşul** | — |
| **Eylem** | Test portları (8000-8005) boş mu, `d:\kasa`'dan koşan artık süreç var mı |
| **Başarı** | Sıfır dinleyici, sıfır artık |
| **Arıza** | Varsa PID'i **komut satırıyla doğrula**, sahibininkiyse dokunma |
| **Durum** | ✅ 2026-08-05 temiz — 6 süreç var, hepsi sahibin (openclaw, streamlit×2, ComfyUI, uvicorn×2) |

Komut:
```powershell
foreach ($p in 8000..8005) { Get-NetTCPConnection -LocalPort $p -State Listen -EA SilentlyContinue }
Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Select ProcessId, CommandLine
```

---

### AŞAMA 1 — Koşulsuz ölçümler (4 iş, bağımsız)

Hiçbiri ajan cevabına bağlı değil. **Bunlar yapılmadan hiçbir sayı savunulamaz.**

| # | İş | Başarı ölçütü | Arıza planı |
|---|---|---|---|
| **B1** | 20/20'yi önceden var olan meşru hafızayla yeniden koş | Sayı ya ayakta kalır ya düşer; **ikisi de yayımlanabilir** | `errors` boş değilse **hüküm okunmaz** |
| **B2** | Notlamaya başka-sözcük (paraphrase) koşulu ekle | Kopyalama mı inanç mı olduğu ayrışır | İmleç enjekte metinde geçiyorsa test geçersiz |
| **B3** | İyi niyetli yazmaların geçiş oranını ölç | Çalışma noktası çıkar | Masum vaka seti yoksa önce o kurulur |
| **C1** | Yük çifti + tam kapı izini yayımlanabilir esere çevir | **Yabancı 10 dakikada tekrarlar** | Tekrarlanamıyorsa eser değil, anekdot |

**Her koşumda kaydedilecek:** git SHA, model etiketi, tarih, `errors` alanı, ham model çıktısı.
Bunlar olmadan ölçüm tekrar edilemez.

---

### AŞAMA 2 — Savunma değerlendirmesi (tıkalı)

| | |
|---|---|
| **Soru** | MemTxn'in Ordered PatchTest'i ve OWASP Agent Memory Guard **bizim yükümüzü** yakalıyor mu |
| **Önkoşul** | İki belgenin tam metni |
| **Durum** | 🔴 **TIKALI** — Fable 5 ajanı 3 kez API 529'dan düştü |
| **Arıza planı** | **Kendim okurum.** İki belge, delege etmeye değmez. Ajan denemesi en fazla 1 kez daha. |

**Neden önemli:** yakalıyorsa hamlemiz saldırmak değil, *yayımlanmış bir savunmayı yerel-öncelikli
zeminde 7-8B modellerle uygulayıp ölçmek* olur — bunu kimse yapmadı. **Yakalaması iyi haber.**

---

### AŞAMA 3 — Kayıt düzeltmesi (Aşama 1'den sonra)

Yayımladığımız arşiv, özgünlük denetiminin çürüttüğü iddialar taşıyor.

| Dosya | Düzeltilecek |
|---|---|
| `docs/KNOWLEDGE_ARCHIVE.md` | Fikir #11 → C2PA §7.2 ve Clark-Wilson'a atfedilmeli |
| `SECURITY.md` | F-POISON → alan bağlamı + "replikasyon + artım" çerçevesi |
| İkisi de | F-POISON'un öncel sanatı yokmuş gibi okunduğu her yer |

**Neden Aşama 1'den sonra:** sayılar kesinleşmeden metni iki kez yazmayalım.

---

### AŞAMA 4 — Sahip kararları (bloklayıcı)

| | Karar | Bağımlı olduğu |
|---|---|---|
| **A4** | r/mcp `p0xmazq` yorumu bizim mi? Bizse üçüncü taraf öncel sanat diye anılamaz | — **hâlâ cevapsız** |
| **D1** | Ad-uzayı atlatması: belgele / destek kontrolü uygula / karantina | Aşama 2 |
| **D2** | 6 commit push edilecek mi | — |
| **D3** | APAS yanıtını yeniden yaz | Aşama 2 + A4 |

---

## 2. Arıza sınıfları ve korumaları / Failure modes and guards

| Arıza | Belirti | Koruma |
|---|---|---|
| **Ajan API yüklenmesi** | 529 / "Overloaded" | En fazla 1 tekrar, sonra kendim yaparım. Küçük iş zaten delege edilmez. |
| **Sessiz yanlış-negatif** | Boş sonuç, `errors` dolu | **Kural: `errors` boş değilse hüküm YAZILMAZ.** Betik bunu kendi basar. |
| **Ölçülen şey değişiyor** | Sayı tutmuyor | Her ölçümle **git SHA** kaydedilir |
| **Sentez ≠ kaynak** | İkinci elden alıntı | **Yayımlanacak hiçbir alıntı özetleyiciden alınmaz** |
| **Gerçek vault'a bulaşma** | — | Test **daima** izole vault, `KASA_VAULT_PATH` ayrı dizin |
| **Artık süreç/sunucu** | Port dolu, CPU | Her testten sonra Aşama 0 |
| **Sahibin süreçlerine dokunma** | — | PID öldürmeden **komut satırı doğrulanır** |

---

## 3. Haberdarlık kuralları / Notification discipline

**Başlarken:** ne başlattığımı, neyi ölçtüğünü ve ne kadar süreceğini söylerim.
**Biterken:** sonucu ham hâliyle veririm — `errors` alanı dahil.
**Takılınca:** üç kez denemem. İkinci arızada durur, size söyler, alternatif öneririm.
**Beklerken:** boş beklemem; koşulsuz işlerden birini yaparım.

**Asla:** arka planda kendi kafasına iş bırakmam. Koşan her şeyin bu belgede bir satırı olur.

---

## 4. Şu anki durum / Current state

```
AŞAMA 0  ✅ temiz (portlar boş, geçici vault'lar silindi)
AŞAMA 1  ✅ tamam — B1/B2/B3 ölçüldü (B-STAGE-CAVEATS), C1 eser koşuldu ve doğrulandı
AŞAMA 2  ✅ çözüldü — MemTxn okundu ve ÖLÇÜLDÜ (MEMTXN-GAP): Ordered PatchTest yükümüzü de KABUL ediyor; önceleme yok, komşu
AŞAMA 3  ✅ kayıt düzeltmesi — F-IMP senkronu + tezgah sayıları + atıf (aşağıya bak)
AŞAMA 5  ✅ F-IMP canlı doğrulandı (7/7) ve dallar birleşti
AŞAMA 4  ⏸ sahip kararı bekliyor — A4 (p0xmazq), D1 (ad-uzayı politikası), PR #2 birleştirme
```

### AŞAMA 5 — 2026-08-05: yayımlanan kayıt gerçeğin GERİSİNDEYDİ

Bu oturuma kadar aradığımız sessiz arıza hep aynı yöndeydi: *olduğundan iyi görünen*. Bu kez
tersi çıktı ve aynı ölçüde bir kayıt hatasıdır.

| Bulunan | Nasıl fark edildi | Ders |
|---|---|---|
| Kimlik bağlama kodda KURULU, ama README/SECURITY/THREAT_MODEL "kurulmadı" diyor | F-IMP grep'i | Belge de ölçülen bir şeydir; gerisinde kalması da hatadır |
| `origin/main` düzeltmeyi HİÇ içermiyor — `tests/test_identity_binding.py` orada yok | `git cat-file -e origin/main:...` | Dalda yeşil olmak yayımlanmış olmak değildir |
| PR #2 **ÇATIŞMALI** → düzeltme iki gündür kapıda bekliyor | `gh pr view 2` | "Commit edildi" ile "ulaştı" ayrı şeyler |
| Tezgah SCAN-SECRETS hükmü **yazı-tura** — kendi çıktısını tarıyor | FAIL'in gerekçesi okundu | Rengi rastgele bir parmak izine bağlı kontrol ölçüm değildir |

Çatışmaların 5'i satır-sonu farkıydı (içerik bayt bayt aynı) — **ölçüm JSON'ları el ile
birleştirilmedi**; birleştirilseydi uydurma olurdu.

Kapanan: F-IMP (7/7 canlı, `_orch/redteam/fimp_live_verify.py`), hız-sınırı baypası
(300 istekte 240×429; öncesi 150'de 0), SCAN-SECRETS yazı-turası (testli),
SCAN-BAK-HYGIENE (artık dosya arşive taşındı). 13 Bandit MEDIUM de triyaj edildi
(9 yanlış-pozitif, 4 kabul edilen kalıntı; negatif kontrollü). **Tezgah: 21 PASS / 0 FAIL /
0 WARN**, commit `5a703cd`.

> *Pano düzeltmesi 18:40:* burada "20 PASS / 1 WARN" yazıyordu ve `docs/REPRODUCE.md` de öyle
> diyordu — ikisi de bayattı. Bunu ben yakalamadım; proje bağlamı belgesini yazan alt-ajan
> makine JSON'u ile belgeleri karşılaştırıp yakaladı. Aynı gün içinde ikinci kez: bir sayıyı
> bir yerde güncelleyip diğerinde bırakmak, bu projenin baş düşmanının ta kendisi.

**B-aşaması sonucu (2026-08-05, kasa-agent:8b, n=5):** B1 tohumlu-hafıza saldırıyı düşürmedi
(5/5→5/5, sayı ayakta); B2 paraphrase 5/5 (kopyalama değil benimseme); B3 benign utility 5/5
(çalışma noktası var). Dürüst sınır: tek model, tek tohum boyutu, damıtıcı modeli.

**C1 eseri:** `_orch/redteam/poison_reproduce.py` — izole vault'ta uçtan uca koşuldu, naif
ENGELLENDİ + ad-uzayına uyan GEÇTİ, `errors: []`, kendi dürüst sınırlarını basıyor.

**Koşan iş:** yok. **Push edilmemiş commit:** 0 (gerçek uzağa `ls-remote` ile soruldu).
**Dal durumu:** `security/faz-0-3-owner-scope-hardening`, main birleştirildi, çatışma yok.
**PR #2:** birleştirme sahibin kararı — **78** dosya, güvenlik yüzeyi; buton bizde değil.

> *Pano düzeltmesi 17:11:* burada "74 dosya" yazıyordu, gerçek sayı 78'di — günün
> commit'leriyle büyümüş, pano güncellenmemişti. Küçük ama bu belgenin varlık sebebine
> aykırı: durum bağlamda değil **dosyada** duracaksa, dosya bayat olmamalı.

---

## 5. Geri dönüp bakma / Retrospection — 2026-08-05

Kural: **bir geri, iki ileri.** Her ilerlemeden sonra durup "bu neden oldu" diye sor.

### Bugünkü üç arıza aynı aileden

| # | Arıza | Yönü |
|---|---|---|
| 1 | Tezgahın `SCAN-SECRETS` hükmü, kendi önceki raporunun rastgele `config_hash`'ine bağlıydı | yazı-tura |
| 2 | `poison_reproduce.py` stokastik bir sonucu var/yok diye raporluyordu | **kendi bulgumuzu çürütür gibi** |
| 3 | Kontrol modülü çökerse `SKIP/info` yazılıyordu; hüküm süzgeci `ERROR`+high arıyor | sessizce temiz |

**Ortak kök neden:** her üçünde de **hata yolu, güven veren bir durum yazıyordu.**
`info`, `SKIP`, `BLOCKED`, `0 FAIL` — hepsi "sorun yok" gibi okunur. Arıza yolunun
varsayılanı iyimserdi.

**Ders (kodda kural haline getirildi):** bir `except` bloğu ya da bir varsayılan dal,
*ölçemedim*'i **asla** *temiz* gibi yazamaz. Üç durum ayrı: **bulundu / bulunamadı /
bakılamadı.** Üçüncüyü ikinciye katan her satır bir sahte-PASS üreticisidir.

### İkinci ders: sözleşmesi olmayan rapor eksiğini göremez

3 numaranın altında daha derin bir açık vardı: tezgahın **hangi kontrollerin koşması
gerektiğine dair bir listesi yoktu**. 21 satır 15 olsa kimse fark etmezdi. Artık
`EXPECTED_CHECK_IDS` var ve eksik olan her kimlik `ERROR/critical` olarak rapora giriyor.
Yeni kontrol ekleyen kişi ID'yi oraya da yazmak zorunda — bu bir yük değil, kapının kendisi.

### Üçüncü ders: ölçüm mantığı test edilemiyorsa test edilmez

Hüküm mantığı `main()` içinde gömülüydü; sınamak için ~5 dakikalık, ağ bağımlı tam bir
tezgah koşumu gerekiyordu. Pratikte hiç sınanmadı — sessiz-SKIP hatası tam bu yüzden yaşadı.
`verdict()` ve `_coverage_gaps()` ayrıldı; artık 8 test 0.08 saniyede koşuyor.

---

Yazar / Author: [@aikadimsoy](https://github.com/aikadimsoy)
