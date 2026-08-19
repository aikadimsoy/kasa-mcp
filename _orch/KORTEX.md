# KORTEX — KASA çalışma hafızası

Anlık görüntü: **2026-08-05** · kaynak: `~/.claude/projects/d--kasa/memory/` (10 dosya) · sıkıştırılmış.

> Bunlar **zaman-anı gözlemleri**, canlı durum değil. Bir dosya:satır ya da bayrak adı geçiyorsa
> önerimden önce kodda doğrulanmalı.

---

## 0. Bir cümlede

Bu projede en tekrar eden arıza bir güvenlik açığı değil, **kendi ölçüm aletimizin yalan
söylemesi**. Her şey buna göre okunmalı: *kurulu olmak ≠ çalışmak.*

---

## 1. Kişi ve çalışma tarzı

| | |
|---|---|
| **Kim** | Erhan · GitHub [@aikadimsoy](https://github.com/aikadimsoy) · Türkçe okur/yazar |
| **Depo** | `aikadimsoy/kasa-mcp` (AGPL-3.0 + ticari) · Windows · tek geliştirici |

### Yayın düğmesi onda `[feedback]`
Push · `main`'e merge · dışarıya gönderim → **hepsi tek kelime bekler.** Yerel commit serbest.
**Neden:** kamuya kalıcı kayıt bırakan hiçbir adım otomatik değil; "hazır" ile "yayımlanmalı"
ayrı şeyler. **Nasıl:** işi *tam* bitir (çatışma çöz, test/tezgah koştur, metni yaz, bağlantıyı
doğrula), sonra **tek cümlelik karar** olarak sun. "Sen seç" derse seçimi **yap ve gerekçesini
yaz** — ama yayın adımını yine ona bırak. Açık "push et/gönder" izni **yalnız o adım** içindir.

### Devretme ve peşin karar `[feedback]`
Plan/analiz istendiğinde **kendim yazarım**; alt-ajanı yalnız keşif/arama için kullanırım,
muhakeme için değil. Alt-ajan istemine **kendi sonucumu "olgu" diye koymam**.
**Neden:** bir kez planı bir ajana yaptırıp cevabını isteme sorusunun içine gömdüm; yakalandı.
Süreci işin önüne geçirmiştim. **Ek:** hızlı belge üretme momentumu (v1→v2→v3) "dur ve ne
soruldu" refleksini eziyor — uzun üretim serilerinden sonra özellikle dikkat.

### Kamuya açık iletişim tonu `[feedback]`
Minimum bilgi · abartısız · nazik + teşekkür. Ne ölçtüğünle aç, bir soruyla bitir.
Açıklık/exploit reçetesi dışarı dökülmesin; övünme rakamları gereksizse çıkar.

### Kod yazım kuralı `[feedback]`
Kod **İngilizce**; açıklama **Türkçe** ve **açıkladığı satırın hemen altına** (üstüne blok değil —
kod değişince öksüz kalıyor). Arayüz Türkçe. Diyakritikler kullanılır. Not sadece hatırlatma
değil, **öğretici**: İngilizce terimi çevirir ve ne işe yaradığını anlatır.
*"Türkçe karakter sorun çıkarıyor" diye yorumlama* — kayıp UTF-8 sabitlenmemesinden olur.

---

## 2. Ortam tuzakları

### `python` bu makinede çalışmaz `[project]`
`python` → Microsoft Store saplaması → **çıkış kodu 9009**.
Gerçek yorumlayıcı yolu ortam değişkenlerinden veya `pythoncore-3.14-64\python.exe` yolundan çözülür.

Bu yüzden kullanıcının **8 hook'unun 7'si sessizce ölüydü**: `shared_context.json` 2026-07-01'den
beri boş, sıfır-token politikası bana **hiç ulaşmadı** (görmezden gelmedim — hiç almadım).
2026-08-05'te tam yola çevrildi (yedek: `settings.json.bak-hookfix`); **etki yeniden başlatınca**.

**Hâlâ açık:** `notify_asistan.py` ve `shared_context_updater.py` stdin'den `transcript` (dizi)
bekliyor, Stop hook'u `transcript_path` (yol) gönderiyor → alan hep boş, dosya "başarıyla" ama
içi boş yazılıyor. İkisinde de sonda `except Exception: pass`.

### Hazır altyapı — yeni araç önermeden önce bak `[project]`
`D:\AgentPool` altında: `task_board.py` (kanban), `session_journal.py`, `context_compressor.py`,
`knowledge_graph.py`, `skb_bm25_hybrid.py` + reranker, `context_packs/`, `token_stats.py`,
`local_worker.py`, `hermes_task_runner.py`, `prof_router.py`.
**Hangisinin canlı olduğu ölçülmeli** — kurulu olması çalıştığı anlamına gelmiyor.

### Diğer sabitler
- Test **daima izole vault** (`KASA_VAULT_PATH` ayrı dizin); gerçek vault'a dokunma.
- Makinede sahibin süreçleri koşuyor (openclaw, streamlit, ComfyUI, uvicorn) — **PID öldürme**.
- Konsol cp1254 → betiğin başında `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`.
- `SendUserFile` devre dışı olabilir — dosya yolu ver.

---

## 3. Alt-ajan kuralları

### İzolasyon kısıtı açıkça verilmeli `[feedback]`
Bir workflow alt-ajanı **gerçek vault'u arayıp kopyaladı ve sorguladı** (`agent_tokens` dahil).
CLAUDE.md bunu yasaklıyor ama **kural alt-ajana kendiliğinden geçmiyor**. Aynı gün Fable ajanına
kısıtı *açıkça yazdım* ve uydu; workflow ajanlarına yazmadım ve biri uymadı. **Fark benim
istemimde.** Ayrıca bunu ben yakalamadım — sistem uyarısı yakaladı.

**Nasıl:** her isteme, ilgisiz görünse bile ve **istemin başında**:
*"Gerçek vault'a DOKUNMA; yalnız izole geçici kasa. Hiçbir PID öldürme. Kimlik-bilgisi
dosyalarını arama/kopyalama."* Tarama bitince `%TEMP%` kontrol et — 2026-08-05'te orada
**101 geçici dizin, 31 anahtar seti** birikmişti (silindi).

*Dürüstlük notu:* o kopyanın gerçek vault mu yoksa taze kasa mı olduğu **doğrulanamadı**
(sınıflandırıcı engelledi, etrafından dolaşılmadı). "Kopyalanmadı" değil — **"bakamadım"**.

### Delegasyon pratiği `[feedback]`
1. **Brief'i işin gerçek çerçevesiyle yaz.** Alt-ajan taze bağlamda çalışır, oturumdaki "yetkili
   loopback lab, izole kasa" bağlamını görmez. Doğru tarif: *yetkili erişim-kontrolü regresyon
   ölçümü* — "şu uç, şu kimlik-bilgisiyle beklenen HTTP kodunu dönüyor mu". Bu kelime oyunu değil,
   **işin doğru adı**; `door_inventory` bu dille yazıldı ve daha iyi bir ölçüm üretti.
2. **Asıl arıza sebebi kapasite.** Fable 5 ajanları 2026-08-05'te **4 kez** `API 529 Overloaded`
   ile düştü; ilkinde 15 dakikalık iş kayboldu çünkü hiçbir şey diske yazılmamıştı.
   → küçük işi delege etme · delege edersen **"önce dosyayı yaz, sonra koştur"** de ·
   **en fazla bir tekrar**, sonra kendim yaparım.
3. **Model damgası** `measured_by_model` — dikkat: **yazanı** kaydeder, koşanı değil (statik dize).

---

## 4. Proje kararları

### Model seçimi: `hermes3:8b` (paketlenmiş: `kasa-agent:8b`) `[project]`
Dayanak **skor farkı değil** (78.1 vs 75.4 tek koşu gürültüsünde), **A1 dolaylı enjeksiyon
sonucunun üç bağımsız koşuda tekrarlanması**. Alaka için `bge-m3`.

Üç kalıcı bulgu:
1. **Model gücü savunmayı güçlendirmiyor** — en büyük model (deepseek-coder-v2:16b) en kötü
   dayanıklı çıktı; enjeksiyon zaten talimat-izleme yeteneğini sömürüyor.
2. `format:"json"` üç modelde de dizi garantisi vermedi → **şema kısıtlı çıktı** gerekiyor.
3. İnce ayar itaati artırırken enjeksiyon direncini düşürebilir → bağlayıcı kural:
   `MB-INJ-A1` PASS'tan FAIL'e düşerse **ince ayar reddedilir**.

**2026-08-04 daraltma:** direnç **stile özgü**. Hermes3 dahil bütün yerel modeller *kaba override*
stiline ("yukarıdakini yok say, sadece X yaz") direnemiyor. Tercih A1 zemininde savunulabilir
kalır; genel ders pekişir — **model enjeksiyon direncine güvenme, yapısal savunma birincil.**

### Güvenlik işinin durumu `[project]`
`security/faz-0-3-owner-scope-hardening` — her şey push'lu, **PR #2 MERGEABLE**, bekleyen tek şey
sahip birleştirme kararı.

**Ayrıntı kasten burada değil, repoda** — tek kaynak olsun diye:
`_orch/archive/measurements.json` (27 ölçüm) · `docs/REPRODUCE.md` (her iddia için komut +
*neyi göstermediği*) · `_orch/IS_HATTI.md` (aşama panosu + "Geri dönüp bakma") · `SECURITY.md`.

> Bu dosya bir gün boyunca *"PUSH YOK, mühür bekliyor"* yazdı ve o hüküm çoktan geçersizdi.
> İki kaynağı paralel tutmak, birinin bayatlaması demek.

### Qwen kod incelemesi `[reference]`
Tamamlandı (32/32 dosya), `huihui_ai/qwen2.5-coder-abliterate:14b` ile.
Çıktı: `_orch/qwen_review/kasa_qwen_review.md`.

---

## 5. Ölçüm disiplini — pratikte ne demek

Kural metni `CLAUDE.md` ve `_orch/IS_HATTI.md`'de. Burada yalnız **bedelle öğrenilen kısım**:

| Yaşanan | Nasıl göründü |
|---|---|
| Tezgah `KASA_ALLOWED_HOSTS` ayarlamıyordu → her istek 400, `!=200` yüklemli kontroller PASS | temiz |
| `SCAN-SECRETS` hükmü kendi önceki raporunun rastgele `config_hash`'ine bağlıydı | yazı-tura |
| Kontrol modülü çökerse `SKIP/info` yazılıyordu; süzgeç `ERROR`+high arıyor | sessizce temiz |
| `poison_reproduce.py` stokastik sonucu var/yok raporluyordu | **kendi bulgumuzu çürütür gibi** |
| Test HTTP 405 aldı, profil boş kaldı | savunma tutmuş gibi |

**Ortak kök neden:** hata yolunun varsayılanı **iyimserdi**. `info`, `SKIP`, `BLOCKED`, `0 FAIL` —
hepsi "sorun yok" diye okunur.

> **Üç durum ayrıdır: bulundu / bulunamadı / BAKILAMADI.**
> Üçüncüyü ikinciye katan her satır bir sahte-PASS üreticisidir.

Ve: **boş sonuç başarılı savunmadan ayırt edilemez.** Bir dedektör hiç ateşlemiyorsa boş listesi
"temiz" değil, **anlamsızdır** — dedektörün kendisi sınanmalı.

---

## 6. Şu an bekleyen sahip kararları (7)

1. **PR #2 birleştirme** — MERGEABLE, CI yeşil, 78 dosya
2. **APAS yanıtı** gönderilsin mi — metin hazır, savunmamızın nasıl aşılacağını tarif ediyor
3. **A4** — r/mcp `p0xmazq` yorumu sizin mi (bizse öncel sanat diye anılamaz)
4. **D1** — ad-uzayı politikası: belgele / taint zorla / karantina
   *(MemTxn'in Ordered PatchTest'i yükümüzü de kabul ediyor — "onu uygula" tek başına çözmez)*
5. **`%TEMP%` anahtar setleri** — silindi; **token rotasyonu** gerekir mi
6. **Gerçek vault kopyalandı mı** — ölçülmedi, sınıflandırıcı engelledi
7. **F-DISTILL-PLAINTEXT düzeltmesi** — damıtıcı `profile.value`'yu düz metin yazıyor; düzeltmek
   ilkece küçük ama **mevcut satırlar göç gerektiriyor**

---

*Üretim: 2026-08-05 · `~/.claude/projects/d--kasa/memory/` içindeki 10 dosyadan sıkıştırıldı.*
*Kanonik kaynak o dizindir; bu bir okuma kopyasıdır ve otomatik güncellenmez.*
