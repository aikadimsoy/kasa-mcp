# KASA — çalışma kuralları / working rules

KASA: yerel-öncelikli, izin-brokerli, MCP üzerinden sunulan ajan hafıza kasası. Windows.
Kod İngilizce; öğretici düzyazı ve arayüz Türkçe.

## Ölçüm disiplini (asıl IP — atlanmaz)

- **Uydurma skor/olasılık yok.** Nesnel geç/kal.
- **found → proved → closed:** canlı/test edilmiş kanıt olmadan "düzeltildi" yok; repro olmadan "açık" yok.
- **"tespit + sınırla"** de, "önle/çözdüm" değil.
- Her iddiada **ölçüm seviyesi:** `RAN-LIVE` / `CODE-STRUCTURE` / `DOCUMENTED`. Yaptığından bir seviye üstünü **asla** raporlama.
- **Pozitif VE negatif kontrol** her iddiada. Her şeyi engelleyen kapı savunma değildir.
- Sınırları açıkça yaz. Neyi kapsamadığını söyle.

## Sessiz arıza — bu projenin baş düşmanı

Bu oturumda tekrar tekrar aynı kalıp: **başarı gibi görünen arıza.** Bench yanlış-GEÇTİ üretti (400 dönüyordu, kontrol 200 değil sanıyordu); test HTTP 405 aldı, profil boş kaldı, savunma tutmuş göründü; hook'lar exit 9009'la ölmüştü ama sessizdi.

Kural: **bir mekanizmanın kurulu/yeşil olması çalıştığı anlamına gelmez.** Her zaman canlı kanıt ara — `errors` alanı, çıkış kodu, dosya zaman damgası, git SHA. **`errors` boş değilse hüküm yazma.**

## Tehdit modeli — aktör etiketi (ZORUNLU)

Her bulgu hangi aktöre ait olduğunu söylemeli. Etiketsiz bulgu geçersiz.
- **A1** prompt-zehirli model → savunma yapısal olmalı (kodda kapı, model yargısı değil)
- **A2** kötücül araç · **A3** ziyaret edilen sayfa (JS) · **A4** aynı-OS kullanıcı (genelde KAPSAM DIŞI, açıkça belirt)

## Bilinen ortam tuzakları

- `python` → Microsoft Store saplaması, **çıkış kodu 9009**. Gerçek yorumlayıcı yolu Windows ortam değişkeninden veya Python kurulum dizininden çözülür.
- `SendUserFile` devre dışı olabilir — dosya yolu ver.
- Test **daima izole vault** (`KASA_VAULT_PATH` ayrı dizin); gerçek vault'a dokunma.
- PID öldürmeden önce komut satırını doğrula — makinede sahibin süreçleri koşuyor (openclaw, streamlit, ComfyUI, uvicorn).

## Git

- Commit/push **yalnızca istenince**. Varsayılan dalda değil, dal aç.
- Commit mesajı **neden**i anlatır, "ne değişti" listesi değil.
- Değişiklikten sonra **git durumunu doğrula** (yerel takip referansına değil gerçek uzağa sor).

## Kamuya iletişim tonu

PR/README/açıklama/forum: minimum bilgi, abartısız, nazik, teşekkürle. Ürün satma; **ne ölçtün** ile aç, bir soruyla bitir. Özgünlük iddiası kurmadan önce öncel sanat taraması yap.

## Delegasyon

- Küçük iş delege edilmez — ajan API yüklenmesinden düşebilir (bu oturumda 3 kez oldu).
- Yayımlanacak hiçbir alıntı özetleyiciden alınmaz; birincil kaynaktan.
- Sentez birincil kaynağın yerine geçmez.

## Yerleşim

`_orch/` — ölçüm kayıtları, araştırma, taslaklar (ör. `IS_HATTI.md`, `archive/measurements.json`, `OZGUNLUK_DENETIMI_*.md`). Kalıcı görev durumu: native Task listesi (`CLAUDE_CODE_TASK_LIST_ID=kasa`).
