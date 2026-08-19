# KASA Aracılık Kıyası — "KASA var / yok" engelleme matrisi (2026-08-04)

> **Amaç:** KASA'nın çekirdek iddiası *total mediation* (tam aracılık). Bu belge o iddiayı
> **ölçümle** sınar: aynı yerel kaynaklara (model, veri, araç, ağ) KASA **olmadan** (doğrudan)
> ve KASA **ile** (aracılı) erişimi yan yana koyar; her hücrede *engellendi mi / engellenmedi mi*
> sorusunu somut HTTP kodu / dosya kanıtıyla yanıtlar.
>
> **Ölçüm disiplini:** tüm satırlar `ÇALIŞTIRILDI` seviyesindedir (canlı çalıştırıldı, kod-yapısı
> okumasıyla değil). Ölçüm-referanssız "kanıtlanmış/hardened" iddiası yok; skor/olasılık uydurulmadı.

## Yöntem
- **Hedef:** deponun güncel HEAD kodu, izole `KASA_HOME` (tempfile), **taze vault**
  (`start_isolated_server`, `_orch/redteam/live_mcp_attack.py`). Gerçek kullanıcı vault'una dokunulmadı.
- **Kimlikler:** `low_priv` (scope YOK), `writer` (yalnız `events:write`), `owner` (bearer).
  Deny-by-default: bir token owner grant edene kadar hiçbir kapsama sahip değildir.
- **"KASA yok" yolu:** aynı kaynağa aracı katman olmadan doğrudan erişim (Ollama 11434'e tokensiz
  HTTP; vault dosyasına doğrudan `sqlite3`). Bu yol tanımı gereği **A4 aktörüdür** (aynı-OS süreç).

## Matris

| # | Kaynak / Eylem | KASA YOK (doğrudan) | KASA — düşük-yetki | KASA — owner/yetkili | Aktör |
|---|---|---|---|---|---|
| 1 | Yerel model (Ollama) | İZİNLİ — HTTP 200, tokensiz | **ENGELLİ 403** | İZİNLİ 200 (aracılı) | A4 / A2 |
| 2 | Profil okuma (in-use) | ↓ doğrudan DB (sat. 4) | **ENGELLİ 403** | İZİNLİ 200 (maskeli) | A2 |
| 3 | Olay yazma (event_ingest) | İZİNLİ — plaintext INSERT | **ENGELLİ 403** (scope yok) | İZİNLİ 200 (şifreli+audit) | A2 |
| 4 | Vault at-rest (ham dosya) | direct-marker **OKUNUR** (plaintext) | KASA-marker **ŞİFRELİ** (dosyada yok) | anahtar aynı-OS → A4 çözer | A4 |
| 5 | Kimlik taklidi (agent_id spoof) | — (kimlik kavramı yok) | **ENGELLİ 403** (mismatch) | ENGELLİ 403 | A1 / A2 |
| 6 | Hız-sınırı (65 istek burst) | SINIRSIZ — 65/65 → 200 | **4×429** (61×200 sonra sınır) | 4×429 | A1 |
| 7 | Yetkisiz araç (audit_read) | — (araç kavramı yok) | **ENGELLİ 403** (deny-by-default) | — | A2 |
| 8 | Dışa ağ (evil.example) | SINIRSIZ (guard yok) | **ENGELLİ** (`urlparse` loopback) | ENGELLİ | A1 / A2 |
| 9 | Denetim izi | **İZ YOK** (doğrudan INSERT) | attributed (64 satır) | attributed | — |

**Efsane:** İZİNLİ = açık/geçer · ENGELLİ = 403/429/reddedildi · sat. 4 kısmi (aşağıda açıklandı).

## Satır kanıtları (ölçülen ham değerler)
- **1 model:** `POST 11434/api/generate` tokensiz → 200; `GET /v1/agent/models` düşük → 403, owner → 200.
- **2 profil:** `GET /v1/dashboard/profile` düşük → 403, owner → 200 (`read-through-redact`).
- **3 olay:** doğrudan `sqlite3 INSERT` → yazıldı (plaintext); `/v1/ingest event_ingest` scope-yok → 403,
  `events:write` verilmiş → 200.
- **4 at-rest:** aynı DB dosyasına iki markör: doğrudan yazılan `DIRECTPLAIN_9931` ham baytlarda **VAR**
  (plaintext); KASA ile yazılan `VIAKASA_7742` ham baytlarda **YOK** (AES-GCM cell_crypt). Anahtar
  dosyası mevcut (DPAPI ile korunur).
- **5 spoof:** `writer` token'ı + gövdede `agent_id="someone_else"` → 403 ("token'a bağlı kimlikle uyuşmuyor").
- **6 rate:** Ollama 65/65 → 200; KASA `writer` 65 ardışık ingest → 61×200, 4×429 (kova ~60 kapasite, ~1/sn dolum).
- **7 tool scope:** `execute_tool audit_read` düşük-yetki → 403 (izin yok).
- **8 egress:** `_is_loopback_url("http://127.0.0.1:8780")` → True; `_is_loopback_url("http://evil.example")` → False.
- **9 audit:** 64 audit satırı, atıf kimlikleri `{low_priv, writer}`; doğrudan INSERT audit'e **yazmaz** (izsiz).

## Okuması (neden-sonuç)
- **KASA YOK** = koruma katmanı yok: model açık, yazma plaintext + izsiz, hız sınırsız, dışa ağ serbest.
- **KASA — düşük-yetki** = yetkisiz her yol **reddedilir** (403/429/engelli). Bu, tam aracılığın çalışan hali.
- **KASA — owner** = geçer ama **aracılı**: maskeli okuma, şifreli yazma, kimlik-atıflı denetim.
- Bu oturumdaki red-team bulguları (F-DASH, F-OWNER-SCOPE) tam bu aracı katmandaki deliklerdi; kapatılınca
  "KASA — düşük-yetki" sütununun 403'leri geri geldi (ayrı belge: `KASA_REDTEAM_PLANI_2026-08-03.md`).

## Dürüst sınırlar
- **"KASA YOK" sütunu = A4 aktörü** (aynı-OS, keyfi kod). KASA bunu **kapsam dışı** bırakır
  (`THREAT_MODEL.md`); ajanın HTTP erişimini yönetir, işletim sistemini değil.
- **At-rest şifreleme** çalınan-disk / başka-OS-kullanıcı senaryosuna karşı korur; DPAPI anahtarı aynı-OS
  kullanıcıya bağlı olduğundan **A4'e karşı korumaz**. Ayrıca KASA'yı atlayan doğrudan yazıcı plaintext bırakır.
- Bu matris **ürün talebi** hakkında hiçbir şey söylemez; yalnızca aracılık katmanının *var/yok* farkını ölçer.

## Dürüstlük iddiaları
- `real_owner_vault_used: false` (izole tempfile vault)
- `external_network_used: false` (yalnız loopback: 11434 + izole HEAD portu)
- `scores_or_probabilities_invented: false`
- `measurement_level: CALISTIRILDI` (tüm satırlar canlı çalıştırıldı)
