# KASA — Lab Red-Team + Bağımsız Uzlaştırma + HEAD Kapanış İspatı (2026-08-04)

> **Ölçüm seviyesi:** CANLI (throwaway lab 8780, v0.2.0) + KOD-YAPISI (HEAD regresyon pinleri).
> **Sınır:** yalnız izole loopback throwaway instance; gerçek yerel vault verisine dokunulmadı.
> Güvenlik-kritik kod Claude yazar, **sahip mühürler**, push yok.

## 1. Bağlam

İzole bir "KASA Agent Lab" (harness `8877/api/briefing` → hedef `8780`, sürüm **v0.2.0**,
**düzeltme-öncesi** build) üzerinde 35 turluk canlı red-team + bir bağımsız AI test-eden ("port
sahibi") karşı-testi koşuldu. Amaç: HEAD'deki düzeltmelerin **canlı-sömürülebilir** açıkları
kapattığını yanlışlanabilir biçimde göstermek. Lab, fix-öncesi "önce" hedefidir.

## 2. Canlı lab bulguları (v0.2.0, AÇIK) — actor etiketli

| Bulgu | Aktör | Şiddet | Kanıt (CANLI) |
|---|---|---:|---|
| **F-OWNER-SCOPE** | A1/A2 | yüksek | Düşük-yetki *gerçek* brifing token'ı (yazma-reddi 403 → sub-owner) → owner-read uçları **200** |
| **F-OWNER-MUTATE** | A1/A2 | yüksek | Aynı token `POST /v1/agent/model` → **200** `{"selected":"qwen2.5:7b"}` (kurulu-model sınırlı; ad-enjeksiyon **bloklu**) |
| **F-OWNER-TERMS** | A1/A2 | orta | Aynı token `POST /v1/terms/accept` → **200** `{"accepted":true}` |
| **G2-HOST** | A3 | orta | Herhangi `Host`/`Forwarded` → `GET /` **200** (loopback allow-list yok; DNS-rebind savunma-derinliği) |
| AUDIT-INFO-DISCLOSURE | A2 | düşük | Düşük-yetki `audit/report` → `python_version 3.14.5 [MSC…AMD64]` + health |

**Doğrulanan savunmalar (lab'da bile KAPALI/olumlu):** forgery→401; routing auth-bypass yok
(43 varyant); token-değer sıkı; model-adı enjeksiyon bloklu; 500/crash yok; **chat A1 enjeksiyonu
(blunt+ince+exfil) çevrelendi** (token sızmadı); **audit yazma-denemelerini logluyor** (records
397→401, Δ4); CORS izinsiz; rate-limit ~60 istek/kimlik (execute_tool).

## 3. Bağımsız uzlaştırma (port sahibi ↔ Claude)

Port sahibi karşı-testi **sahte/forge JWT** kullandı → korunan uçlar **401** (doğru). Bu, benim
bulgularımı **çürütmez**: bulgular **brifingin dağıttığı gerçek token'la** üretiliyor. İki ayrı iddia:

- **A — scope-escalation (iddia edilen, KANIT):** geçerli-ama-yazma-reddi token owner uçlarına
  ulaşıyor. **Tek kimlikle** kanıt (`write=403 & owner=200`). A/B **gerekmez**.
- **B — çapraz-sahip sızıntısı (iddia EDİLMEDİ):** owner A token'ı owner B verisini okur. A/B
  gerektirir; harness ikinci owner-tier kimlik dağıtmadığı için **koşulamadı**.

**İki yönlü yanlış-pozitif düzeltmeleri (yanlışlanabilirlik disiplini çalıştı):** F-DASH-leak
(placeholder + nonce-kapılı; ham token sızmıyor), AUTH-PARSE-LOOSE (RFC-uyumlu case-insensitive
şema), RATE-LIMIT-COVERAGE (belirsiz), AUTH-TIMING (iş-yükü farkı; port sahibinin daha temiz
4-koşul testiyle **düşük-şiddet hijyen notuna** indirildi — sömürülebilirlik kanıtlı değil).

## 4. HEAD kapanış ispatı (KOD-YAPISI, regresyon pini)

Lab'ın AÇIK gösterdiği matris HEAD'e karşı TestClient'la koşuldu; HEAD `require_owner` + Faz-0
Host-guard uyguladığı için **hepsi 403/400**. Regresyon pinleri (`tests/test_owner_surface_authz.py`,
`tests/test_host_guard.py`) — **305 passed / 1 xfailed**:

| Lab (v0.2.0 "önce") | HEAD (pin, "sonra") | Pin |
|---|---|---|
| F-OWNER-SCOPE read 200 | düşük-yetki → **403** | `test_low_priv_bound_token_cannot_reach_owner_endpoints` (5 uç) |
| F-OWNER-MUTATE model 200 | düşük-yetki → **403** | `test_low_priv_bound_token_cannot_mutate_or_use_bridge` (agent/model) |
| F-OWNER-TERMS accept 200 | düşük-yetki → **403** | aynı pin (terms/accept) |
| agent bridge 200 | düşük-yetki → **403** | aynı pin (models/chat/race, audit/report) |
| G2 Host 200 | loopback-dışı Host → **400** | `test_host_guard.py` (Faz-0) |
| — | audit çıktısı ham bearer içermez | `test_audit_outputs_do_not_leak_bearer_token` (port-sahibi önerisi) |
| — (pozitif kontrol) | owner **kilitlenmez** (models/terms ≠ 403) | `test_POSITIVE_owner_not_locked_out_of_bridge_and_terms` |

## 5. Değerlendirilen ama uygulanmayan (dürüst gerekçe)

- **auth-önce-parse (bozuk JSON → 422, 401'den önce):** düşük — `/openapi.json` şemayı zaten
  tümüyle açık ediyor; 422/401 farkı yeni bilgi sızdırmıyor. Kırılgan middleware yeniden-sıralaması
  riskine değmez → **kabul-edilen-düşük-risk** olarak belgelendi.
- **openapi/docs kapı-arkası (production):** yerel-first loopback aracı için `/docs` geliştirici-dostu;
  paketlenmiş build'de bir `KASA_DISABLE_DOCS` bayrağı makul → **backlog** (marjinal hardening).

## 6. Sahibe devir (owner-side, benim yapamadığım)

1. **Mühür + push:** F-DASH/F-OWNER-SCOPE + Faz 0/1/2/3 + belgeler + skill + bu oturumun pinleri —
   hepsi yerel/mühürsüz. "Bul→kanıtla→**kapat**" ancak yayınlanınca tamamlanır.
2. **(ops.) Lab'ı HEAD'den yeniden başlat** → aynı 35 tur bu 4 bulguyu 403/400'e çevirmeli (canlı kapanış).
3. **(ops.) İkinci owner-tier test kimliği enjekte et** → iddia B (çapraz-sahip A/B) için kesin test.

## 7. Dürüstlük iddiaları

- `scores_or_probabilities_invented: false` · `real_vault_touched: false` (yalnız 8780 throwaway)
- `false_positives_retracted: [F-DASH-leak, AUTH-PARSE-LOOSE, RATE-LIMIT-COVERAGE, AUTH-TIMING→düşük]`
- `head_closure: CODE-STRUCTURE (305 passed/1 xfailed)` · `claim: "tespit + kapat", "önleme" değil`
