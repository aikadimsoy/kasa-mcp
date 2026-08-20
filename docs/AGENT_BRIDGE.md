# KASA Ajan Köprüsü — model seçimi + KASA'yı kullandırma

> 2026-07-10 · Kanonik. Plan: `jolly-riding-gadget.md` · Araştırma: `ORCHESTRATOR_SURVEY.md`.
> "Model düşünür; harness sürer; son söz her zaman deterministik kuralda."

## Amaç
Seçilen **yerel** model KASA'yı araçlarla kullanır (salt-okunur, maskeli). Ayrıca gerçek MCP
adaptörü ile Claude Code/Goose/Cline KASA'ya bağlanabilir. Bulut-model ERTELENDİ (owner-gated).

## Parçalar
1. **MCP adaptörü** (`src/mcp_adapter/`, resmi `mcp` SDK **MIT**, exe-DIŞI):
   - `proxy.py` (SDK'siz çekirdek, birim-test edilebilir): `build_settings()` (loopback zorlar,
     `system` reddeder) + `execute()` (→ `POST /v1/execute_tool` + bearer).
   - `__main__.py`: FastMCP ile 6 PUBLIC_TOOLS'u MCP olarak sunar. `grant_permission` YOK.
   - Bağla: `claude mcp add kasa -- py -3.12 -m src.mcp_adapter`. Sunucuya SIFIR değişiklik;
     tüm authz (bearer + allow-list + rezerve-id + deny-by-default izin) aynen devrede.
   - Owner izin: `py tools/grant_agent_scope.py grant mcp_client audit:read` (system + admin:grant
     CLI'dan verilemez — yükselme kapısı).
   - **TR-NOT (2026-08-20, canlı ölçüm):** yukarıdaki `audit:read` örneği doğru ama eksiksiz bir
     kurulum reçetesi **değil**. Gerçek bir stdio MCP istemcisiyle koşuldu; iki şey ölçüldü:
     - Hiçbir yetki verilmeden bağlanan istemci sağlam bir el sıkışma ve **her çağrıda HTTP 403**
       alır (`Ajan 'legacy' için yazma izni yok`). Deny-by-default böyle görünüyor.
     - **Düz `profile:read` hiçbir okumayı karşılamaz.** `tools.py:176` `profile_read` için
       `profile:read:<kapsam>` sorar; `tools.py:324` `list_quarantined` için düz `profile:read`
       sorar — aynı dize, iki anlam. İzin kontrolü tam eşitlik ya da `*` ile biten yetki aradığı
       için düz yetki profil okumalarında eşleşmez. Ölçüldü: `grant my_agent profile:read`
       sonrası çağrı 403; `profile:read:*` verilince aynı çağrı 200.
       `grant_agent_scope.py` artık bu durumda uyarıyor (`tests/test_grant_scope_hint.py`).
     - Tam reçete ve ölçülen çıktılar: `README.md` → "Connecting an AI client"
       (Türkçesi `README.tr.md` → "Bir AI istemcisini bağlamak").

2. **Ajan köprüsü** (`src/agent/`, exe-İÇİ):
   - `gate.py` — **elle carve-out** (güvenlik sınırı). Ad allow-list + **İÇERİK kapısı**
     (`redact.CREDENTIAL_DENY`; ad-listesi ≠ içerik kapısı) + arg tip/aralık/uzunluk + bütçe
     sabitleri (5 iter, 120/300s, 8k/16k char) + model-adı regex + kurulu-üyelik.
   - `harness.py` — **elle carve-out**. Sınırlı tool-calling döngüsü: her model çağrısı
     `asyncio.to_thread` (SQLite affinity için vault okumaları loop-thread'de); **her araç çağrısı
     `gate.validate_call`'dan geçer**; araç sonucu geri-beslemeden önce kırp+`redact.scan`+
     `sanitize_untrusted_text`. Araç yüzeyi = maskeli pano fonksiyonları (`stats.py`); ham
     VaultTools KAPALI. JSON-fence yedeği (tool-desteksiz model). `run_race` = aynı soruyu
     2-4 modele izole (biri patlarsa diğerleri sürer).
   - `routes.py` / `store.py` — yerel-model üretimi. `add_api_route` (starlette include_router
     düşürüyor); tüm handler `async def`. Seçili model `<DATA_DIR>/agent_config.json`.

3. **"Ajan" paneli** (5. görünüm, `dashboard_ui`): model seçici · sohbet · görünür araç-izleri ·
   **Yarış Modu** (2-4 model yan yana, her birinin izi, "Bunu seç"). Yalnız `textContent`.

## Endpoint sözleşmeleri (hepsi bearer)
| Endpoint | Girdi | Çıktı |
|---|---|---|
| `GET /v1/agent/models` | — | `{service_up, models:[{name,size}], selected}` |
| `POST /v1/agent/model` | `{name}` | `{ok, selected}` \| 400/503 |
| `POST /v1/agent/chat` | `{message, history?}` | `{reply, model, iterations, elapsed_ms, trace}` \| 400/409/503 |
| `POST /v1/agent/race` | `{message, models[], history?}` | `{results:[{model, reply/error, ...}]}` \| 400/409/503 |

## Güvenlik değişmezleri (test edildi)
- **Redact sınırı**: model yalnız maskeli/aggregate görür; ham sır cevaba/trace'e SIZMAZ
  (birim + gerçek-model canlı smoke ile kanıtlı).
- **Gate uygulaması**: yasadışı araç/arg/aralık → `gate_reject` (trace'te görünür), vault'a ulaşmaz.
- **Air-gap**: yalnız 127.0.0.1 (yerel model servisi + loopback). Dış çağrı YOK (owner kararı
  2026-07-10: yalnız yerel). Bulut-model gelecekte owner-gated + redact-sonrası.
- **Salt-okunur**: `kasa_note` (yazıcı) gate'te tanımlı ama `allow_notes=False` bayrağıyla KAPALI;
  izin de seed edilmez.

## Test + doğrulama
- `py -m pytest tests/test_agent_*.py tests/test_mcp_adapter.py -q` → 44 test.
- Tam suite: **179 passed, 1 xfailed**.
- Canlı: `qwen2.5:7b` sohbet PASS (kasa_stats çağırdı, sızıntı yok); yarış `qwen2.5:3b` vs
  `llama3.2:3b` PASS (biri aracı kullandı, biri uydurdu — yarışın değeri).
- Build: `pwsh -File build_kasa.ps1` (src.agent dahil; mcp_adapter DAHİL DEĞİL — SDK exe'ye girmez).

## Telif
Yeni bağımlılık yalnız `mcp` (MIT, adaptör-only, exe-dışı). Köprü = stdlib urllib; ollama/anthropic
SDK yok; Atoms.dev'den yalnız **desen** (Race Mode) alındı, kod değil. GPL kopyası yok.
