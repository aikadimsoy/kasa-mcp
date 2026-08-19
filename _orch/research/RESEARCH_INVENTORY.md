# KASA Araştırma Envanteri — Taksonomi + Protokol

> **Amaç:** eğitim envanteri + yerel-AI deneyleri için, KASA'nın kategorisindeki
> standartları, min/max eşikleri, başarılı/başarısız girişimleri, güncel teknolojik
> yenilikleri (başarı sebepleriyle) ve uluslararası güvenlik disiplinlerini derinlemesine
> haritalamak. **Kural:** yerel model çıktısı ADAY'dır; web'de doğrulanmadan envantere GİRMEZ.

## 0. İş bölümü (neden böyle — cause/effect)

| Katman | Kim | Neden |
|---|---|---|
| Taksonomi + yargı + seçim | **Claude** | Listeyi kurmak, kaynağı elemek, çelişkiyi çözmek muhakeme işi |
| Canlı/güncel web (edu, HF, Reddit, forum, arXiv) | **Claude (WebSearch/WebFetch)** | Yerel Ollama modelleri canlı web'e ÇIKAMAZ — "gezemezler" |
| Toplu sentez / dal genişletme / taslak | **Yerel Ollama** (qwen2.5:7b, hermes3:8b, deepseek-r1:14b) | Ücretsiz breadth; bilgi bayat + uydurabilir → web-doğrulama şart |

**Doğrulama disiplini:** her madde `[ADAY]` (yerel üretti) → `[TEYİT]` (web'de en az 1
otoriter kaynak) → `[ENVANTER]`. Ölçüm-referanssız "en iyi/kanıtlanmış" iddiası yasak
(KASA'nın kendi dürüstlük kuralı).

---

## B1 — Ajan-güvenlik standartları + tam-aracılık soyu
**KASA bağı:** çekirdek iddia "total mediation". Onu kıyaslayacak otoriter çerçeveler.
- **OWASP**: LLM Uygulamaları için Top 10 (2025), Agentic AI Threats & Mitigations, ASVS (L1–L3 olgunluk = min/max)
- **MITRE ATLAS** (adversarial ML tehdit matrisi)
- **NIST**: AI RMF (AI 100-1), SSDF (SP 800-218), Zero Trust (SP 800-207)
- **Klasik referans-monitör / tam-aracılık soyu**: Anderson 1972 (reference monitor),
  Saltzer & Schroeder 1975 (8 ilke: complete mediation, least privilege, fail-safe
  defaults, economy of mechanism, open design, separation of privilege, least common
  mechanism, psychological acceptability) — KASA'nın dili birebir buradan gelir
- **Ajan-spesifik**: confused deputy, capability security, "lethal trifecta" (Simon Willison),
  MCP güvenlik (Anthropic MCP spec + bilinen MCP açıkları), prompt-injection savunma literatürü
- **min/max:** ASVS seviyeleri; pass/fail = "her ayrıcalıklı yol tek kapıdan mı geçiyor" evet/hayır

## B2 — AI yönetim + risk uluslararası standartları
**KASA bağı:** hibe/kurumsal güvenilirlik + NLnet Avrupa boyutu.
- ISO/IEC 42001 (AI yönetim sistemi), ISO/IEC 23894 (AI risk), ISO/IEC 27001/27002,
  ISO/IEC 27701 (gizlilik), SOC 2, EU AI Act, GDPR
- **LINDDUN** (gizlilik tehdit modelleme) — STRIDE'ın gizlilik karşılığı

## B3 — Local-first / egemenlik / kişisel veri depoları
**KASA bağı:** konumlandırmanın kalbi.
- Local-first software (Ink & Switch; Kleppmann'ın 7 ilkesi)
- Solid (Inrupt/Berners-Lee), MyData, PDS, Bluesky PDS mimarisi
- Gizli hesaplama (confidential computing): TEE, Intel SGX/TDX, AMD SEV, ARM CCA; cihaz-üstü çıkarım
- Veri egemenliği düzenlemeleri

## B4 — LLM hafıza sistemleri
**KASA bağı:** KASA bir hafıza kasası; rakip + teknik manzara.
- MemGPT/Letta, Mem0, Zep, Cognee, LangMem
- Vektör DB'ler, RAG, GraphRAG; damıtma + provenans mimarileri

## B5 — Yerel model ekosistemi
**KASA bağı:** KASA yerel model çalıştırır; deneyin zemini.
- Ollama, llama.cpp, GGUF, vLLM, LM Studio, MLX
- Nicemleme (GGUF/AWQ/GPTQ), küçük-model trendleri, HF Hub, model lisansları

## B6 — Pazar: başarılı/başarısız girişimler (başarı sebepleriyle)
**KASA bağı:** kategoride kim kazandı/kaybetti, NEDEN.
- Traction: Ollama, LM Studio, Letta, Mem0, Pieces, Rewind→Limitless, Private LLM
- Zorlanan/pivot/başarısız: (araştırılacak — hafıza/PDS girişimleri)
- Giren devler: Docker MCP Gateway, Anthropic self-hosted sandbox, Google agent yığını
- **Başarı-sebebi taksonomisi:** dağıtım, DX, zamanlama, hendek (moat), OSS-topluluk

## B7 — Eklemek istediğim disiplinler (kullanıcının söylediğinin ÖTESİNDE — her biri neden)
- **Formal tehdit modelleme**: STRIDE, LINDDUN, saldırı ağaçları
- **Tedarik zinciri güvenliği**: SLSA, SBOM, tekrarlanabilir derleme, Sigstore — KASA'yı yayımlamak için
- **Adversarial ML / prompt-injection akademisi**
- **Diferansiyel gizlilik / PII işleme**
- **Güvenli UX / kullanılabilir güvenlik** — /dashboard bulgusu tam burada yaşıyor
- **Açık kaynak yönetişimi + fonlama**: AGPL, NLnet/NGI, sürdürülebilirlik
- **Tekrarlanabilir bilim / değerlendirme metodolojisi** — "negatif kontrol" tezine bağlanır
- **Akademik mekanlar**: USENIX Security, IEEE S&P, NDSS, PoPETs, ACM CCS

## B8 — Kaynak haritası (nereden kazınacak) + doğrulama kuralı
- **Akademik**: arXiv (cs.CR, cs.AI), USENIX/IEEE S&P/NDSS/PoPETs, Stanford CRFM, Berkeley Sky/RISE
- **HF**: papers sayfası, modeller, forumlar
- **Reddit**: r/LocalLLaMA, r/netsec, r/MachineLearning, r/selfhosted, r/privacy
- **Forum/topluluk**: Ollama GitHub+Discord, Hacker News, lobste.rs, Simon Willison blog, LessWrong
- **Python güvenlik**: PyPI advisory DB, Bandit, PyCQA, python-security
- **Twitter/X**: adı geçen güvenlik+AI araştırmacıları
- **Kural (tekrar):** yerel = aday; en az 1 otoriter web kaynağıyla teyit → envanter.

---

## Araştırma günlüğü (uygula → düşün → tekrar)
Her döngü: (1) yerel model dalı genişletir [ADAY], (2) Claude web'de teyit/düzeltir [TEYİT],
(3) vetted maddeler aşağıya işlenir + başarı-sebebi/eşik notuyla. Sıra: B1 → B7 → B6 → B4 → B5 → B3 → B2 → B8.

---

# DÖNGÜ 1 — B1 vetted (2026-08-03)

**Boru hattı kanıtı (neden-sonuç):** yerel qwen2.5:7b klasik ilkeleri doğru verdi
(Saltzer-Schroeder, Bell-LaPadula, capability security) AMA ajan-spesifik güncel çerçeveleri
KAÇIRDI ve "MLOps/MLflow"u güvenlik çerçevesi diye UYDURDU. Güncel/doğru kısmı web+Claude
kapattı. → İş bölümü doğrulandı: yerel=klasik breadth, web+yargı=güncel+doğruluk.

## B1.1 — OWASP Top 10 for Agentic Applications **2026** [TEYİT]
En taze otoriter ajan-güvenlik çerçevesi (Black Hat Europe 2025'te açıklandı, 100+ uzman).
KASA'nın yaptığı işle 1:1 örtüşüyor — bu tesadüf değil, aynı problemin bağımsız haritası:

| Kod | Risk | KASA'daki karşılığı |
|---|---|---|
| **ASI01** | Agent Goal Hijack (prompt/instruction injection) | A1 aktörü; damıtma enjeksiyon savunması (olasılıksal — açık kalem) |
| **ASI02** | Tool Misuse & Exploitation | 6-araç allow-list + kapsam denetimi; batch amplifikasyon → 429 |
| **ASI03** | **Agent Identity & Privilege Abuse** (impersonation, role circumvention) | **Tam bu:** kimlik bağlama (F-IMP) + F-OWNER-SCOPE. Kapatıldı+canlı doğrulandı |
| **ASI04** | Agentic Supply Chain Compromise | src'de sıfır dinamik yükleme (A2 yok); B7 tedarik-zinciri disiplini |
| **ASI05** | Unexpected Code Execution | subprocess tek yerde (tray); eval/exec yok |
| **ASI06** | **Memory & Context Poisoning** | **KASA'nın kalbi:** kasa bir hafıza deposu; damıtma denetimsiz yazımı = açık kalem |
| **ASI07** | Insecure Inter-Agent Communication | yalnız-loopback; MCP adaptör air-gap (urlparse guard) |
| **ASI08** | Cascading Agent Failures | ajan-başı debi tavanı (DEBI) + rate limit |
| **ASI09** | Human-Agent Trust Exploitation | "yayına hazır değil" öz-beyanı; UX-güvenlik (B7) |
| **ASI10** | Rogue Agents (goal drift, reward hacking) | denetim zinciri (attribution) — ama damıtma yolu kapsam dışı |

**Sonuç:** KASA'nın kapattığı iki açık (ASI03, kısmen ASI02) 2026 çerçevesinde **1. sınıf
risk**; açık kalan iki alan (ASI06 damıtma, ASI01 enjeksiyon olasılığı) da adıyla listede.
Bu, NLnet başvurusu için güçlü sinyal: "adı konmuş 2026 risklerini ölçüp kapatıyoruz."

## B1.2 — OWASP Top 10 for LLM Applications **2025** [TEYİT]
Uygulama-merkezli; ajan listesini tamamlar.
- **LLM01 Prompt Injection** (#1, değişmedi) — A1
- **LLM02 Sensitive Information Disclosure** — redact/aggregate katmanı
- **LLM06 Excessive Agency** — tam-aracılık kaygısının OWASP adı
- **LLM07 System Prompt Leakage** (2025'te YENİ) — **/dashboard & /terms owner-token sızıntısı tam bu kategoriydi** (F-DASH); kapatıldı
- **LLM08 Vector & Embedding Weaknesses** (2025'te yeni) — KASA'da vektör yok (şimdilik kapsam dışı)
- **LLM10 Unbounded Consumption** — hız sınırı + DEBI tavanı

## B1.3 — Klasik referans-monitör / erişim-kontrol ilkeleri [TEYİT]
- **Saltzer & Schroeder 1975** — 8 ilke. KASA dili birebir buradan: *complete mediation*
  (tam-aracılık belgesi), *least privilege* + *fail-safe defaults* (deny-by-default),
  *economy of mechanism* (6 araç, dinamik yükleme yok), *psychological acceptability* (launcher UX)
- **Anderson 1972** — reference monitor: her erişim tek, atlatılamaz, doğrulanabilir noktadan.
  KASA'nın "istek yolu tam aracılı, süreç-içi değil" ölçümü tam bu çerçevenin dili.
- **Capability security / confused deputy** — F-DASH bir confused-deputy örneğiydi (owner
  token'ı yetkisiz çağırana servis etmek). Token'a-bağlı kimlik = capability'ye yaklaşma.
- **"Lethal trifecta"** (Simon Willison) — özel veri + kötü içerik maruziyeti + dışa
  iletişim aynı ajanda birleşince exfiltration. KASA: loopback air-gap dış-iletişimi keser.

## B1.4 — Kurumsal/ulusal çerçeveler [TEYİT — B2'de derinleşecek]
- **NIST**: AI RMF (AI 100-1), SSDF (SP 800-218), Zero Trust (SP 800-207 — "hiçbir istek
  varsayılan güvenilmez", require_owner'ın ilkesi)
- **MITRE ATLAS** — adversarial ML saldırı matrisi (red-team senaryolarını buna eşle)
- **ISO/IEC 42001 / 27001** — B2

**B1 eşik/başarı notu:** bu kategoride "geçti" ölçütü ikili değil olgunluk seviyesidir
(ASVS L1-L3). KASA bugün: istek-yolu aracılığı ~L2 (ölçüldü, canlı), süreç-içi ~L1 (açık
kalemler var). "Kanıtlanmış" demek için bağımsız denetim şart — henüz yok, dürüst sınır.

---

# DÖNGÜ 2 — B6 (pazar: başarılı/başarısız + güncel yenilikler) vetted (2026-08-03)

**Boru hattı kanıtı (daha da net):** yerel qwen2.5:7b B6'da B1'den de KÖTÜ çıktı — "Qwen'i
runner", "Mem0'ı recall app" sandı, kategorileri karıştırdı. Girişim manzarası tümüyle
web'den doğrulandı. → Ders: olgusal/güncel pazar bilgisi ASLA yerel modele bırakılmaz.

## B6.1 — Traction (2026, web-teyitli)
| Ürün | Ne | Traction | Başarı sebebi |
|---|---|---|---|
| **Ollama** | yerel model runner+API | 100k+ yıldız, fiili standart, MLX backend | dağıtım + hafiflik + API ekosistemi |
| **LM Studio** | masaüstü testbench | ticari-lisans şartını kaldırdı | cilalı UX; Ollama'yla tamamlayıcı |
| **Mem0** | vektör-öncelikli hafıza katmanı | $24M, AWS Agent SDK'nın münhasır hafızası, 186M çağrı/Q3, 51k yıldız | **dağıtım** (AWS) + bolt-on DX |
| **Letta** (eski MemGPT) | OS-tarzı katmanlı hafıza runtime | $10M/$70M, Jeff Dean+Clem Delangue, 13k yıldız, self-host | araştırma soyu + self-hostable |
| **MemPalace** | yerel-öncelikli hafıza | 54k yıldız, MIT, SIFIR API, LongMemEval %96.6 | **yerel-first + açık + benchmark** |
| **Zep** (Graphiti) | zamansal bilgi grafiği | bulut/SaaS-eğilimli (tek kaynak, teyitsiz) | grafik-tabanlı fark |

## B6.2 — Başarısızlık vakası (KASA için en önemli ders): **Rewind → Limitless → Meta → kapanış**
- Rewind: her-an kişisel-recall uygulaması (KASA'ya çok yakın konum). 2024'te Limitless'a
  rebrand + $99 donanım pendant pivotu. **Meta satın aldı; Mac app 19 Aralık 2025'te kapandı.**
- Ölüm sebebi (kaynak): *"donanım pivotu, bulut bağımlılığı, ve her gizlilik vaadini çürüten
  bir Meta satın alımı."* Kullanıcılar yandı → yerinde-çalışan alternatifler (Screenpipe, LUCI) doğdu.
- **KASA dersi (neden-sonuç):** gizlilik bir *vaat* değil, *mimari* olmalı. Bulut bağımlılığı +
  satın-alınabilir şirket = gizlilik her an bozulabilir. KASA'nın **yalnız-loopback + AGPL +
  cihaz-üstü + bulutsuz** duruşu tam bu yaranın panzehiri: gizlilik satın-alımla bozulamaz
  çünkü veri hiç çıkmıyor ve lisans türev-kapatmayı engelliyor.

## B6.3 — Başarı-sebebi taksonomisi (sentez)
1. **Dağıtım** (Mem0→AWS, Ollama→her yer) > ürün parlaklığı.
2. **Araştırma soyu → güven** (MemGPT paper → Letta).
3. **Yerel-first + açık + benchmark → bulutsuz topluluk** (MemPalace, Ollama).
4. **Gizlilik = mimari zorunluluk**, vaat değil (Rewind'in çöküşü bunu kanıtladı).

## B6.4 — KASA konumlandırması (en kritik sentez)
- Hafıza-katmanı alanı (Mem0/Zep/Letta) **kalabalık** ve çoğu **bulut/DX-odaklı**.
- Yerel-recall alanında yüksek-profilli bir **başarısızlık** (Rewind) gizlilik-duyarlı
  kullanıcıları yaktı → gerçek-yerel/egemen hafızaya **kanıtlanmış talep**.
- **KASA'nın farkı hafıza KALİTESİ değil** (MemPalace zaten yerelde benchmark lideri) —
  **hafızaya ARACILI + DENETLENEN + EGEMEN erişim.** Hiçbir hafıza oyuncusu güvenlik/aracılık
  katmanına odaklanmıyor. KASA bir *kasa* (erişim kontrolü + audit + tam-aracılık), bir
  *hafıza-kalitesi* oyunu değil. Bu, kalabalık pazarda boş bir niş.
- **Moat:** Rewind dersi KASA'nın AGPL + yalnız-yerel duruşunu bir güven hendeğine çeviriyor:
  mimariyle-zorlanan gizlilik, satın-alımla bozulamaz.
