# Ajan Hafıza Güvenliği — güncel durum, en yeni yaklaşımlar, felsefe (2026-08-04)

> **Amaç:** KASA'nın **geride** olduğu alanlarda (kriptografik-doğrulama, zehirleme-savunması,
> capability/dataflow, cihaz-üstü egemenlik/TEE) güncel konjonktürü, en yeni teknik yaklaşımları ve
> altlarındaki **felsefe/düşünce-şeklini** haritalamak; KASA'nın nerede hizalı / nerede geride olduğunu koymak.
>
> **Yöntem (dürüst iş bölümü):** yerel model (`qwen2.5:7b`) **KASA'nın agent-bridge'i üzerinden**
> (`/v1/agent/chat`, owner + `gate.validate_message` + tek-akış — dogfood) bir **arama-planı iskeleti**
> çizdi [ADAY]; canlı kaynaklar **WebSearch/WebFetch** ile getirilip doğrulandı [TEYİT]. Uydurma URL yok.

## Yerel taslağın değerlendirmesi (KASA kapısından geçti)
Yerel model 4 alt-konuyu **jenerik** doğru buldu (ZKP, Homomorphic Encryption, Trust Scores, TEE, Capability-based
Security) — ama **hiçbir güncel-spesifik projeyi bilemedi** (MemLineage, Notarized Agents, CaMeL, Progent, MemGuard,
Portable Agent Memory, Zero-Trust-for-Agents). Bu, boru hattı kuralını kanıtlıyor: **yerel = jenerik iskelet;
güncel-olgu = web.** Yerel modeli "daha güncel bul" diye yeniden yönlendirmek işe yaramaz (gezemez); onun rolü
iskelet + (istenirse) doğrulanmış bulguları düzyazıya dökmek.

---

## 1) Kriptografik / doğrulanabilir hafıza — **en aktif alan**
| Proje/yaklaşım | Ne | Olgunluk |
|---|---|---|
| **MemLineage** [2605.14421](https://arxiv.org/html/2605.14421) | RFC-6962 Merkle log + **per-entry Ed25519 imza** + ağırlıklı **türetme-DAG** (hangi girdi hangi hafızayı etkiledi) | öneri/kanıtlı |
| **Notarized Agents** [2606.04193](https://arxiv.org/pdf/2606.04193) | **MCP governance proxy**: her araç çağrısına Ed25519 imzalı makbuz, hash-linked tamper-evident zincir; Ed25519 + **ML-DSA-65 (post-quantum)** + SHA-256 + Merkle | öneri |
| **Immutable Memory Systems** [2506.13246](https://arxiv.org/html/2506.13246) | Blockchain-indexed, **ECDH-keyed Merkle chains**; "hafıza = ledger, cache değil" | öneri |
| **Portable Agent Memory** [2605.11032](https://arxiv.org/html/2605.11032) | Merkle-DAG provenance + capability-scoped erişim + injection-dirençli re-hydration; %100 değişiklik-tespiti | öneri |

**Felsefe/düşünce-şekli:** *"Hafıza bir cache değil, bir **ledger**"* — protokolle zorlanan, kriptografiyle bağlı,
formal mantıkla kısıtlı; çıktıları **kanıtlanabilir türetilmiş, zamansal-çapalı, sonradan-revize-edilemez**. Revizyon
= yeni imzalı kayıt (yıkıcı değil, tarihlenmiş).
**KASA konumu:** KASA'nın hash-zinciri tamper-evident **ama depo-içi**; **per-entry Ed25519 imza yok, Merkle yok,
türetme-DAG yok, post-quantum yok.** → **GERİDE.** Notarized Agents = KASA'nın tam ikizi (MCP + imzalı makbuz); benimsenecek referans.

## 2) Hafıza zehirleme savunması (G3/ASI06)
- **MemGuard** [repo](https://github.com/ac12644/MemGuard): Mem0/Zep/Letta/LangMem'i **gerçeğe-karşı** doğrular; trust-score + **karantina** + tamper-proof audit. (= senin "ikinci değerlendirici + karantina" fikrin, ürün.)
- **A-MemGuard / MOSS** [2607.04391](https://arxiv.org/pdf/2607.04391): proaktif doğrulama + çift-hafıza / auditable agentic memory.
- **MemLineage türetme-DAG**: zehri **atıfla** izler (hangi kaynak besledi).
**KASA konumu:** trust-score/karantina/gerçeğe-karşı-doğrulama **yok** → **GERİDE**; ama audit-zinciri + provenance
altyapısı bunları eklemeye uygun. Dürüst sınır: **semantik-geçerli zehir hâlâ endüstri-açık** (MINJA sanitizasyonu deler).

## 3) Capability / dataflow / quarantined-LLM
- **CaMeL** [2503.18813](https://arxiv.org/abs/2503.18813): Privileged+Quarantined LLM + capability + dataflow izleme.
- **Progent** [2504.11703](https://arxiv.org/pdf/2504.11703): ajanlara privilege control.
- **Design Patterns** [2506.08837](https://arxiv.org/abs/2506.08837): Action-Selector, Plan-Then-Execute, Dual-LLM…
**KASA konumu:** deny-by-default scope + token-kimlik = **hizalı**; **dataflow/taint + Quarantined-LLM yok** → o kısımda geride.

## 4) Cihaz-üstü egemenlik + Confidential Computing (TEE)
- **OpenPcc** [2606.11145](https://arxiv.org/html/2606.11145): commodity TEE'lerde açık/gizli LLM servisi. **Apple Private Cloud Compute** (tüketici ölçeği), **Google Private Cloud AI** (AMD SEV-SNP+TPU), **Anthropic** enclave tasarımı, **Nvidia Hopper CC** (+Intel TDX/AMD SEV-SNP, <%7 perf kaybı).
- **Survey: Confidential Computing for Agentic AI** (4 May 2026): TEE'yi ajan ihtiyaçlarına (plan, araç, kalıcı hafıza, MCP delege) eşliyor. **Açık bulgu:** *"henüz üretim-ajan-AI için tutarlı bir uçtan-uca güvenlik zemini bağlayan yaygın bir çerçeve yok."*
- **Kritik uyarı:** [Enclaves neyi koruyamaz](https://www.llm-hacking.com/hacks/confidential-computing-agentic-ai.md/) — TEE **kullanımdaki-veriyi** korur ama **enjeksiyona / ele geçmiş ajan mantığına karşı korumaz**. TEE ≠ enjeksiyon savunması.
**KASA konumu:** TEE, KASA'nın **G1/A4** boşluğunu (aynı-OS'un vault anahtarını/çıkarımını koklaması) **kısmen** kapatabilir — sub-7B model + CPU TEE (Intel SGX) fizibil. Ama enjeksiyon/mantık katmanını çözmez. Şu an KASA'da **yok** → egemenlik-derinliğinde geride, ama fırsat somut.

---

## Felsefe/mindset — konjonktürün yönü (kullanıcının asıl sorusu)
1. **Zero-Trust for AI Agents (Anthropic, Mayıs 2026):** never-trust/assume-breach/least-privilege → kriptografik ajan-kimliği, **kısa-ömürlü token**, deny-by-default, scoped izin, sandboxed yürütme. **Bu birebir KASA'nın duruşu** — artık Anthropic adını koydu. KASA felsefede **hizalı/önde**; alanın eklediği: kısa-ömürlü token + kriptografik imza + sandbox (KASA'da eksik). [Cequence Agentic Zero Trust](https://www.cequence.ai/wp-content/uploads/2026/05/Agentic-Zero-Trust-Research-Paper-v3.pdf) · [Mneme "verify the diff"](https://mnemehq.com/insights/zero-trust-for-ai-agents-architectural-governance/).
2. **"Hafıza = ledger, cache değil":** imzalı, append-only, geri-yazılamaz tarih.
3. **Provenance/lineage-first:** her girdi türetme-soyağacı taşır ([Evidence Tracing survey 2606.04990](https://arxiv.org/pdf/2606.04990)).
4. **Assume-breach + verify-the-diff:** kimliği değil, **değişikliğin kendisini** doğrula.

## Sentez — KASA nerede (net)
- **Felsefede HİZALI/ÖNDE:** zero-trust, deny-by-default, token-kimlik, tam-aracılık — Anthropic'in adını koyduğu duruşu KASA zaten uyguluyor.
- **Uygulamada GERİDE:** per-entry Ed25519+Merkle imza, türetme-DAG lineage, trust-score+karantina, dataflow/quarantined-LLM, TEE (A4), post-quantum, kısa-ömürlü token.
- **Somut benimseme sırası (araştırmanın verdiği):** (1) Notarized-Agents-tarzı **Ed25519 imzalı MCP makbuzu + Merkle** (audit-zinciri zaten yakın), (2) MemLineage **türetme-DAG + karantina** (G3), (3) Dual/Quarantined-LLM, (4) sub-7B için **CPU-TEE** (A4 kısmi).

## Değerlendirme + yeniden-yönlendirme kararı
- Yerel taslak = jenerik iskelet (beklendiği gibi). Güncel-spesifik katman **web'den** geldi.
- **Yerel modeli "daha güncel ara" diye yönlendirmek anlamsız** (gezemez). Anlamlı yeniden-yönlendirme: yerel modele
  **bu doğrulanmış bulguları** verip düzyazı/özet ürettirmek (grounded drafting) — istenirse KASA kapısından yapılır.

## Dürüstlük iddiaları
- `local_model_via_kasa_gate: true` (qwen2.5:7b, /v1/agent/chat, owner+gate, 3 iter, 14s)
- `external_network_used: true` (WebSearch/WebFetch — açık literatür)
- `scores_or_probabilities_invented: false` · her proje/iddia kaynak-bağlı, olgunluk-etiketli
