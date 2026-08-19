# Novelty Audit / Özgünlük Denetimi — 2026-08-05

**Verdict: our F-POISON finding is a replication. All three novelty claims were refuted.**
**Hüküm: F-POISON bulgumuz replikasyon. Üç özgünlük iddiamızın üçü de çürütüldü.**

Method / Yöntem: a 12-agent multi-modal public-source sweep (7 search streams + 3 adversarial
refutation lenses + synthesis + completeness critic), followed by hand-verification of three
primary sources. Agents were instructed explicitly: *"your job is not to flatter us; a finding
that we are unoriginal is more valuable than one that we are novel, because we are about to speak
publicly."*

> **This document invalidates statements in `docs/KNOWLEDGE_ARCHIVE.md` and `SECURITY.md`.**
> Correcting them is listed as open work in §7.
> **Bu belge, arşiv ve SECURITY.md'deki bazı ifadeleri geçersiz kılar.** Düzeltmeleri §7'de.

---

## 0. How to read this / Bu belge nasıl okunur

**EN.** Every section below is written as three things, in this order:

- **CAUSE** — what is actually true, with the evidence. Not opinion.
- **JUSTIFICATION** — why that fact matters to us specifically. The consequence.
- **NEED** — what must therefore be done, or stopped.

This shape is deliberate. A finding without a stated consequence gets forgotten; a consequence
without a stated action gets admired and ignored.

**TR.** Aşağıdaki her bölüm şu üçlüyle yazıldı:

- **NEDEN** — gerçekte ne doğru, kanıtıyla. Görüş değil.
- **GEREKÇE** — o gerçek bizim için neden önemli. Sonucu.
- **İHTİYAÇ** — dolayısıyla ne yapılmalı ya da neye son verilmeli.

Bu biçim kasıtlı. Sonucu yazılmamış bir bulgu unutulur; eylemi yazılmamış bir sonuç takdir edilip
rafa kalkar.

---

## 1. The headline / Ana hüküm

### CAUSE / NEDEN

**EN.** Agent memory poisoning is a crowded, consolidating research area — not a sparse one. It
went from a blog demonstration (Rehberger, 2024-05) to a NeurIPS paper (AgentPoison, 2024) to an
ICLR benchmark module (ASB, 2025) to an OWASP category, to at least eight 2026 preprints attacking
or defending our exact pipeline shape. Franziska Roesner's group (UW) is in it.

**TR.** Ajan hafıza zehirlenmesi kalabalık ve konsolide olan bir alan — seyrek değil. Blog
gösteriminden (Rehberger, 2024-05) NeurIPS makalesine, oradan ICLR ölçüt modülüne ve OWASP
kategorisine geçmiş; 2026'da bizim hat şeklimize saldıran ya da onu savunan en az sekiz ön-baskı
var. Roesner'ın grubu da alanda.

### JUSTIFICATION / GEREKÇE

**EN.** We were one message away from telling a stranger we fill a gap that a single search
falsifies. That would have cost more credibility than the finding was ever worth, and it would
have been the exact failure our own methodology exists to prevent: using an unverified assumption
as if it were measured.

**TR.** Bir yabancıya "boşluğu dolduruyoruz" demeye bir mesaj kalmıştı ve tek bir arama bunu
çürütüyor. Bu, bulgunun değerinden fazlasına mal olurdu — üstelik tam da kendi metodolojimizin
önlemek için var olduğu hata: doğrulanmamış bir varsayımı ölçülmüş gibi kullanmak.

### NEED / İHTİYAÇ

**EN.** Never make a novelty claim without a prior-art search first. Treat "I haven't heard much
about this" — ours or anyone's — as a statement about a vantage point, never about a field.

**TR.** Öncel sanat taraması yapmadan özgünlük iddiası kurulmayacak. "Bu konuda pek bir şey
duymadım" cümlesi — bizimki de başkasınınki de — bir **bakış açısı** beyanıdır, alan hakkında bir
tespit değil.

---

## 2. Three refuted claims / Çürütülen üç iddia

### 2.1 "Nobody has published measured data" — FALSE

**CAUSE / NEDEN**

| Work | URL | Date | Numbers |
|---|---|---|---|
| AgentPoison (NeurIPS 2024) | arxiv.org/abs/2407.12784 | 2024-07-17 | ≥80% ASR at <0.1% poison rate |
| Agent Security Bench (ICLR 2025) | arxiv.org/abs/2410.02644 | 2024-10-03 | 84.30% top avg ASR; **includes a memory-poisoning module** |
| **MINJA** | arxiv.org/abs/2503.03704 | 2025-03-05 | **98.2% ISR / 76.8% ASR**, 9 independent experiments per config |
| Fake Memories (ElizaOS) | arxiv.org/abs/2503.16248 | 2025-03-20 | ~55.1% ASR |
| **MPBench** | arxiv.org/abs/2606.04329 | 2026-06-03 | **3,240 attack + 2,997 benign cases**; 50.46% ASR / 41.05% RSR |
| Manufactured Confidence | arxiv.org/abs/2606.29279 | 2026-06-28 | targets the consolidation/distiller stage specifically |
| GhostWriter | arxiv.org/abs/2607.06595 | 2026-07-06 | ~98% injection / ~60% activation |
| MemSecBench | arxiv.org/html/2607.27080 | 2026-07-29 | 310 cases, 24 configurations |

**JUSTIFICATION / GEREKÇE**

**EN.** Our n=20 (4 configs × 5 runs) is small against 3,240 cases and 9-experiments-per-config.
A reviewer reads our number and asks about statistical power before they ask about the finding.

**TR.** n=20'miz, 3.240 vakanın ve yapılandırma başına 9 deneyin yanında küçük kalıyor. Hakem
bulguyu sormadan önce istatistiksel gücü sorar.

**NEED / İHTİYAÇ**

**EN.** Cite this literature ourselves, in our own words, before anyone hands it to us. Being the
one who names MINJA and MPBench reads as current; being told about them reads as uninformed.

**TR.** Bu literatürü **kendimiz** sayacağız, biri bize uzatmadan önce. MINJA ve MPBench'i anan
taraf olmak "güncel" okunur; onları öğrenen taraf olmak "habersiz".

### 2.2 "Permission mediation covers authority, not truth" is our contribution — FROM 1987

**CAUSE / NEDEN**

- Saltzer & Schroeder, complete mediation (1975)
- **Clark–Wilson internal vs external consistency (IEEE S&P, 1987)** — this exact distinction
- Williams & LaPadula (1995)
- **CaMeL §3.1, Google DeepMind, 2025-03-24**, verbatim:
  > *"CaMeL doesn't aim to defend against attacks that do not affect the control nor the data
  > flow. In particular, we recognize that it cannot defend against text-to-text attacks which
  > have no consequences on the data flow, e.g., an attack prompting the assistant to summarize
  > an email to something different than the actual content of the email"*
- Restated four more times in the field in the eight weeks before our measurement.

**JUSTIFICATION / GEREKÇE**

**EN.** A security engineer reading our sentence says "yes — that is why integrity models exist."
Presenting a 39-year-old distinction as an insight is the single fastest way to be dismissed by
the audience we most want.

**TR.** Cümlemizi okuyan bir güvenlik mühendisi "evet, bütünlük modelleri bunun için var" der.
39 yıllık bir ayrımı içgörü diye sunmak, en çok istediğimiz okuyucu tarafından reddedilmenin en
hızlı yolu.

**NEED / İHTİYAÇ**

**EN.** Keep the sentence — it is true and it frames the work — but **attribute it**. Crediting
Clark–Wilson and CaMeL §3.1 costs nothing and buys the cheapest credibility available.

**TR.** Cümleyi tutalım — doğru ve işi çerçeveliyor — ama **atıfla**. Clark–Wilson ve CaMeL §3.1'i
anmak bedava ve odada kazanılabilecek en ucuz itibar.

### 2.3 "Nobody named the utility cost of taint enforcement" — FALSE

**CAUSE / NEDEN**

- **CaMeL abstract (2025-03):** *"solving 77% of tasks with provable security (compared to 84% with an undefended system)"*
- **Fides (2025-05-29):** *"the task completion rate drops significantly by up to 40 % for gpt-4o"*
- **Louck (2026-06-23):** *"Driving laundering-ASR to 0% requires θ=0, which blocks every action (utility 0%)"*
- MemLineage has a section literally headed *"Where coarse taint loses utility"*
- The observation itself: **Willison, April 2023.**

**JUSTIFICATION / GEREKÇE**

**EN.** The tradeoff we thought we had spotted is a headline number in the flagship paper's
abstract. Worse, we were going to offer it to our correspondent as a gift.

**TR.** Fark ettiğimizi sandığımız takas, alanın amiral gemisi makalesinin özetinde sayı olarak
duruyor. Dahası, onu muhatabımıza **hediye** olarak sunacaktık.

**NEED / İHTİYAÇ**

**EN.** Delete "nobody has worked this out." If we ever publish a utility number it must come from
an actual strictness sweep with legitimate-task pass rates — which is exactly what those four
papers did and we have not.

**TR.** "Kimse bunu hesaplamadı" silinecek. Bir fayda sayısı yayımlayacaksak, gerçek bir katılık
taraması ve meşru-görev geçiş oranıyla gelmeli — ki o dört makale tam olarak bunu yaptı, biz
yapmadık.

---

## 3. Three primary sources, hand-verified / Elle doğrulanan üç birincil kaynak

### 3.1 MemTxn — adjacent, NOT preempting / komşu, ÖNCELEMİYOR

> **Amended 2026-08-05 after measurement.** This section first read *"preempts us"*. Measuring the
> mechanism instead of trusting its abstract changed the conclusion. The original reasoning is kept
> below; the correction follows it.
> **Ölçümden sonra düzeltildi.** Bu bölüm önce *"bizi önceliyor"* diyordu. Mekanizmayı özetine
> güvenmek yerine ölçmek sonucu değiştirdi.

arXiv:2607.27834 · Cui, Tang, Yao, Meng, Ma, Jia · **2026-07-30** (six days before our exchange)

**CAUSE / NEDEN.** Verbatim from the abstract:
> *"MemTxn verifies whether an update is supported by its source."*
> *"The system uses Ordered PatchTest to validate writes…"*
> *"On an item-disjoint audit, MemTxn accepts all 60 supported originals and rejects all 179 hard negatives."*

**JUSTIFICATION / GEREKÇE**

**EN.** Both our observation ("provenance verifies existence, not support") and the defense
experiment we were about to propose are taken. But the gap that remains is real: their evaluation
is an *item-disjoint audit* — supported originals versus hard negatives. That is a **detector
benchmark, not an adversarial evaluation against an adapting attacker.** And it runs on
LongMemEval-S / LoCoMo / MemoryAgentBench, not against a permission broker.

**TR.** Hem gözlemimiz hem önereceğimiz deney alınmış. Ama kalan boşluk gerçek: değerlendirmeleri
*item-disjoint audit* — desteklenenlere karşı zor negatifler. Bu bir **dedektör ölçümü**, uyum
sağlayan saldırgana karşı düşmanca değerlendirme değil. Ve bir izin brokerine karşı koşulmamış.

**NEED / İHTİYAÇ**

**EN.** Determine mechanically whether Ordered PatchTest catches *our* payload — a fabrication
citing a real but non-supporting event. If it catches it, our move is to **implement and measure a
published defense in a local-first substrate with 7–8B models**, which nobody has done. If it
misses it, we have an adaptive-attacker result against a six-day-old defense. Either answer is
work worth doing; neither is an assertion we may make today.

**TR.** Ordered PatchTest'in **bizim** yükümüzü yakalayıp yakalamadığı mekanik olarak
belirlenecek. Yakalıyorsa hamlemiz *yayımlanmış bir savunmayı yerel-öncelikli zeminde 7–8B
modellerle uygulayıp ölçmek* — ki bunu kimse yapmadı. Kaçırıyorsa elimizde altı günlük bir
savunmaya karşı uyum sağlayan-saldırgan sonucu olur. İkisi de yapılacak iş; ikisi de bugün
iddia edilebilecek şey değil.

### 3.2 Bad Memory — NOT a contradiction / çelişki DEĞİL

arXiv:2607.14611 · Gadgil, Alexander, Sunku, Roesner (UW) · 2026-07-16

**CAUSE / NEDEN.** Verbatim from the abstract:
> *"although it is difficult to make an agent overwrite its own memory files using untrusted
> external content, payloads already planted in those files can successfully attack current and
> future sessions."*

Their setup: Claude Code and Codex — **coding agents being subverted into overwriting their own
memory files.** Ours: a distiller whose designed job is to write facts from content.

**These do not contradict. They are different write paths:**

| | Bad Memory | KASA |
|---|---|---|
| Writing is | an **exception** the agent must be subverted into | the **designed function** |
| Injection must | redirect the agent away from its task | only change *what* is written |
| Result | rarely succeeds | 20/20 |

**JUSTIFICATION / GEREKÇE**

**EN.** The 12-agent synthesis flagged this as *"the most interesting thing you have — lead the
technical part with it."* Reading the primary source for thirty seconds showed it is a misreading.
Had we published it, a competent reader catches it immediately, and every other claim in the
message inherits the doubt.

**TR.** 12 ajanlık sentez bunu *"elinizdeki en ilginç şey, teknik kısmı bununla açın"* diye
işaretlemişti. Birincil kaynağı otuz saniye okumak yanlış okuma olduğunu gösterdi. Yayımlasaydık
yetkin bir okuyucu anında yakalar ve mesajdaki diğer her iddia bu şüpheyi devralırdı.

**NEED / İHTİYAÇ**

**EN.** Never let a synthesis — ours or an agent's — stand in for a primary source on a claim we
intend to publish. The narrower observation that survives (*the design of the write path
determines exploitability*) is already published anyway, in MPBench: *"agents designed to write
and retrieve memory more aggressively are more exploitable."*

**TR.** Yayımlayacağımız bir iddiada hiçbir sentez — bizimki de ajanınki de — birincil kaynağın
yerine geçmeyecek. Ayakta kalan dar gözlem (*yazma yolunun tasarımı sömürülebilirliği belirler*)
zaten MPBench'te yayımlanmış.

### 3.3 MPBench — verified, and our only strengthened ground / doğrulandı, tek güçlenen yerimiz

arXiv:2606.04329, from the full text

**CAUSE / NEDEN.** Verbatim, §2.3.3 and Appendix A.1:
> *"No Write-Path Validation. There is typically no validation step between the memory write
> decision and persistent memory storage."*
> *"Memory writes are executed through direct storage operations without any intermediate validation."*

And decisively: **neither evaluated system (OpenClaw, HERMES) implements authorization or
permission controls on the memory write path.**

Their attack class 4, *Policy-Conformant Fact Injection* (§3.2):
> *"The attacker presents fabricated information as legitimate knowledge without explicit
> instructions, structured to satisfy the agent's vague retention policy as world facts or
> user-specific statements."*

**JUSTIFICATION / GEREKÇE**

**EN.** Our payload is exactly that class. The difference is precise and defensible: theirs
satisfies a **vague retention policy**, ours satisfies a **deterministic allow-list**. So the claim
"we attacked the recommended defense instead of its absence" is verified — it is an increment on a
named class, not a discovery.

**TR.** Yükümüz tam olarak o sınıf. Fark kesin ve savunulabilir: onlarınki **muğlak bir saklama
politikasına**, bizimki **deterministik bir izin listesine** uyuyor. Yani "tavsiye edilen savunmayı
kurup ona saldırdık, yokluğuna değil" iddiası doğrulandı — adı konmuş bir sınıf üzerinde bir
**artım**, keşif değil.

**NEED / İHTİYAÇ**

**EN.** Say "increment" out loud, and cite MPBench for the class name. Claiming discovery of a
class someone benchmarked with 3,240 cases two months earlier is the one move that would make the
increment worthless.

**TR.** "Artım" kelimesini açıkça kullanacağız ve sınıf adı için MPBench'e atıf yapacağız. İki ay
önce 3.240 vakayla ölçülmüş bir sınıfı keşfetmiş gibi davranmak, artımı değersizleştirecek tek
hamle.

---

## 4. What must never be claimed / Kamuya asla söylenmeyecekler

| Sentence to delete / Silinecek | Refuting evidence / Çürüten kanıt |
|---|---|
| "We fill a measurement gap" | MINJA 98.2%, 2025-03 |
| "Permission mediation covers authority, not truth" *as ours* | Clark–Wilson 1987 · CaMeL §3.1 |
| "Provenance verifies existence, not support" *as new* | MemTxn 2026-07-30 · ALCE 2023 |
| "Permission-gated memory had not been adversarially tested" | Misattribution Gap: zero detections across 510 checkpoints |
| "Persistent writes are outside agent-security benchmarks" | ASB (ICLR 2025) includes a memory-poisoning module |
| "Nobody measured the utility cost of taint" | CaMeL 77%/84% · Fides up to 40% |
| Bare "20/20" without conditions | 2601.05504: realistic conditions *dramatically* reduce effectiveness |
| "We contradict Bad Memory" | **We do not — different write path** (§3.2) |

And **C2PA Explainer 2.4 §7.2** already publishes our signed-receipt observation, verbatim:
> *"provenance information alone cannot tell you whether the digital content is true, accurate or factual"*

---

## 5. What survives / Ayakta kalan

**CAUSE / NEDEN.** Every attack in the literature targets stores with **no write-path validation** —
MPBench says so itself. We built the recommended defense and attacked it, with a negative control:
the naive payload was **blocked** by the namespace allow-list; a namespace-conformant variant of the
same fabrication passed **every** deterministic gate and committed to the live profile with a valid
Ed25519 chain entry and a clean success report.

**JUSTIFICATION / GEREKÇE**

**EN.** "Found blocked → adapted → passed" is stronger evidentiary structure than the
single-instance demonstrations in this space and than most of the papers, which run against ungated
pipelines. It is the one place we beat published work — on **method**, not on novelty or on N.

**TR.** "Engellendi → uyarlandı → geçti" yapısı, bu alandaki tek-örnek demo'lardan ve kapısız
hatlara koşan çoğu makaleden daha güçlü kanıt yapısı. Yayımlanmış işi geçtiğimiz tek yer burası —
**yöntemde**, özgünlükte ya da örneklem büyüklüğünde değil.

**NEED / İHTİYAÇ**

**EN.** Publish the payload pair and the full gate trace as an artifact a stranger can reproduce in
ten minutes. Unpublished, it is an anecdote. This is the highest-value single task on the list.

**TR.** Yük çiftini ve tam kapı izini, bir yabancının on dakikada tekrarlayabileceği bir esere
çevireceğiz. Yayımlanmazsa anekdot kalır. Listedeki en yüksek değerli tek iş bu.

---

## 6. Mandatory self-caveats / Zorunlu kendi-itiraflarımız

**EN.** Stated by us, before anyone asks. A caveat we volunteer is credibility; the same caveat
extracted from us is a retraction.

**TR.** Sorulmadan, kendimiz söyleyeceğiz. Gönüllü verilen çekince itibardır; sökülüp alınan aynı
çekince geri adımdır.

| Caveat | Why it matters |
|---|---|
| **n=20** (4 configs × 5 runs) | MINJA: 9 independent experiments per config; MPBench: 3,240 cases |
| **Clean-memory condition** | 2601.05504 shows realistic conditions reduce effectiveness sharply |
| **Verbatim-marker grading** | May measure copying fidelity rather than induced false belief |
| **No benign pass rate** | Without an operating point, "the gates are not weak" is unsupported |
| **We measured the write** | 2605.08442 shows storage ASR (>97.5%) and execution ASR (0–95%) diverge |

---

## 7. Open work, organised by need / Açık işler, ihtiyaca göre

### 7.1 Unconditional — required in every branch / Koşulsuz — her dalda gerekli

| | Task | Need it serves |
|---|---|---|
| **B1** | Re-run the 20/20 with pre-existing legitimate memory in the store | The number is indefensible until this runs. One condition change; either answer is publishable. |
| **B2** | Add a paraphrase condition to the grader | We do not currently know whether we measure copying or belief. |
| **B3** | Measure the benign write pass rate | No operating point means no defensible claim about the gates. |
| **C1** | Turn the payload pair + gate trace into a reproducible artifact | Our only surviving asset is currently unpublished. |

### 7.2 Record correction — required because of this document / Kayıt düzeltmesi

**EN.** Our own published archive now contains claims this audit refutes. Leaving them is exactly
the failure mode we spent the session hunting: a record that no longer matches what we know.

**TR.** Yayımladığımız arşiv, bu denetimin çürüttüğü iddialar içeriyor. Bırakmak, bütün oturum
avladığımız hatanın ta kendisi olur: bildiğimizle uyuşmayan bir kayıt.

- `docs/KNOWLEDGE_ARCHIVE.md` idea #11 ("A verifiable chain is not a true claim") → must be
  attributed to C2PA §7.2 and Clark–Wilson, not carried as our principle
- `SECURITY.md` F-POISON → add field context and the "replication + increment" framing
- Both documents → anywhere F-POISON currently reads as a finding without prior art

### 7.3 Owner decisions / Sahip kararları

- **A4 — resolved conservatively, pending confirmation.** The r/mcp comment `p0xmazq`
  (2026-07-31, *"The auth succeeds. The call succeeds. The emptiness is the lie."*) was flagged
  by the completeness critic as stylistically close to our own house voice. Authorship is
  **unconfirmed**. Until the owner confirms it is *not* ours, it is **struck from the evidence
  base and must not be cited as third-party prior art** — citing our own words back as
  independent corroboration would be misrepresentation, and the refutation does not depend on it
  (MINJA alone is sufficient). No claim in this document rests on it.
  *Yazarlığı doğrulanmadı; sahibi "bizim değil" diyene kadar kanıt tabanından ÇIKARILDI. Kendi
  sözümüzü bağımsız teyit gibi göstermek yanlış beyan olurdu ve çürütme buna dayanmıyor.*
- **D1** — namespace bypass: document as a known limit / implement MemTxn-style support checking /
  quarantine untrusted-derived facts. **Depends on §3.1.**
- **D2** — push the pending commits?

### 7.4 Running / Koşan iş

A Fable 5 agent is determining whether MemTxn's Ordered PatchTest and OWASP Agent Memory Guard
catch our specific payload. **If MemTxn catches it, that is the most useful answer, not the least
—** it converts our next move from attacking a defense to implementing and measuring a published
one in a substrate nobody has tested.

---

## 8. Method note / Yöntem notu

**EN.** This audit is the clearest example of what the project does best: we tried to refute our
own claim *before* speaking publicly, and it broke. More telling still, the 12-agent synthesis
named a "most valuable finding" (the Bad Memory contradiction) that turned out to be **a misreading
correctable in thirty seconds by opening the primary source.** We had to audit our own instrument
as well as ourselves.

Our value is not in originality. It is in method. The reviewer's only compliment was exactly that:
our negative control is *"stronger evidentiary structure than anything in row (b) and than most of
row (a)."*

**TR.** Bu denetim, projenin en iyi yaptığı şeyin en net örneği: kamuya konuşmadan **önce** kendi
iddiamızı çürütmeye çalıştık ve çürüdü. Daha da öğreticisi, 12 ajanlık sentezin "en değerli
bulgunuz" dediği madde, **birincil kaynağı açınca otuz saniyede düzelen bir yanlış okuma** çıktı.
Kendimizi denetlerken aracımızı da denetlemek zorunda kaldık.

Değerimiz özgünlükte değil, yöntemde.

---

Author / Yazar: [@aikadimsoy](https://github.com/aikadimsoy) · Repository: <https://github.com/aikadimsoy/kasa-mcp>
