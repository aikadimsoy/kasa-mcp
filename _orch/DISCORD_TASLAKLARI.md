# Discord notları — taslak

İki mecra, iki ayrı metin. Aynı metni ikisine atmak, ikisinde de yanlış okunur.

---

## 1. MCP Contributors Discord → `#security-ig`

**Davet:** https://discord.gg/6CSzBmMkjX

**Uyulması gereken kural (doğrulandı, modelcontextprotocol.io/community/communication):**
> *"Service or product marketing — keep discussions vendor-neutral; mentions of brands are discouraged except as examples relevant to the specification."*

**Tüzükten (doğrulandı):**
> *"The group is looking for contributors who will engage with proposals and help drive work forward rather than observe."*

Bu yüzden metin **ürünle değil bulguyla** açılıyor, marka en sonda ve "isterseniz" tonunda. Ayrıca bir **soru** soruyor — gözlemci değil katkıcı olmanın en ucuz yolu.

**Sıra önemli:** Bunu atmadan önce en az bir Office Hours'a katıl ve başkalarının önerilerine yorum yap. Soğuk giriş yapan bir hesap, kuralı çiğnemese bile "gelip link bırakan" diye okunur.

### Metin

```
Measured something on the ingest side of an MCP server that I think generalises past my
implementation, and I'd like a sanity check before writing it up as a proposal.

Setup: a server exposes a write tool. A component in the pipeline processes untrusted page
content and produces structured facts that get persisted. Injected text in that content
instructs the component to emit a fact the source does not support. Four local model
configurations, five runs each — 20/20 emitted the attacker's fact with confidence 1.0.

The part I'd like this group's read on: every authorization check passed. The writing agent
held the scope legitimately, the audit entry was valid and tamper-evident, nothing
malfunctioned. Permission mediation did exactly what it was specced to do, and it is not the
control that stops this. Authority and truth are different problems and the spec currently
only addresses the first.

Two questions:

1. Has content-origin propagation through tool results been considered? I went through the
   discussions and found the Agent Identity and Delegation thread, which is adjacent but
   about *who* called, not *where the content came from*. I may have missed prior art.

2. Is "provenance recorded at write time, surfaced at read time" the right shape, or does it
   just relocate the trust decision to whoever consumes the fact later?

Happy to bring this to an Office Hours as a deployment report if that's the right slot.
Probe source and raw results are public and reproducible — I'll link on request rather than
dropping it here.
```

**Not:** Link kasten yok. Birisi "nerede?" derse verirsin — bu, kural ihlali riskini sıfırlar ve ilgi olduğunu da kanıtlar.

---

## 2. AI Village Discord → `#research` veya `#tools-and-code`

**Davet:** https://discord.com/invite/rDhxjWa69
Önce `#start-here`'a kısa bir tanıtım yaz, "Villager" rolü açılsın.

Buranın öz-tanıtım politikası **yayımlanmamış**; `#tools-and-code` paylaşım için tasarlanmış görünüyor ama bu çıkarım, alıntılanmış kural değil. Yine de ton daha rahat, link doğrudan verilebilir.

### Metin

```
Built a local-first memory vault for AI agents on the premise that the model is never the
security boundary — authorization lives in deterministic code behind an MCP server. Then I
measured the attack that premise does not cover, and it's the more interesting result.

Injected page content gets the memory distiller to write an attacker-chosen *durable* fact
into the vault. Four configurations (hermes3:8b, qwen2.5 7b/3b, and a hardened Modelfile),
five runs each: 20/20. Every permission check passed — the agent legitimately holds the write
scope, and the hash-chained audit ledger faithfully records a valid entry containing a lie.
The broker mediates authority, not truth.

Three other probes in the same run, and the pattern surprised me: resistance isn't a ranking.
hermes3:8b is the strongest config on indirect injection (0/5 compromised) and the weakest on
tool poisoning (5/5). qwen2.5:7b is the exact inverse.

Raw data, probe source and the writeup, including three corrections I had to make to my own
methodology:
https://github.com/aikadimsoy/kasa-mcp/discussions/1

Not release-ready and says so in its own benchmark. Posting for critique, not users —
particularly on whether provenance marking is the right direction here.
```

---

## 3. Hugging Face veri seti kartına yönlendirme

Kartın en üstüne, başlığın hemen altına eklenecek satır. (Uygulamak için kısa ömürlü bir HF token turu gerekiyor — bir sonraki HF değişikliğiyle birlikte yapılabilir.)

```markdown
> **Context and full writeup:** this dataset records a finding from
> [KASA MCP](https://github.com/aikadimsoy/kasa-mcp) — a permission-brokered memory server —
> and the finding is that the broker does not stop the attack.
> Background, method and the corrections we had to make:
> [KASA MCP v0.1 — the attack our own broker does not stop](https://github.com/aikadimsoy/kasa-mcp/discussions/1)
```

---

## 4. GitHub — yapıldı

Depo "website" alanı tanıtım yazısına ayarlandı; About kutusunda bağlantı olarak görünüyor:
`https://github.com/aikadimsoy/kasa-mcp/discussions/1`

Açıklama zaten MCP ile açılıyor:
> KASA MCP — a permission-brokered MCP server for agent memory. Local-first, encrypted at the cell level, hash-chained audit. Research preview: we publish the attacks our own broker does not stop.

---

## Her iki metnin de uyduğu kural

Ne satıyorsun değil, **ne ölçtün** ile açılıyor; ve ikisi de bir soruyla bitiyor. Bu tesadüf değil: ekosistemin şu anki refleksi "MCP güvenliği" başlıklı tanıtımlara karşı sert (r/mcp bunu doğrudan yasaklıyor, MCP Discord vendor-neutral istiyor). Bulgu paylaşan biri o refleksi tetiklemez; ürün tanıtan biri tetikler.

En güçlü kartın da bu zaten: kendi mimarinin durduramadığı saldırıyı sen yayınlıyorsun. Bunu kimse pazarlama sanmaz.
