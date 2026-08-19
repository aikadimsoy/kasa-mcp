# APAS / cloister yazarına yanıt — taslak

**Durum: GÖNDERİLMEDİ.** Bekleyen şart **çözüldü** ve metin ona göre **yeniden yazıldı**
(§Özgünlük koşulu). Kalan tek şey sahip onayı.
Tarih: 2026-08-05 · Yazar: [@aikadimsoy](https://github.com/aikadimsoy)

---

## Bağlam — kim, ne dedi

Biri KASA duyurumuza yanıt yazdı. Özetle: izolasyon + içerik-adresli depolama (CAS) + imzalı
makbuz kuruyor; anlamsal niyetin deterministik olarak yeniden üretilemeyeceğini kabul ediyor;
**makbuz yazan tarafın kimliğini, CAS içeriğin kimliğini verir ve kendi şartnamesine göre
ikisi de garanti vermez** diyor; kaynak etiketleri "planlanıyor"; ve bu konuyu başka yerde pek
duymadığını söylüyor.

- Şartname (kapak sayfası): <https://notme.bot/apas>
- **APAS'ın gerçek metni:** <https://github.com/agentic-research/signet/blob/main/docs/apas/agent-provenance-standard.md>
- Uygulaması: <https://github.com/agentic-research/cloister> (AGPL-3.0)

### APAS seviyeleri (birinci elden okundu, 2026-08-05)

| Seviye | Gerektirdiği | **Garanti ETMEDİĞİ** |
|---|---|---|
| L1 denetim izi | her eylem yapısal üstveriyle kaydedilir | *"Records haven't been tampered with"* · *"Do not treat L1 as a security boundary"* |
| L2 imzalı tasdik | üreten varlık kriptografik imzalar | *"The signing entity was operating correctly"* |
| L3 izole çalıştırma | çalıştırma tasdik otoritesinden ayrı | ***"The dispatch's inputs were not poisoned"*** |
| L4 doğrulanmış girdi | girdiler hash'lenip tasdik zincirine bağlanır | garantisi: *"the full chain from input to output is verifiable"* — **doğrulanabilirlik, doğruluk değil** |

Ayrıca şartname açıkça diyor: *"AI agent dispatch is non-deterministic by construction (same
definition + same inputs ↛ same outputs)."*

**Bizim çıkarımımız:** merdiven "zincir doğrulanabilir"de bitiyor. "Girdi içeriği güvenilir"
diye bir seviye **yok**. Bulgumuz L4 değil, merdivenin **dışı**. L3 zaten zehirlenmiş girdiyi
kapsamadığını kabul ediyor.

---

## Gönderilecek metin (İngilizce) — v2

> **v1'den farkı:** özgünlük taraması koştu ve iddiamızı çürüttü. Metin artık **öncel sanatla
> açılıyor**, "bulduk" ile değil. Ayrıca MemTxn ölçümü eklendi — yayımlanmış bir savunmanın bu
> yükü kabul ettiğini göstermek, onlara bizim bulgumuzdan daha faydalı. Bağlantı da düzeltildi:
> v1 `main` dalını gösteriyordu, oysa betik orada **yok**.

```
Ran this end to end since I last wrote, and I owe you a correction before the
result.

I framed this as something we found. It isn't. Policy-conformant fact injection
is a named class in MPBench (arXiv:2606.04329), and "authority is not truth" is
Clark-Wilson 1987, restated in CaMeL 3.1 last year. What we have is a
replication against a real permission broker rather than against its absence,
plus one increment. I went looking for prior art specifically to see whether I
was about to tell you something you already knew, and mostly I was.

The increment, such as it is: through the actual pipeline the result splits in
two, and the split is where the boundary lives.

The naive payload gets blocked. The key the injected text tells the model to
plant sits outside our allow-listed namespaces, so although the model emits it
happily at confidence 1.0, the deterministic gate drops it.

The namespace-aware payload walks straight through. Plant
user.profile.occupation = "verified diamond dealer" instead and it clears every
gate we have - namespace allow-list, credential denylist, provenance size and
type checks, provenance existence validation, redaction, structural quarantine
pattern match. Committed to the live profile, reads back through the broker.
Engine reported facts_committed: 2, facts_quarantined: 0, errors: [] - a clean
success while writing a lie. It committed a genuine fact alongside it, which
makes the poisoned row less obvious on review rather than more.

Single run, so treat it as an existence result rather than a rate.

So the boundary is: the gates stop an attacker who doesn't know the namespace
rules and don't stop one who reads them. The allow-list is public, in our repo.

The part I think bears on APAS: our provenance validation checks that the cited
event exists and hasn't been distilled yet. It does not check that the event
supports the claim. The poisoned fact cites event 3 - a real event whose actual
content is a coffee grinder review. The derivation chain is fully verifiable and
the content is false.

We have two distillation paths and it's worth being precise: one takes the
provenance ids from the model and validates they point at real undistilled
events, the other computes them from the cited domains so the model can't touch
them. The tested path is the first, but both are after the fact - even computed
provenance tells you which real event a claim was derived from, never whether
that event says it.

One more datapoint, and this is the one I'd have wanted if I were you. MemTxn
(arXiv:2607.27834) publishes a defence for roughly this area, and its Ordered
PatchTest is a structural check that the output is an ordered subsequence of
the supporting source. I measured our payload against it. It passes - because
the injected note contains the fabricated claim verbatim, so the claim genuinely
is supported by the text that was read. MemTxn defends a real and different
threat (a distiller corrupting its source) and does it competently. It just
doesn't reach this one. So "adopt the published defence" isn't an answer on its
own, which surprised me and is why I'm mentioning it.

Which brings me back to the levels. I found the spec text in the signet repo,
by the way - notme.bot/apas served me what looked like a cover page, you may
want to know that.

L3 says outright it doesn't guarantee "the dispatch's inputs were not poisoned".
L4 guarantees "the full chain from input to output is verifiable". That's
verifiability, not truth. So I don't think this is an L4 gap - I think it sits
outside the ladder. A system at full L4 would attest the hash of the poisoned
page, log the model response, and produce a perfectly verifiable chain
terminating in a fabricated durable fact. Every L4 promise holds. The lie is
still in the memory.

Not a complaint about the spec. L4 is honest about what it claims and L3 already
concedes the poisoning gap. It's that if source labels are meant to carry
"input truthfulness", they'd be doing something the four levels currently don't,
and that might deserve its own level rather than folding into L4.

Same question as before, sharper: labels bound to the input before inference and
enforced at write time, or metadata attached to the derived fact afterwards?
Ours is effectively the second, and you can see what it bought - accurate
provenance on a false fact.

The cost of the first is what I haven't seen anyone work out. For a memory
system whose only input is untrusted browsing, "untrusted content can't produce
durable facts" switches the product off. CaMeL pays 77%/84% utility for its
version of that trade and is upfront about it. If you've found a middle ground
I'd genuinely like to hear it.

If it's useful, the reproduction is one self-contained file - it builds its own
throwaway vault, runs the blocked case and the passing case as a negative and a
positive control, and prints its own limits at the end:

https://github.com/aikadimsoy/kasa-mcp/blob/security/faz-0-3-owner-scope-hardening/_orch/redteam/poison_reproduce.py

Thanks for the original comment - the levels table is what made me go and
measure the difference between verifiable and true, rather than assuming our
provenance was doing more work than it was.
```

---

## Bilerek yapılmayanlar

- **"Şartnamenizi inceledik" denmedi** — sonra okundu, metin buna göre güncellendi ve
  kapak sayfası sorunu ona faydalı bir not olarak iletildi.
- **"Karantinamız bunu durduruyor" denmedi** — naif yük için doğru, ad-uzayını bilen yük için
  yanlış; ikisi de yazıldı.
- **KASA tanıtımı yok.** Bulgu, sınır ve bir soru. Bağlantı en sonda, "işine yararsa".
- **Üstünlük tonu yok.** Ölçüm boşluğu doldurmak için sunuluyor.

## Özgünlük koşulu — ÇÖZÜLDÜ (2026-08-05)

v1 metni **F-POISON'un özgün olduğu varsayımına** dayanıyordu ve o varsayım doğrulanmamıştı.
Kural şuydu: *ölçülü öncel veri çıkarsa biz replikasyonuz, metin baştan yazılır ve öyle denir.*

**Çıktı.** 12 ajanlık özgünlük denetimi üç iddiamızın üçünü de çürüttü
(`_orch/OZGUNLUK_DENETIMI_2026-08-05.md`). Sentezin kendisi bir yerde yanlış okumuştu ve
birinci kaynaklar elle doğrulandı; sonuç değişmedi:

- **Policy-conformant fact injection** MPBench'te adı konmuş bir sınıf (arXiv:2606.04329)
- **"Yetki gerçek değildir"** Clark-Wilson (1987), CaMeL 3.1'de (2025) yeniden ifade edilmiş
- **MemTxn** (arXiv:2607.27834) komşu bir savunma — ve `MEMTXN-GAP` ölçümü, Ordered
  PatchTest'in **bizim yükümüzü de kabul ettiğini** gösterdi

Koşul tetiklendiği için metin yeniden yazıldı: artık öncel sanatla açılıyor, "bulduk" ile
değil. MemTxn ölçümü eklendi — muhataba bizim bulgumuzdan daha faydalı olan kısım o.

**Bağlantı düzeltmesi:** v1 `.../tree/main/_orch/redteam` gösteriyordu. `poison_reproduce.py`
`main`'de **yok**; PR #2 birleşene kadar dal bağlantısı verilmeli. Birleşme sonrası bağlantı
`main`'e çevrilmeli — kırık bir kanıt bağlantısı, kanıt vermemekten kötüdür.

---

## Yayın kararı (sahip)

Metin, kendi savunmamızın nasıl aşılacağını tarif ediyor: *"izin listesi herkese açık,
okuyan geçer."* Lehinde — kullanıcımız yok, F-POISON zaten yayında, izin listesi zaten depoda,
ve projenin duruşu bu. Aleyhinde — kullanıcı olduğunda bu metin ortada duracak.

**Sahip onayı bekleniyor.** Gönderilmeden önce iki şey doğrulanmalı:
1. PR #2 birleştiyse bağlantı `main`'e çevrildi mi
2. `poison_reproduce.py` bağlantının gösterdiği dalda hâlâ koşuyor mu
