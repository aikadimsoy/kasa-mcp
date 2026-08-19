# MCP Ecosystem — Distilled Notes / MCP Ekosistemi — Damıtılmış Notlar

**What other MCP servers do that we do not, how they do it, and with what code.**
**Diğer MCP sunucularının bizden farklı yaptıkları, nasıl yaptıkları ve hangi kodla.**

Date / Tarih: **2026-08-05** · Author / Yazar: [@aikadimsoy](https://github.com/aikadimsoy)
Companion to / Eşlik ettiği belge: [`KNOWLEDGE_ARCHIVE.md`](KNOWLEDGE_ARCHIVE.md)

---

## 0. Method and honest limits / Yöntem ve dürüst sınırlar

**EN.** Sources actually read are listed in §7. Two limits stated up front:

- **Reddit was not read.** `r/mcp` and `r/MCPservers` are blocked to the fetch tool used here.
  Reading them requires the isolated browser profile, un-authenticated, at human pace. **Not
  done in this pass** — nothing in this document is sourced from Reddit.
- **SDK claims are verified against the installed package**, not against documentation.
  Where a web source and the installed SDK disagreed, the installed SDK won. One such
  disagreement is recorded in §3.

**TR.** Gerçekten okunan kaynaklar §7'de. İki sınır peşinen:

- **Reddit okunmadı.** `r/mcp` ve `r/MCPservers` burada kullanılan getirme aracına kapalı.
  Okunması izole tarayıcı profilini, oturumsuz ve insan temposunda gerektiriyor. **Bu turda
  yapılmadı** — bu belgedeki hiçbir bilgi Reddit kaynaklı değil.
- **SDK iddiaları kurulu pakete karşı doğrulandı**, belgeye karşı değil. Web kaynağı ile kurulu
  SDK çeliştiğinde kurulu SDK kazandı. Böyle bir çelişki §3'te kayıtlı.

---

## 1. The directory finding / Dizin bulgusu

**EN.** `allmcpservers.com` lists 19 servers: GitHub, GitHub Actions, Playwright, Docker,
Browserbase, Notion, PostgreSQL, Supabase, Tavily, Firecrawl, Confluence, Contentful, Neo4j,
Kubernetes, Obsidian, Perplexity, Reddit, Figma, Firebase.

**Every one is a capability server** — it connects an agent to an external system. There is
**not one memory server and not one permission/authorization server in the list.** The site
also does not display transport type, install command, or auth method for any entry.

**Conclusion: this directory cannot fill our gaps, because it does not contain our category.**
Its value to us is **distribution** (being listed) and **positioning** (we are not competing
with anything on it) — not architecture. That is a different gap from the one diagnosed in
`KNOWLEDGE_ARCHIVE.md §5.2`, and it should not be confused with it.

**TR.** `allmcpservers.com` 19 sunucu listeliyor ve **hepsi yetenek sunucusu** — ajanı bir dış
sisteme bağlıyor. Listede **tek bir hafıza sunucusu ve tek bir izin/yetkilendirme sunucusu
yok.** Site ayrıca hiçbir kayıt için transport türü, kurulum komutu veya kimlik doğrulama
yöntemi göstermiyor.

**Sonuç: bu dizin bizim eksiklerimizi kapatamaz, çünkü bizim kategorimizi içermiyor.** Bize
değeri **dağıtım** (listelenmek) ve **konumlandırma** (üzerindeki hiçbir şeyle rekabet
etmiyoruz) — mimari değil.

---

## 2. Primitive gap — we use one of four / İlkel gediği — dörtte birini kullanıyoruz

**EN.** MCP defines several server primitives. Verified against the installed SDK
(`mcp 1.29.0`), `FastMCP` exposes decorators for: `tool`, `resource`, `prompt`, `completion`,
`custom_route`. **KASA uses `tool` only.** All six of our surfaces are tools.

**TR.** MCP birden çok sunucu ilkeli tanımlar. Kurulu SDK'ya karşı doğrulandı: `FastMCP`
`tool`, `resource`, `prompt`, `completion`, `custom_route` dekoratörlerini sunuyor.
**KASA yalnızca `tool` kullanıyor.** Altı yüzeyimizin altısı da araç.

### 2.1 What the official memory server does differently / Resmî hafıza sunucusu ne yapıyor

The official `modelcontextprotocol/servers` memory server publishes its **entire graph as an
MCP Resource**:

```
memory://knowledge-graph      (MIME: application/json)
```

and **emits update notifications when the graph mutates.**

**TR açıklama:** Fark şu: bir *araç* çağrılmayı bekler — istemci sormazsa hiçbir şey olmaz.
Bir *kaynak* ise istemcinin bağlam olarak tutabileceği, değiştiğinde haber alabileceği bir
şeydir. Yani hafıza, "sorulunca cevap veren bir fonksiyon" olmaktan çıkıp "izlenebilir bir
durum" hâline geliyor.

**Their pattern / Onların kalıbı:**

```python
@mcp.resource("memory://knowledge-graph")
def knowledge_graph() -> str:
    """The complete graph, published as readable context."""
    return json.dumps(load_graph())
```

**What the equivalent would be for KASA / KASA'daki karşılığı ne olurdu:**

```python
@mcp.resource("kasa://profile/{scope}")
def profile_resource(scope: str) -> str:
    """Redacted profile facts as a subscribable resource.

    NOTE: this must go through the SAME broker as profile_read. A resource read is a
    read — it needs the identical 'profile:read:<scope>' check, or the resource
    primitive becomes an authorization bypass around our own gate.
    """
    return json.dumps(_execute("profile_read", {"scope": scope}))
```

**TR açıklama — ve buradaki tuzak:** Kaynaklar okuma yüzeyidir. Eğer kaynağı brokerdan
geçirmezsek, kendi kapımızın etrafından dolaşan bir okuma yolu açmış oluruz. Yani bu özelliği
eklemek "bir dekoratör eklemek" değil; **yetkilendirmenin ikinci bir giriş noktası** demektir.
Bu yüzden ucuz görünüp ucuz olmayan maddelerden biri.

### 2.2 Prompts — a surface we have not considered / Düşünmediğimiz bir yüzey

**EN.** `@mcp.prompt` lets a server ship reusable prompt templates to the client. For a memory
server this is a natural fit: *"summarise what you know about me before answering"*.

**Risk note, specific to us:** a prompt shipped by the server is text the client model will
follow. Our entire threat model says model-facing text is untrusted. Shipping prompts means
**we become a prompt-injection source for our own users** if any vault content is interpolated
into them. Worth building, worth building carefully.

**TR.** `@mcp.prompt`, sunucunun istemciye yeniden kullanılabilir şablonlar göndermesini sağlar.
Bize özel risk: sunucunun gönderdiği şablon, istemci modelinin izleyeceği metindir. Eğer içine
vault içeriği gömülürse **kendi kullanıcılarımız için bir enjeksiyon kaynağı hâline geliriz.**
Yapılabilir ama dikkatle.

---

## 3. Transport gap — one argument, not a rewrite / Transport gediği — yeniden yazım değil, tek argüman

**EN.** Verified against the installed `mcp 1.29.0`:

```python
FastMCP.run(transport: Literal['stdio', 'sse', 'streamable-http'] = 'stdio',
            mount_path: str | None = None) -> None
```

`FastMCP` also exposes `run_streamable_http_async`, `streamable_http_app`, `sse_app`, and
`session_manager`.

**Correction recorded:** an earlier note in this project implied remote transport arrives with
SDK 2.x. It does not — **it is already in the version we pinned.** Our line today is:

```python
mcp.run()  # stdio transport (varsayilan)
```

Remote would be:

```python
mcp.run(transport="streamable-http")
```

**TR açıklama — ama asıl mesele bu değil.** Transport'u değiştirmek tek satır. Değişmeyen şey
şu: loopback'ten çıktığın anda tehdit modelin değişir. Bugün `src/mcp_adapter/proxy.py`
yalnızca loopback'e konuşmayı **zorluyor** (`_is_loopback_url`), sunucu tarafında da
Host-başlığı koruması var (G2, DNS-rebinding savunması). Uzak MCP bunların ikisini de anlamsız
kılar ve yerine OAuth 2.1 koymayı gerektirir.

**Yani gerçek maliyet transport değil, yetkilendirme ve tehdit modelidir.** Bunu "yapmadık"
diye değil, "yerel-öncelik tezimiz gereği bilerek yapmıyoruz" diye yazmalıyız — çünkü teknik
engel yok, tercih var. Bu ikisi çok farklı iddialardır.

---

## 4. Data model gap / Veri modeli farkı

| | Official memory server | Zep / Graphiti | mem0 | **KASA** |
|---|---|---|---|---|
| Model | entities · relations · observations | temporal knowledge graph | vector store **+** knowledge graph | **profile keys + events** |
| Time | — | **fact validity windows** (bi-temporal) | timestamps | **TTL + provenance event ids** |
| Retrieval | `search_nodes` string search | graph traversal, temporal | semantic + graph | scope match + `user.*` wildcard |
| Storage | `memory.jsonl` plaintext file | Neo4j / FalkorDB / Kuzu | vector DB + graph | **SQLite, per-cell AES-256-GCM with AAD** |
| Scoping | — | — | user / session / agent | **deny-by-default permission scopes** |
| Audit | — | — | — | **hash-chained, Ed25519-signed** |

### 4.1 Their shape / Onların şekli

```json
{"name": "John_Smith", "entityType": "person",
 "observations": ["works at Anthropic", "prefers dark roast"]}
{"from": "John_Smith", "to": "Anthropic", "relationType": "works_at"}
```

### 4.2 Our shape / Bizim şeklimiz

```json
{"key": "kasa_user_interests", "value": "coffee grinder",
 "confidence": 0.9, "provenance": [17, 23]}
```

**EN — the real difference.** They model **relationships**; we model **origin**. Their
`observations` are free strings with no record of where they came from. Our `provenance` field
points at the event ids a fact was derived from.

That is the more interesting axis, and it is ours — but note what
`KNOWLEDGE_ARCHIVE.md §3.2` measured: **provenance is recorded and it did not prevent
F-POISON.** Knowing which event produced a fact does not tell you whether the event was
truthful. Provenance is necessary for the fix and is not itself the fix.

**TR — asıl fark.** Onlar **ilişkiyi** modelliyor; biz **kökeni**. Onların `observations`
alanı, nereden geldiği kayıtlı olmayan serbest metinlerdir. Bizim `provenance` alanımız,
olgunun türetildiği olay kimliklerini gösterir.

Bu daha ilginç eksen ve bizim ekseninmiz — ama arşivin ölçtüğünü unutmayalım: **köken kayıtlı
ve F-POISON'ı engellemedi.** Bir olgunun hangi olaydan geldiğini bilmek, o olayın doğru olup
olmadığını söylemez. Köken, çözümün ön koşuludur; çözümün kendisi değil.

### 4.3 Retrieval — a genuine capability gap / Gerçek bir yetenek eksiği

**EN.** mem0 runs a dual store (vector for semantic search + graph for entity relations).
Zep/Graphiti makes time first-class, storing **fact validity windows** rather than snapshots —
reportedly 63.8% vs mem0's 49.0% on LongMemEval.

**KASA has no semantic retrieval at all** — scope match and a `user.*` wildcard. For a vault
holding a handful of profile keys this is adequate; at scale it is not. We also **publish no
retrieval benchmark**, so we cannot compare and should not imply we can.

**TR.** mem0 çift depo (anlamsal arama için vektör + varlık ilişkileri için graf) çalıştırıyor.
Zep/Graphiti zamanı birinci sınıf yapıyor: anlık görüntü yerine **olgu geçerlilik pencereleri**.
**KASA'da anlamsal getirme hiç yok** — kapsam eşleşmesi ve `user.*` joker. Az sayıda profil
anahtarı için yeterli, ölçekte değil. Ayrıca **hiçbir getirme ölçütü yayımlamıyoruz**, o yüzden
kıyaslayamayız ve kıyaslayabiliyormuş gibi de yazmamalıyız.

**Honest note / Dürüst not:** none of the compared systems publishes an **attack** benchmark.
They compete on recall quality; nobody in this set publishes the attacks their own design does
not stop. That remains our differentiator — and it is a *methodology* differentiator, not a
capability one. Kıyaslanan sistemlerin hiçbiri **saldırı** ölçütü yayımlamıyor. Onlar getirme
kalitesinde yarışıyor. Bizim ayrımımız orada — ve bu bir *yöntem* ayrımı, yetenek ayrımı değil.

---

## 5. Packaging and distribution / Paketleme ve dağıtım

**EN.** The convention across the ecosystem is a **one-line install** the user pastes into a
client config. Official memory server ships via `npx` and Docker. KASA currently requires
cloning a repository, installing Python dependencies, starting a REST server, and running an
owner CLI to grant scopes — and until today's fixes, that path did not work at all
(`KNOWLEDGE_ARCHIVE.md §2`).

Their shape / Onların şekli:

```json
{ "mcpServers": {
    "memory": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"] } } }
```

Ours today / Bugün bizimki:

```json
{ "mcpServers": {
    "kasa": { "command": "py", "args": ["-3.12", "-m", "src.mcp_adapter"] } } }
```

**TR açıklama.** Bizim satır kısa görünüyor ama yanıltıcı: çalışması için önce REST sunucusunun
ayakta olması, `kasa.toml`'un bulunması ve sahibin `grant_agent_scope.py` ile kapsam vermiş
olması gerekiyor. Bu üç önkoşul **hiçbir yerde yazmıyor** — bu, arşivdeki açık maddelerden biri
(§2.3). Kısa kurulum satırı yazmak kolay; **kısa kurulum satırının doğru olması** ayrı iştir.

---

## 6. What to adopt, ranked by cost / Ne alınmalı, maliyete göre sıralı

| # | Item | Effort | Why / Neden |
|---|---|---|---|
| 1 | **Honest install docs** — state the three prerequisites | very low | Today a first run ends in 403 with no explanation; that reads as "broken", not "secure". |
| 2 | **Get listed on directories** | low | Pure distribution. Nothing on those lists competes with us. |
| 3 | **`@mcp.resource` for redacted profile reads** | medium | Real ecosystem convention — but **must route through the broker**, or the resource primitive becomes a bypass around our own gate (§2.1). |
| 4 | **Semantic retrieval** | high | Genuine capability gap. Only worth it once a vault holds enough to need it. |
| 5 | **Streamable HTTP + OAuth 2.1** | high | One argument for transport; everything else is auth and threat model. **Contradicts the local-first thesis — recommend not doing it**, and saying so openly in the README. |
| 6 | ~~Feature-matching the directory~~ | — | **Rejected.** The directory contains no server in our category (§1). Copying feature lists from capability servers would push us toward being a worse version of something we are not. |

---

## 7. Measured comparison — our own instrument, not quoted claims / Ölçülen kıyas — blog iddiası değil, kendi aletimiz

**EN.** Everything above §6 is read from documentation. This section is **measured**: the rival
servers were installed and probed with a real MCP stdio client and with `pip install --dry-run`,
under the same conditions used on KASA in `KNOWLEDGE_ARCHIVE.md §2.5`.

**TR.** §6'ya kadar olan her şey belgeden okundu. Bu bölüm **ölçüldü**: rakip sunucular kurulup
gerçek bir MCP stdio istemcisiyle ve `pip install --dry-run` ile, KASA'ya uygulanan aynı
koşullarda sınandı.

### 7.1 Protocol surface — official memory server v0.6.3 / Protokol yüzeyi

Level: `RAN-LIVE` (MCP Inspector + a purpose-written stdio client)

| | **KASA** (before) | **KASA** (after fix) | **official memory server** |
|---|---|---|---|
| capabilities | tools | tools | tools **+ resources** |
| tools | 6 | 6 | 9 |
| with descriptions | 6/6 | 6/6 | 9/9 |
| **with annotations** | **0/6** | **6/6** | **9/9** |
| flagged `destructiveHint` | **none** | `profile_write`, `forget`, `prune_expired_events` | `delete_entities`, `delete_observations`, `delete_relations` |
| flagged `readOnlyHint` | none | 2 | 3 |
| resources | **0** | **0** | 1 (`memory://knowledge-graph`) |

**Finding against us — found and closed in the same pass / Bize karşı bulgu — aynı turda
bulundu ve kapatıldı.** KASA shipped **two destructive tools** (`forget`,
`prune_expired_events`) with **no `destructiveHint`**. A client cannot warn the user before a
deletion, because we never told it the tool deletes.

Fixed: all six tools now carry `ToolAnnotations`, verified **on the wire** with Inspector, not
merely in code. `profile_write` was also marked destructive — overwriting a key destroys the
previous value, and in a security product the correct way to be unsure is to warn.
`openWorldHint=False` on all six, because KASA operates on a closed local vault. Guarded by
three tests in `tests/test_mcp_adapter_wiring.py`.

*Düzeltildi: altı aracın altısı da işaretli, Inspector ile **telde** doğrulandı. Bir anahtarı
yeniden yazmak önceki değeri yok ettiği için `profile_write` da yıkıcı sayıldı — güvenlik
ürününde emin olmamanın doğru yolu uyarmaktır.*

**Still open / Hâlâ açık:** KASA exposes **no resources**. See §2.1 — and note the trap
recorded there: a resource must route through the broker, or it becomes a read path around our
own gate.

### 7.2 The same negative control, applied to them / Aynı negatif kontrol, onlara uygulandı

Level: `RAN-LIVE`. The identical fabricated fact from F-POISON was used.

| Call | KASA | official memory server |
|---|---|---|
| write a fabricated fact | requires granted scope | **allowed, no gate** |
| read it back | requires granted scope | **allowed, no gate** |
| destructive delete | **HTTP 403 refused** (`isError: true`) | **allowed, no gate** |
| storage at rest | per-cell AES-256-GCM | **plaintext JSONL** |

Measured storage / Ölçülen depolama:

```json
{"type":"entity","name":"kasa_user","entityType":"person",
 "observations":["is a verified diamond dealer","holds vault admin rights"]}
```

The fabricated fact is readable directly off disk with any text editor.

**Fair statement / Adil ifade:** the official server **does not claim** to have an
authorization layer — it is a reference implementation, not a competitor that failed a test we
set. What the measurement establishes is narrower and more useful: **the ecosystem's default
memory server has no mediation and no encryption at rest**, which is precisely the gap KASA
exists to address. It also means F-POISON is not a KASA-specific defect — on this server the
same write needs no injection at all, because nothing would have stopped it anyway.

*Resmî sunucu yetkilendirme iddiasında bulunmuyor; sınavı geçemeyen bir rakip değil, referans
uygulama. Ölçümün gösterdiği daha dar ve daha yararlı: ekosistemin varsayılan hafıza sunucusunda
ne aracılık ne de diskte şifreleme var.*

### 7.3 Supply-chain surface / Tedarik zinciri yüzeyi

Level: `RAN-LIVE` (`pip install --dry-run` in a clean venv, identical method for both)

| | transitive dependencies | packages with an egress path |
|---|---|---|
| **KASA** (`requirements.txt`) | **36** | **0** |
| `mem0ai` | 36 | 3 — `openai`, `posthog`, `qdrant-client` |
| `basic-memory` | **165** (4.6×) | 13 — `sentry-sdk`, `logfire`, full OTLP stack, `openai`, `litellm`, `huggingface_hub`, `fastapi-cloud-cli` |

**Method note / Yöntem notu:** "egress path" means the package *can* open an outbound
connection. It is **not** evidence that data is sent. Bir paketin listede olması veri
gönderdiğini **kanıtlamaz**; yalnızca yolun var olduğunu gösterir.

### 7.4 Telemetry defaults / Telemetri varsayılanları

Level: `CODE-STRUCTURE` — read from the installed/downloaded package source, **not** observed
on the wire. Kaynaktan okundu, **ağ üzerinde gözlenmedi**.

**mem0** (`mem0/memory/telemetry.py`):

```python
MEM0_TELEMETRY = os.environ.get("MEM0_TELEMETRY", "True")   # default: ON
HOST = "https://us.i.posthog.com"
```

**basic-memory** (`basic_memory/cli/analytics.py`):

```python
_DEFAULT_UMAMI_HOST    = "https://api-gateway.umami.dev"
_DEFAULT_UMAMI_SITE_ID = "f6479898-ebaf-4e60-bce2-6dc60a3f6c5c"

def _analytics_disabled() -> bool:
    value = os.getenv("BASIC_MEMORY_NO_PROMOS", "").strip().lower()
    return value in {"1", "true", "yes"}        # off ONLY if explicitly set
```

Both are **on by default, opt-out, with hardcoded endpoints.**

**Fairness, stated deliberately / Kasıtlı olarak belirtilen adalet payı:**

- The events observed in source are **usage/CLI analytics**, not memory content. mem0 carries
  explicit redaction filters for telemetry. **We did not observe memory content being sent and
  do not claim it is.** *Kullanım analitiği; hafıza içeriği gönderildiğini gözlemlemedik ve
  iddia etmiyoruz.*
- `logfire` spans in basic-memory normally require a token; whether they transmit without one
  was **not verified**.
- These are `CODE-STRUCTURE` findings. Confirming them would need packet capture, which was not
  performed.

**Why it matters to us / Bize neden önemli:** KASA's "local-first" is now a **measured** claim
on this axis — 36 dependencies, zero with an egress path, no telemetry code — rather than a
slogan. That is worth stating precisely because it is the one place where we can currently show
a number rather than an intention.

### 7.5 What we did NOT do / Yapmadıklarımız

- **basic-memory was not run.** Only its wheel was downloaded and read (165 transitive
  dependencies made a full install disproportionate for the question being asked).
- **Zep / Graphiti was not tested.** It requires a graph database (Neo4j / FalkorDB / Kuzu) plus
  an LLM key — out of proportion for this pass.
- **mem0 was installed but not exercised end-to-end** — it requires an LLM API key for
  extraction, which is itself the finding: mem0 is not local-first by construction.
- **No packet capture.** Every telemetry claim here is source-level.

---

## 8. Sources actually read / Gerçekten okunan kaynaklar

- [allmcpservers.com](https://www.allmcpservers.com/) — directory listing, 19 servers
- [modelcontextprotocol/servers — memory server README](https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/memory/README.md) — data model, tool names, resource URI
- [modelcontextprotocol/python-sdk README](https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/main/README.md) — `@mcp.resource` example
- **Installed `mcp 1.29.0` package, inspected directly** — authoritative for all SDK claims here
- [Mem0 vs Zep (Graphiti): AI Agent Memory Compared (2026)](https://vectorize.io/articles/mem0-vs-zep)
- [Best MCP Memory Server 2026 — Mem0 vs Letta vs Zep](https://synabun.ai/blog/mcp-memory-servers-comparison)
- [Zep vs Mem0: Which AI Memory Layer Fits Your Stack?](https://atlan.com/know/zep-vs-mem0/)
- [Best Memory & Knowledge MCP Servers in 2026](https://chatforest.com/guides/best-memory-mcp-servers/)

**Not read / Okunmayanlar:** `r/mcp`, `r/MCPservers` — blocked to the fetch tool; requires the
isolated browser profile. Benchmark figures quoted in §4.3 (LongMemEval 63.8% / 49.0%) are
**second-hand from vendor-adjacent comparison articles and were not independently verified.**
§4.3'teki ölçüt sayıları **ikinci eldendir ve bağımsız olarak doğrulanmamıştır.**

---

**KASA** — a sovereign, local-first memory vault for agentic browsing.
Author / Yazar: [@aikadimsoy](https://github.com/aikadimsoy) ·
Repository: <https://github.com/aikadimsoy/kasa-mcp>
