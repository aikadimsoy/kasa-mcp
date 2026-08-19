# Kasa - Security Tests and Architectural Defense Report

This document contains the list of empirical security tests, testing methodologies, and objectives implemented on the Kasa (Vault) system. The Kasa project does not only address autonomous agent (LLM) threats; it pursues a layered "Defense-in-Depth" approach.

> **Measurement stamp (2026-08-05).** This project's rule is: *nothing is sealed until it is measured.*
> Every item below carries the measurement it rests on (file:line or a `docs/` stamp); a claim without
> a measurement is not written at all. The current security benchmark reads 21 checks:
> **21 PASS · 0 FAIL · 0 WARN** (`docs/SECURITY_BENCHMARK.md`, commit `5a703cd`) and stamps the word
> *release candidate*. **That word is the bench's, not the project's** — it means no check in a narrow
> suite fails, while finding F-POISON is open and that suite contains no check for it
> (`docs/SECURITY_BENCH_LIMITS.md`). Open findings and known limits are listed in
> `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4 and §7. Nothing in this document should be read
> as "proven / unbreakable / 100% secure".

## 1. Entropy Threshold Validation (Entropy Backstop)
- **How it was done:** Shannon entropy (4.3 threshold) was tested against both synthetic datasets and a live `kasa.db` (Dry-Run scans).
- **Purpose / Target:** To measure whether it is possible to distinguish secrets from benign text relying solely on entropy.
- **Note:** It was empirically shown that real secrets (e.g., AKIA) and URLs/file paths overlap in entropy space. Entropy was relegated to a "Backstop" (safety net) rather than the primary shield.

## 2. Base64 Noise Reduction (Base64 Floor)
- **How it was done:** An entropy floor condition of `H >= 4.0` was appended to the Base64 detection regex.
- **Purpose / Target:** To prevent benign file paths (like `run/this/path`) from being falsely flagged and masked by the Base64 rule (False Positive).
- **Note:** This prevented the system from self-DoS (obfuscating legitimate data) without dropping actual Base64 secrets. The separating window was measured: benign path H~3.92 vs. real base64 secret H>=4.66 (`src/vault/redact.py:23-26`).

## 3. Structured Prefix Shield
- **How it was done:** Direct Regex patterns were implemented for known low-entropy keys such as `AKIA...`, `ghp_...`, and `sk_live_...`.
- **Purpose / Target:** To catch cloud service credentials that fail to meet the entropy threshold (H < 4.3) with deterministic, entropy-**independent** patterns.
- **Measured coverage:** `src/vault/redact.py:49-60` defines prefix patterns for **10 provider families** (AWS access key, GitHub classic token, GitHub fine-grained PAT, Stripe secret, Stripe restricted, OpenAI, Google API key, Slack, Google OAuth, npm). A key matching one of these is masked without ever reaching the entropy gate — and the reason is measured: an `AKIA`-prefixed key has Shannon entropy **H = 3.68**, below even pure hex (`src/vault/redact.py:46`).
- **Note (honest limit):** No "100% accuracy" claim is made. Coverage is bounded by the listed families; a provider format that is not listed is not caught by this rule and falls through to the entropy backstop (§1). Additionally, the repo-wide independent scan check `SCAN-SECRETS` (detect-secrets) is currently **FAIL** — see `docs/SECURITY_BENCHMARK.md` and the triage in `docs/SECRET_SCAN_CORPUS.md`. The prefix approach of industry tools such as TruffleHog and GitLeaks was used as the reference.

## 4. Delimiter Breakout Protection
- **How it was done:** Markers such as `<<<` and `>>>` from untrusted sources were neutralized by replacing them with Zero-Width Spaces (ZWSP) prior to LLM ingestion.
- **Purpose / Target:** To prevent attackers from escaping data blocks to perform "Semantic Prompt Injections".
- **Note:** This targets one concrete vector (structural delimiter escape); it is not a general solution to prompt injection, which remains an open industry-wide problem class.

## 5. Read-Time Redaction (Data in Use Protection)
- **How it was done:** Sensitive cells are written to the database (SQLite) AES-GCM encrypted (for the exact scope of that encryption, see §11). Redaction is strictly enforced at read-time (when accessed by an LLM or external API) via the `redact.scan` module.
- **Purpose / Target:** To establish a "Zero-Trust" air-gap between the Kasa vault and Artificial Intelligence components.
- **Note:** Designed on the principle that AI (LLMs) should be treated as "maximally evil" and never inherently trusted with raw data.

## 6. Source Code Protection (Native Compilation)
- **How it was done:** Security-critical files like `redact.py` and `cell_crypt.py` were compiled into native machine code (via a C compiler) using Nuitka.
- **Purpose / Target:** To **raise the bar** against malicious actors extracting IP (Intellectual Property) and the redaction/encryption algorithms via reverse engineering (decompilation).
- **Measurement (2026-07-10, `docs/EXE_PACKAGING_LOG.md`):** In the compiled distribution — and also inside the onefile extraction directory `%LOCALAPPDATA%\KASA\0.1.0` — the count of `src/*.py` files is **0**; `redact.py`, `cell_crypt.py`, `server.py` and `routes.py` are **absent** as files, and no readable `.pyc` is present. The classic `pyinstxtractor` + decompiler chain therefore has **no target to operate on** in this binary.
- **Note (honest limit):** Nuitka's Python → C compilation makes `.pyc` extraction and decompilation **substantially** harder; **100% protection is not possible.** String constants and logic traces remain in the binary and can be analyzed through disassembly — see `docs/SOURCE_PROTECTION_NOTES.md` §2 and §5 ("100% protection is impossible"). By Kerckhoffs's principle, KASA's **security does not rest on source secrecy** in the first place: the secret is the DPAPI-protected vault key, not the code. Source protection here is an **intellectual-property** measure, not a security boundary. UI files (`dashboard_ui/`) are deliberately left in plain text.

## 7. Audit Integrity (Hash-Chaining)
- **How it was done:** Every record in the `audit` table includes a cryptographic hash (SHA-256) of the previous record, forming a chain — `src/vault/audit.py:71-93`, in encrypt-then-hash order.
- **Purpose / Target:** To **detect** tampering with, or deletion of, past events and logs.
- **Measurement:** `AUDIT-VERIFY` PASS ("3-record chain verified"), `AUDIT-TAMPER-MODIFY` PASS ("Tampering detected in row 2"), `AUDIT-TAMPER-DELETE` PASS ("Deletion detected in row 2") — `docs/SECURITY_BENCHMARK.md`. Changing a single character of an encrypted cell breaks the chain.
- **Note (what the chain does NOT prove):** The chain proves that a record **has not been altered**; it does **not** prove "agent X performed this action". `agent_id` arrives in the request body and is not verified, so **audit attribution is forgeable**. Measurement: `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.1 — 300 requests with a rotating `agent_id` triggered the rate limiter **0 times** and wrote **300 permanent rows** to the chain. This is why no guarantee such as "no activity can ever be silently erased" is written here. The accurate statement is: *deletion and modification are detectable; identity attribution is not guaranteed* (remediation path: P1 "identity binding" in the same document).

## 8. XSS (Cross-Site Scripting) Protection
- **How it was done:** The Dashboard UI builds its DOM using only `textContent` and `createElement`; inside `dashboard_ui/` no data-rendering path uses `innerHTML` or `eval()`.
- **Purpose / Target:** To prevent malicious HTML or JavaScript payloads stored in untrusted events from executing in the dashboard.
- **Measurement (static, 2026-08-03):** `dashboard_ui/app.js` contains **71 `textContent` assignments, 0 `innerHTML` assignments and 0 `eval(` calls**. (The word `textContent` occurs 73 times in that file; 2 of those are comments. The word `innerHTML` occurs 5 times; **all five** are comments.) The single `innerHTML` assignment inside `dashboard_ui/` is at `dashboard_ui/terms.html:130` and writes a **constant string literal** — no vault or event data is interpolated.
- **Scope (the surface this measurement does NOT cover — honest limit):** The measurement above covers **`dashboard_ui/` only**. The embedded JS shell of the browser window opened from the tray menu (`src/browser/browser_window.py`, invoked via `src/tray/app.py:116`) **does use `innerHTML`**: 13 assignments. Twelve of them write constant literals or constant SVG/icon markup (`:204, :208, :212, :634, :683, :702, :744, :784, :842, :857, :907, :1459`), but **`:152` interpolates `window.location.href` while building the address bar** — only the `"` character is escaped (to `&quot;`); `<`, `>` and `&` are not. That path has **not** been triaged. Therefore "there is no `innerHTML` anywhere in the UI" **cannot** be said; the measured accurate statement is: *the dashboard has no `innerHTML` on a data path; the browser-window shell does, and one of those interpolates the visited page's URL.*
- **Note (honest limit):** This is a **code-discipline measurement, not an attack measurement.** The 21-check security benchmark contains **no XSS check**; no independent XSS penetration test has been run (`docs/SECURITY_BENCHMARK.md`). Therefore "zero-risk" is not claimed — what can be claimed is that the known XSS carrier (`innerHTML` on a data path) is measurably absent **in the dashboard**.

## 9. Air-Gap & Local-First Architecture
- **How it was done:** The architecture has no cloud component; the API binds to `127.0.0.1` by default and the CORS allow-list is read from configuration (`src/mcp_server/server.py:57`, `:109-114`).
- **What CORS actually is, measured (honest limit):** The in-code default is `["http://localhost", "http://127.0.0.1"]` (`src/config.py:11`), but `kasa.toml.example:8` — the file the README tells you to copy — **also adds the `"null"` origin**. The `null` origin is what sandboxed iframes, `data:` and `file://` contexts send, so on a fresh install CORS is **not** "localhost only". CORS is therefore not treated as a boundary on its own here; the actual gate is the bearer token in §10 (`FUZZ-NOAUTH` / `AUTHZ-TOKEN-*` PASS).
- **Purpose / Target:** To remove from the architecture every path that would **require** vault data to leave the user's machine.
- **Measurement:** `AUTHZ-BIND` PASS — `Default host: 127.0.0.1` (`docs/SECURITY_BENCHMARK.md`). KASA does not initiate outbound connections on its own; distillation also targets a local Ollama (`localhost:11434`).
- **Note (the UNmeasured part — important):** KASA does **not restrict and does not observe** outbound network traffic on the machine. Egress control is planned in `docs/GUVENLIK_CIKIS_PLANI.md` Phases 1-4 and **none of it has been built** (`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.4 and E3). Consequently it cannot be said that data exfiltration is "categorically impossible": for a process running on the same machine that can read the bearer token, the outbound path is simply unmeasured. The accurate statement is: *vault access is kept narrow by the permission broker, everything read passes the redaction gate, and KASA itself does not call out — but egress is not closed with evidence.*

## 10. Unauthorized API Access (Bearer Token)
- **How it was done:** The local API (FastAPI) enforces a `KASA_TOKEN` Bearer Token check on every request; the token is generated on first run and stored in `kasa.toml`.
- **Purpose / Target:** To block Server-Side Request Forgery (SSRF) and Cross-Site Request Forgery (CSRF) from web pages or from processes running under a different OS user.
- **Measurement:** `AUTHZ-TOKEN-MISSING` PASS (401), `AUTHZ-TOKEN-WRONG` PASS (401), `FUZZ-NOAUTH` PASS (401) — `docs/SECURITY_BENCHMARK.md`.
- **Note (honest limit):** The token is **not single-use**; it is a persistent shared secret stored in **plain text** in `kasa.toml` — this is part of the benchmark's `SCAN-SECRETS` finding. Applied mitigation: file ACL restricted to owner + SYSTEM + Administrators; rotation and DPAPI wrapping are pending an owner decision (`docs/SECRET_SCAN_CORPUS.md` §6, `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.3). In practice the token is a boundary **against other OS users and web pages**, not between Kasa and code running in the same user context — every agent connecting over MCP also knows this token.

## 11. Cell-Level Encryption (Data at Rest - AES-GCM)
- **How it was done:** Sensitive database cells in SQLite are encrypted using Authenticated Encryption (AES-256-GCM) with a per-cell random nonce and Associated Data (AAD) binding each cell to its context.
- **Purpose / Target:** To ensure that if malware steals the physical `kasa.db` file, **the contents of the encrypted columns** remain unreadable.
- **Measurement:** `CRYPTO-ATREST` PASS (canary absent from `kasa.db` and its side files), `CRYPTO-KDF` PASS (scrypt), `CRYPTO-DPAPI` PASS, `CRYPTO-EXPORT` PASS (wrong password rejected) — `docs/SECURITY_BENCHMARK.md`. **175 encrypted cells** were counted in the live vault; row/column swapping fails with `InvalidTag` thanks to AAD (`test_aad_swap_breaks_decrypt`).
- **Scope (honest limit — the most important line in this item):** `kasa.db` is **not an encrypted file**; it is a plain SQLite database whose header reads `SQLite format 3`. Encryption is **cell-level and covers exactly three columns**: `events.content`, `profile.value`, `audit.details`. All other columns — `timestamp`, `session_id`, `source`, `type`, `ttl_expiry`, `distilled`, `profile.key`, `provenance`, `profile.created_at`, `profile.updated_at`, `agent_id`, `action`, the hashes, and `permissions.*` — are **plain text**, deliberately left unencrypted because queryability, TTL scanning and the hash chain depend on them. Column-by-column measurement: `docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §1. Full-database at-rest encryption (SQLCipher) is **not sealed** — `docs/adr/0003-at-rest-sifreleme-boslugu.md`.
- **Consequence (measured):** Whoever obtains the file cannot read the **content**, but can read the **pattern**: which profile keys exist, how many events there are, and in which time window browsing happened — all derivable from plain-text metadata (demonstrated in §1 of the same document). This is not a closed hole but a **documented trade-off**; the user-side mitigation is to place the vault directory on an encrypted volume such as BitLocker.
- **Note:** The decryption key (`.vaultkey`) is kept separately from the database and protected by Windows DPAPI. Malware running in the same user context can call DPAPI as well; this is an unclosable, documented limit (`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.5).
