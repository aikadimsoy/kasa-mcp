# Scan profiles

A profile tells `kasa-scan` **what language your server speaks**. Nothing else about the
scanner changes — the same checks run, they just address your endpoint and your field names.

```powershell
python -m tools.scanner.cli --url http://127.0.0.1:9000 --profile tools/scanner/profiles/example-generic.json
python -m tools.scanner.cli --profile my_server.json --print-profile   # see exactly what will be sent
python -m tools.scanner.cli --list-checks                              # see what can be run
python -m tools.scanner.cli --url ... --only POSITIVE-CONTROL,AUTHZ-NO-TOKEN
```

## Why this exists

The scanner was written against KASA, with `/v1/execute_tool`, `profile_read` and
`profile_write` compiled into the source. Pointed at any other agent server it returned
`SKIP` for every check — so the claim "audit any MCP server" was, in practice, empty.

That emptiness only became visible after `SKIP` stopped being reported as `PASS`. Before that
fix a foreign server scored 60% and looked audited. **Making the tool honest is what exposed
the fact that it was narrow.** Profiles are the answer to the narrowness; they are not a fix
for the honesty problem, which is handled separately and unconditionally.

## Fields

| Field | Meaning | Default (KASA) |
|---|---|---|
| `name` | Label for the profile | `kasa` |
| `endpoint` | Path the tool-invocation POST goes to | `/v1/execute_tool` |
| `tool_field` | Body key naming the tool | `tool` |
| `args_field` | Body key holding tool arguments | `arguments` |
| `agent_field` | Body key the caller uses to *claim* an identity | `agent_id` |
| `read_tool` | A read-only tool name | `profile_read` |
| `write_tool` | A tool that writes to memory | `profile_write` |
| `read_args` | Arguments passed to `read_tool` | `{"scope": "user.*", "reason": "scan"}` |
| `write_key` | Key the injection payload is written under | `user.security.rule` |
| `injection_payload` | The imperative string used for the poisoning check | see `kasa.json` |
| `quarantine_path` | Where in the response body the write's fate is reported | `["result", "status"]` |
| `quarantine_value` | The value at that path meaning "quarantined" | `quarantined` |
| `reserved_agent_id` | A privileged identity a caller must not be able to claim | `system` |
| `unknown_agent_id` | An identity with no grants | `kasa_scan_unknown_agent` |
| `deny_statuses` | Status codes that count as a refusal | `[401, 403]` |

An unrecognised field is a hard error, not a warning. Silently ignoring a key you wrote would
let you believe you configured something you did not.

## What a profile cannot do

Writing a profile does not widen the tool past its transport. `kasa-scan` sends **HTTP POST
with a JSON body and an optional bearer token**. Out of scope:

- JSON-RPC envelopes (`{"jsonrpc": "2.0", "method": ...}`)
- stdio-transported MCP servers
- SSE / streaming responses
- OAuth, mTLS, or any multi-step auth handshake
- gRPC or anything non-HTTP

If your server speaks one of those, the honest result is `SKIP` for every check, and that is
what you will get. A profile will not turn `SKIP` into `PASS`, and no combination of settings
will make the tool claim it measured something it did not.

## Two things to keep in mind when you write one

**Run the positive control.** Pass `--token` with a credential that is *supposed* to work.
Without it the scanner only ever sends attack-shaped requests, and a server that refuses
**everything** — including all legitimate use — passes every one of them. Measured
2026-08-19: a server answering HTTP 403 to every request scored 100%. With `--token` the
positive control catches exactly that, and without it the report says so on the score line.

**A narrowed scan is not a full scan.** Checks excluded with `--only` or `--skip-checks` appear
in the report as `SKIP` with the reason written out. They are never silently dropped and never
counted as passes.
