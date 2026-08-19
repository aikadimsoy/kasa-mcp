# KASA Güvenlik Benchmark — Kanıt Raporu
2026-08-19T19:40:19, Windows-11-10.0.26200-SP0, 3.14.5
**Damga:** commit `0ba1dc5` · config-hash `7ec93e4833a5` · WebView2 `151.0.4129.93` · OS build `10.0.26200` · katman **base** · host `DESKTOP-ABPQV0G`
## 🟢 YAYIN-ADAYI
| Total | PASS | FAIL | ERROR | WARN | SKIP |
|-------|------|------|-------|------|------|
| 21 | 21 | 0 | 0 | 0 | 0 |

## Authz
| ID | Başlık | Durum | Önem | Kanıt |
|----|--------|-------|-------|-------|
| AUTHZ-TOKEN-MISSING | POST with NO Authorization header | ✅ PASS | critical | `Status code: 401` |
| AUTHZ-TOKEN-WRONG | POST with header Bearer 'definitely-wrong-token' | ✅ PASS | critical | `Status code: 401` |
| AUTHZ-C5 | bound token for agent_id='system' (reserved identity claimed from the network) | ✅ PASS | critical | `Status code: 403 (reserved-identity block exercised; body: {"detail":"Ajan kimliği mevcut değil."})` |
| AUTHZ-C7 | valid token, agent_id='tester', tool_name='grant_permission' | ✅ PASS | high | `Status code: 404 (rota yok)` |
| AUTHZ-C8 | valid token, agent_id='tester', tool_name='_check_permission' | ✅ PASS | high | `Status code: 404 (rota yok)` |
| AUTHZ-DENY | bound token for agent_id='unauthz_e7c5a9' with NO grants, tool profile_read | ✅ PASS | critical | `Status code: 403; permission-broker refusal: True; body: {"detail":"Ajan 'unauthz_e7c5a9' için 'user.name' okuma izni yok."}` |
| AUTHZ-BIND | Static check on server binding host | ✅ PASS | high | `Default host: 127.0.0.1` |

## Crypto
| ID | Başlık | Durum | Önem | Kanıt |
|----|--------|-------|-------|-------|
| CRYPTO-EXPORT | Prove vault crypto properties (Export) | ✅ PASS | high | `Events count: 1` |
| CRYPTO-EXPORT | Prove vault crypto properties (Export) | ✅ PASS | high | `wrong-pw rejected` |
| CRYPTO-KDF | Prove vault crypto properties (Key Derivation Function) | ✅ PASS | medium | `scrypt parameters found` |
| CRYPTO-ATREST | Prove vault crypto properties (At Rest) | ✅ PASS | critical | `canary absent from kasa.db + yan dosyalar (1 dosya, 94208 bytes; app-layer AES-GCM)` |
| CRYPTO-DPAPI | Prove vault crypto properties (Data Protection API) | ✅ PASS | info | `DPAPI CryptProtectData available for key file` |

## Audit
| ID | Başlık | Durum | Önem | Kanıt |
|----|--------|-------|-------|-------|
| AUDIT-VERIFY | Audit Chain Integrity Verified | ✅ PASS | high | `3-record chain verified` |
| AUDIT-TAMPER-MODIFY | Audit Chain Tamper Detection | ✅ PASS | critical | `Tampering detected in row 2` |
| AUDIT-TAMPER-DELETE | Audit Chain Deletion Detection | ✅ PASS | critical | `Deletion detected in row 2` |

## Scan
| ID | Başlık | Durum | Önem | Kanıt |
|----|--------|-------|-------|-------|
| SCAN-BANDIT | Static Analysis with Bandit (triyaj-suzulmus) | ✅ PASS | high | `High: 0, Medium: 15 (15 denetlenmis, 0 denetlenmemis)` |
| SCAN-PIPAUDIT | Dependency Audit with pip-audit | ✅ PASS | high | `Vulnerable dependencies: 0` |
| SCAN-SECRETS | Secret Detection with Detect-Secrets (allowlist-suzulmus) | ✅ PASS | critical | `0 denetlenmemis secret (28 allowlist'li bastirildi; gerekce: secret_allowlist.json)` |
| SCAN-BAK-HYGIENE | No stray backups + bounded _bak_archive | ✅ PASS | medium | `No stray backups; _bak_archive bounded (24/200)` |

## Fuzz
| ID | Başlık | Durum | Önem | Kanıt |
|----|--------|-------|-------|-------|
| FUZZ-NOAUTH | Malformed unauthenticated request rejected | ✅ PASS | critical | `Status code: 401` |
| FUZZ-EXECUTE | Malformed payload robustness (execute_tool) | ✅ PASS | high | `10 malformed payloads sent, 0 caused 5xx` |

## Düzeltme Önerileri

## Bilinen Sınırlar (dürüst)
- fingerprint B1/B3/B4 still open;
- non-Windows DPAPI no-op;
- this benchmark does not cover network MITM or physical access.