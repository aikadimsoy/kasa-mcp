# -*- coding: utf-8 -*-
"""
L1 secret-allowlist icin KALICI negatif-vaka testleri (Controller).
Kanit yuku: allowlist bir GERCEK secret'i (bearer_token) ASLA gizleyememeli ve
allowlist kaldirilinca/bir fixture disi secret eklenince FAIL uretmeli.
"tek sefer kanitla" degil "surekli kanitla" — false-PASS avi.
"""
import sys
import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (tests/ -> parent = depo koku). Sabit yol, depoyu klonlayan herkeste ve
# CI kosucusunda bu testi kirardi.
_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)
from tools.security_bench.checks import scan


# bearer_token'in detect-secrets'te goründügü hal: kasa.toml + Base64 High Entropy String.
REAL_TOKEN_FINDING = {"kasa.toml": [{"type": "Base64 High Entropy String", "line_number": 4}]}


def test_real_bearer_token_is_never_suppressed():
    """kasa.toml token'i allowlist'te OLMADIGI icin, tam gercek allowlist ile bile 'real'de kalmali."""
    allow = scan.load_allowlist()  # gercek secret_allowlist.json
    real, suppressed = scan.filter_secrets(REAL_TOKEN_FINDING, allow)
    assert any("kasa.toml" in r for r in real), f"bearer_token gizlendi! real={real}"
    assert suppressed == 0


def test_allowlist_actually_suppresses_known_fixture():
    """Bilinen fixture (red-team) allowlist ile bastirilmali — allowlist gercekten calisiyor."""
    allow = scan.load_allowlist()
    fixture = {"_orch\\redteam\\ai_test_auth.json": [{"type": "Hex High Entropy String", "line_number": 1}]}
    real, suppressed = scan.filter_secrets(fixture, allow)
    assert real == [] and suppressed == 1


def test_empty_allowlist_is_fail_closed():
    """Allowlist bos olursa (dosya okunamaz) HICBIR sey bastirilmamali (fail-closed = daha cok FAIL)."""
    real, suppressed = scan.filter_secrets(REAL_TOKEN_FINDING, set())
    assert suppressed == 0 and len(real) == 1


def test_new_secret_in_non_allowlisted_path_trips():
    """Allowlist'te olmayan bir yola sahte secret eklenirse 'real'e dusmeli (negatif kontrol)."""
    allow = scan.load_allowlist()
    planted = {"src/mcp_server/server.py": [{"type": "Secret Keyword", "line_number": 99}]}
    real, suppressed = scan.filter_secrets(planted, allow)
    assert len(real) == 1 and suppressed == 0


def test_bench_own_report_hex_is_suppressed_but_only_that_type():
    """SCAN-SECRETS'in KENDI raporunu taramasi bir yazi-tura uretiyordu — bu onu sabitler.

    Turkce not — NEDEN VAR (olculdu 2026-08-05): tezgah her kosumda
    docs/security_bench_result.json'u yeniden yaziyor ve BIR SONRAKI kosum onu tariyor.
    Dosyanin 9. satirindaki meta.config_hash 12 karakterlik bir SHA-256 kesitidir; degeri
    her yapilandirma degisiminde degisir. Ayni kod ve ayni depoda yalnizca bu deger
    f8b97a921348 -> 7ec93e4833a5 olarak degistiginde hukum 1 FAIL -> 0 FAIL'e dondu:
    biri entropi esigini geciyor, oteki gecmiyor. Yani kontrol OLCUM degil, bir onceki
    kosumun rastgele parmak izine bagli KURA idi -- ve kurayi kaybeden bir kosum "kritik
    acik" diye raporlaniyordu. allowlist girdisi bunu deterministik yapar.

    Bu test iki yonu birden tutar, cunku tek yonu tutmak yetmez: bastirma CALISMALI
    (pozitif) ve ayni dosyada BASKA tipte gercek bir bulgu HALA gecmeli (negatif) --
    aksi halde girdi, raporun tamamini kor bir noktaya cevirirdi.
    """
    allow = scan.load_allowlist()
    report = {"docs/security_bench_result.json": [
        {"type": "Hex High Entropy String", "line_number": 9},    # config_hash parmak izi
        {"type": "Base64 High Entropy String", "line_number": 42},  # allowlist DISI -> real
    ]}
    real, suppressed = scan.filter_secrets(report, allow)
    assert suppressed == 1, f"tezgahin kendi config_hash'i hala FAIL uretiyor: {real}"
    assert len(real) == 1 and "Base64" in real[0], \
        f"ayni dosyada farkli tip bir bulgu da gizlendi -- girdi cok genis: real={real}"


def test_same_file_different_type_not_hidden():
    """Allowlist (path,type) ciftine baglidir: allowlist'li dosyada FARKLI tip yeni secret gizlenmemeli."""
    allow = scan.load_allowlist()
    # run.py Base64 allowlist'li; ama ayni dosyada bir 'Secret Keyword' cikarsa YAKALANMALI.
    mixed = {"tools/security_bench/run.py": [
        {"type": "Base64 High Entropy String", "line_number": 43},  # allowlist'li (GUID)
        {"type": "Secret Keyword", "line_number": 999},             # allowlist DISI -> real
    ]}
    real, suppressed = scan.filter_secrets(mixed, allow)
    assert suppressed == 1 and len(real) == 1 and "Secret Keyword" in real[0]
