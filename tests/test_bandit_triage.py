# -*- coding: utf-8 -*-
"""Bandit triyaj suzgeci + B608 ailesinin NEGATIF KONTROLU.

NEDEN BU DOSYA VAR
------------------
2026-08-05'e kadar `SCAN-BANDIT` ham sayi raporluyordu: "Medium: 13" -> WARN. Sayi hicbir
sey soylemiyordu, cunku 13'un kaci gercek kaci gurultu ayirt edilmiyordu. Uc aile tek tek
kod okunarak incelendi (gerekceler tools/security_bench/bandit_triage.json icinde,
her biri dosya:satir kaniti ile).

Triyajin kendisi bir RISKTIR: cok genis yazilirsa raporu kor eder. Bu yuzden anahtar
(test_id, path, COUNT) -- satir numarasi degil (satirlar kayar, triyaj bayatlar) ve yalniz
(test_id, path) degil (ayni dosyada acilan YENI bulgu gizlenirdi). Asagidaki testler
suzgecin hem CALISTIGINI hem de KOR OLMADIGINI birlikte tutar.

Ve bir sey daha: B608 ailesi icin "parametrelidir, guvenlidir" demek bir IDDIADIR.
Bu projede iddia olcum ister. Son iki test gercek `forget()` yolunu SQL meta-karakterleriyle
surer ve tablolarin ayakta kaldigini gosterir -- pozitif kontrolu de yaninda.
"""
import os as _os
import sys
import time

import pytest

_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from tools.security_bench.checks.scan import filter_bandit, load_bandit_triage


def _bandit(rows):
    """rows: [(test_id, path, line, severity)] -> bandit JSON bicimi."""
    return {"results": [{"test_id": t, "filename": f"d:\\kasa\\{p.replace('/', chr(92))}",
                         "line_number": ln, "issue_severity": sev, "issue_text": "x"}
                        for (t, p, ln, sev) in rows]}


# --- Suzgec: pozitif kontrol ------------------------------------------------

def test_POSITIVE_real_triage_suppresses_the_known_thirteen():
    """Gercek triyaj dosyasi, 2026-08-05'te olculen 13 MEDIUM'u dusurmeli."""
    triage = load_bandit_triage()
    assert triage, "triyaj dosyasi okunamadi -> suzgec fail-closed calisir, test anlamsiz"
    measured = _bandit([
        ("B310", "src/agent/harness.py", 61, "MEDIUM"),
        ("B310", "src/agent/harness.py", 87, "MEDIUM"),
        ("B310", "src/browser/browser_window.py", 1108, "MEDIUM"),
        ("B310", "src/browser/browser_window.py", 1177, "MEDIUM"),
        ("B310", "src/desktop/launch.py", 127, "MEDIUM"),
        ("B104", "src/desktop/preflight.py", 63, "MEDIUM"),
        ("B310", "src/distill/engine.py", 183, "MEDIUM"),
        ("B608", "src/distill/engine.py", 242, "MEDIUM"),
        ("B608", "src/distill/engine.py", 275, "MEDIUM"),
        ("B310", "src/distill/profile_enrich.py", 86, "MEDIUM"),
        ("B310", "src/mcp_adapter/proxy.py", 136, "MEDIUM"),
        ("B608", "src/mcp_server/tools.py", 260, "MEDIUM"),
        ("B608", "src/mcp_server/tools.py", 393, "MEDIUM"),
    ])
    untriaged, suppressed = filter_bandit(measured, triage)
    assert untriaged == [], f"denetlenmis bulgular hala yuzeyde: {untriaged}"
    assert suppressed == 13


# --- Suzgec: kor nokta uretmiyor (negatif kontroller) -----------------------

def test_NEGATIVE_extra_finding_in_an_already_triaged_file_surfaces():
    """Triyajin en tehlikeli hatasi bu olurdu: ayni dosyada YENI bir bulguyu gizlemek."""
    triage = load_bandit_triage()
    rows = _bandit([("B608", "src/distill/engine.py", 242, "MEDIUM"),
                    ("B608", "src/distill/engine.py", 275, "MEDIUM"),
                    ("B608", "src/distill/engine.py", 999, "MEDIUM")])  # UCUNCU, denetlenmemis
    untriaged, suppressed = filter_bandit(rows, triage)
    assert suppressed == 2
    assert len(untriaged) == 1 and "999" in untriaged[0], untriaged


def test_NEGATIVE_same_test_in_a_new_file_is_not_suppressed():
    triage = load_bandit_triage()
    rows = _bandit([("B608", "src/vault/database.py", 10, "MEDIUM")])
    untriaged, suppressed = filter_bandit(rows, triage)
    assert suppressed == 0 and len(untriaged) == 1


def test_NEGATIVE_high_severity_is_never_touched_by_triage():
    """Triyaj YALNIZCA MEDIUM icindir; HIGH suzgecten hic gecmez."""
    triage = load_bandit_triage()
    rows = _bandit([("B608", "src/distill/engine.py", 242, "HIGH")])
    untriaged, suppressed = filter_bandit(rows, triage)
    assert (untriaged, suppressed) == ([], 0), "HIGH bulgu MEDIUM suzgecine karisti"


def test_NEGATIVE_empty_triage_is_fail_closed():
    rows = _bandit([("B608", "src/distill/engine.py", 242, "MEDIUM")])
    untriaged, suppressed = filter_bandit(rows, {})
    assert suppressed == 0 and len(untriaged) == 1


# --- B608 ailesinin ASIL kaniti: gercek yolu SQL ile surmek ----------------

@pytest.fixture()
def tools(tmp_path):
    """Izole kasa + tam izinli VaultTools (gercek kasaya DOKUNMAZ)."""
    import sqlite3
    from src.vault.database import Vault
    from src.vault.schema import ALL_TABLES, ALL_INDEXES
    from src.mcp_server.tools import VaultTools

    vault = Vault(vault_path=str(tmp_path))
    vault.connect()
    conn = vault.get_connection()
    for sql in ALL_TABLES + ALL_INDEXES:
        conn.execute(sql)
    for scope in ("admin:forget", "profile:write", "events:write"):
        conn.execute("INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?,?,?)",
                     ("t_agent", scope, time.time()))
    conn.commit()
    yield VaultTools(vault, agent_id="t_agent")
    try:
        vault.close()
    except Exception:
        pass


#: forget() iki B608 satirini birden surer: profile'da `key LIKE ?`, events'te
#: `DELETE ... WHERE id IN (<placeholders>)`.
_SQL_PAYLOADS = [
    "'; DROP TABLE events; --",
    "x') OR 1=1 --",
    "1); DELETE FROM profile; --",
    "\" OR \"\"=\"",
]


@pytest.mark.parametrize("payload", _SQL_PAYLOADS)
def test_NEGATIVE_sql_injection_through_id_lists_does_not_execute(tools, payload):
    """SQL meta-karakterli bir topic tablolari DUSURMEMELI ve her sey ayakta kalmali."""
    import sqlite3
    tools.profile_write("user.profile.keepme", "kalmali", [])
    tools.forget(payload)

    conn = sqlite3.connect(tools.vault.db_path)
    try:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"events", "profile", "audit", "permissions"} <= names, \
            f"enjeksiyon tablo dusurdu: eksik={ {'events','profile','audit','permissions'} - names }"
        keys = [k for (k,) in conn.execute("SELECT key FROM profile").fetchall()]
        assert "user.profile.keepme" in keys, "enjeksiyon alakasiz profil satirini sildi"
    finally:
        conn.close()


def test_POSITIVE_forget_actually_deletes_the_matching_row(tools):
    """Kontrol: forget kor bir no-op degil -- MESRU bir konu gercekten siliniyor.

    Bu olmadan yukaridaki dort test, forget() hicbir sey yapmasa da yesil yanardi.
    """
    import sqlite3
    tools.profile_write("user.profile.occupation", "x", [])
    tools.profile_write("user.preferences.coffee", "y", [])
    tools.forget("user.profile.")

    conn = sqlite3.connect(tools.vault.db_path)
    try:
        keys = [k for (k,) in conn.execute("SELECT key FROM profile").fetchall()]
    finally:
        conn.close()
    assert "user.profile.occupation" not in keys, "forget hicbir sey silmedi -> negatif testler anlamsiz"
    assert "user.preferences.coffee" in keys, "forget kapsam disini da sildi"
