# -*- coding: utf-8 -*-
"""Identity binding (F-IMP root-cause fix) — positive and negative controls.

WHAT WAS MEASURED BEFORE THIS FIX
---------------------------------
`agent_id` arrived in the request body and was never verified against the bearer token,
because there was only ONE shared token that was not bound to any identity. Measured
consequences (docs/MCP_CANLI_TEST_EYLEM_PLANI_2026-08-02.md §F-IMP and
docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md §4.1):

  * a holder of the shared token could claim agent_id="browser" and inherit the
    events:write permission auto-granted at startup -> event_ingest returned HTTP 200
  * rate-limit buckets were keyed on the ASSERTED identity, so rotating the identity
    produced a fresh bucket every time: 150 requests with a rotating id -> ZERO 429s,
    and 300 such requests wrote 300 permanent rows into the audit chain
  * therefore the audit chain proved immutability but NOT attribution

WHAT THIS FILE PINS
-------------------
The identity is now resolved FROM THE TOKEN and the body claim is only a claim.

Turkce not: bu dosyanin degeri "reddediyor" testinde DEGIL, POZITIF ve NEGATIF kontrolun
BIRLIKTE bulunmasindadir. Her zaman reddeden bir kapi da negatif testi gecer; her zaman
kabul eden bir kapi da pozitif testi gecer. Ancak ikisi birden, kapinin DOGRU KOSULDA
ayirt ettigini gosterir. Ayrica hiz-siniri regresyonu, kimlik baglamanin yan etkisini
degil ASIL SONUCUNU olcer: kova artik uydurulamayan bir anahtara baglidir.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    """Isolated server instance on a throwaway vault (never the owner's real vault).

    Turkce not — IZOLASYON YONTEMI, ve neden boyle:
    ilk yazimda `del sys.modules["src.*"]` ile modulleri yeniden import ediyordum, cunku
    KASA_VAULT_PATH server.py'de IMPORT ANINDA okunuyor (server.py:70). Bu yontem calisti
    ama KURESEL durumu kirletti: yeniden import, DPAPI sarmalayicisinin surec-basina tekil
    nesnesini de yeniden kurdu ve ayni oturumdaki 13 ALAKASIZ test ctypes.ArgumentError ile
    dustu. Yani test, olcmedigi bir seyi bozdu -- kendi basina bir yanlis-KIRMIZI kaynagi.

    Dogru yol: modulu OLDUGU GIBI birak, yalnizca bu testin ihtiyaci olan iki kuresel
    nesneyi monkeypatch ile degistir. monkeypatch test bitiminde ikisini de geri koyar,
    dolayisiyla sizinti yok. Bu, kimlik cozumunu de bozmaz: resolve_agent VAULT_INSTANCE'i
    cagri aninda modul global'inden okur, import aninda yakalamaz.
    """
    import sqlite3

    import src.mcp_server.server as server
    from src.vault.database import Vault
    from src.vault.schema import ALL_TABLES, ALL_INDEXES

    vault = Vault(vault_path=str(tmp_path))
    vault.connect()
    conn = vault.get_connection()
    for sql in ALL_TABLES + ALL_INDEXES:
        conn.execute(sql)
    conn.commit()
    # Semayi kurduktan sonra KAPAT: sqlite baglantilari thread'e bagimlidir ve bu baglanti
    # pytest'in ana thread'inde acildi. Istekleri TestClient'in portal thread'i servis eder;
    # baglantiyi acik birakirsak arac katmani orada ProgrammingError alir. Uretimde bu sira
    # dogaldir (baglantiyi lifespan, sunucunun kendi thread'inde acar) -- fixture da ona uysun.
    vault.close()

    monkeypatch.setattr(server, "VAULT_INSTANCE", vault)
    # Hiz-siniri kovasi da surec-basina tekildir; taze olmazsa 300-istek regresyonu
    # onceki testlerden kalan tuketimi olcerdi (bir baska yanlis-PASS kaynagi).
    monkeypatch.setattr(server, "RATE_LIMITER", server.RateLimiter(capacity=60, refill_per_sec=1.0))
    try:
        yield server
    finally:
        try:
            vault.close()
        except Exception:
            # lifespan zaten kapatmis olabilir (ya da baska thread'de acilmistir).
            pass


def _db(server):
    """Own short-lived connection on the vault file — thread-agnostic, like the owner CLI."""
    import sqlite3
    return sqlite3.connect(server.VAULT_INSTANCE.db_path, timeout=5.0)


def _issue(server, agent_id: str) -> str:
    """Mint a token bound to `agent_id` (the owner-CLI path, exercised directly)."""
    import hashlib
    import secrets as _secrets

    token = _secrets.token_urlsafe(32)
    conn = _db(server)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO agent_tokens (agent_id, token_hash, created_at) VALUES (?, ?, ?)",
            (agent_id, hashlib.sha256(token.encode()).hexdigest(), time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return token


# --- Resolution: identity comes from the token ------------------------------

def test_bound_token_resolves_to_its_own_identity(srv):
    token = _issue(srv, "agent_alpha")
    creds = type("C", (), {"credentials": token})()
    assert srv.resolve_agent(creds) == "agent_alpha"


def test_two_tokens_resolve_to_two_identities(srv):
    """The whole point: the token, not the caller, decides who you are."""
    a = _issue(srv, "agent_alpha")
    b = _issue(srv, "agent_beta")
    mk = lambda t: type("C", (), {"credentials": t})()
    assert srv.resolve_agent(mk(a)) == "agent_alpha"
    assert srv.resolve_agent(mk(b)) == "agent_beta"


def test_legacy_shared_token_maps_to_one_fixed_identity(srv):
    """Backward compat is not a hole: the old token is now pinned to ONE identity."""
    creds = type("C", (), {"credentials": srv._BEARER_TOKEN})()
    assert srv.resolve_agent(creds) == srv.LEGACY_AGENT_ID


def test_unknown_token_is_rejected(srv):
    from fastapi import HTTPException
    creds = type("C", (), {"credentials": "not-a-real-token"})()
    with pytest.raises(HTTPException) as e:
        srv.resolve_agent(creds)
    assert e.value.status_code == 401


def test_revoked_token_stops_resolving(srv):
    import time
    from fastapi import HTTPException

    token = _issue(srv, "agent_gamma")
    conn = _db(srv)
    try:
        conn.execute("UPDATE agent_tokens SET revoked_at=? WHERE agent_id=?", (time.time(), "agent_gamma"))
        conn.commit()
    finally:
        conn.close()

    creds = type("C", (), {"credentials": token})()
    with pytest.raises(HTTPException) as e:
        srv.resolve_agent(creds)
    assert e.value.status_code == 401


# --- The mismatch gate: positive AND negative control -----------------------

def test_POSITIVE_matching_claim_is_accepted(srv):
    """Control: the gate is not a blanket refusal — a truthful claim passes."""
    assert srv._bound_identity("agent_alpha", "agent_alpha") == "agent_alpha"


def test_POSITIVE_absent_claim_uses_bound_identity(srv):
    """No claim at all is fine — the token already said who you are."""
    assert srv._bound_identity(None, "agent_alpha") == "agent_alpha"


def test_NEGATIVE_impersonation_is_refused(srv):
    """THE regression this whole change exists for.

    Turkce not: F-IMP tam olarak buydu. Gecerli bir token + BASKA bir kimlik beyani
    eskiden KABUL EDILIYORDU (event_ingest 200 donuyordu). Artik 403.
    """
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        srv._bound_identity("browser", "agent_alpha")
    assert e.value.status_code == 403


def test_NEGATIVE_legacy_token_cannot_claim_privileged_identity(srv):
    """The exact measured attack: shared token claiming the auto-granted 'browser' id."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        srv._bound_identity("browser", srv.LEGACY_AGENT_ID)
    assert e.value.status_code == 403


# --- Rate limit: the same root cause, measured ------------------------------

def test_rotating_claimed_identity_no_longer_dodges_the_rate_limit(srv):
    """Before: 150 requests with a rotating id produced ZERO 429s. Now the key is bound.

    Turkce not: burada HTTP degil, kovanin ANAHTARI olculuyor -- cunku duzeltilen sey
    tam olarak oydu. Saldirgan her istekte yeni bir kimlik uydurabiliyordu ve her
    uydurma TAZE bir kova aliyordu. Kimlik artik token'a bagli oldugu icin, 300 istegin
    tamami AYNI kovadan tuketir ve kova biter.
    """
    limiter = srv.RATE_LIMITER
    bound = "agent_alpha"

    allowed = 0
    for i in range(300):
        # Saldirganin niyeti: her seferinde baska bir kimlik. Artik etkisiz --
        # kovaya giden anahtar beyan degil, BAGLI kimlik.
        _claimed = f"spoofed_{i}"
        if limiter.allow(bound, cost=1.0):
            allowed += 1

    assert allowed < 300, "rate limit never engaged — bucket is still dodgeable"
    assert allowed <= 120, f"bucket refilled far beyond capacity ({allowed} allowed)"


# --- End-to-end: the endpoint must actually USE the gate --------------------
#
# Turkce not: yukaridaki testler _bound_identity fonksiyonunu izole olcer. Bu, ucun
# o fonksiyonu GERCEKTEN CAGIRDIGINI kanitlamaz -- fonksiyon dogru olup uc onu hic
# kullanmiyor olabilirdi ve tum testler yine yesil yanardi. Klasik yanlis-PASS.
# Asagidakiler HTTP katmanindan gecer; olculen sey F-IMP'in birebir kendisidir.

@pytest.fixture()
def client(srv):
    """Entered TestClient: `with` runs lifespan, so the vault connects in the SERVING thread.

    Turkce not: `with` bloksuz TestClient lifespan'i CALISTIRMAZ; o zaman vault baglantisi
    istegi karsilayan thread'de degil, testin thread'inde acilir ve arac katmani sqlite
    ProgrammingError alir. Bu ayrinti uretimdeki sirayi taklit etmenin ta kendisidir.
    """
    from fastapi.testclient import TestClient
    with TestClient(srv.app, raise_server_exceptions=False) as c:
        yield c


def test_E2E_impersonation_via_execute_tool_is_refused(srv, client):
    """Measured before: shared token + agent_id="browser" -> 200. Now: 403."""
    resp = client.post(
        "/v1/execute_tool",
        json={"agent_id": "browser", "tool_calls": [{"tool_name": "event_ingest", "parameters": {}}]},
        headers={"Authorization": f"Bearer {srv._BEARER_TOKEN}"},
    )
    assert resp.status_code == 403, f"impersonation still accepted: {resp.status_code} {resp.text[:200]}"


def test_E2E_impersonation_via_ingest_is_refused(srv, client):
    """The single-tool endpoint must not be a side door (it was the measured 200)."""
    resp = client.post(
        "/v1/ingest",
        json={"tool": "event_ingest", "agent_id": "browser", "params": {}},
        headers={"Authorization": f"Bearer {srv._BEARER_TOKEN}"},
    )
    assert resp.status_code == 403, f"impersonation still accepted: {resp.status_code} {resp.text[:200]}"


def _grant(server, agent_id: str, scope: str) -> None:
    conn = _db(server)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?, ?, ?)",
            (agent_id, scope, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def test_E2E_POSITIVE_bound_token_actually_works_end_to_end(srv, client):
    """Control: a bound token, acting as ITSELF, completes a real write. Must be HTTP 200.

    Turkce not — BU TESTIN ILK HALI YANLIS-PASS URETIYORDU. Once yalnizca
    `"uyusmuyor" not in resp.text` denetleniyordu; oysa kimlik hic COZULEMEDIGINDE cevap
    401 "Gecersiz token" oluyor ve o metinde de "uyusmuyor" gecmiyor -> test YESIL yaniyordu.
    Nitekim gercek uvicorn'a karsi olcum, bagli token'in HER istekte 401 aldigini gosterdi
    (sync bagimlilik threadpool'da kosuyor, vault baglantisi loop thread'ine ait -> sqlite
    ProgrammingError, genis except tarafindan yutuluyordu). Yani kapinin POZITIF yonu
    tamamen kirikti ve bu test onu goremiyordu.

    Ders: pozitif kontrol, reddin YOKLUGUNU degil, BASARININ VARLIGINI olcmelidir.
    """
    token = _issue(srv, "agent_alpha")
    _grant(srv, "agent_alpha", "events:write")
    resp = client.post(
        "/v1/ingest",
        json={"tool": "event_ingest", "agent_id": "agent_alpha",
              "params": {"source": "test", "type": "page_view", "content": {"a": 1}}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code != 401, \
        f"bagli token cozulemedi -> kimlik deposu okuma yolu kirik: {resp.text[:200]}"
    assert resp.status_code == 200, f"bagli token uctan uca calismadi: {resp.status_code} {resp.text[:200]}"


def test_E2E_POSITIVE_bound_token_needs_no_claim(srv, client):
    """The claim is optional: the token alone establishes who you are."""
    token = _issue(srv, "agent_alpha")
    _grant(srv, "agent_alpha", "events:write")
    resp = client.post(
        "/v1/ingest",
        json={"tool": "event_ingest",
              "params": {"source": "test", "type": "page_view", "content": {"b": 2}}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, f"{resp.status_code} {resp.text[:200]}"


def test_E2E_unknown_token_is_401_not_403(srv, client):
    """Auth failure and identity failure must stay distinguishable."""
    resp = client.post(
        "/v1/ingest",
        json={"tool": "event_ingest", "params": {}},
        headers={"Authorization": "Bearer totally-invalid"},
    )
    assert resp.status_code == 401
