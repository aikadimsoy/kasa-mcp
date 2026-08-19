# -*- coding: utf-8 -*-
"""Katman 1 — Duman testi: cekirdek ayakta mi?
Fixture'lar conftest.py'den gelir (tmp_vault, vault, tools, server_client);
burada YENIDEN tanimlanmaz."""
import pytest


def test_schema_has_four_tables(vault):
    """Sema kuruldu mu: 4 cekirdek tablo mevcut olmali."""
    conn = vault.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    table_names = {row[0] for row in cursor.fetchall()}
    # sqlite_sequence (AUTOINCREMENT) de olusabilir -> tam esitlik degil, altkume kontrolu
    assert table_names.issuperset({"events", "profile", "permissions", "audit"})


def test_event_roundtrip(tools):
    """Vault acik + yaz/oku: event_ingest success + int event_id dondurmeli."""
    result = tools.event_ingest("smoke", "page_view", {"k": "v"})
    assert result["status"] == "success"
    assert isinstance(result["event_id"], int)


def test_event_ingest_rejects_bad_ttl(tools):
    """Hata yolu: ttl_days=0 gecersiz -> ValueError."""
    with pytest.raises(ValueError):
        tools.event_ingest("smoke", "page_view", {"k": "v"}, ttl_days=0)


def test_health_check(server_client):
    """:8000 ayakta mi: GET / auth'suz 200 + status ok."""
    response = server_client["client"].get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_end_to_end_ingest(server_client, issue_token):
    """Uctan uca: yetkili POST /v1/ingest (browser, events:write auto-grant) -> 200 + success.
    Not: 'system' artik ag disindan reddedilir (C5 fix); mesru ajan 'browser' kullanilir.

    Turkce not (kimlik baglama sonrasi): bu test eskiden PAYLASILAN token ile
    agent_id="browser" BEYAN ederek 200 aliyordu -- yani F-IMP'in ta kendisi olan yoldan
    geciyordu. Uretimde artik boyle bir yol yok; bu yuzden test browser'a BAGLI bir token
    kullaniyor. Olculen sey aynidir (uctan uca yazma calisiyor mu), gecilen yol gercek.
    """
    headers = issue_token("browser")
    payload = {
        "tool": "event_ingest",
        "agent_id": "browser",
        "params": {"source": "smoke", "type": "page_view", "content": {"a": 1}},
    }
    response = server_client["client"].post(
        "/v1/ingest", headers=headers, json=payload
    )
    assert response.status_code == 200
    assert response.json()["result"]["status"] == "success"


def test_ingest_requires_token(server_client):
    """Hata yolu: token'siz POST /v1/ingest -> 401/403."""
    payload = {
        "tool": "event_ingest",
        "agent_id": "system",
        "params": {"source": "smoke", "type": "page_view", "content": {"a": 1}},
    }
    response = server_client["client"].post("/v1/ingest", json=payload)
    assert response.status_code in (401, 403)


def test_audit_log_written(tools, vault):
    """Log yazildi mi: KASA'nin kalici logu = audit tablosu; op sonrasi > 0 satir."""
    tools.event_ingest("smoke", "page_view", {"k": "v"})
    conn = vault.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit")
    assert cursor.fetchone()[0] > 0


def test_run_module_wires_up():
    """run.py cokmeden import ediliyor + main() cagirilabilir (main() CALISTIRILMAZ)."""
    import run
    assert callable(run.main)
