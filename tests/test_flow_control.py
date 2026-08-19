# kasa/tests/test_flow_control.py

"""
DEBI (debi/akış kontrolü) katmanı testleri:
  DEBI-0 rate limit (429), DEBI-1 event dedup (HMAC + sayaç),
  DEBI-2 audit checkpoint/arşiv (zincir bütünlüğü korunur),
  DEBI-3 tombstone prune (provenance kökeni kopmaz).
"""

import importlib
import json


# ---------- DEBI-1: event dedup ----------

def test_event_dedup_same_content_single_row(tools, vault):
    r1 = tools.event_ingest("browser", "page_view", {"url": "https://example.com"})
    r2 = tools.event_ingest("browser", "page_view", {"url": "https://example.com"})
    assert r1["deduplicated"] is False
    assert r2["deduplicated"] is True
    assert r2["event_id"] == r1["event_id"]
    rows = vault.get_connection().execute(
        "SELECT occurrence_count, last_seen FROM events").fetchall()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2
    assert rows[0]["last_seen"] is not None


def test_event_dedup_different_content_two_rows(tools, vault):
    tools.event_ingest("browser", "page_view", {"url": "https://a.example"})
    tools.event_ingest("browser", "page_view", {"url": "https://b.example"})
    count = vault.get_connection().execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 2


def test_event_dedup_source_type_distinguish(tools, vault):
    # Ayni icerik, farkli source/type -> farkli kimlik (HMAC girdisi source|type icerir)
    tools.event_ingest("browser", "page_view", {"url": "https://x.example"})
    tools.event_ingest("browser", "form_submit", {"url": "https://x.example"})
    count = vault.get_connection().execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 2


def test_event_dedup_resets_distilled_flag(tools, vault):
    r1 = tools.event_ingest("browser", "page_view", {"url": "https://r.example"})
    conn = vault.get_connection()
    conn.execute("UPDATE events SET distilled = 1 WHERE id = ?", (r1["event_id"],))
    conn.commit()
    tools.event_ingest("browser", "page_view", {"url": "https://r.example"})
    row = conn.execute("SELECT distilled FROM events WHERE id = ?", (r1["event_id"],)).fetchone()
    assert row["distilled"] == 0  # tekrar = damitma icin yeni sinyal


# ---------- DEBI-0: rate limit ----------

def test_rate_limit_returns_429(server_client, issue_token):
    srv = importlib.import_module("src.mcp_server.server")
    srv.RATE_LIMITER.capacity = 3
    srv.RATE_LIMITER.refill_per_sec = 0.0
    srv.RATE_LIMITER.reset()
    client = server_client["client"]
    headers = issue_token("browser")   # kimlik artik token'dan cozulur (F-IMP fix)
    body = {"agent_id": "browser",
            "tool_calls": [{"tool_name": "event_ingest",
                            "parameters": {"source": "browser", "type": "page_view",
                                           "content": {"url": "https://rl.example"}}}]}
    codes = [client.post("/v1/execute_tool", json=body, headers=headers).status_code
             for _ in range(4)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429


def test_rate_limit_bucket_is_per_agent(server_client, issue_token):
    """Kovalar ajan basinadir -- ve ajan artik BEYAN degil, token'dan cozulen kimliktir.

    Turkce not: bu testin anlami kimlik baglamayla DEGISTI. Eskiden tek token ile
    govdedeki agent_id degistirilerek iki ayri kova elde ediliyordu; o yol tam olarak
    hiz-siniri baypasinin kendisiydi (donen kimlikle 150 istekte 0 adet 429). Ayrimin
    hala gecerli oldugunu gostermek icin artik IKI AYRI BAGLI TOKEN gerekiyor --
    yani ayricalik sahibin bilerek urettigi token'dan geliyor, saldirganin beyanindan degil.
    """
    srv = importlib.import_module("src.mcp_server.server")
    srv.RATE_LIMITER.capacity = 1
    srv.RATE_LIMITER.refill_per_sec = 0.0
    srv.RATE_LIMITER.reset()
    client = server_client["client"]
    hdr_a = issue_token("agent_a")
    hdr_b = issue_token("agent_b")

    def call(headers):
        return client.post("/v1/execute_tool", json={
            "tool_calls": [{"tool_name": "audit_read", "parameters": {}}]}, headers=headers)

    first = call(hdr_a)
    second = call(hdr_a)
    other = call(hdr_b)
    assert first.status_code != 429
    assert second.status_code == 429   # agent_a kovasi bos
    assert other.status_code != 429    # agent_b kendi kovasindan tuketir

    # NEGATIF KONTROL: ayni token ile BASKA bir kimlik beyan edip taze kova almak
    # artik mumkun mu? Olmamali -- bu, duzeltilen kok nedenin ta kendisi.
    spoof = client.post("/v1/execute_tool", json={
        "agent_id": "agent_b",   # A'nin token'i, B'nin kimligi
        "tool_calls": [{"tool_name": "audit_read", "parameters": {}}]}, headers=hdr_a)
    assert spoof.status_code == 403, \
        f"kimlik beyaniyla taze kova alinabildi -> hiz-siniri hala delik ({spoof.status_code})"


# ---------- DEBI-2: audit checkpoint + arsiv ----------

def _audit_count(vault):
    return vault.get_connection().execute("SELECT COUNT(*) FROM audit").fetchone()[0]


def test_audit_checkpoint_archive_preserves_chain(tools, vault):
    for i in range(5):
        tools.event_ingest("browser", "page_view", {"url": f"https://cp{i}.example"})
    chain = vault.audit_chain
    assert chain.verify_chain() is True
    before = _audit_count(vault)

    cp = tools.audit_checkpoint()
    assert cp["status"] == "success"
    res = tools.audit_archive(cp["checkpoint_id"])
    assert res["deleted"] == before  # muhur kapsamindaki her sey silindi
    assert _audit_count(vault) == 2  # kalan: checkpoint-kaydi + archive-kaydi
    assert chain.verify_chain() is True  # zincir muhurden tohumlanir, kirilmaz

    # Arsiv sonrasi yeni kayitlar zincire sorunsuz eklenir
    tools.event_ingest("browser", "page_view", {"url": "https://after.example"})
    assert chain.verify_chain() is True


def test_audit_archive_requires_checkpoint(tools, vault):
    import pytest
    with pytest.raises(ValueError):
        tools.audit_archive(999)  # muhursuz aralik silinemez


def test_audit_tamper_detected_after_archive(tools, vault):
    tools.event_ingest("browser", "page_view", {"url": "https://t.example"})
    cp = tools.audit_checkpoint()
    tools.audit_archive(cp["checkpoint_id"])
    tools.event_ingest("browser", "page_view", {"url": "https://t2.example"})
    conn = vault.get_connection()
    conn.execute("UPDATE audit SET action = 'tampered' WHERE id = (SELECT MAX(id) FROM audit)")
    conn.commit()
    assert vault.audit_chain.verify_chain() is False


def test_audit_checkpoint_seed_not_spoofable(tools, vault):
    # Ilk satirin previous_hash'i genesis-degil ama checkpoint tablosunda YOKSA -> FAIL.
    # (Muhur iddia degil, tabloda dogrulanan kayittir.)
    tools.event_ingest("browser", "page_view", {"url": "https://s.example"})
    conn = vault.get_connection()
    conn.execute("UPDATE audit SET previous_hash = 'deadbeef' WHERE id = (SELECT MIN(id) FROM audit)")
    conn.commit()
    assert vault.audit_chain.verify_chain() is False


# ---------- DEBI-3: tombstone prune ----------

def test_prune_tombstones_referenced_deletes_unreferenced(tools, vault):
    kept = tools.event_ingest("browser", "page_view", {"url": "https://keep.example"})
    dropped = tools.event_ingest("browser", "page_view", {"url": "https://drop.example"})
    tools.profile_write("user.test_pref", "value", [kept["event_id"]])

    conn = vault.get_connection()
    conn.execute("UPDATE events SET ttl_expiry = 0, distilled = 1")
    conn.commit()

    res = tools.prune_expired_events()
    assert res["tombstoned"] == 1
    assert res["deleted"] == 1

    rows = {r["id"]: r["content"] for r in conn.execute("SELECT id, content FROM events").fetchall()}
    assert kept["event_id"] in rows
    assert rows[kept["event_id"]].startswith("tombstone:")  # icerik gitti, satir kaldi
    assert dropped["event_id"] not in rows

    # Ikinci prune ayni satiri tekrar saymaz (idempotent)
    res2 = tools.prune_expired_events()
    assert res2["tombstoned"] == 0 and res2["deleted"] == 0


def test_tombstone_not_matched_by_dedup(tools, vault):
    r1 = tools.event_ingest("browser", "page_view", {"url": "https://tomb.example"})
    tools.profile_write("user.tomb", "v", [r1["event_id"]])
    conn = vault.get_connection()
    conn.execute("UPDATE events SET ttl_expiry = 0, distilled = 1")
    conn.commit()
    tools.prune_expired_events()
    # Ayni olay tekrar gelirse mezar tasina dedup OLMAZ; taze satir acilir
    r2 = tools.event_ingest("browser", "page_view", {"url": "https://tomb.example"})
    assert r2["deduplicated"] is False
    assert r2["event_id"] != r1["event_id"]


def test_forget_still_hard_deletes(tools, vault):
    # T5: unutulma hakki tombstone'dan ustundur -> forget gercek silme yapar
    e = tools.event_ingest("browser", "page_view", {"url": "https://secret-topic.example"})
    tools.profile_write("user.secret-topic", "v", [e["event_id"]])
    res = tools.forget("secret-topic")
    assert res["status"] == "success"
    count = vault.get_connection().execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0
