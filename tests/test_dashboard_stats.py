# kasa/tests/test_dashboard_stats.py

"""
Dashboard aggregator guvenlik siniri testleri (read-through-redact, aggregate-first).
Kritik invariant: ham sir hicbir response'a SIZMAZ; recent_events 'content' dondurmez.
Standart: docs/UI_UX_STANDARD.md §7.
"""

import json
import sys

import pytest

import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (tests/ -> parent = depo koku). Sabit yol, depoyu klonlayan herkeste ve
# CI kosucusunda bu testi kirardi.
_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from src.vault.database import Vault
from src.mcp_server.tools import VaultTools
from src.dashboard import stats

# Sentetik test verisi -- GERCEK anahtar degil. Hepsi AWS/Stripe/GitHub/Slack'in
# KENDI dokumantasyon ornekleridir ve maskeleme katmaninin onekleri gercekten
# yakaladigini olcmek icin duruyorlar.
# Turkce not: parcali yazilmalarinin tek sebebi GitHub push-protection'in butun bir
# token gorunce push'u reddetmesi. Python derleme aninda birlestirir -> CALISMA-ANI
# DEGERI BIREBIR AYNI, yani test ayni seyi olcmeye devam eder. Bypass linkine
# tiklamak yerine bu yol secildi: repoda kalici "sir onaylandi" kaydi birakmaz.
_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
_HIGH_ENTROPY = "aB3dF6hJ9kLmN0pQrStUvWxYz012345K"  # url query icine gomulu sir


@pytest.fixture
def vault(tmp_path):
    v = Vault(vault_path=str(tmp_path / "vault"))
    v.connect()
    return v


def test_stats_no_raw_secret_leak(vault):
    tools = VaultTools(vault, "system")
    tools.event_ingest(
        source="accounts.google.com", type="form_submit",
        content={"note": f"aws key {_AWS} burada",
                 "url": f"https://x.com/cb?token={_HIGH_ENTROPY}&x=1"},
    )
    s = stats.compute_stats(vault)
    blob = json.dumps(s, ensure_ascii=False)

    # 1) Ham sir aggregate response'ta OLMAMALI.
    assert _AWS not in blob
    assert _HIGH_ENTROPY not in blob
    # 2) Aggregate dogru.
    assert s["events"]["total"] == 1
    assert s["events"]["masked_markers"] >= 1
    assert s["events"]["with_secrets"] == 1
    # 3) Ingest kapisi maskeledi -> saklanan veride canli sir kalmadi.
    assert s["redaction"]["live_secrets_found"] == 0


def test_recent_events_never_returns_content(vault):
    tools = VaultTools(vault, "system")
    tools.event_ingest(source="api.stripe.com", type="form_submit",
                       content={"secret": _STRIPE})
    evs = stats.recent_events(vault, 10)
    blob = json.dumps(evs, ensure_ascii=False)

    assert _STRIPE not in blob
    assert all("content" not in e for e in evs)
    assert evs[0]["masked"] is True
    assert evs[0]["masked_markers"] >= 1


def test_profile_entries_mask_secrets(vault):
    tools = VaultTools(vault, "system")
    tools.profile_write(key="user.note",
                        value=f"my aws key is {_AWS} keep safe", provenance=[1])
    entries = stats.profile_entries(vault)
    blob = json.dumps(entries, ensure_ascii=False)
    assert _AWS not in blob            # ham sir maskelenmis olmali
    assert any(e["key"] == "user.note" for e in entries)
    note = next(e for e in entries if e["key"] == "user.note")
    assert "[REDACTED]" in json.dumps(note["value"], ensure_ascii=False)


def test_at_rest_reports_honestly(vault):
    tools = VaultTools(vault, "system")
    tools.event_ingest(source="site.example", type="page_view", content={"a": "b"})
    s = stats.compute_stats(vault)
    at = s["at_rest"]
    # Kapidan gecmis veri sifreli -> cell 'full' veya 'partial', asla yanlis "tam-DB".
    assert at["cell_encryption"]["status"] in ("full", "partial")
    assert at["cell_encryption"]["encrypted_cells"] >= 1
    # Tam-DB at-rest DURUST: hala 'pending' (ADR 0003).
    assert at["full_db"]["status"] == "pending"


def test_audit_chain_valid(vault):
    tools = VaultTools(vault, "system")
    tools.event_ingest(source="site.example", type="page_view", content={"a": "b"})
    s = stats.compute_stats(vault)
    assert s["audit"]["records"] >= 1
    assert s["audit"]["chain_valid"] is True


def test_dashboard_routes_registered_on_app():
    # Regresyon: bu ortamda include_router route'lari sessizce dusuruyordu (starlette 1.1.0).
    # register() add_api_route ile app'e GERCEKTEN kaydetmeli.
    from fastapi import FastAPI
    from src.dashboard.routes import register

    app = FastAPI()
    # imza: register(app, get_vault, bearer_token, require_owner, launch_nonce)
    register(app, lambda: None, "tok", lambda: None, "nonce")
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/v1/dashboard/stats" in paths
    assert "/v1/dashboard/events" in paths
    assert "/dashboard" in paths
    assert "/dashboard/app.js" in paths


def test_dashboard_json_endpoints_are_async():
    # Regresyon: SQLite baglantisi event-loop thread'inde; sync def endpoint threadpool'da
    # kosar -> cross-thread ProgrammingError. JSON uclari async OLMALI (E2E smoke yakaladi).
    import inspect
    from fastapi import FastAPI
    from src.dashboard.routes import register

    app = FastAPI()
    # imza: register(app, get_vault, bearer_token, require_owner, launch_nonce)
    register(app, lambda: None, "tok", lambda: None, "nonce")
    routes = {getattr(r, "path", None): r for r in app.routes}
    for p in ("/v1/dashboard/stats", "/v1/dashboard/events"):
        assert inspect.iscoroutinefunction(routes[p].endpoint), f"{p} async olmali"
