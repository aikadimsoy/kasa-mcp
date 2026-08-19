# -*- coding: utf-8 -*-
"""
L4 KALICI regresyon (Controller): execute_tool/ingest hata->HTTP status eslemesi.
Yakalanan hatalar: (1) ValueError (gecersiz girdi, orn. TTL araligi) 500'e dusuyordu -> 400 olmali;
(2) generic 500 govdesinde str(e) ile ic detay SIZIYORDU -> genel mesaj, sizinti yok.
"""
import os
import sys
import importlib
import tempfile

import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (tests/ -> parent = depo koku). Sabit yol, depoyu klonlayan herkeste ve
# CI kosucusunda bu testi kirardi.
_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)
from fastapi.testclient import TestClient


def _client():
    os.environ["KASA_VAULT_PATH"] = tempfile.mkdtemp()
    import src.mcp_server.server as srv
    importlib.reload(srv)
    return srv, TestClient(srv.app, raise_server_exceptions=False)


def _auth(srv):
    return {"Authorization": "Bearer " + srv._BEARER_TOKEN}


def _post_profile_read(srv, client):
    with client:
        # agent_id beyani KALDIRILDI (kimlik baglama sonrasi): paylasilan token artik
        # "tester" kimligini soyleyemez, 403 alirdi ve istek profile_read'e ULASMAZDI.
        # Bu dosya hata->HTTP eslemesini olcuyor; olcum icin cagrinin araca varmasi sart.
        return client.post("/v1/execute_tool", headers=_auth(srv), json={
            "tool_calls": [{"tool_name": "profile_read", "parameters": {"scope": "user.x"}}],
        })


def test_valueerror_maps_to_400_not_500():
    srv, client = _client()
    import src.mcp_server.tools as tools
    orig = tools.VaultTools.profile_read
    tools.VaultTools.profile_read = lambda self, scope: (_ for _ in ()).throw(ValueError("gecersiz TTL araligi"))
    try:
        r = _post_profile_read(srv, client)
        assert r.status_code == 400, f"ValueError 400'e eslenmeli, geldi: {r.status_code}"
    finally:
        tools.VaultTools.profile_read = orig
        os.environ.pop("KASA_VAULT_PATH", None)


def test_internal_500_body_does_not_leak_details():
    srv, client = _client()
    import src.mcp_server.tools as tools
    SECRET = "INTERNAL_SECRET_XYZ_9931"
    orig = tools.VaultTools.profile_read
    tools.VaultTools.profile_read = lambda self, scope: (_ for _ in ()).throw(RuntimeError(SECRET))
    try:
        r = _post_profile_read(srv, client)
        assert r.status_code == 500, f"generic hata 500 olmali, geldi: {r.status_code}"
        assert SECRET not in r.text, "500 govdesi ic detay (str(e)) SIZDIRDI!"
    finally:
        tools.VaultTools.profile_read = orig
        os.environ.pop("KASA_VAULT_PATH", None)
