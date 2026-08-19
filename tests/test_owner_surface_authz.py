# -*- coding: utf-8 -*-
"""Owner-surface authorization — F-DASH + F-OWNER-SCOPE regression pins.

WHAT THIS PINS (proven live against an independent lab, 2026-08-03)
------------------------------------------------------------------
Two structural holes, both independently confirmed by a separate AI model's lab run
(verdict 9 pass / 3 open = T7-OWNER-DASHBOARD, T8-OWNER-AGENT-BRIDGE, T9-OWNER-TERMS) and
by a from-zero-credentials escalation chain:

  F-DASH:        GET /dashboard (and /terms) served the owner bearer token embedded in HTML
                 with NO authentication -> anyone who can reach the loopback port reads the
                 owner token and escalates. Root cause: dashboard_index/terms_index have no
                 Security(verify_token) and the HTML embeds `bearer_token`.
  F-OWNER-SCOPE: the owner-UI JSON endpoints (/v1/dashboard/*, /v1/agent/models,
                 /v1/terms/status) require only `verify_token` (ANY valid bearer), not an
                 owner scope -> a deliberately low-privilege bound token gets HTTP 200.

Turkce not: bu dosya SIMDI KIRMIZI olmali -- guvenli davranisi iddia ediyor, kod ise henuz
acik. Kimlik BAGLAMANIN dogru calismasi (test_identity_binding.py yesil) bu iki bulguyu
KAPATMAZ: kimlik dogru cozuluyor ama (a) owner token zaten herkese servis ediliyor,
(b) owner uclari kimligin KAPSAMINI denetlemiyor. Iki ayri kapi, iki ayri fix.

The tests assert the SECURE behavior. Until the fix lands they FAIL, and that failure is
the measurement. This is negative-control discipline: the pin must be red before it is green.
"""
import hashlib
import os
import re
import secrets
import sqlite3
import sys
import time

import pytest

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)


def _low_priv_headers(server_client) -> dict:
    """A bound token for a deliberately low-privilege identity (owner never granted it scope)."""
    import importlib
    srv = importlib.import_module("src.mcp_server.server")
    token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(srv.VAULT_INSTANCE.db_path, timeout=5.0)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO agent_tokens (agent_id, token_hash, created_at) VALUES (?, ?, ?)",
            ("low_priv_agent", hashlib.sha256(token.encode()).hexdigest(), time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"Authorization": f"Bearer {token}"}


# --- F-DASH: the owner token must not be served without authorization ------------

@pytest.mark.parametrize("path", ["/dashboard", "/terms"])
def test_owner_ui_does_not_leak_bearer_without_auth(server_client, path):
    """Tokenless GET of an owner UI page must NOT return the bearer token in the body.

    Measured breach: 200 + a 40+ char token string embedded in the HTML.
    """
    import importlib
    srv = importlib.import_module("src.mcp_server.server")
    real_token = srv._BEARER_TOKEN

    resp = server_client["client"].get(path)
    body = resp.text if resp.status_code == 200 else ""
    assert real_token not in body, (
        f"F-DASH: {path} owner bearer token'i AUTH'SUZ sizdirdi "
        f"(HTTP {resp.status_code}); soket acan herkes owner'a yukselir."
    )


# --- F-OWNER-SCOPE: owner endpoints must check scope, not just a valid bearer ----

@pytest.mark.parametrize("path", [
    "/v1/dashboard/profile",
    "/v1/dashboard/stats",
    "/v1/dashboard/events",
    "/v1/dashboard/audit/run",
    "/v1/terms/status",
])
def test_low_priv_bound_token_cannot_reach_owner_endpoints(server_client, path):
    """A valid but low-privilege bound token must be refused (403) on owner surfaces.

    Measured breach: HTTP 200. `verify_token` accepts ANY valid bearer; there is no
    owner-scope gate, so identity binding is bypassed at the authorization layer.
    """
    headers = _low_priv_headers(server_client)
    resp = server_client["client"].get(path, headers=headers)
    assert resp.status_code == 403, (
        f"F-OWNER-SCOPE: dusuk-yetkili token {path} ucuna girdi "
        f"(HTTP {resp.status_code}); owner yuzeyi kapsam denetlemiyor."
    )


def test_POSITIVE_no_token_still_rejected_on_owner_endpoints(server_client):
    """Control: with NO token the owner endpoints already reject (this must stay true)."""
    resp = server_client["client"].get("/v1/dashboard/profile")
    assert resp.status_code in (401, 403), f"beklenen 401/403, geldi {resp.status_code}"


# --- F-OWNER-MUTATE + F-OWNER-TERMS + agent-bridge: MUTATION/kontrol yuzeyi ----------
#
# Turkce not: yukaridaki pinler owner-OKUMA yuzeyini kapatir. Bagimsiz lab (2026-08-04, v0.2.0
# duzeltme-oncesi build) OKUMANIN OTESINDE MUTASYON'u da acik gosterdi: dusuk-yetkili gercek
# token (yazma-reddi ile sub-owner oldugu kanitli) `POST /v1/agent/model` (model DEGISTIR),
# `POST /v1/terms/accept` (owner onayi FLIP) ve tum ajan-koprusu uclarina 200 aldi. HEAD bunlara
# require_owner uyguluyor -> asagidaki pinler HEAD'de YESIL olmali (canli lab'daki acik = "once";
# bu pinler "kapat"in kanitidir). Mutasyon-yarisi okuma-yarisindan daha ciddi: yazma-reddi bir
# token owner AYARINI (model/terms) degistiremez -- tenancy'den bagimsiz yetki ihlali.

_OWNER_ONLY_MUTATE_OR_BRIDGE = [
    ("GET", "/v1/dashboard/audit/report", None),
    ("GET", "/v1/agent/models", None),
    ("POST", "/v1/agent/model", {"name": "any-model"}),        # F-OWNER-MUTATE
    ("POST", "/v1/agent/chat", {"message": "selam"}),
    ("POST", "/v1/agent/race", {"models": ["a", "b"], "message": "selam"}),
    ("POST", "/v1/terms/accept", {}),                          # F-OWNER-TERMS
]


@pytest.mark.parametrize("method,path,body", _OWNER_ONLY_MUTATE_OR_BRIDGE)
def test_low_priv_bound_token_cannot_mutate_or_use_bridge(server_client, method, path, body):
    """A low-privilege bound token must be refused (403) on owner mutation + agent-bridge.

    Measured breach on the independent lab (v0.2.0): HTTP 200 -- `POST /v1/agent/model` returned
    {"ok":true,"selected":...} and `POST /v1/terms/accept` returned {"accepted":true}. HEAD gates
    all of these with require_owner, so the low-priv token must get 403 here (auth before body).
    """
    headers = _low_priv_headers(server_client)
    resp = server_client["client"].request(method, path, headers=headers, json=body)
    assert resp.status_code == 403, (
        f"F-OWNER-MUTATE/BRIDGE: dusuk-yetkili token {method} {path} ucunu kullandi "
        f"(HTTP {resp.status_code}); owner mutasyon/kopru yuzeyi kapsam denetlemiyor."
    )


def test_audit_outputs_do_not_leak_bearer_token(server_client):
    """Audit outputs (report + run) must never contain the raw owner bearer token.

    Turkce not: bagimsiz port-sahibi lab raporu (2026-08-04) audit-cikti maskeleme regresyonu
    onerdi. Audit/report sistem-bilgisi (python_version vb.) donduruyor; bu pin asil sirrin --
    ham owner bearer'inin -- audit ciktisina SIZMADIGINI kilitler. (agent_id gibi ATIF bilgisi
    mesru; yasak olan ham kimlik-materyalidir.)
    """
    import importlib
    srv = importlib.import_module("src.mcp_server.server")
    h = server_client["headers"]
    for path in ("/v1/dashboard/audit/report", "/v1/dashboard/audit/run"):
        r = server_client["client"].get(path, headers=h)
        assert r.status_code == 200, f"{path} owner icin 200 donmedi: {r.status_code}"
        assert srv._BEARER_TOKEN not in r.text, f"{path} ham owner bearer token'i sizdirdi"


def test_POSITIVE_owner_not_locked_out_of_bridge_and_terms(server_client):
    """Control: the owner bearer must NOT be 403 on the bridge/terms surface (fix must not brick).

    (agent/models tolerates a down local model service -> 200 with service_up False; terms/accept
    is a pure owner action -> 200. Neither should ever be 403 for the owner.)
    """
    h = server_client["headers"]
    r_models = server_client["client"].get("/v1/agent/models", headers=h)
    r_terms = server_client["client"].post("/v1/terms/accept", headers=h, json={})
    assert r_models.status_code != 403, f"owner agent/models'ten reddedildi: {r_models.status_code}"
    assert r_terms.status_code != 403, f"owner terms/accept'ten reddedildi: {r_terms.status_code}"


# --- POSITIVE controls: the fix must not brick the legitimate owner flow ---------
#
# Turkce not: negatif pinler (yukarida) "dusuk-yetkili giremez" der. Ama HER SEYI reddeden
# bir kapi da onlari gecerdi. Asagidaki pozitif kontroller, SAHIBIN gercekten calistigini
# olcer: (a) owner bearer'i owner uclarina girer, (b) gecerli launch nonce ile owner UI
# token'i alir. Negatif + pozitif birlikte = kapi DOGRU KOSULDA ayirt ediyor.

def test_POSITIVE_owner_bearer_reaches_owner_endpoints(server_client):
    """The owner (holder of the configured bearer) must NOT be locked out (not 403)."""
    resp = server_client["client"].get("/v1/dashboard/profile", headers=server_client["headers"])
    assert resp.status_code == 200, f"owner kendi ucundan reddedildi: {resp.status_code} {resp.text[:200]}"


def test_POSITIVE_owner_ui_serves_token_with_valid_nonce(server_client):
    """With the launch nonce, /dashboard DOES embed the token (owner launcher path works)."""
    import importlib
    srv = importlib.import_module("src.mcp_server.server")
    resp = server_client["client"].get(f"/dashboard?k={srv._LAUNCH_NONCE}")
    assert resp.status_code == 200
    assert srv._BEARER_TOKEN in resp.text, "gecerli nonce ile owner token gomulmedi -> launcher kirik"


def test_NEGATIVE_wrong_nonce_does_not_serve_token(server_client):
    """A wrong/guessed nonce must NOT unlock the token (constant-time compare)."""
    import importlib
    srv = importlib.import_module("src.mcp_server.server")
    resp = server_client["client"].get("/dashboard?k=wrong-nonce-guess")
    assert srv._BEARER_TOKEN not in resp.text, "yanlis nonce token'i acti -> nonce kapisi delik"
