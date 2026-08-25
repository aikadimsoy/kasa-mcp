# kasa/tests/test_mcp_adapter_e2e.py

"""Adaptör → gerçek sunucu: uçtan uca.

Türkçe not (neden bu dosya var):

Bu depoda adaptörle ilgili üç test dosyası vardı ve **hiçbiri** adaptörün ürettiği
gövdeyi gerçek sunucuya göndermiyordu:

* `test_mcp_adapter.py`      → `urlopen`'ı monkeypatch eder, sunucu yok
* `test_mcp_adapter_wiring.py` → araçların **varlığını** ve SDK kablolamasını sınar
* `test_mcp_adapter_contract.py` → parametreleri imzaya **bağlar**, ağ yok

Uçtan uca (adaptör → HTTP → sunucu) test sayısı **sıfırdı**. İki üretim kusuru tam
bu boşlukta yaşadı:

1. `profile_read` sunucunun zorunlu kıldığı `reason` alanını göndermiyordu
   → `TypeError` → **HTTP 422** (2026-08-05'te ölçüldü, 2026-08-20'de düzeltildi).
2. Adaptör sahip kimlik-bilgisiyle koşarken `agent_id="mcp_client"` beyan ediyordu;
   sunucu kimliği `"legacy"` çözüyor ve `server.py:333` çelişkiyi **HTTP 403** ile
   reddediyordu — izin kapısına bile varmadan (2026-08-20'de ölçüldü ve düzeltildi).

İkisi de burada koşan tek bir testle yakalanırdı. Bu dosyanın varlık sebebi budur.

NEYİ GÖSTERMEZ: bu bir MCP **protokol** koşumu değildir (o MCP Inspector işi) ve
gerçek bir istemci süreciyle stdio üzerinden konuşmaz. Gösterdiği şey: adaptörün
ürettiği gövde, sunucunun tam yetki yığınından geçer ve beklenen sonucu alır.
"""

from __future__ import annotations

import io
import json
import os as _os
import sys

import pytest

_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from src.mcp_adapter import proxy  # noqa: E402


class _FakeResponse:
    """urlopen'ın döndürdüğü nesnenin proxy tarafından kullanılan yüzeyi."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._payload


@pytest.fixture
def adapter_through_server(server_client, monkeypatch):
    """
    Adaptörün urlopen'ını GERÇEK sunucuya bağlar.

    Türkçe not: Soketten geçmiyoruz ama gövde, başlıklar ve yetki yığını gerçek —
    yani `_bound_identity`, izin kapısı, hız sınırı ve denetim zinciri hepsi koşar.
    Ölçülen şey adaptörün ürettiği isteğin sunucuda ne yaptığıdır.
    """
    client = server_client["client"]
    seen: dict = {}

    def _fake_urlopen(req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        seen["body"] = body
        seen["auth"] = req.headers.get("Authorization")
        resp = client.post(
            "/v1/execute_tool", json=body,
            headers={k: v for k, v in req.headers.items() if k.lower() != "content-length"},
        )
        seen["status"] = resp.status_code
        if resp.status_code >= 400:
            # proxy urllib.error.HTTPError bekler; aynı yüzeyi taklit ediyoruz.
            import urllib.error
            # Turkce not: fp gercek bir dosya-benzeri olmali; SimpleNamespace
            # kullanmak yorumlayici kapanirken "no attribute 'close'" uyarisi
            # uretiyordu. Test dosyasinin kendisi de temiz kosmali.
            raise urllib.error.HTTPError(
                req.full_url, resp.status_code, resp.text, hdrs=None,
                fp=io.BytesIO(resp.content))
        return _FakeResponse(resp.content)

    monkeypatch.setattr(proxy.urllib.request, "urlopen", _fake_urlopen)
    return {"seen": seen, "token": server_client["token"], "client": client}


def _grant(client, token, agent_id, scope):
    """
    Izin verir — testin kendi kurulumu, olculen sey degil.

    Turkce not: TAZE baglanti aciliyor. VAULT_INSTANCE'in baglantisi TestClient'in
    lifespan thread'inde acildi ve sqlite baglantilari thread'e bagimlidir; ayni
    gerekce tests/conftest.py:76'da da yazili. Sahibin CLI'si de ayri bir surecten
    yazar, yani bu uretimdeki yolun taklidi.
    """
    import sqlite3
    from src.mcp_server import server as srv
    conn = sqlite3.connect(srv.VAULT_INSTANCE.db_path, timeout=5.0)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?, ?, ?)",
            (agent_id, scope, 1000.0))
        conn.commit()
    finally:
        conn.close()


def _owner_settings(token):
    """Belgelenen varsayılan: KASA_MCP_TOKEN yok, kasa.toml'daki sahip token'ı."""
    return {"bearer": token, "base_url": "http://127.0.0.1:8000",
            "agent_id": None, "owner_credential": True}


# ----------------------------------------------------------------------
# POZİTİF: belgelenen varsayılan kurulum GERÇEKTEN çalışmalı
# ----------------------------------------------------------------------
def test_owner_fallback_profile_read_succeeds(adapter_through_server):
    """
    Regresyon kilidi (403).

    Adaptör sahip kimlik-bilgisiyle koşuyor, kimlik beyan etmiyor; sunucu kimliği
    'legacy' çözüyor. Bu, README'nin ve `__main__.py` PREREQUISITES bölümünün
    tarif ettiği kurulumdur ve ÇALIŞMAK ZORUNDADIR.
    """
    ctx = adapter_through_server
    _grant(ctx["client"], ctx["token"], "legacy", "profile:read:user.*")

    proxy.execute(_owner_settings(ctx["token"]), "profile_read",
                  {"scope": "user.*", "reason": "e2e-test"})

    assert ctx["seen"]["status"] == 200, (
        "Belgelenen varsayilan kurulum HTTP %s dondu. Adaptorun beyan ettigi kimlik "
        "sunucunun cozdugu kimlikle celisiyorsa server.py:333 403 verir."
        % ctx["seen"]["status"])
    assert "agent_id" not in ctx["seen"]["body"], (
        "Sahip geri-dususunde govdede agent_id olmamali (beyan yok = catisma yok).")


def test_profile_read_carries_reason_end_to_end(adapter_through_server):
    """
    Regresyon kilidi (422).

    `VaultTools.profile_read` `reason`'i zorunlu kilar; adaptor gondermezse sunucu
    `method(**params)` ile cagirdiginda TypeError -> 422 olur.
    """
    ctx = adapter_through_server
    _grant(ctx["client"], ctx["token"], "legacy", "profile:read:user.*")

    proxy.execute(_owner_settings(ctx["token"]), "profile_read",
                  {"scope": "user.*", "reason": "neden-beyani"})

    params = ctx["seen"]["body"]["tool_calls"][0]["parameters"]
    assert params.get("reason"), "reason gonderilmemis -> uretimde HTTP 422"
    assert ctx["seen"]["status"] == 200


def test_event_ingest_succeeds_end_to_end(adapter_through_server):
    """Yazma yolu da uctan uca kosmali — tek arac degil, yuzey sinanir."""
    ctx = adapter_through_server
    _grant(ctx["client"], ctx["token"], "legacy", "events:write")

    proxy.execute(_owner_settings(ctx["token"]), "event_ingest",
                  {"source": "test", "type": "e2e", "content": {"k": "v"}, "ttl_days": 1})

    assert ctx["seen"]["status"] == 200


# ----------------------------------------------------------------------
# NEGATİF: kimlik kapısı hâlâ çalışmalı (düzeltme onu köreltmedi)
# ----------------------------------------------------------------------
def test_conflicting_declared_identity_is_still_refused(adapter_through_server):
    """
    Duzeltme kimlik kapisini KORELTMEDI.

    Turkce not: Cozum "her zaman beyan etme" DEGIL. Kullanici KASA_MCP_AGENT_ID'yi
    acikca verdiyse beyan gonderilir ve token'a bagli kimlikle celisiyorsa 403
    almasi DOGRUDUR -- sessiz duzeltme, istemcinin yanlis kimlikle is yaptigini
    gizler ve denetim kaydini yanlis okutur (server.py:329-332).
    """
    ctx = adapter_through_server
    _grant(ctx["client"], ctx["token"], "legacy", "profile:read:user.*")
    _grant(ctx["client"], ctx["token"], "mcp_client", "profile:read:user.*")

    settings = _owner_settings(ctx["token"])
    settings["agent_id"] = "mcp_client"   # acik ve CELISKILI beyan

    with pytest.raises(Exception):
        proxy.execute(settings, "profile_read", {"scope": "user.*", "reason": "e2e"})

    assert ctx["seen"]["status"] == 403, (
        "Celiskili kimlik beyani reddedilmeliydi; alinan: %s. Izin HER IKI kimlige "
        "verildi, yani red izin kapisindan degil kimlik kapisindan gelmelidir."
        % ctx["seen"]["status"])


def test_unauthenticated_call_is_refused(adapter_through_server):
    """Pozitif kontrol degil, NEGATIF kontrol: kapi kor bir 'evet' degil."""
    ctx = adapter_through_server
    settings = _owner_settings("kesinlikle-yanlis-token")

    with pytest.raises(Exception):
        proxy.execute(settings, "profile_read", {"scope": "user.*", "reason": "e2e"})

    assert ctx["seen"]["status"] in (401, 403)
