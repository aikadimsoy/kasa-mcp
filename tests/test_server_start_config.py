# kasa/tests/test_server_start_config.py

"""`start_server()` yapılandırmadaki host/port'u gerçekten kullanmalı.

Türkçe not (2026-08-20, ölçülmüş sessiz arıza):

`start_server()`'ın imzası `host="127.0.0.1", port=8000` idi ve
`if __name__ == "__main__":` bloğu onu **argümansız** çağırıyordu. Yani
`python -m src.mcp_server.server` ile koşan bir kullanıcının `kasa.toml`
içindeki `[server] port` ayarı **sessizce yok sayılıyordu** — ne kullanılıyor
ne de uyarı basılıyordu.

Ölçüm (RAN-LIVE): `KASA_CONFIG` ile `port = 8791` veren geçici bir config
hazırlandı ve sunucu o config'le başlatıldı. Sunucu **8000**'de açıldı.
Aynı config'ten vault yolu ve bearer token **doğru** okunuyordu
(`server.py:67`, `_CONFIG_PATH` `KASA_CONFIG`'i onurlandırıyor) — geçici vault
dizininde `kasa.db`, `.vaultkey`, `.auditsignkey` oluştu ve gerçek
`~/.kasa/vault` hiç açılmadı. Yani okunmayan **tek** şey porttu.

Bu, "kullanıcı indirip kullanabilir mi" yolundaki bir kusurdur: ayarı
değiştirmek hiçbir şey yapmıyordu.
"""

from __future__ import annotations

import os
import sys

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from src.mcp_server import server as server_mod  # noqa: E402


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, app, host=None, port=None, **kw):
        self.calls.append({"host": host, "port": port})


def test_start_server_uses_configured_host_and_port(monkeypatch):
    """POZITIF: argüman verilmezse yapılandırma kullanılır. (Regresyon.)"""
    rec = _Recorder()
    monkeypatch.setattr(server_mod.uvicorn, "run", rec)
    monkeypatch.setattr(server_mod, "_cfg",
                        {"server": {"host": "127.0.0.1", "port": 8791}})

    server_mod.start_server()

    assert rec.calls, "uvicorn.run hic cagrilmadi"
    assert rec.calls[0]["port"] == 8791, (
        "yapilandirmadaki port yok sayildi: %r" % rec.calls[0])
    assert rec.calls[0]["host"] == "127.0.0.1"


def test_explicit_arguments_still_win(monkeypatch):
    """NEGATIF: açık argüman yapılandırmayı ezer — `run.py` bu yolu kullanır."""
    rec = _Recorder()
    monkeypatch.setattr(server_mod.uvicorn, "run", rec)
    monkeypatch.setattr(server_mod, "_cfg",
                        {"server": {"host": "127.0.0.1", "port": 8791}})

    server_mod.start_server(host="127.0.0.1", port=9123)

    assert rec.calls[0]["port"] == 9123
    assert rec.calls[0]["host"] == "127.0.0.1"


def test_missing_config_keys_fall_back_to_defaults(monkeypatch):
    """Yapılandırma eksikse çökmez; belgelenen varsayılana düşer."""
    rec = _Recorder()
    monkeypatch.setattr(server_mod.uvicorn, "run", rec)
    monkeypatch.setattr(server_mod, "_cfg", {"server": {}})

    server_mod.start_server()

    assert rec.calls[0]["host"] == "127.0.0.1"
    assert rec.calls[0]["port"] == 8000


def test_port_zero_is_honoured_not_treated_as_missing(monkeypatch):
    """
    `port = 0` (işletim sisteminden boş port iste) geçerli bir değerdir.

    Türkçe not: düzeltmede `port or _cfg[...]` yazmak bu değeri sessizce
    yutardı çünkü `0` Python'da falsy'dir — `port is not None` kontrolü
    bilerek seçildi. Bu test o seçimi tutar.
    """
    rec = _Recorder()
    monkeypatch.setattr(server_mod.uvicorn, "run", rec)
    monkeypatch.setattr(server_mod, "_cfg",
                        {"server": {"host": "127.0.0.1", "port": 8791}})

    server_mod.start_server(port=0)

    assert rec.calls[0]["port"] == 0, "port=0 sessizce yapilandirmaya dusuruldu"
