# kasa/tests/test_mcp_adapter_contract.py

"""Adaptörün GÖNDERDİĞİ ile sunucunun BEKLEDİĞİ arasındaki sözleşme.

Türkçe not (neden bu dosya var — ölçülmüş bir arıza):

`src/mcp_adapter/__main__.py` bir AI istemcisine altı araç ilan eder. Sunucu bu
çağrıları `server.py` içinde `method(**params)` ile dağıtır. Yani adaptörün
gönderdiği sözlüğün anahtarları, `VaultTools` metodunun imzasına **bağlanabilmek
zorundadır**; bağlanamazsa `TypeError` oluşur ve istemci **HTTP 422** alır.

Bu tam olarak yaşandı ve 2026-08-05'te canlı HTTP isteğiyle ölçüldü
(`docs/KASA_WORKCELL_RAPOR_DEGERLENDIRME_2026-08-05.md`): `profile_read` sunucuda
`reason` parametresini **zorunlu** kılıyordu, adaptör ise yalnız `scope`
gönderiyordu. Sonuç: bir modelin yapabileceği en temel işlem — hafızayı okumak —
her seferinde 422 dönüyordu.

Neden 15 gün boyunca hiçbir test yakalamadı: `tests/test_mcp_adapter.py`
**yalnızca** `proxy.py`'yi (SDK'siz çekirdek) içe aktarır,
`tests/test_mcp_adapter_wiring.py` ise araçların **varlığını** ve kablolamayı
sınar. Hiçbiri araç fonksiyonlarını **gerçek parametrelerle çağırıp** sunucu
imzasına bağlamıyordu. Yani test edilen yüzey, çalışan yüzey değildi.

Bu dosyanın yaptığı: her aracı gerçekten çağırır, gönderdiği parametreleri
yakalar ve `inspect.signature().bind()` ile sunucu imzasına bağlar. Bağlanamayan
her araç, üretimde 422 üretecek olan araçtır.

NEYİ GÖSTERMEZ: bu bir protokol koşumu değildir (o MCP Inspector işi). Sözleşme
uyumunu gösterir, sunucunun o çağrıya doğru **cevap verdiğini** göstermez —
onu `test_mcp_adapter_wiring.py` ve canlı ölçümler kapsar.
"""

from __future__ import annotations

import importlib
import inspect
import os as _os
import sys

import pytest

_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from src.mcp_server.tools import VaultTools  # noqa: E402


def _load_adapter(monkeypatch, tmp_path):
    """Adaptörü, ağa çıkmadan içe aktarır ve gönderdiği parametreleri yakalar."""
    # Türkçe not: Adaptör import anında ayarları çözer; sahte bir kasa.toml ve
    # token vererek onu ağa hiç çıkmadan ayağa kaldırıyoruz.
    cfg = tmp_path / "kasa.toml"
    cfg.write_text(
        '[server]\nbearer_token = "test-token"\nhost = "127.0.0.1"\nport = 8000\n',
        encoding="utf-8")
    monkeypatch.setenv("KASA_CONFIG", str(cfg))
    monkeypatch.setenv("KASA_MCP_TOKEN", "test-token")
    monkeypatch.setenv("KASA_SERVER_URL", "http://127.0.0.1:8000")

    mod = importlib.import_module("src.mcp_adapter.__main__")
    mod = importlib.reload(mod)

    sent: dict = {}

    def _capture(tool_name, parameters):
        sent["tool"] = tool_name
        sent["params"] = dict(parameters)
        return {"status": "captured"}

    monkeypatch.setattr(mod, "_execute", _capture)
    return mod, sent


# Adaptör aracı -> (çağrı argümanları, sunucudaki karşılık gelen metot adı)
# Türkçe not: Ad listesi elle yazılmadı; aşağıdaki test bu sözlüğün adaptörün
# İLAN ETTİĞİ araç kümesiyle birebir aynı olduğunu ayrıca doğrular (D21 ek kuralı:
# elle yazılan ad listesi, listede olmayan dalı "yok" gösterir).
CALLS = {
    "event_ingest": (dict(source="web", type="visit", content={"a": 1}), "event_ingest"),
    "profile_read": (dict(scope="user.*", reason="scan"), "profile_read"),
    "profile_write": (dict(key="user.x", value="v", provenance=[1]), "profile_write"),
    "forget": (dict(topic="x"), "forget"),
    "audit_read": (dict(start_index=0, count=10), "audit_read"),
    "prune_expired_events": (dict(), "prune_expired_events"),
}


def test_call_table_covers_every_advertised_tool(monkeypatch, tmp_path):
    """Bu dosyadaki tablo, adaptörün ilan ettiği araçların TAMAMINI kapsamalı."""
    mod, _sent = _load_adapter(monkeypatch, tmp_path)
    advertised = {
        name for name in dir(mod)
        if callable(getattr(mod, name, None)) and name in CALLS or name in (
            "event_ingest", "profile_read", "profile_write",
            "forget", "audit_read", "prune_expired_events")
    }
    missing = advertised - set(CALLS)
    assert not missing, (
        "Adaptor yeni arac ilan etmis ama bu sozlesme testi onu kapsamiyor: %s" % missing)


@pytest.mark.parametrize("tool_name", sorted(CALLS))
def test_adapter_params_bind_to_server_signature(tool_name, monkeypatch, tmp_path):
    """
    Adaptörün gönderdiği parametreler sunucu metoduna BAĞLANABİLMELİ.

    Sunucu `method(**params)` ile çağırır; bağlanamayan çağrı `TypeError` üretir
    ve istemciye HTTP 422 döner. Bu testin kırmızı olması, o aracın üretimde
    ÇALIŞMADIĞI anlamına gelir.
    """
    mod, sent = _load_adapter(monkeypatch, tmp_path)
    kwargs, server_method_name = CALLS[tool_name]

    getattr(mod, tool_name)(**kwargs)

    assert sent.get("tool") == server_method_name, (
        "Adaptor '%s' icin sunucuda '%s' cagiriyor" % (tool_name, sent.get("tool")))

    server_method = getattr(VaultTools, server_method_name)
    sig = inspect.signature(server_method)
    try:
        # self yerine None: yalniz parametre BAGLAMASI sinaniyor, calistirma degil.
        sig.bind(None, **sent["params"])
    except TypeError as exc:
        pytest.fail(
            "SOZLESME KIRIK: adaptor '%s' aracini %s parametreleriyle gonderiyor, "
            "ama sunucu imzasi %s%s. Uretimde sonuc: TypeError -> HTTP 422. Hata: %s"
            % (tool_name, sorted(sent["params"]), server_method_name, sig, exc))


def test_profile_read_sends_reason(monkeypatch, tmp_path):
    """
    Regresyon kilidi — bu tam olarak 2026-08-05'te olculen ariza.

    `VaultTools.profile_read` `reason` olmadan `ValueError` atar (tools.py:119).
    Adaptor bu alani gondermezse istemci her okumada 422 alir.
    """
    mod, sent = _load_adapter(monkeypatch, tmp_path)
    mod.profile_read(scope="user.*", reason="neden-beyani")

    assert "reason" in sent["params"], (
        "profile_read 'reason' gondermiyor; sunucu onu ZORUNLU kiliyor "
        "(src/mcp_server/tools.py:104,119). Uretimde HTTP 422.")
    assert str(sent["params"]["reason"]).strip(), (
        "'reason' bos gonderilmis; tools.py:119 bos degeri ValueError ile reddeder.")


def test_no_server_method_has_unfilled_required_param(monkeypatch, tmp_path):
    """
    Butun sinifi kilitler: HICBIR aracta doldurulmamis zorunlu parametre kalmamali.

    Turkce not: Tek bir arizayi (profile_read/reason) duzeltip gecmek, ayni sinifin
    diger orneklerini birakmak demek olurdu (O4: bir hata sinifini duzeltince ayni
    sinifin diger yerlerini tararim).
    """
    mod, sent = _load_adapter(monkeypatch, tmp_path)
    broken = []
    for tool_name, (kwargs, server_method_name) in sorted(CALLS.items()):
        sent.clear()
        getattr(mod, tool_name)(**kwargs)
        sig = inspect.signature(getattr(VaultTools, server_method_name))
        try:
            sig.bind(None, **sent["params"])
        except TypeError as exc:
            broken.append("%s: %s" % (tool_name, exc))
    assert not broken, "Sunucu imzasina baglanamayan arac(lar):\n  " + "\n  ".join(broken)
