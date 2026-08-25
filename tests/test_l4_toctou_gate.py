# -*- coding: utf-8 -*-
"""
L4 TOCTOU / owner-gate KALICI regresyon (Controller, plan §2 ilke 9).
paranoid (agresif/site-kirabilen) kademe yalniz owner-sifresiyle ACIK oturumda gecerli olmali.
Kanit: (1) set_level gate kilitliyken reddeder; (2) EYLEM NOKTASINDA (boot) config dogrudan
'paranoid'e kurcalanmis olsa bile strict'e dusurur -> gate yalniz set_level'da degil, yuklemede de.
"""
import sys
import os
import json
import tempfile

import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (tests/ -> parent = depo koku). Sabit yol, depoyu klonlayan herkeste ve
# CI kosucusunda bu testi kirardi.
_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)
import src.browser.browser_window as bw



class _FakeWindow:
    """
    KasaApi'nin origin kapisi icin asgari pencere taklidi.

    Turkce not (2026-08-20): Bu sinif, commit 53cca97 ile eklenen
    `_verify_origin()` kapisi yuzunden gerekli oldu. Kapi `self._win` yoksa
    False doner (browser_window.py:1076-1077) ve `set_level` daha kilit
    mantigina VARMADAN "strict" dondurur (browser_window.py:1170-1172).
    Testler KasaApi'yi ciplak kuruyordu, yani kapiyi degil onun yoklugunu
    olcuyorlardi.

    DIKKAT -- bos URL kullanilmaz: browser_window.py:1082 `if not url: return True`
    diyor, yani bos URL veren bir sahte pencere kapiyi OTOMATIK gecer ve kapiyi
    hic sinamamis oluruz. Bu yuzden gercekci bir loopback URL'i veriliyor.
    """

    def __init__(self, url="http://127.0.0.1:8000/dashboard"):
        self._url = url

    def get_current_url(self):
        return self._url


def _tmp_cfg(content):
    p = os.path.join(tempfile.mkdtemp(), "browser_config.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(content, f)
    return p


def test_set_level_paranoid_rejected_when_locked(monkeypatch):
    cfg = _tmp_cfg({"privacy_level": "strict"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    api = bw.KasaApi()
    # Turkce not (2026-08-20): Bu satir eskiden YOKTU ve test YANLIS SEBEPTEN
    # geciyordu. `_verify_origin()` pencere olmadigi icin False donuyor,
    # set_level "strict" veriyor ve `res != "paranoid"` sarti sagleniyordu --
    # yani test, olcmek istedigi KILIDI degil origin blogunu dogruluyordu.
    # Sessiz yanlis-PASS. Pencere verilerek kapi acilir, boylece reddin
    # gercekten kilitten geldigi olculur.
    api.set_window(_FakeWindow())
    api._adv_unlocked = False
    res = api.set_level("paranoid")
    assert res != "paranoid", f"kilitliyken paranoid kabul edildi: {res}"
    assert json.load(open(cfg, encoding="utf-8"))["privacy_level"] != "paranoid"


def test_set_level_paranoid_allowed_when_unlocked(monkeypatch):
    cfg = _tmp_cfg({"privacy_level": "strict"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    api = bw.KasaApi()
    api.set_window(_FakeWindow())          # origin kapisi ACIK olmali ki KILIT olculsun
    api._adv_unlocked = True
    assert api.set_level("paranoid") == "paranoid"


def test_boot_downgrades_tampered_paranoid(monkeypatch):
    # TOCTOU / eylem-noktasi: config DOGRUDAN paranoid'e kurcalanmis (set_level bypass) ->
    # boot _adv_unlocked=False oldugundan strict'e dusurmeli.
    cfg = _tmp_cfg({"privacy_level": "paranoid"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    bw.KasaApi()  # __init__ boot-downgrade
    assert json.load(open(cfg, encoding="utf-8"))["privacy_level"] == "strict", \
        "kurcalanmis paranoid boot'ta strict'e dusurulmedi (action-point gate ihlali)"


# --------------------------------------------------------------------------
# ORIGIN KAPISININ KENDI TESTI (iki yonlu)
#
# Turkce not: Kapi commit 53cca97 ile eklendi ama onu DOGRUDAN sinayan tek bir
# test yoktu; varligini yalniz baska testleri kirarak belli etti. Bir kapi,
# "yabanciyi reddediyor" ve "sahibi geciriyor" birlikte olculmeden dogrulanmis
# sayilmaz -- her seyi reddeden bir kapi da tek yonlu testi gecer.
# --------------------------------------------------------------------------
def test_origin_gate_refuses_foreign_page(monkeypatch):
    """NEGATIF: loopback disi bir sayfa ayricalikli API'yi cagiramaz."""
    cfg = _tmp_cfg({"privacy_level": "strict"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    api = bw.KasaApi()
    api.set_window(_FakeWindow("https://evil.example/attack"))
    api._adv_unlocked = True               # kilit ACIK -- red YALNIZ origin'den gelmeli
    assert api.set_level("paranoid") != "paranoid",         "yabanci origin ayricalikli cagriyi yapabildi"


def test_origin_gate_allows_loopback_page(monkeypatch):
    """POZITIF: loopback sayfasi gecmeli -- kapi kor bir red degil."""
    cfg = _tmp_cfg({"privacy_level": "strict"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    api = bw.KasaApi()
    api.set_window(_FakeWindow("http://localhost:8000/"))
    api._adv_unlocked = True
    assert api.set_level("paranoid") == "paranoid"


def test_origin_gate_refuses_when_no_window(monkeypatch):
    """Pencere hic yoksa reddedilir (browser_window.py:1076-1077)."""
    cfg = _tmp_cfg({"privacy_level": "strict"})
    monkeypatch.setattr(bw, "_BROWSER_CONFIG_PATH", cfg)
    api = bw.KasaApi()
    api._adv_unlocked = True
    assert api.set_level("paranoid") != "paranoid"
