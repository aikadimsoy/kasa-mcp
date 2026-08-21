# -*- coding: utf-8 -*-
"""Asset envanteri olcum/contract testleri (P1b, 2026-08-21).

Bu tur URUN DAVRANISI DEGISMEZ; testler yalniz RAN-LIVE envanterin kilit
bulgularini dondurur ve regresyonu (gizli bir tuketici/asset baglantisinin
sessizce ortaya cikmasi) yakalar. Detayli tablo: docs/ASSET_INVENTORY_2026-08-21.md
"""
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _src_files(*exts):
    for p in (_ROOT / "src").rglob("*"):
        if p.is_file() and p.suffix in exts:
            yield p


def test_design_system_not_loaded_at_runtime():
    """H2: design_system/tokens.css runtime'da YUKLENMIYOR -> onefile'da DEAD payload.

    Not (D21/D24): ilk versiyon bare isim-anmasini (yorum + footer atif) consumer
    saniyordu; dogru olcut YUKLEME'dir. Dashboard token'lari INLINE eder ve tokens.css'i
    <link>/@import ile CEKMEZ; hicbir .py design_system'i acmaz. Isim-atif serbest.
    """
    idx = (_ROOT / "src" / "dashboard" / "ui" / "index.html").read_text(encoding="utf-8", errors="replace")
    assert not re.search(r"<link[^>]+tokens\.css", idx, re.I), "dashboard tokens.css'i <link> ile yukluyor"
    assert not re.search(r"@import[^;]+tokens\.css", idx, re.I), "dashboard tokens.css'i @import ile yukluyor"
    py_hits = []
    for p in _src_files(".py"):
        if "design_system" in p.read_text(encoding="utf-8", errors="replace"):
            py_hits.append(str(p.relative_to(_ROOT)))
    assert not py_hits, f"bir .py design_system'i aciyor (dead-payload degil): {py_hits}"


def test_dashboard_ui_is_self_contained_wrt_assets():
    """Dashboard UI /assets'e bagli DEGIL (paketli kurulumda /assets atlansa da calisir).

    index.html @font-face / /assets/fonts / .woff YUKLEMEMELI (yalniz font-family adi).
    """
    idx = (_ROOT / "src" / "dashboard" / "ui" / "index.html").read_text(encoding="utf-8", errors="replace")
    assert "@font-face" not in idx, "dashboard artik self-hosted font yukluyor -> /assets bagimliligi"
    assert "/assets/fonts" not in idx, "dashboard /assets/fonts istiyor -> paketli kurulumda 404"
    assert ".woff" not in idx.lower(), "dashboard woff yukluyor -> /assets bagimliligi"


def test_icon_ico_not_a_runtime_dependency():
    """H1: icon.ico runtime'da OKUNMUYOR (tray PIL ile uretilir). Yalniz build (Nuitka).

    src/ runtime kodunda 'icon.ico' gecmemeli (build_kasa.ps1 haric -- o repo kokunde).
    """
    hits = []
    for p in _src_files(".py"):
        t = p.read_text(encoding="utf-8", errors="replace")
        if "icon.ico" in t.lower():
            hits.append(str(p.relative_to(_ROOT)))
    assert not hits, f"icon.ico runtime kodda referans edilmis (build-only olmali): {hits}"
