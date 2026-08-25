# -*- coding: utf-8 -*-
"""build_kasa.ps1 build-root tasinabilirligi sozlesmesi (2026-08-21).

Makineye-bagimli sabit gelistirme yolu KALDIRILDI; root precedence
-Root > KASA_BUILD_ROOT > $PSScriptRoot ve yanlis agac fail-fast olmali.
Bu STATIK contract testi CI'da regresyonu (sabit yolun geri gelmesi) yakalar.
"""
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PS1 = _ROOT / "build_kasa.ps1"


def _text():
    return _PS1.read_text(encoding="utf-8", errors="replace")


def test_no_hardcoded_dev_root():
    """Sabit 'd:/kasa' (herhangi bicimde) build scriptte OLMAMALI."""
    t = _text()
    assert not re.search(r"d:[\\/]+kasa", t, re.IGNORECASE), "sabit gelistirme yolu geri gelmis"


def test_root_precedence_present():
    """precedence: -Root param + KASA_BUILD_ROOT env + $PSScriptRoot."""
    t = _text()
    assert re.search(r"\[string\]\s*\$Root", t), "-Root parametresi yok"
    assert "KASA_BUILD_ROOT" in t, "KASA_BUILD_ROOT env fallback yok"
    assert "$PSScriptRoot" in t, "$PSScriptRoot son fallback yok"
    assert "Resolve-Path" in t, "Resolve-Path normalizasyonu yok"


def test_fail_fast_checks_present():
    """Yanlis/eksik agac fail-fast: kasa_app.py + src kontrolu + throw."""
    t = _text()
    assert "kasa_app.py" in t and "throw" in t, "kasa_app.py fail-fast yok"
    assert re.search(r"Test-Path[^\n]*\$Root/src", t), "src dizini fail-fast yok"
