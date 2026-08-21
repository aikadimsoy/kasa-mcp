# -*- coding: utf-8 -*-
"""Dashboard UI paketleme sozlesmesi (2026-08-21, P1a).

UI dosyalari src/dashboard/ui/ altinda TEK kaynak ve importlib.resources ile okunur.
routes._read_ui uc dosyayi dondurmeli; olmayan kaynakta SESSIZ bos DEGIL, ACIK hata.
pyproject package-data ui/*.html + ui/*.js bildirmis olmali (wheel'e girmesi icin).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.dashboard import routes  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject():
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    return tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_read_ui_returns_all_three():
    """SUSMALI: uc UI dosyasi importlib.resources ile okunur ve dolu."""
    for name, marker in (("index.html", "<!doctype html"),
                         ("app.js", None),
                         ("terms.html", None)):
        txt = routes._read_ui(name)
        assert txt and len(txt) > 100, name
        if marker:
            assert marker in txt.lower()


def test_read_ui_missing_raises_explicit():
    """ATESLEMELI: olmayan kaynak -> ACIK RuntimeError (sessiz bos/fallback HTML YOK)."""
    with pytest.raises(RuntimeError) as ei:
        routes._read_ui("olmayan-dosya.html")
    assert "bulunamadi" in str(ei.value)


def test_ui_files_live_under_src_dashboard_ui():
    """TEK kaynak: dosyalar src/dashboard/ui altinda; eski dashboard_ui/ kopyasi YOK."""
    ui = _ROOT / "src" / "dashboard" / "ui"
    for n in ("index.html", "app.js", "terms.html"):
        assert (ui / n).is_file(), n
    # eski konumda kopya kalmamali (iki UI zamanla sapar)
    old = _ROOT / "dashboard_ui"
    assert not (old / "index.html").exists(), "eski dashboard_ui/index.html hala var (kopya)"


def test_pyproject_declares_dashboard_package_data():
    data = _pyproject()
    pd = data["tool"]["setuptools"]["package-data"]["src.dashboard"]
    assert "ui/*.html" in pd and "ui/*.js" in pd
