# -*- coding: utf-8 -*-
"""Paketleme sozlesmesi (2026-08-21, ChatGPT operator karari).

RAN-LIVE olcum: `pip install .` eskiden EXIT 0 ile KODSUZ wheel uretiyordu.
Bu testler o rejimi kilitler; regresyonu erken yakalar. Iki yonlu (D24):
ateslemeli (yanlis hedef) ve susmali (dogru hedef) durumlar acikca ayrilir.

NOT: tam wheel-build + repo-disi E2E ayri kosulur (CI release gate karari
ChatGPT'de). Burasi build gerektirmeyen, ag gerektirmeyen sozlesme testleridir.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import config  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject():
    try:
        import tomllib
    except ImportError:  # py<3.11 (CI 3.12'dir; guvenlik agi)
        import tomli as tomllib  # type: ignore
    return tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


# --- config resolver: tek dogruluk kaynagi ---

def test_resolve_config_path_kasa_config_wins(tmp_path, monkeypatch):
    """SUSMALI: KASA_CONFIG acikca verilmisse aynen o kullanilir (test izolasyonu)."""
    p = tmp_path / "explicit.toml"
    monkeypatch.setenv("KASA_CONFIG", str(p))
    assert config.resolve_config_path() == Path(str(p))


def test_resolve_config_path_home_over_local(tmp_path, monkeypatch):
    """~/.kasa/kasa.toml mevcutsa ./kasa.toml'a TERCIH edilir (ChatGPT precedence)."""
    home = tmp_path / "home"
    (home / ".kasa").mkdir(parents=True)
    (home / ".kasa" / "kasa.toml").write_text("x=1", encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "kasa.toml").write_text("y=1", encoding="utf-8")
    monkeypatch.delenv("KASA_CONFIG", raising=False)
    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(proj)
    assert config.resolve_config_path() == home / ".kasa" / "kasa.toml"


def test_resolve_config_path_local_when_no_home(tmp_path, monkeypatch):
    """~/.kasa yoksa ./kasa.toml (kaynak/dev geriye uyumluluk)."""
    home = tmp_path / "home"
    home.mkdir()  # .kasa YOK
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "kasa.toml").write_text("y=1", encoding="utf-8")
    monkeypatch.delenv("KASA_CONFIG", raising=False)
    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(proj)
    assert config.resolve_config_path() == Path("./kasa.toml")


def test_resolve_config_path_create_target_is_home(tmp_path, monkeypatch):
    """Hicbiri yoksa olusturma hedefi ~/.kasa/kasa.toml (site-packages DEGIL)."""
    home = tmp_path / "home"
    home.mkdir()  # .kasa YOK
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.delenv("KASA_CONFIG", raising=False)
    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(empty)
    got = config.resolve_config_path()
    assert got == home / ".kasa" / "kasa.toml"
    assert "site-packages" not in str(got)


# --- pyproject: build-system + entry-point + paket kesfi ---

def test_pyproject_has_build_system():
    data = _pyproject()
    assert data["build-system"]["build-backend"] == "setuptools.build_meta"
    assert any("setuptools" in r for r in data["build-system"]["requires"])


def test_pyproject_declares_console_scripts():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["kasa-server"] == "src.mcp_server.server:start_server"
    assert scripts["kasa-mcp"] == "src.mcp_adapter.__main__:main"


def test_pyproject_packages_find_includes_src():
    find = _pyproject()["tool"]["setuptools"]["packages"]["find"]
    assert "src*" in find["include"]


def test_entry_point_targets_exist():
    """Ateslemeli-degil: entry-point'lerin isaret ettigi callable'lar GERCEKTEN var."""
    from src.mcp_server.server import start_server
    assert callable(start_server)
    src = (_ROOT / "src" / "mcp_adapter" / "__main__.py").read_text(encoding="utf-8")
    assert "def main(" in src and "main()" in src
