# kasa/tests/test_dependency_parity.py

"""`requirements.txt` ile `pyproject.toml` bağımlılıkları AYNI olmalı.

Türkçe not (2026-08-20, neden bu dosya var — ölçülmüş bir kayma):

`pyproject.toml`'daki bağımlılık bloğunun üstünde şu yazıyordu:

    # BAGIMLILIKLAR: requirements.txt'ten AYNEN kopyalandi (surum sinirlari dahil).
    # Tek dogruluk kaynagi hala requirements.txt'tir; orasi degisirse burasi da degismeli.

Ama kopya **kaymıştı**: `requirements.txt` `mcp>=1.2,<2` derken `pyproject.toml`
yalnız `mcp>=1.2` diyordu. Ölçüm (RAN-LIVE, 2026-08-20):

* `pip index versions mcp` → en yenisi **2.0.0**
* `mcp-2.0.0-py3-none-any.whl` içinde 'fastmcp' geçen **hiçbir dosya yok**
  (`mcp/server/` altında yalnız `auth`, `lowlevel`, `mcpserver`)
* `src/mcp_adapter/__main__.py:60` → `from mcp.server.fastmcp import FastMCP`

Yani `pip install -r requirements.txt` ile kuran kullanıcı sağlam, `pip install .`
ile kuran kullanıcının MCP adaptörü **import bile edilemiyordu**. İki dosya
arasındaki bir boşluk, ürünün "başkası indirip kullanabilsin" yolunu kırıyordu.

Bir yorum satırı bunu engellemeye yetmedi (yetmedi çünkü yorum bir mekanizma
değildir). Bu dosya mekanizmadır: kayma olursa takım kırmızıya döner.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - CI py3.12 kullanıyor
    tomllib = None


def _norm(spec: str) -> str:
    """Karşılaştırma için normalleştirir: boşluklar atılır, ad küçültülür.

    Sürüm sınırları KORUNUR — kaymanın yaşandığı yer tam olarak orası.
    """
    spec = re.sub(r"\s+", "", spec)
    m = re.match(r"^([A-Za-z0-9._-]+)(.*)$", spec)
    if not m:
        return spec.lower()
    return m.group(1).lower() + m.group(2)


def dependency_drift(requirements: list, pyproject_deps: list) -> list:
    """İki listeyi karşılaştırır; farkları insan-okunur satırlar olarak döner.

    Ayrı bir fonksiyon çünkü **aletin kendisi** de test edilmeli (D24): gerçek
    dosyalar uyumluyken bu fonksiyon hiç çalışmamış olsa da testler yeşil
    görünürdü.
    """
    req = {_norm(x) for x in requirements}
    proj = {_norm(x) for x in pyproject_deps}
    problems = []
    for missing in sorted(req - proj):
        problems.append("pyproject.toml'da eksik/farkli: %s" % missing)
    for extra in sorted(proj - req):
        problems.append("requirements.txt'te eksik/farkli: %s" % extra)
    return problems


def _read_requirements() -> list:
    path = os.path.join(_KASA_ROOT, "requirements.txt")
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                out.append(line)
    return out


def _read_pyproject_deps() -> list:
    """Cekirdek + `desktop` ekstrasi.

    Turkce not: `requirements.txt` sahibin Windows MASAUSTU kurulumudur ve
    PyQt5'i icerir. `pyproject.toml`'un cekirdegi ise sunucu/MCP adaptoru icin
    yeterli olmali (olculdu: PyQt5 ve webview bloklanarak import edildi,
    src.mcp_server.server ve src.mcp_adapter.__main__ SORUNSUZ). Bu yuzden
    esitlik su bicimde kurulur:
        requirements.txt  ==  dependencies + optional-dependencies['desktop']
    Boylece hem bolunme mumkun olur hem de kayma yakalanir.
    """
    path = os.path.join(_KASA_ROOT, "pyproject.toml")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    deps = list(data["project"]["dependencies"])
    deps += list(data["project"].get("optional-dependencies", {}).get("desktop", []))
    return deps


def _read_pyproject_core() -> list:
    path = os.path.join(_KASA_ROOT, "pyproject.toml")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return list(data["project"]["dependencies"])


# ----------------------------------------------------------------------
# 1. GERÇEK DOSYALAR
# ----------------------------------------------------------------------
@pytest.mark.skipif(tomllib is None, reason="tomllib gerekli (py3.11+)")
def test_pyproject_and_requirements_agree():
    problems = dependency_drift(_read_requirements(), _read_pyproject_deps())
    assert not problems, (
        "Bagimlilik listeleri kaymis. pyproject.toml kendi yorumunda "
        "'requirements.txt'ten AYNEN kopyalandi' diyor:\n  - "
        + "\n  - ".join(problems))


@pytest.mark.skipif(tomllib is None, reason="tomllib gerekli (py3.11+)")
def test_mcp_has_an_upper_bound_in_both_files():
    """
    `mcp` üst sınırı HER İKİ dosyada da bulunmalı.

    Genel eşitlik testi bunu zaten kapsar; ayrıca yazıldı çünkü kırılan
    **bu** bağımlılıktı ve sebebi belgeye bağlı: mcp 2.0 `mcp.server.fastmcp`
    modülünü kaldırdı, adaptör onu import ediyor.
    """
    for name, specs in (("requirements.txt", _read_requirements()),
                        ("pyproject.toml", _read_pyproject_deps())):
        mcp = [s for s in specs if _norm(s).startswith("mcp")]
        assert mcp, "%s icinde mcp bagimliligi yok" % name
        assert "<2" in _norm(mcp[0]), (
            "%s: mcp ust siniri yok (%r). mcp 2.0 'mcp.server.fastmcp'i kaldirdi; "
            "src/mcp_adapter/__main__.py onu import ediyor." % (name, mcp[0]))


# ----------------------------------------------------------------------
# 2. ALETİN KENDİSİ — iki yönlü (D24)
# ----------------------------------------------------------------------
def test_drift_checker_detects_a_missing_bound():
    """POZITIF: tam olarak yaşanan kayma yakalanmalı."""
    problems = dependency_drift(["mcp>=1.2,<2"], ["mcp>=1.2"])
    assert problems, "ust sinir kaymasi yakalanmadi"
    assert any("mcp" in p for p in problems)


def test_drift_checker_detects_a_missing_package():
    problems = dependency_drift(["fastapi>=0.100.0", "cryptography>=42.0.0"],
                                ["fastapi>=0.100.0"])
    assert any("cryptography" in p for p in problems)


def test_drift_checker_is_silent_when_equal():
    """NEGATIF: yalnız boşluk/büyük-küçük harf farkı kayma DEĞİLDİR."""
    assert dependency_drift(["FastAPI >= 0.100.0", "mcp>=1.2,<2"],
                            ["fastapi>=0.100.0", "mcp >= 1.2, <2"]) == []


# ----------------------------------------------------------------------
# 3. CEKIRDEK, GUI'SIZ KURULABILIR OLMALI
# ----------------------------------------------------------------------
@pytest.mark.skipif(tomllib is None, reason="tomllib gerekli (py3.11+)")
def test_core_dependencies_carry_no_gui_toolkit():
    """
    `pip install .` bir GUI kutuphanesi kurmamali.

    Olculdu (2026-08-20): PyQt5 ve webview import'lari bloklandiginda
    src.mcp_server.server, src.mcp_adapter.__main__, src.mcp_server.tools ve
    src.vault.database SORUNSUZ import edildi. PyQt5'e dokunan yalniz
    src/tray/app.py ve run.py var (masaustu baslaticilar).

    Neyi cozmez: bu test import edilebilirligi degil, BEYAN EDILEN bagimlilik
    listesini denetler. Bir gun sunucu yoluna PyQt5 sizarsa burasi yesil kalir
    -- onu yakalayan test asagidaki test_server_imports_without_gui_deps.
    """
    core = {_norm(x).split(">")[0].split("<")[0].split("=")[0] for x in _read_pyproject_core()}
    for gui in ("pyqt5", "pyqt6", "pyside2", "pyside6", "pywebview"):
        assert gui not in core, (
            "%s cekirdek bagimlilik olarak beyan edilmis; masaustu ekstrasina taşinmali" % gui)


def test_server_imports_without_gui_deps():
    """
    Beyanin DOGRU oldugunu davranisla olcer: PyQt5/webview yokmus gibi
    davranildiginda sunucu ve MCP adaptoru yine import edilebilmeli.

    (D24 eki 2: liste denetimi ile calisma-ani denetimi ayri sorulardir.)
    """
    import subprocess
    probe = '''
import sys, builtins, os
os.chdir(ROOT); sys.path.insert(0, ROOT)
BLOCKED = {"PyQt5", "webview"}
_real = builtins.__import__
def _imp(name, *a, **k):
    if name.split(".")[0] in BLOCKED:
        raise ImportError("bloklandi (olcum)")
    return _real(name, *a, **k)
builtins.__import__ = _imp
import src.mcp_server.server
import src.mcp_adapter.__main__
print("PROBE-OK")
'''
    code = "ROOT = %r\n" % _KASA_ROOT + probe
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", env=env)
    assert "PROBE-OK" in (out.stdout or ""), (
        "sunucu/adaptor GUI bagimliliklari olmadan import edilemedi:\n"
        + (out.stderr or "")[-2000:])
