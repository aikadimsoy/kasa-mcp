# -*- coding: utf-8 -*-
"""README onboarding sozlesmesi (P2, 2026-08-21).

README'nin OLCULMUS gerceklikle tutarli kalmasini kilitler: eski (yanlis) iddialar
geri gelmesin, dogru paket yolu (3 entry-point, deny-by-default, Windows hedef,
browser disabled, PyPI yok) korunsun. Urun davranisini DEGISTIRMEZ; regresyon yakalar.
"""
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EN = (_ROOT / "README.md").read_text(encoding="utf-8", errors="replace")
_TR = (_ROOT / "README.tr.md").read_text(encoding="utf-8", errors="replace")


def test_no_stale_pip_install_unsupported_claim():
    """`pip install .` artik CALISIYOR -> README 'basarisiz/desteklenmiyor' DEMEMELI."""
    for name, txt in (("EN", _EN), ("TR", _TR)):
        assert "No module named 'src'" not in txt, f"{name}: eski 'pip install . kirik' iddiasi kalmis"
    assert "there is no `pip install kasa`" not in _EN.lower() or "no `pip install kasa`" in _EN.lower()
    # PyPI'da yayimli DEGIL -- bunu ACIKCA soylemeli (uydurma paket gibi davranmamali)
    assert "pip install kasa`" in _EN and "not published" in _EN.lower()
    assert "PyPI'da `pip install kasa` YOKTUR" in _TR


def test_three_console_entry_points_documented():
    """kasa-server + kasa-mcp + kasa-admin ucu de README'de gecmeli (2 degil 3)."""
    for name, txt in (("EN", _EN), ("TR", _TR)):
        for cmd in ("kasa-server", "kasa-mcp", "kasa-admin"):
            assert cmd in txt, f"{name}: {cmd} README'de yok"


def test_python_312_not_310():
    """Python badge/hedef 3.12 olmali (3.10+ DEGIL -- pyproject >=3.12,<3.13)."""
    assert "python-3.12" in _EN and "python-3.10" not in _EN
    assert "3.10+" not in _EN


def test_windows_target_no_crossplatform_secure_vault_claim():
    """Platform: Windows hedef; 'cross-platform secure vault' gibi parity iddiasi OLMAMALI."""
    assert "Windows only" in _EN
    assert not re.search(r"cross-platform\s+secure\s+vault", _EN, re.I)
    # macOS/Linux'ta DPAPI no-op (parity yok) acikca yazili
    assert "DPAPI" in _EN and "no-op" in _EN


def test_browser_ships_disabled_is_clear():
    """Browser'in disabled statusu README'de acik olmali."""
    assert "ships disabled" in _EN
    assert "disabled" in _TR.lower() or "KASA_ENABLE_BROWSER" in _TR


def test_onboarding_uses_agent_bound_token():
    """Onboarding least-privilege AGENT token'i tarif etmeli; owner fallback tercih EDILMEMELI."""
    assert "KASA_MCP_AGENT_ID" in _EN and "agent-bound token" in _EN
    assert "prefer the agent" in _EN.lower()
