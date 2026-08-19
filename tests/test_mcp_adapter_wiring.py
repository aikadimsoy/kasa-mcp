# kasa/tests/test_mcp_adapter_wiring.py

"""MCP SDK wiring tests — the layer that actually speaks MCP.

Turkce not (2026-08-05, neden bu dosya var): tests/test_mcp_adapter.py YALNIZ proxy.py'yi
(SDK'siz cekirdek) ice aktarir ve urlopen'i monkeypatch eder. Yani MCP konusan katmanin test
kapsami SIFIRDI. Sonuc: takim yesilken MCP sunucusu (a) import edilemiyor, (b) kimlik
dogrulayamiyor ve (c) hic protokol el sikismasi tamamlamamis olabiliyordu. Uc canli bulgu bu
kor noktadan cikti:

  F-MCP-DEP    : requirements.txt 'mcp>=1.2' ust sinirsizdi; SDK 2.0.0 mcp.server.fastmcp'yi
                 kaldirdi -> temiz kurulumda adaptor IMPORT bile edilemiyordu.
  F-MCP-BEARER : proxy bearer'i config'ten DOGRUDAN okuyordu -> DPAPI-SARMALI dize
                 gonderiyordu, sunucu duz token bekliyordu -> her cagri HTTP 401.
  (surukleme)  : adaptorun ilan ettigi araclar ile sunucunun PUBLIC_TOOLS listesi ayrisabilir.

Bu dosya uctan uca protokol kosumunun yerini TUTMAZ (o MCP Inspector isi, bkz.
docs/KNOWLEDGE_ARCHIVE.md 2.5); amaci o uc regresyonu ucuz ve otomatik yakalamaktir.
"""

import asyncio
import importlib
import os as _os
import re
import sys

import pytest

_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

#: The adapter's advertised surface. Must equal PUBLIC_TOOLS in the server.
_EXPECTED_TOOLS = {
    "event_ingest", "profile_read", "profile_write",
    "forget", "audit_read", "prune_expired_events",
}


def _write_cfg(tmp_path, bearer: str):
    cfg = tmp_path / "kasa.toml"
    cfg.write_text(
        f'[server]\nbearer_token = "{bearer}"\nhost = "127.0.0.1"\nport = 8000\n',
        encoding="utf-8")
    return cfg


def _fresh_main(monkeypatch, cfg_path):
    """Import src.mcp_adapter.__main__ fresh (module-level build_settings() runs on import)."""
    monkeypatch.setenv("KASA_CONFIG", str(cfg_path))
    monkeypatch.delenv("KASA_SERVER_URL", raising=False)
    monkeypatch.delenv("KASA_MCP_AGENT_ID", raising=False)
    monkeypatch.delenv("KASA_MCP_TOKEN", raising=False)  # gelistirici kabugundan sizmasin
    sys.modules.pop("src.mcp_adapter.__main__", None)
    return importlib.import_module("src.mcp_adapter.__main__")


def test_sdk_import_path_exists():
    """F-MCP-DEP regression: the SDK import the adapter depends on must resolve.

    Turkce not: mcp 2.x'e siciris bu satiri kirar. requirements.txt 'mcp>=1.2,<2' ile
    sabitlendi; bu test o sabitin gercekten tuttugunu dogrular.
    """
    from mcp.server.fastmcp import FastMCP  # noqa: F401


def test_adapter_registers_exactly_the_public_tools(tmp_path, monkeypatch):
    """The advertised MCP tool surface must match the server's allow-list exactly."""
    main = _fresh_main(monkeypatch, _write_cfg(tmp_path, "tok123"))
    names = {t.name for t in asyncio.run(main.mcp.list_tools())}
    assert names == _EXPECTED_TOOLS


def test_no_drift_against_server_public_tools():
    """Read PUBLIC_TOOLS from the server SOURCE (no import: importing has side effects).

    Turkce not: sunucu modulunu ice aktarmak config/vault yaratir; test bunu istemez.
    O yuzden kaynak metinden okunur — surukleme kontrolu icin yeterli.
    """
    src = _os.path.join(_KASA_ROOT, "src", "mcp_server", "server.py")
    with open(src, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"PUBLIC_TOOLS\s*=\s*\{(.*?)\}", text, re.S)
    assert m, "PUBLIC_TOOLS not found in server.py"
    assert set(re.findall(r'"([a-z_]+)"', m.group(1))) == _EXPECTED_TOOLS


def test_every_tool_has_a_description(tmp_path, monkeypatch):
    """A tool with no description is an unusable tool for a client model."""
    main = _fresh_main(monkeypatch, _write_cfg(tmp_path, "tok123"))
    for t in asyncio.run(main.mcp.list_tools()):
        assert t.description and t.description.strip(), f"{t.name} has no description"


#: Tools that delete or overwrite. A client cannot warn the user about a tool we never
#: declared destructive — see docs/MCP_ECOSYSTEM_NOTES.md 7.1 for the measurement that
#: prompted this (official memory server: 9/9 annotated, KASA was 0/6).
_DESTRUCTIVE = {"forget", "prune_expired_events", "profile_write"}
_READ_ONLY = {"profile_read", "audit_read"}


def test_every_tool_is_annotated(tmp_path, monkeypatch):
    main = _fresh_main(monkeypatch, _write_cfg(tmp_path, "tok123"))
    for t in asyncio.run(main.mcp.list_tools()):
        assert t.annotations is not None, f"{t.name} carries no ToolAnnotations"


def test_destructive_tools_are_flagged(tmp_path, monkeypatch):
    """A destructive tool that is not flagged destructive is a silent footgun."""
    main = _fresh_main(monkeypatch, _write_cfg(tmp_path, "tok123"))
    for t in asyncio.run(main.mcp.list_tools()):
        if t.name in _DESTRUCTIVE:
            assert t.annotations.destructiveHint is True, f"{t.name} not flagged destructive"
        if t.name in _READ_ONLY:
            assert t.annotations.readOnlyHint is True, f"{t.name} not flagged read-only"
            assert t.annotations.destructiveHint is False, f"{t.name} flagged destructive"


def test_no_tool_claims_open_world(tmp_path, monkeypatch):
    """KASA operates on a closed local vault; openWorldHint must be False everywhere."""
    main = _fresh_main(monkeypatch, _write_cfg(tmp_path, "tok123"))
    for t in asyncio.run(main.mcp.list_tools()):
        assert t.annotations.openWorldHint is False, f"{t.name} claims open-world"


# Turkce not (kapsam siniri): bearer COZUMU (duz gecis, DPAPI acma, bos token reddi) BILEREK
# burada test EDILMEZ. O regresyonlar tests/test_mcp_adapter.py icinde zaten var
# (test_build_settings_unwraps_dpapi_bearer, test_resolve_bearer_token_*). Ayni seyi iki
# dosyada tutmak, birini degistirip digerini unutmaya davetiye cikarir.
#
# Asagidakiler farkli bir sey sinar: hangi KIMLIK-BILGISININ secildigi (F-MCP-OWNER-BEARER).


def test_agent_token_is_preferred_over_owner_credential(tmp_path, monkeypatch):
    """F-MCP-OWNER-BEARER: KASA_MCP_TOKEN varsa SAHIP bearer'i KULLANILMAMALI.

    Turkce not: adaptor eskiden sahip kimlik-bilgisini tasimak ZORUNDAYDI; o sir
    require_owner() kapisina da yetiyordu. Ajan-bagli token verildiginde artik ona hic
    dokunulmadigini burada sabitliyoruz.
    """
    from src.mcp_adapter import proxy
    monkeypatch.setenv("KASA_CONFIG", str(_write_cfg(tmp_path, "OWNER_SECRET_do_not_use")))
    monkeypatch.setenv("KASA_MCP_TOKEN", "agent_bound_token_xyz")
    s = proxy.build_settings()
    assert s["bearer"] == "agent_bound_token_xyz"
    assert s["owner_credential"] is False
    assert "OWNER_SECRET" not in s["bearer"]


def test_owner_credential_fallback_is_flagged(tmp_path, monkeypatch):
    """Sahip bearer'ina dusuldugunde bu SESSIZ olmamali — cagiran taraf bilmeli."""
    from src.mcp_adapter import proxy
    monkeypatch.setenv("KASA_CONFIG", str(_write_cfg(tmp_path, "owner_tok")))
    monkeypatch.delenv("KASA_MCP_TOKEN", raising=False)
    s = proxy.build_settings()
    assert s["bearer"] == "owner_tok"
    assert s["owner_credential"] is True


def test_agent_id_is_honoured_with_an_agent_token(tmp_path, monkeypatch):
    """Ajan-bagli token ile KASA_MCP_AGENT_ID ARTIK anlamli (eskiden pratikte islevsizdi)."""
    from src.mcp_adapter import proxy
    monkeypatch.setenv("KASA_CONFIG", str(_write_cfg(tmp_path, "owner_tok")))
    monkeypatch.setenv("KASA_MCP_TOKEN", "agent_bound_token_xyz")
    monkeypatch.setenv("KASA_MCP_AGENT_ID", "mcp_client")
    assert proxy.build_settings()["agent_id"] == "mcp_client"


def test_reserved_system_identity_still_refused_with_agent_token(tmp_path, monkeypatch):
    """Yeni kimlik-bilgisi yolu, rezerve kimlik kapisini ATLAMAMALI."""
    from src.mcp_adapter import proxy
    monkeypatch.setenv("KASA_CONFIG", str(_write_cfg(tmp_path, "owner_tok")))
    monkeypatch.setenv("KASA_MCP_TOKEN", "agent_bound_token_xyz")
    monkeypatch.setenv("KASA_MCP_AGENT_ID", "system")
    with pytest.raises(ValueError, match="reserved"):
        proxy.build_settings()
