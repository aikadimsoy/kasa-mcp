# -*- coding: utf-8 -*-
"""Owner CLI (kasa-admin / src.owner_cli) birim + regresyon testleri (2026-08-21).

Iki yonlu (D24): dogru cagri islerken, yasakli (reserved agent / escalation scope)
RED doner. Ayrica KRITIK invariant: server ve owner CLI AYNI vault'u cozer
(eski "default vault = repo koku" tehlikesi kapatildi).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src import owner_cli, config  # noqa: E402


def test_issue_grant_list_roundtrip(tmp_path, capsys, monkeypatch):
    """SUSMALI: issue-token -> grant -> list dogru calisir."""
    monkeypatch.setenv("KASA_VAULT_PATH", str(tmp_path))
    assert owner_cli.main(["issue-token", "mcp_client"]) == 0
    out = capsys.readouterr().out
    assert "ISSUED for 'mcp_client'" in out
    assert owner_cli.main(["grant", "mcp_client", "profile:write"]) == 0
    assert "GRANTED" in capsys.readouterr().out
    assert owner_cli.main(["grant", "mcp_client", "profile:read:user.*"]) == 0
    capsys.readouterr()
    assert owner_cli.main(["list", "mcp_client"]) == 0
    listed = capsys.readouterr().out
    assert "profile:write" in listed and "profile:read:user.*" in listed


def test_reserved_agent_refused(tmp_path, monkeypatch):
    """ATESLEMELI: 'system' rezerve -> grant ve issue-token RED (exit 2)."""
    monkeypatch.setenv("KASA_VAULT_PATH", str(tmp_path))
    assert owner_cli.main(["grant", "system", "profile:write"]) == 2
    assert owner_cli.main(["issue-token", "system"]) == 2


def test_escalation_scope_refused(tmp_path, monkeypatch):
    """ATESLEMELI: 'admin:grant' kendine-tirmanma -> RED (exit 2)."""
    monkeypatch.setenv("KASA_VAULT_PATH", str(tmp_path))
    assert owner_cli.main(["grant", "mcp_client", "admin:grant"]) == 2


def test_resolve_vault_path_precedence(tmp_path, monkeypatch):
    """KASA_VAULT_PATH oncelikli; yoksa config vault path; site-packages DEGIL."""
    monkeypatch.setenv("KASA_VAULT_PATH", str(tmp_path / "v1"))
    assert config.resolve_vault_path() == os.path.expanduser(str(tmp_path / "v1"))
    monkeypatch.delenv("KASA_VAULT_PATH", raising=False)
    cfg = {"vault": {"path": "~/somewhere/vault"}}
    got = config.resolve_vault_path(cfg)
    assert got == os.path.expanduser("~/somewhere/vault")
    assert "site-packages" not in got


def test_server_and_admin_resolve_same_vault(tmp_path, monkeypatch):
    """INVARIANT: ayni env/config -> server-yolu ve admin-yolu AYNI vault.

    server.py: VAULT_PATH = resolve_vault_path(_cfg)
    owner_cli.main: vault = resolve_vault_path()
    Ikisi de config.resolve_vault_path -> ayni sonuc."""
    vp = str(tmp_path / "shared_vault")
    monkeypatch.setenv("KASA_VAULT_PATH", vp)
    admin_side = config.resolve_vault_path()          # owner CLI yolu
    server_side = config.resolve_vault_path(None)      # server yolu (cfg gecse de env oncelikli)
    assert admin_side == server_side == os.path.expanduser(vp)


def test_owner_cli_default_vault_is_not_repo_root(tmp_path, monkeypatch):
    """REGRESYON: --vault verilmezse default REPO KOKU OLMAMALI (eski tehlike).

    KASA_VAULT_PATH silinip config ~/.kasa'ya yonlendirilir; owner CLI'nin sectigi
    vault repo koku degil, resolver'in dondugu yol olmali."""
    monkeypatch.delenv("KASA_VAULT_PATH", raising=False)
    home = tmp_path / "home"
    (home / ".kasa").mkdir(parents=True)
    # USERPROFILE/HOME esitlenir -> Path.home() ve os.path.expanduser TUTARLI yonlenir.
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)
    monkeypatch.chdir(tmp_path)  # cwd'de ./kasa.toml OLMASIN
    resolved = config.resolve_vault_path()
    repo_root = str(Path(__file__).resolve().parent.parent)
    assert repo_root not in resolved
    assert str(home) in resolved
