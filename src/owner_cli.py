# -*- coding: utf-8 -*-
"""KASA owner CLI (kasa-admin) — ajan kimligine izin KAPSAMI + kimlik TOKEN'i yonetir.

Paketlenebilir GERCEK implementasyon (2026-08-21, ChatGPT operator karari). Eski
`tools/grant_agent_scope.py` artik bunun ince bir geriye-uyumluluk wrapper'idir;
tek implementasyon burasidir.

KRITIK duzeltme: eski CLI default vault olarak REPO KOKUNU seciyordu. Wheel'den
kurulan pakette repo koku yoktur; dahasi KASA_VAULT_PATH verilmezse sahibin gercek
kasasi yerine yanlis bir yere BASARIYLA izin yazilabilirdi. Artik vault, server ile
AYNI ortak cozucuden gelir: config.resolve_vault_path() (KASA_VAULT_PATH > config
vault path). "system" (reserved) ve "admin:grant" (kendine-tirmanma) bilerek verilemez.

Kullanim (kurulu pakette):
  kasa-admin issue-token mcp_client
  kasa-admin grant mcp_client profile:write
  kasa-admin grant mcp_client "profile:read:user.*"
  kasa-admin list  mcp_client
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import time

# Turkce not: repo-koku sys.path hilesi YOK. Kurulu pakette `src` zaten
# import edilebilir; kaynaktan kosuldugunda wrapper repo kokunu ekler.
from .vault.database import Vault
from .config import resolve_vault_path

# Rezerve kimlik + kendi-kendine-yukselme kapisi (red-team dersi: grant_permission C7).
_FORBIDDEN_AGENTS = {"system"}
_FORBIDDEN_SCOPES = {"admin:grant"}


def _connect(vault_path: str) -> Vault:
    v = Vault(vault_path=vault_path)
    v.connect()
    return v


def cmd_list(conn, agent_id: str) -> int:
    rows = conn.execute(
        "SELECT scope, granted_at, revoked_at FROM permissions WHERE agent_id = ? ORDER BY scope",
        (agent_id,),
    ).fetchall()
    if not rows:
        print(f"(no scopes for '{agent_id}')")
        return 0
    for scope, granted_at, revoked_at in rows:
        state = "ACTIVE" if revoked_at is None else f"revoked@{time.strftime('%Y-%m-%d', time.localtime(revoked_at))}"
        print(f"{scope:32s} {state}  granted@{time.strftime('%Y-%m-%d %H:%M', time.localtime(granted_at))}")
    return 0


# Turkce not (2026-08-20, OLCULDU): duz 'profile:read' yetkisi HICBIR profil
# okumasini karsilamaz (tools.py profile_read `profile:read:<scope>` ister;
# _check_permission yalniz tam esitlik ya da '*' ile biten yetkide prefix esler).
_SCOPED_PREFIXES = ("profile:read",)


def _warn_if_scope_matches_nothing(scope: str) -> None:
    if scope in _SCOPED_PREFIXES:
        print(
            f"  UYARI: duz '{scope}' yetkisi profil OKUMALARINI karsilamaz.\n"
            f"         profile_read '{scope}:<kapsam>' ister; izin kontrolu tam\n"
            f"         esitlik ya da '*' ile biten yetki arar.\n"
            f"         Muhtemelen istedigin: {scope}:*   ya da  {scope}:user.preferences.*\n"
            f"         (Duz '{scope}' yine de bir ise yarar: list_quarantined onu kontrol eder.)"
        )


def cmd_grant(conn, agent_id: str, scope: str) -> int:
    if agent_id in _FORBIDDEN_AGENTS:
        print(f"REFUSED: agent id '{agent_id}' is reserved.", file=sys.stderr)
        return 2
    if scope in _FORBIDDEN_SCOPES:
        print(f"REFUSED: scope '{scope}' cannot be granted via CLI (escalation gate).", file=sys.stderr)
        return 2
    cur = conn.execute(
        "UPDATE permissions SET revoked_at = NULL, granted_at = ? WHERE agent_id = ? AND scope = ?",
        (time.time(), agent_id, scope),
    )
    if cur.rowcount == 0:
        conn.execute(
            "INSERT INTO permissions (agent_id, scope, granted_at) VALUES (?, ?, ?)",
            (agent_id, scope, time.time()),
        )
    conn.commit()
    print(f"GRANTED: {agent_id} <- {scope}")
    _warn_if_scope_matches_nothing(scope)
    return 0


def cmd_revoke(conn, agent_id: str, scope: str) -> int:
    cur = conn.execute(
        "UPDATE permissions SET revoked_at = ? WHERE agent_id = ? AND scope = ? AND revoked_at IS NULL",
        (time.time(), agent_id, scope),
    )
    conn.commit()
    if cur.rowcount == 0:
        print(f"(nothing to revoke: {agent_id} / {scope})")
    else:
        print(f"REVOKED: {agent_id} -x- {scope}")
    return 0


def cmd_issue_token(conn, agent_id: str) -> int:
    """Mint a bearer token BOUND to one agent id. Printed once; only its hash is stored."""
    if agent_id in _FORBIDDEN_AGENTS:
        print(f"REFUSED: agent id '{agent_id}' is reserved.", file=sys.stderr)
        return 2

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Bir kimlik = bir etkin token (onceki iptal edilir).
    conn.execute(
        "UPDATE agent_tokens SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
        (time.time(), agent_id),
    )
    conn.execute("DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,))
    conn.execute(
        "INSERT INTO agent_tokens (agent_id, token_hash, created_at) VALUES (?, ?, ?)",
        (agent_id, digest, time.time()),
    )
    conn.commit()

    print(f"ISSUED for '{agent_id}'. Store it now -- it is NOT recoverable:\n")
    print(f"    {token}\n")
    print("Use as:  Authorization: Bearer <token>")
    print(f"Scopes are still deny-by-default; grant them with:  grant {agent_id} <scope>")
    return 0


def cmd_revoke_token(conn, agent_id: str) -> int:
    cur = conn.execute(
        "UPDATE agent_tokens SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
        (time.time(), agent_id),
    )
    conn.commit()
    if cur.rowcount == 0:
        print(f"(no active token for '{agent_id}')")
    else:
        print(f"TOKEN REVOKED: {agent_id}")
    return 0


def cmd_list_tokens(conn, agent_id: str) -> int:
    rows = conn.execute(
        "SELECT created_at, revoked_at FROM agent_tokens WHERE agent_id = ?",
        (agent_id,),
    ).fetchall()
    if not rows:
        print(f"(no token for '{agent_id}')")
        return 0
    for created_at, revoked_at in rows:
        state = "ACTIVE" if revoked_at is None else "revoked"
        print(f"token {state}  created@{time.strftime('%Y-%m-%d %H:%M', time.localtime(created_at))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="kasa-admin",
        description="Grant/revoke/list KASA agent permission scopes and identity tokens (owner CLI).")
    p.add_argument("action", choices=["list", "grant", "revoke", "issue-token", "revoke-token", "list-tokens"])
    p.add_argument("agent_id")
    p.add_argument("scope", nargs="?", default=None)
    # KRITIK: default vault = server ile AYNI ortak cozucu (repo koku DEGIL).
    p.add_argument("--vault", default=None,
                   help="vault path (default: KASA_VAULT_PATH, else config [vault] path -- "
                        "server ile ayni resolve_vault_path())")
    args = p.parse_args(argv)

    if args.action in ("grant", "revoke") and not args.scope:
        p.error("scope is required for grant/revoke")

    vault_path = args.vault or resolve_vault_path()
    v = _connect(vault_path)
    try:
        conn = v.get_connection()
        # agent_tokens tablosu eski vault'larda yok olabilir -> idempotent olustur.
        from .vault.schema import CREATE_AGENT_TOKENS_TABLE, CREATE_AGENT_TOKENS_INDEX
        conn.execute(CREATE_AGENT_TOKENS_TABLE)
        conn.execute(CREATE_AGENT_TOKENS_INDEX)

        if args.action == "list":
            return cmd_list(conn, args.agent_id)
        if args.action == "grant":
            return cmd_grant(conn, args.agent_id, args.scope)
        if args.action == "issue-token":
            return cmd_issue_token(conn, args.agent_id)
        if args.action == "revoke-token":
            return cmd_revoke_token(conn, args.agent_id)
        if args.action == "list-tokens":
            return cmd_list_tokens(conn, args.agent_id)
        return cmd_revoke(conn, args.agent_id, args.scope)
    finally:
        v.close()


if __name__ == "__main__":
    raise SystemExit(main())
