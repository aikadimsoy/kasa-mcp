# kasa/tools/grant_agent_scope.py

"""
Owner CLI: grant/revoke/list permission scopes for an agent id.

KASA permissions are deny-by-default (permissions table). External agents (e.g. the MCP
adapter's "mcp_client") can call PUBLIC_TOOLS over the network, but each tool still checks
its scope — so nothing works until the OWNER grants scopes here, deliberately.

Usage (from repo root; vault path via KASA_VAULT_PATH or --vault):
  py tools/grant_agent_scope.py list  mcp_client
  py tools/grant_agent_scope.py grant mcp_client events:write
  py tools/grant_agent_scope.py grant mcp_client "profile:read:user.*"
  py tools/grant_agent_scope.py revoke mcp_client events:write

Deliberately NOT grantable here: scopes for agent id "system" (reserved) and the
"admin:grant" scope (self-escalation — owner edits are this script itself).

Turkce not: Sahip CLI'si — bir ajan kimligine izin KAPSAMI verir/alir/listeler. KASA izinleri
VARSAYILAN-RED: disaridan gelen ajan (or. adaptorun "mcp_client"i) PUBLIC_TOOLS'u agdan
cagirabilir ama her arac yine kendi kapsamini dener; sahip burada BILEREK kapsam vermeden
hicbir sey calismaz. "system" (reserved) ve "admin:grant" (kendine-tirmanma) bilerek verilemez.
"""

from __future__ import annotations

import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (1 ust dizin = depo koku). Sabit yol, depoyu klonlayan herkeste ve CI
# kosucusunda bu araci calismaz kilardi.
_KASA_ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".."))

import argparse
import hashlib
import os
import secrets
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.vault.database import Vault  # noqa: E402

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


def cmd_grant(conn, agent_id: str, scope: str) -> int:
    if agent_id in _FORBIDDEN_AGENTS:
        print(f"REFUSED: agent id '{agent_id}' is reserved.", file=sys.stderr)
        return 2
    if scope in _FORBIDDEN_SCOPES:
        print(f"REFUSED: scope '{scope}' cannot be granted via CLI (escalation gate).", file=sys.stderr)
        return 2
    # Soft-revoke edilmis satir varsa yeniden aktive et; yoksa ekle.
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
    """Mint a bearer token BOUND to one agent id. Printed once; only its hash is stored.

    Turkce not: kimlik baglamanin (F-IMP fix) sahip tarafindaki yarisi budur. Sunucu
    kimligi token'dan cozer; token'i da buradan uretirsin. Duz token DISKE YAZILMAZ --
    yalnizca SHA-256'si saklanir, dolayisiyla kaybedilirse geri getirilemez, yenisi
    uretilir (eskisi ayni komutla otomatik iptal olur).
    """
    if agent_id in _FORBIDDEN_AGENTS:
        print(f"REFUSED: agent id '{agent_id}' is reserved.", file=sys.stderr)
        return 2

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Ayni kimlik icin ONCEKI token'i iptal et: bir kimlik = bir etkin token.
    # Sebep: iki etkin token, "hangisi sizdi" sorusunu cevaplanamaz kilar.
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
    p = argparse.ArgumentParser(description="Grant/revoke/list KASA agent permission scopes and identity tokens (owner CLI).")
    p.add_argument("action", choices=["list", "grant", "revoke", "issue-token", "revoke-token", "list-tokens"])
    p.add_argument("agent_id")
    p.add_argument("scope", nargs="?", default=None)
    p.add_argument("--vault", default=os.environ.get("KASA_VAULT_PATH", _KASA_ROOT),
                   help="vault path (default: KASA_VAULT_PATH, else the repo root)")
    args = p.parse_args(argv)

    if args.action in ("grant", "revoke") and not args.scope:
        p.error("scope is required for grant/revoke")

    v = _connect(args.vault)
    try:
        conn = v.get_connection()
        # agent_tokens tablosu eski vault'larda yok olabilir -> idempotent olustur.
        from src.vault.schema import CREATE_AGENT_TOKENS_TABLE, CREATE_AGENT_TOKENS_INDEX
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
