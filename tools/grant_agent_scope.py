# kasa/tools/grant_agent_scope.py
# -*- coding: utf-8 -*-
"""Geriye-uyumluluk WRAPPER'i — gercek implementasyon: src/owner_cli.py (kasa-admin).

2026-08-21 (ChatGPT operator karari): owner CLI paketlenebilir hale getirildi
(`kasa-admin` konsol komutu, src.owner_cli). Eski cagri yolu KORUNUR:
    python tools/grant_agent_scope.py issue-token mcp_client
    python tools/grant_agent_scope.py grant mcp_client profile:write
ama TEK implementasyon src.owner_cli'dir (vault artik server ile AYNI ortak
cozucuden gelir; eski "default vault = repo koku" tehlikesi kalkti).
"""
from __future__ import annotations

import os
import sys

# Kaynaktan kosulurken repo kokunu sys.path'e ekle (kurulu pakette gerek yok).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Geriye-uyum: eski `import grant_agent_scope` yolundan erisilen semboller
# src.owner_cli'ye tasindi; burada YENIDEN DISA AKTARILIR ki eski cagiranlar
# (ve mevcut testler: tests/test_grant_scope_hint.py) kirilmasin.
from src.owner_cli import (  # noqa: E402,F401
    main,
    cmd_list,
    cmd_grant,
    cmd_revoke,
    cmd_issue_token,
    cmd_revoke_token,
    cmd_list_tokens,
    _connect,
    _warn_if_scope_matches_nothing,
    _SCOPED_PREFIXES,
    _FORBIDDEN_AGENTS,
    _FORBIDDEN_SCOPES,
)

if __name__ == "__main__":
    raise SystemExit(main())
