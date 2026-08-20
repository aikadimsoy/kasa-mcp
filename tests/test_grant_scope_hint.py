# kasa/tests/test_grant_scope_hint.py

"""`grant_agent_scope.py` hiçbir şeyi karşılamayan bir yetkide uyarmalı.

Türkçe not (2026-08-20, canlı ölçüm):

`src/mcp_server/tools.py:176` `profile_read` için **`profile:read:<kapsam>`**
izni sorar; `:324` `list_quarantined` için **düz `profile:read`** sorar. Aynı
dize, iki anlam. `_check_permission` yalnız tam eşitlik ya da `*` ile biten bir
yetki için prefix eşlemesi yaptığından, düz `profile:read` yetkisi **hiçbir
profil okumasını** karşılamaz.

Gerçek bir stdio MCP istemcisinden ölçüldü:

* `grant my_agent profile:read` → çağrı **HTTP 403**:
  `Ajan 'my_agent' için 'user.preferences' okuma izni yok`
* `grant my_agent "profile:read:*"` → aynı çağrı **başarılı**

Sahip yetkiyi verdiğini sanıp çalışmayan bir kurulumla baş başa kalıyordu ve
hiçbir yerde uyarı yoktu. Bu, davranışı değil **geri bildirimi** düzeltir —
izin anlamlarına dokunulmadı (o sahibin kararı).
"""

from __future__ import annotations

import io
import os
import sys
import contextlib

import pytest

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)
sys.path.insert(0, os.path.join(_KASA_ROOT, "tools"))

import grant_agent_scope as gas  # noqa: E402


def _capture(scope):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        gas._warn_if_scope_matches_nothing(scope)
    return buf.getvalue()


def test_warns_on_bare_profile_read():
    """POZITIF: ölçülen tuzak uyarı üretmeli."""
    out = _capture("profile:read")
    assert "UYARI" in out
    assert "profile:read:*" in out, "dogru duzeltme onerilmemis"


@pytest.mark.parametrize("scope", [
    "profile:read:*",
    "profile:read:user.preferences.*",
    "profile:write",
    "events:write",
    "admin:grant",
    "audit:read",
])
def test_silent_on_scopes_that_work(scope):
    """NEGATIF: çalışan yetkilerde susmalı — gürültü uyarıyı değersizleştirir."""
    assert _capture(scope) == "", scope


def test_hint_matches_the_actual_permission_check():
    """
    Uyarı, koddaki gerçek izin dizesine bağlı olmalı.

    Türkçe not: uyarı metnini elle yazıp `tools.py`'deki dize değişirse uyarı
    sessizce yanlışlaşır. Bu test ikisini birbirine bağlar — `profile_read`
    gerçekten `profile:read:` önekiyle mi soruyor?
    """
    src = os.path.join(_KASA_ROOT, "src", "mcp_server", "tools.py")
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert '_check_permission(f"profile:read:{scope}")' in text, (
        "profile_read artik 'profile:read:<kapsam>' sormuyor olabilir; "
        "grant_agent_scope.py'deki uyari guncellenmeli")
    assert 'profile:read' in gas._SCOPED_PREFIXES
