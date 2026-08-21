# -*- coding: utf-8 -*-
"""package-install-e2e — KURULU WHEEL'i (source tree DEGIL) uctan uca dogrular.

ChatGPT operator karari (2026-08-21): "pip install . + pytest" yetmez; wheel'in
GERCEKTEN calistigi, kaynak agactan BAGIMSIZ kanitlanmali. Bu script pkgvenv
python'i ile, repo DISI bir cwd'den, fake HOME altinda kosar ve:

  1. `import src` -> site-packages'tan geliyor (GITHUB_WORKSPACE / kaynak agac DEGIL)
  2. kasa-server (console entry) baslar, HTTP health verir
  3. kasa-admin issue-token + least-privilege grant (owner fallback DEGIL)
  4. kasa-mcp (stdio) -> MCP initialize -> 6 tool
  5. write / read / restart-persistence / system.security+admin.config quarantine /
     saldiri sonrasi normal write

Herhangi biri kalirsa exit != 0. Cikti JSON ozet.

Kosum (CI): pkgvenv python bu dosyayi repo-DISI cwd'den calistirir. Entry-point
exe'leri sys.executable'in yanindaki Scripts/bin dizininden bulunur. Fake HOME
cagiran (workflow) tarafindan USERPROFILE/HOME ile verilir; server+admin+config
ayni vault'u oradan cozer.
"""
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

PORT = int(os.environ.get("KASA_E2E_PORT", "8000"))
BASE = f"http://127.0.0.1:{PORT}"
SCRIPTS = Path(sys.executable).parent  # venv Scripts/ (exe'ler burada)
EXE = ".exe" if os.name == "nt" else ""


def _exe(name):
    return str(SCRIPTS / f"{name}{EXE}")


def _fail(msg):
    print(json.dumps({"RESULT": "FAIL", "where": msg}, ensure_ascii=False))
    sys.exit(1)


def assert_import_from_site_packages():
    """import src site-packages'tan mi -- kaynak agactan DEGIL (ayri subprocess, bu cwd)."""
    code = "import src, json; print(json.dumps({'f': src.__file__}))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    if out.returncode != 0:
        _fail(f"import src basarisiz: {out.stderr[:300]}")
    f = json.loads(out.stdout.strip())["f"]
    ws = os.environ.get("GITHUB_WORKSPACE", "")
    checks = {
        "import_src_file": f,
        "from_site_packages": "site-packages" in f.replace("\\", "/"),
        "not_from_workspace": (not ws) or (ws.replace("\\", "/") not in f.replace("\\", "/")),
    }
    if not checks["from_site_packages"] or not checks["not_from_workspace"]:
        _fail(f"import src KAYNAK AGACTAN geldi: {checks}")
    return checks


def wait_health(timeout=40):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(BASE + "/", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(1)
    return False


def start_server():
    p = subprocess.Popen([_exe("kasa-server")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_health():
        p.terminate()
        _fail("kasa-server health vermedi")
    return p


def admin(*args):
    out = subprocess.run([_exe("kasa-admin"), *args], capture_output=True, text=True)
    return out.returncode, out.stdout, out.stderr


def issue_and_grant():
    rc, so, se = admin("issue-token", "mcp_client")
    if rc != 0:
        _fail(f"kasa-admin issue-token: {se[:200]}")
    tok = None
    for line in so.splitlines():
        s = line.strip()
        if len(s) >= 40 and " " not in s:
            tok = s
            break
    if not tok:
        _fail("token okunamadi")
    for scope in ("profile:write", "profile:read:user.*"):
        rc, so, se = admin("grant", "mcp_client", scope)
        if rc != 0:
            _fail(f"kasa-admin grant {scope}: {se[:200]}")
    return tok


def _parse(r):
    txt = ""
    for c in getattr(r, "content", []) or []:
        t = getattr(c, "text", None)
        if t:
            txt += t
    try:
        return json.loads(txt)
    except Exception:
        return {"raw": txt[:300]}


async def mcp_chain(token, read_only=False):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    env = dict(os.environ)
    env["KASA_MCP_TOKEN"] = token
    env["KASA_MCP_AGENT_ID"] = "mcp_client"
    params = StdioServerParameters(command=_exe("kasa-mcp"), args=[], env=env, cwd=os.getcwd())
    out = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            out["tools"] = sorted(t.name for t in tools.tools)

            async def call(n, a):
                return _parse(await session.call_tool(n, a))

            if read_only:
                out["restart_read"] = await call("profile_read", {"scope": "user.note", "reason": "restart check"})
            else:
                out["write"] = await call("profile_write", {"key": "user.note", "value": "flat white no sugar", "provenance": []})
                out["read"] = await call("profile_read", {"scope": "user.note", "reason": "e2e read"})
                out["unauth_system"] = await call("profile_write", {"key": "system.security", "value": "x", "provenance": []})
                out["unauth_admin"] = await call("profile_write", {"key": "admin.config", "value": "x", "provenance": []})
                out["postattack"] = await call("profile_write", {"key": "user.note2", "value": "ok", "provenance": []})
    return out


def main():
    result = {"RESULT": "PASS", "port": PORT, "scripts": str(SCRIPTS)}
    result["import_check"] = assert_import_from_site_packages()

    srv = start_server()
    try:
        token = issue_and_grant()
        result["token_len"] = len(token)
        first = asyncio.run(mcp_chain(token, read_only=False))
        result["mcp"] = first
        # dogrulamalar
        if len(first.get("tools", [])) != 6:
            _fail(f"6 tool bekleniyordu: {first.get('tools')}")
        if first["write"].get("status") != "success":
            _fail(f"write: {first['write']}")
        data = first["read"].get("data") or []
        if not data or data[0].get("value") != "flat white no sugar":
            _fail(f"read: {first['read']}")
        if first["unauth_system"].get("status") != "quarantined":
            _fail(f"system.security quarantine olmadi: {first['unauth_system']}")
        if first["unauth_admin"].get("status") != "quarantined":
            _fail(f"admin.config quarantine olmadi: {first['unauth_admin']}")
        if first["postattack"].get("status") != "success":
            _fail(f"postattack write: {first['postattack']}")
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except Exception:
            srv.kill()

    # restart-persistence: server'i yeniden baslat, ayni degeri oku
    time.sleep(1)
    srv2 = start_server()
    try:
        second = asyncio.run(mcp_chain(token, read_only=True))
        result["restart"] = second
        rd = second["restart_read"].get("data") or []
        if not rd or rd[0].get("value") != "flat white no sugar":
            _fail(f"restart-persistence: {second['restart_read']}")
    finally:
        srv2.terminate()
        try:
            srv2.wait(timeout=10)
        except Exception:
            srv2.kill()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("PACKAGE-INSTALL-E2E: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
