# -*- coding: utf-8 -*-
"""F-IMP live verification — identity binding, against a REAL uvicorn server.

WHY THIS EXISTS AND WHY TestClient WAS NOT ENOUGH
-------------------------------------------------
`tests/test_identity_binding.py` already pins the fix and passes 15/15. It is not sufficient
evidence on its own, and this project has the receipt for why: an earlier version of that
suite went green while the POSITIVE side of the gate was completely broken. Against real
uvicorn every bound token got HTTP 401 (the sync dependency ran in a threadpool, the sqlite
connection belonged to the loop thread, and a broad `except` swallowed the ProgrammingError).
The test only asserted that a refusal message was ABSENT, and 401 also lacks that message.

Ders / lesson: pozitif kontrol, reddin YOKLUGUNU degil, BASARININ VARLIGINI olcmelidir --
ve TestClient uretim thread modelini taklit etmez. Bu betik bu yuzden GERCEK uvicorn'a karsi
kosar.

WHAT IS MEASURED (all against an isolated throwaway vault, never the owner's)
  P1  bound token acting as ITSELF, with the scope granted   -> expect 200   (positive)
  P2  bound token with NO body claim at all                  -> expect 200   (positive)
  N1  owner/legacy token claiming agent_id="browser"         -> expect 403   (THE F-IMP attack)
  N2  bound token claiming a DIFFERENT identity              -> expect 403   (negative)
  N3  unknown token                                          -> expect 401   (auth != identity)
  N4  revoked bound token                                    -> expect 401   (negative)
  R1  rotating the CLAIMED identity across 300 requests      -> expect 429s  (bucket is bound)

N1 is the exact request that was measured returning HTTP 200 before the fix
(`docs/MCP_CANLI_TEST_EYLEM_PLANI_2026-08-02.md` §F-IMP). R1 is the same root cause: rotating
the asserted id used to produce a fresh rate-limit bucket every time -- 150 requests, ZERO 429s
(`docs/KASA_DENETIM_VE_PROJEKSIYON_2026-08-01.md` §4.1).

HONEST LIMITS (printed at the end too, read them before citing anything)
  - Identity is bound to a TOKEN, so it is exactly as strong as token secrecy and issuance.
    A same-OS attacker who can read the vault file can mint tokens; that is adversary class
    A4 and it is OUT OF SCOPE by design (`docs/THREAT_MODEL.md`).
  - This proves ATTRIBUTION is no longer forgeable BY A NETWORK CALLER. It says nothing about
    whether the attributed agent told the truth -- see F-POISON.
  - Single host, single run, loopback only.

USAGE:  python _orch/redteam/fimp_live_verify.py
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import sqlite3
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

import live_mcp_attack as L  # proven isolated-server bootstrap (real uvicorn, free port)

OK = "\033[32mGECTI\033[0m"
BAD = "\033[31mKALDI\033[0m"


def _grant(S, agent_id: str, scope: str) -> None:
    conn = sqlite3.connect(S.VAULT_INSTANCE.db_path, timeout=5.0)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?, ?, ?)",
            (agent_id, scope, time.time()))
        conn.commit()
    finally:
        conn.close()


def _revoke(S, agent_id: str) -> None:
    conn = sqlite3.connect(S.VAULT_INSTANCE.db_path, timeout=5.0)
    try:
        conn.execute("UPDATE agent_tokens SET revoked_at=? WHERE agent_id=?", (time.time(), agent_id))
        conn.commit()
    finally:
        conn.close()


def _ingest_body(agent_id, n):
    body = {"tool": "event_ingest",
            "params": {"source": "fimp-verify", "type": "page_view", "content": {"n": n}}}
    if agent_id is not None:
        body["agent_id"] = agent_id
    return body


def main() -> int:
    base, owner_token, home, server, S = L.start_isolated_server()
    print(f"  izole sunucu: {base}   (vault: {home})")
    results = []
    transport_errors = []

    def check(cid, why, code, body_text, expected):
        if code == -1:
            transport_errors.append(f"{cid}: {body_text[:120]}")
        passed = (code == expected)
        results.append({"id": cid, "why": why, "expected": expected, "got": code, "pass": passed,
                        "body": (body_text or "")[:160]})
        print(f"  {cid:<3} beklenen {expected} -> alinan {code}   "
              f"{OK if passed else BAD}   {why}")

    alpha = L.token_for("agent_alpha")
    beta = L.token_for("agent_beta")
    _grant(S, "agent_alpha", "events:write")

    print("\n=== POZITIF KONTROLLER (kapi kor bir ret degil) ===")
    c, t = L._post(base, "/v1/ingest", alpha, _ingest_body("agent_alpha", 1))
    check("P1", "bagli token KENDISI olarak yaziyor", c, t, 200)
    c, t = L._post(base, "/v1/ingest", alpha, _ingest_body(None, 2))
    check("P2", "beyan yok; kimligi token soyluyor", c, t, 200)

    print("\n=== NEGATIF KONTROLLER (olculen saldirinin ta kendisi) ===")
    c, t = L._post(base, "/v1/ingest", owner_token, _ingest_body("browser", 3))
    check("N1", "sahip token'i 'browser' kimligine burunuyor (eskiden 200)", c, t, 403)
    c, t = L._post(base, "/v1/ingest", alpha, _ingest_body("agent_beta", 4))
    check("N2", "bagli token BASKA kimlik beyan ediyor", c, t, 403)
    c, t = L._post(base, "/v1/ingest", "totally-invalid-token", _ingest_body(None, 5))
    check("N3", "taninmayan token (kimlik degil, KIMLIK DOGRULAMA hatasi)", c, t, 401)
    _revoke(S, "agent_beta")
    c, t = L._post(base, "/v1/ingest", beta, _ingest_body(None, 6))
    check("N4", "iptal edilmis token artik cozulmuyor", c, t, 401)

    print("\n=== HIZ SINIRI — ayni kok neden ===")
    # Eskiden: her istekte UYDURULMUS yeni kimlik -> her seferinde TAZE kova -> 150 istekte 0 adet 429.
    # Simdi: kova BAGLI kimlige anahtarli; beyan degistirmek hicbir sey degistirmemeli.
    codes = []
    for i in range(300):
        c, _ = L._post(base, "/v1/ingest", alpha, _ingest_body("agent_alpha", 1000 + i))
        codes.append(c)
        if c == -1:
            transport_errors.append(f"R1[{i}]: tasima hatasi")
            break
    n429 = codes.count(429)
    n200 = codes.count(200)
    r1_pass = n429 > 0
    results.append({"id": "R1", "why": "donen beyan artik taze kova uretmiyor",
                    "expected": ">0 adet 429", "got": f"{n429} adet 429 / {n200} adet 200",
                    "pass": r1_pass})
    print(f"  R1  300 istek -> {n200} adet 200, {n429} adet 429   {OK if r1_pass else BAD}   "
          f"(duzeltmeden once: 150 istekte 0 adet 429)")

    print("\n=== HUKUM ===")
    if transport_errors:
        # IS_HATTI kurali: errors bos degilse hukum YAZILMAZ.
        print(f"  TASIMA HATASI VAR -> hukum OKUNMADI. errors={transport_errors[:3]}")
        return 2
    failed = [r for r in results if not r["pass"]]
    print(f"  {len(results) - len(failed)}/{len(results)} kontrol gecti"
          + (f"  KALANLAR: {[r['id'] for r in failed]}" if failed else ""))
    if not failed:
        print("  F-IMP KAPALI (RAN-LIVE): kimlik token'dan cozuluyor, govdedeki beyan yalnizca")
        print("  bir iddia; celisirse 403. Pozitif yon de CALISIYOR -- kapi kor bir ret degil.")

    print("\n=== DURUST SINIRLAR — alintilamadan once oku ===")
    print("  - Kimlik TOKEN'a baglidir: gucu token gizliligi ve dagitimi kadardir.")
    print("  - Vault dosyasini okuyabilen ayni-OS saldirgani token uretebilir; bu A4 sinifidir")
    print("    ve TASARIMLA KAPSAM DISIDIR (docs/THREAT_MODEL.md).")
    print("  - Kanitlanan sey: AG UZERINDEN atif sahtelenemez. Atfedilen ajanin DOGRU soyleyip")
    print("    soylemedigi ayri bir sorudur -- F-POISON oraya bakar.")
    print("  - Tek host, tek kosum, yalnizca loopback.")

    out = HERE / "fimp_live_result.json"
    out.write_text(json.dumps({
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "level": "RAN-LIVE",
        "transport_errors": transport_errors,
        "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  ham sonuc: {out}")

    try:
        server.should_exit = True
        time.sleep(0.5)
        shutil.rmtree(home, ignore_errors=True)
    except Exception:
        pass
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
