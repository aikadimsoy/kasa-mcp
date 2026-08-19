# -*- coding: utf-8 -*-
"""profile_read'e eklenen zorunlu `reason` parametresi AUTHZ kontrollerini bozuyor mu?

IDDIA (kanitlanmadan yazilmisti, bu betik onu sinar):
"tezgahi bu halde kosarsam AUTHZ kontrolleri yanlis sonuc verebilir."

Bu bir TAHMINDI. Bu projede tahmin hukum yerine gecmez, o yuzden olculuyor.

AYIRT EDICI SORU
Bir istek 4xx/5xx aliyorsa iki bambaska sey olmus olabilir:
  (a) YETKI KAPISI reddetti      -> kontrol gercekten olctugunu olcuyor
  (b) Istek KAPIYA VARMADAN oldu -> kontrol hicbir sey olcmedi, ama bir kod raporluyor
Bunu ayirt eden sey DENETIM ZINCIRIDIR: izin reddi bir audit satiri YAZAR
(tools.py, `_check_permission` basarisiz olunca `audit_chain.record(... permission_denied)`),
oysa arac cagrisi imza hatasiyla coktugunde hicbir satir yazilmaz.

Bu ayrim SECBENCH-HOSTGUARD'in birebir tekrari: orada da tezgah 400 aliyordu, `!=200`
yuklemli kontroller PASS yaniyordu ve broker HIC calismiyordu.

KONTROLLER
  POZITIF : bilinen-iyi bir cagri (izin VERILMIS ajan, gecerli reason) -> 200 + audit satiri
            Bu olmadan "audit satiri yok" bulgusu, audit'in hic calismadigi anlamina da gelebilir.
  NEGATIF : tezgahin fiilen gonderdigi dort istek (reason YOK)

KULLANIM:  python _orch/redteam/authz_reason_impact.py
IZOLASYON: kendi gecici kasasini kurar; gercek vault'a DOKUNMAZ.
"""
from __future__ import annotations

import importlib
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import time

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _which_gate(resp) -> str:
    """Cevap govdesinden REDDI VEREN KAPIYI adlandirir.

    Turkce not: bir kontrolun 'yesil' olmasi yetmez -- DOGRU KAPININ reddettigini gostermek
    gerekir. AUTHZ-C5 rezerve-kimlik blogunu olctugunu SANIYOR; asagidaki siniflandirma
    reddin aslinda KIMLIK BAGLAMA'dan geldigini gosterir, yani hedef yuzeye hic varilmamis.
    """
    body = (resp.text or "").lower()
    if "not authenticated" in body:
        return "auth:no-bearer"
    if "geçersiz token" in body or "gecersiz token" in body:
        return "auth:unknown-token"
    if "uyuşmuyor" in body or "uyusmuyor" in body:
        return "identity-binding:UNREACHED-TARGET"
    if "mevcut değil" in body or "mevcut degil" in body:
        return "reserved-identity"
    if "izni yok" in body:
        return "permission-broker:TARGET"
    if resp.status_code >= 500:
        return f"crash:{resp.status_code}"
    return f"unclassified:{resp.status_code}"


def main() -> int:
    home = tempfile.mkdtemp(prefix="kasa_authzreason_")
    os.environ["KASA_VAULT_PATH"] = home
    os.environ["KASA_ALLOWED_HOSTS"] = "testserver,127.0.0.1,localhost"

    from fastapi.testclient import TestClient
    import src.mcp_server.server as srv
    importlib.reload(srv)
    token = srv._BEARER_TOKEN
    db = srv.VAULT_INSTANCE.db_path

    def audit_rows() -> list[tuple]:
        conn = sqlite3.connect(db)
        try:
            return conn.execute("SELECT agent_id, action FROM audit").fetchall()
        finally:
            conn.close()

    def grant(agent_id: str, scope: str) -> None:
        conn = sqlite3.connect(db)
        try:
            conn.execute("INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) "
                         "VALUES (?,?,?)", (agent_id, scope, time.time()))
            conn.commit()
        finally:
            conn.close()

    #: Tezgahin fiilen gonderdigi istekler (authz.py / fuzz.py'den birebir).
    CASES = [
        {"id": "AUTHZ-TOKEN-MISSING", "headers": {}, "agent": "tester",
         "predicate": "status in [401,403]", "ok": lambda s: s in (401, 403)},
        {"id": "AUTHZ-TOKEN-WRONG", "headers": {"Authorization": "Bearer definitely-wrong-token"},
         "agent": "tester", "predicate": "status == 401", "ok": lambda s: s == 401},
        {"id": "AUTHZ-C5", "headers": {"Authorization": f"Bearer {token}"}, "agent": "system",
         "predicate": "status == 403", "ok": lambda s: s == 403},
        {"id": "AUTHZ-DENY", "headers": {"Authorization": f"Bearer {token}"}, "agent": "unauthz_probe",
         "predicate": "status == 403", "ok": lambda s: s == 403},
    ]

    results = []
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        # --- POZITIF KONTROL: audit gercekten yaziyor mu? ---
        grant(srv.LEGACY_AGENT_ID, "profile:read")
        before = len(audit_rows())
        pos = client.post("/v1/execute_tool", headers={"Authorization": f"Bearer {token}"},
                          json={"tool_calls": [{"tool_name": "profile_read",
                                                "parameters": {"scope": "user.name",
                                                               "reason": "pozitif kontrol"}}]})
        pos_rows = len(audit_rows()) - before
        print("=== POZITIF KONTROL — izinli ajan, GECERLI reason ===")
        print(f"  HTTP {pos.status_code} · yeni audit satiri: {pos_rows}")
        print(f"  govde: {pos.text[:150]}")
        if pos_rows == 0:
            print("\n  AUDIT HIC YAZMIYOR -> 'audit satiri yok' bulgusu ayirt edici DEGIL.")
            print("  Bu kosum GECERSIZ; once audit yolunu kovala.")
            return 2

        print("\n=== NEGATIF — tezgahin fiilen gonderdigi istekler (reason YOK) ===")
        for c in CASES:
            before = len(audit_rows())
            r = client.post("/v1/execute_tool", headers=c["headers"],
                            json={"tool_calls": [{"tool_name": "profile_read",
                                                  "parameters": {"scope": "user.name"}}],
                                  "agent_id": c["agent"]})
            new_rows = len(audit_rows()) - before
            verdict = "PASS" if c["ok"](r.status_code) else "FAIL"
            reached = new_rows > 0
            results.append({"id": c["id"], "http": r.status_code, "bench_verdict": verdict,
                            "predicate": c["predicate"], "audit_rows_written": new_rows,
                            "gate_reached": reached, "refusing_gate": _which_gate(r),
                            "body": r.text[:180]})
            print(f"  {c['id']:<22} HTTP {r.status_code:<4} tezgah={verdict:<4} "
                  f"audit={new_rows} kapiya_vardi={reached}")
            print(f"     REDDEDEN KAPI: {_which_gate(r)}")
            print(f"     govde: {r.text[:120]}")

    print("\n=== HUKUM ===")
    silent = [r for r in results if r["bench_verdict"] == "PASS" and not r["gate_reached"]]
    broken = [r for r in results if r["bench_verdict"] == "FAIL"]

    print(f"  PASS diyen ama kapiya VARMAYAN kontrol : {[r['id'] for r in silent] or 'YOK'}")
    print(f"  FAIL'e donen kontrol                   : {[r['id'] for r in broken] or 'YOK'}")

    shadowed = [r for r in results if "identity-binding" in r["refusing_gate"]]
    if shadowed:
        print(f"  KIMLIK KAPISININ GOLGELEDIGI kontrol   : {[r['id'] for r in shadowed]}")

    if silent:
        print("\n  SAHTE-PASS DOGRULANDI: kontrol yesil yaniyor ama izin brokeri HIC calismadi.")
        print("  SECBENCH-HOSTGUARD ile ayni sinif.")
        if shadowed:
            print("\n  VE SEBEP `reason` DEGIL. Ilk iddiam buydu ve YANLISTI: istekler arac")
            print("  imzasina hic ulasmiyor. Onlari KIMLIK BAGLAMA kapisi (bugun kapatilan")
            print("  F-IMP duzeltmesi) daha once kesiyor. Yani bu iki kontrol -- rezerve-kimlik")
            print("  blogu ve varsayilan-red -- olctugunu SANDIGI seyi olcmuyor; kendi")
            print("  savunmamiz onlari golgeliyor. Ayni tuzak _orch/redteam/live_mcp_attack.py'de")
            print("  ZATEN belgelenmis ve orada BOUND sentinel ile cozulmus; tezgaha")
            print("  tasinmamis.")
    elif broken:
        print("\n  SAHTE-PASS YOK ama SAHTE-FAIL VAR: kontroller kirmizi yaniyor cunku cagri")
        print("  imza hatasiyla oluyor -- bir acik BULUNDUGU icin degil. 'Yanlis sonuc' iddiasi")
        print("  DOGRU ama YON YANLIS: tehlike sessiz yesil degil, gurultulu kirmizi.")
    else:
        print("\n  ETKI YOK: dort kontrol de kapiya varip beklenen kodu aldi. Ilk iddiam")
        print("  ('AUTHZ kontrolleri yanlis sonuc verebilir') bu dort kontrol icin GECERSIZ.")

    out = pathlib.Path(__file__).with_name("authz_reason_impact_result.json")
    out.write_text(json.dumps(
        {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "level": "RAN-LIVE",
         "positive_control": {"http": pos.status_code, "audit_rows": pos_rows},
         "cases": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  ham sonuc: {out}")

    print("\n=== DURUST SINIRLAR ===")
    print("  - Yalnizca profile_read tasiyan AUTHZ kontrolleri olculdu; C7/C8/BIND haric.")
    print("  - TestClient kullanildi (tezgahin kendisi de oyle yapiyor); gercek uvicorn degil.")
    print("  - 'Kapiya vardi' olcutu audit satiridir; audit yazmayan baska bir ret yolu olsaydi")
    print("    bu olcut onu da 'varmadi' sayardi.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
