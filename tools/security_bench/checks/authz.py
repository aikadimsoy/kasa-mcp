import os
import importlib
import tempfile
import inspect
from fastapi.testclient import TestClient


# ===== BOUND deseni + kimlik-kapisi ucuncu hali =====
#
# Turkce not — NEDEN VAR (OLCULDU 2026-08-05, _orch/redteam/authz_reason_impact.py):
# Kimlik baglama (F-IMP duzeltmesi) devreye girdikten sonra, govdede agent_id="X" beyan
# edip PAYLASILAN token tasiyan her istek 403 ile ON KAPIDA duruyor: "agent_id token'a
# bagli kimlikle uyusmuyor". AUTHZ-C5 ve AUTHZ-DENY tam da boyle yaziliydi -> ikisi de
# YESIL yaniyordu ve olctuklerini SANDIKLARI kapiya (rezerve-kimlik blogu, varsayilan-red)
# HIC VARMIYORLARDI. Kanit: izin brokeri reddettiginde audit satiri yazar; bu iki
# kontrolde audit 0 satir. Yani kendi savunmamiz kendi olcum aletimizi kor etti.
#
# C7/C8'de ayni golge daha once fark edilmis ama YUKLEM GENISLETILEREK gecistirilmis
# (403 "kimlik baglama reddi" diye kabul edildi) -- erisim duzeltilmemis.
#
# Ayni tuzak _orch/redteam/live_mcp_attack.py'de ZATEN belgeli ve orada BOUND sentinel
# ile cozulmus; tezgaha tasinmamisti. Cozum ayni: bir kontrol X kimligiyle konusuyorsa
# X'e BAGLI bir token tasisin -> kimlik kapisini gecsin -> ASIL hedeflenen kapiyi denesin.
# (Bu, saldirganin token uretebildigi anlamina GELMEZ; tezgah kurulumudur: "sahip bu
#  ajana token vermis olsaydi, geri kalan savunmalar tutar miydi?")

def _mint_bound_token(srv, agent_id: str) -> str:
    """agent_id'ye BAGLI bir bearer uretir (sahip CLI'sinin yaptigi isin ta kendisi)."""
    import hashlib
    import secrets
    import sqlite3
    import time
    tok = secrets.token_urlsafe(32)
    conn = sqlite3.connect(srv.VAULT_INSTANCE.db_path, timeout=5.0)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO agent_tokens (agent_id, token_hash, created_at) VALUES (?,?,?)",
            (agent_id, hashlib.sha256(tok.encode()).hexdigest(), time.time()))
        conn.commit()
    finally:
        conn.close()
    return tok


#: Kimlik kapisinin reddine ait imza. Bu geldiyse istek HEDEF YUZEYE VARMAMISTIR ->
#: sonuc ne PASS ne FAIL'dir; UCUNCU HAL: olculemedi.
_IDENTITY_GATE_MARK = "uyuşmuyor"


def _unreached(check_id: str, title: str, resp, severity: str = "high") -> dict:
    """Hedef kapiya varilamadiginda uretilen satir. ERROR = 'bakamadik', FAIL = 'delik bulduk'."""
    return {
        "id": check_id, "category": "authz", "title": title,
        "status": "ERROR", "severity": severity,
        "evidence": (f"HEDEF YUZEYE VARILMADI: istek kimlik-baglama kapisinda durdu "
                     f"(HTTP {resp.status_code}). Bu kontrol bu kosumda HICBIR SEY olcmedi."),
        "remediation": "BOUND token kullan: beyan edilen kimlige bagli bearer tasi.",
    }

def check_token_missing():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        response = client.post("/v1/execute_tool", headers={}, json={"tool_calls":[{"tool_name":"profile_read","parameters":{"scope":"user.name"}}], "agent_id":"tester"})
        status = response.status_code
        result = {
            "id": "AUTHZ-TOKEN-MISSING",
            "category": "authz",
            "title": "POST with NO Authorization header",
            "status": "PASS" if status in [401, 403] else "FAIL",
            "severity": "critical",
            "evidence": f"Status code: {status}"
        }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_token_wrong():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        response = client.post("/v1/execute_tool", headers={"Authorization": "Bearer definitely-wrong-token"}, json={"tool_calls":[{"tool_name":"profile_read","parameters":{"scope":"user.name"}}], "agent_id":"tester"})
        status = response.status_code
        result = {
            "id": "AUTHZ-TOKEN-WRONG",
            "category": "authz",
            "title": "POST with header Bearer 'definitely-wrong-token'",
            "status": "PASS" if status == 401 else "FAIL",
            "severity": "critical",
            "evidence": f"Status code: {status}"
        }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_agent_system():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    title = "bound token for agent_id='system' (reserved identity claimed from the network)"
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        # BOUND: 'system'e bagli token -> kimlik kapisi gecilir -> ASIL olculen sey
        # REZERVE-KIMLIK blogudur. Paylasilan token ile bu kontrol kimlik kapisinda
        # oluyordu ve rezerve blogu hic denenmiyordu (olculdu: audit 0 satir).
        bound = _mint_bound_token(srv, "system")
        response = client.post("/v1/execute_tool", headers={"Authorization": f"Bearer {bound}"}, json={"tool_calls":[{"tool_name":"profile_read","parameters":{"scope":"user.name"}}], "agent_id":"system"})
        status = response.status_code
        if _IDENTITY_GATE_MARK in (response.text or ""):
            result = _unreached("AUTHZ-C5", title, response, severity="critical")
        else:
            result = {
                "id": "AUTHZ-C5",
                "category": "authz",
                "title": title,
                "status": "PASS" if status == 403 else "FAIL",
                "severity": "critical",
                "evidence": f"Status code: {status} (rezerve-kimlik blogu denendi; govde: {(response.text or '')[:80]})"
            }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_tool_not_allowed():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        # BOUND: 'tester'a bagli token -> kimlik kapisi gecilir -> olculen sey gercekten
        # "grant_permission AGDAN cagrilamaz" olur. Onceki hali paylasilan token
        # kullaniyordu ve 403 kimlik kapisindan geliyordu; yuklem o 403'u kabul edecek
        # sekilde GENISLETILMISTI -- yani golge fark edilmis ama erisim duzeltilmemisti.
        bound = _mint_bound_token(srv, "tester")
        response = client.post("/v1/execute_tool", headers={"Authorization": f"Bearer {bound}"}, json={"tool_calls":[{"tool_name":"grant_permission","parameters":{}}], "agent_id":"tester"})
        status = response.status_code
        if _IDENTITY_GATE_MARK in (response.text or ""):
            os.environ.pop("KASA_VAULT_PATH", None)
            return [_unreached("AUTHZ-C7", "grant_permission not callable from the network", response)]
        result = {
            "id": "AUTHZ-C7",
            "category": "authz",
            "title": "valid token, agent_id='tester', tool_name='grant_permission'",
            # Turkce not — YUKLEM GERI DARALTILDI (2026-08-05). Onceki hali (403,404)
            # kabul ediyordu; gerekce "kimlik baglama istegi rota aramasindan once
            # kesiyor" idi. Bu, golgeyi fark edip ERISIMI duzeltmek yerine YUKLEMI
            # GENISLETMEKTI -- ve kontrolu kalici bir kor noktaya cevirmisti: artik
            # 403'un hangi kapidan geldigi hic sorulmuyordu. BOUND token ile golge
            # kalktigi icin (olculdu: istek artik 404 aliyor) yuklem asil olculen
            # ozelligine geri baglaniyor: allow-list disi arac adi ROTA BULAMAZ.
            # Kimlik kapisi yine devreye girerse yukaridaki _unreached ERROR uretir,
            # yani daraltma sahte-FAIL riski TASIMAZ.
            "status": "PASS" if status == 404 else "FAIL",
            "severity": "high",
            "evidence": f"Status code: {status} ({'kimlik baglama reddi' if status == 403 else 'rota yok' if status == 404 else 'BEKLENMEYEN'})"
        }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_permission_check():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        # BOUND: C7 ile ayni gerekce -- private metodun ISIMLE cagrilamamasi olculuyor.
        bound = _mint_bound_token(srv, "tester")
        response = client.post("/v1/execute_tool", headers={"Authorization": f"Bearer {bound}"}, json={"tool_calls":[{"tool_name":"_check_permission","parameters":{}}], "agent_id":"tester"})
        status = response.status_code
        if _IDENTITY_GATE_MARK in (response.text or ""):
            os.environ.pop("KASA_VAULT_PATH", None)
            return [_unreached("AUTHZ-C8", "_check_permission not callable by name", response)]
        result = {
            "id": "AUTHZ-C8",
            "category": "authz",
            "title": "valid token, agent_id='tester', tool_name='_check_permission'",
            # Turkce not: C7 ile ayni gerekce ve ayni daraltma -- private metodun
            # ISIMLE cagrilamamasi olculuyor, ve o ozellik 404 demektir.
            "status": "PASS" if status == 404 else "FAIL",
            "severity": "high",
            "evidence": f"Status code: {status} ({'kimlik baglama reddi' if status == 403 else 'rota yok' if status == 404 else 'BEKLENMEYEN'})"
        }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_deny_by_default():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    agent_id = "unauthz_" + os.urandom(3).hex()
    title = f"bound token for agent_id='{agent_id}' with NO grants, tool profile_read"
    with TestClient(srv.app, raise_server_exceptions=False) as client:
        # BOUND: hicbir izni olmayan bir kimlige BAGLI token. Kimlik kapisi gecilir,
        # dolayisiyla olculen sey gercekten IZIN BROKERININ varsayilan-reddidir.
        bound = _mint_bound_token(srv, agent_id)
        response = client.post("/v1/execute_tool", headers={"Authorization": f"Bearer {bound}"}, json={"tool_calls":[{"tool_name":"profile_read","parameters":{"scope":"user.name"}}], "agent_id": agent_id})
        status = response.status_code
        body = response.text or ""
        if _IDENTITY_GATE_MARK in body:
            result = _unreached("AUTHZ-DENY", title, response, severity="critical")
        else:
            # Yuklem SIKILASTIRILDI. Eskiden `status != 200` idi -- yani istegi ERKEN
            # olduren HER SEY (host guard 400, imza hatasi 5xx, kimlik kapisi 403) bu
            # kontrolu YESIL yakiyordu. SECBENCH-HOSTGUARD tam olarak bu yuklemden
            # dogmustu. Artik hem kod 403 olmali HEM de reddin IZIN BROKERINDEN geldigi
            # govdede gorunmeli; aksi halde "reddedildi" demek, "dogru kapi reddetti"
            # demek degildir.
            broker_refusal = "izni yok" in body
            ok = (status == 403) and broker_refusal
            result = {
                "id": "AUTHZ-DENY",
                "category": "authz",
                "title": title,
                "status": "PASS" if ok else "FAIL",
                "severity": "critical",
                "evidence": (f"Status code: {status}; izin-brokeri reddi: {broker_refusal}; "
                             f"govde: {body[:90]}")
            }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def check_default_host():
    try:
        tmp = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = tmp
        import src.mcp_server.server as srv
        importlib.reload(srv)
        token = srv._BEARER_TOKEN
    except Exception:
        return [{"id": "AUTHZ-SKIP", "category": "authz", "title": "Server Initialization Failed", "status": "SKIP", "severity": "info", "evidence": str(Exception)}]
    
    default_host = inspect.signature(srv.start_server).parameters['host'].default
    result = {
        "id": "AUTHZ-BIND",
        "category": "authz",
        "title": "Static check on server binding host",
        "status": "PASS" if default_host in ["127.0.0.1", "localhost"] else "FAIL",
        "severity": "high",
        "evidence": f"Default host: {default_host}"
    }
    os.environ.pop("KASA_VAULT_PATH", None)
    return [result]

def run():
    results = []
    try:
        results += check_token_missing()
        results += check_token_wrong()
        results += check_agent_system()
        results += check_tool_not_allowed()
        results += check_permission_check()
        results += check_deny_by_default()
        results += check_default_host()
    except Exception as e:
        results.append({
            "id": "AUTHZ-ERROR",
            "category": "authz",
            "title": "Unexpected Error in Security Checks",
            "status": "SKIP",
            "severity": "info",
            "evidence": str(e)
        })
    return results


# ===== NEDEN -> SONUC / CAUSE -> EFFECT (yerel model, sifir-token) =====
# Purpose: This file contains functions to perform authorization checks on the server.
# Why (cause -> effect): These checks ensure that the server correctly handles different authorization scenarios, such as missing tokens, wrong tokens, and unauthorized agents.
# Amac: Bu dosya, sunucu üzerinde yetkilendirme kontrollerini gerçekleştiren fonksiyonları içerir.
# Neden -> Sonuc: Bu kontroller, eksik belirtec, yanlış belirteç ve yetkisiz aracılıklar gibi farklı yetkilendirme senaryolarının doğru şekilde işlendiğinden emin olur.
