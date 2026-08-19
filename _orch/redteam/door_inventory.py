# -*- coding: utf-8 -*-
"""
KASA KAPI ENVANTERI — her AG ROTASI icin canli kimlik/izin kapisi olcumu.

NE: FastAPI `app.routes` uzerinden BUTUN rotalari PROGRAMATIK cikarir (elle liste YOK),
    her rotayi UC kimlik-bilgisi profiliyle dener (token yok / dusuk-yetkili bagli ajan
    token'i / sahip bearer'i) ve olculen HTTP kodlarini kaydeder.
NEDEN: "hafizaya ulasan her ag yolu bir kapiyla korunuyor" iddiasi bugune dek ELLE grep ile
    cikarilmis bir tabloya dayaniyordu. Elle liste, unutulan rotayi yapisal olarak GOREMEZ —
    ve unutulan rota tam da aradigimiz seydir. Bu arac listeyi sunucunun KENDI route
    tablosundan alir; yarin eklenen bir rota bu teste kendiliginden dahil olur.
YETKI: Yetkili guvenlik regresyonu — kendi makine, kendi proje, izole gecici vault.
    Gercek vault'a DOKUNULMAZ (live_mcp_attack.start_isolated_server()).

OLCUM SEVIYESI: RAN-LIVE (gercek uvicorn, gercek soket, gercek HTTP kodlari).
    Rota-basi `deps` alani CODE-STRUCTURE'dir (FastAPI dependant agacindan okundu).

DURUSTLUK KURALLARI (bu projenin kurallari):
  - Tasima hatasi (baglanti reddi / zaman asimi) olan rota icin HUKUM YAZILMAZ:
    siniflandirmasi OLCULEMEDI olur, `errors` doldurulur, cikis kodu 2 olur.
  - Uydurma skor/olasilik yok; yalnizca olculen HTTP kodlari.
  - POZITIF kontrol zorunlu: her sey 403 donduren sunucu savunma DEGIL, KIRIK sunucudur.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

# Windows konsolu cp1254; aracin KENDI ciktisi kod sayfasina takilip olmemeli.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

#: Bu olcumu kim kosturdu. Sana verilen model kimligi disinda bir sey YAZMA.
MEASURED_BY_MODEL = "claude-fable-5"

#: Tek istek zaman asimi (sn). Asimlar tasima hatasi sayilir -> hukum yazilmaz.
TIMEOUT = 30

_ANSI = os.environ.get("KASA_NO_COLOR") is None
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _ANSI else s
GREEN = lambda s: _c("32", s)
RED = lambda s: _c("31", s)
YELLOW = lambda s: _c("33", s)
CYAN = lambda s: _c("36", s)
DIM = lambda s: _c("2", s)
BOLD = lambda s: _c("1", s)


# --------------------------------------------------------------- HTTP yardimcilari
def _request(method, url, token=None, body=None):
    """Tek istek. Doner: {code, ctype, text, error}. error dolu ise TASIMA hatasidir
    (baglanti reddi/zaman asimi) — HTTP kodu YOKTUR, hukum yazilmaz."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return {"code": r.status, "ctype": r.headers.get("content-type", ""),
                    "text": r.read().decode("utf-8", "replace"), "error": None}
    except urllib.error.HTTPError as e:
        # HTTP hata kodu bir OLCUMDUR (tasima hatasi degil).
        try:
            txt = e.read().decode("utf-8", "replace")
        except Exception:
            txt = ""
        return {"code": e.code, "ctype": e.headers.get("content-type", "") if e.headers else "",
                "text": txt, "error": None}
    except Exception as ex:
        return {"code": None, "ctype": "", "text": "", "error": f"{type(ex).__name__}: {ex}"}


# ------------------------------------------------------- govde uretimi (programatik)
def _placeholder(ann):
    """Bir tip anotasyonundan minimal gecerli deger uretir (pydantic modellerine iner)."""
    origin = typing.get_origin(ann)
    args = typing.get_args(ann)
    if origin is typing.Union or (origin is not None and str(origin) == "typing.Union"):
        non_none = [a for a in args if a is not type(None)]
        return _placeholder(non_none[0]) if non_none else None
    # PEP 604 (X | None) — Python 3.10+ UnionType
    import types as _types
    if isinstance(ann, getattr(_types, "UnionType", ())):
        non_none = [a for a in typing.get_args(ann) if a is not type(None)]
        return _placeholder(non_none[0]) if non_none else None
    if origin in (list, set, tuple):
        return []
    if origin is dict:
        return {}
    if ann in (str,):
        return "x"
    if ann in (int,):
        return 1
    if ann in (float,):
        return 1.0
    if ann in (bool,):
        return True
    if ann in (list,):
        return []
    if ann in (dict,):
        return {}
    try:
        from pydantic import BaseModel
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            return _auto_body(ann)
    except Exception:
        pass
    return None


def _auto_body(model):
    """Pydantic modelden YALNIZ zorunlu alanlari iceren minimal govde uretir.
    Yeni bir rota eklendiginde govdesi de kendiliginden uretilir (elle bakim gerekmez)."""
    out = {}
    fields = getattr(model, "model_fields", None) or {}
    for name, f in fields.items():
        required = f.is_required() if hasattr(f, "is_required") else True
        if required:
            out[name] = _placeholder(f.annotation)
    return out


#: Yol-basina ANLAMLI govde. Bu bir ROTA LISTESI DEGILDIR — rotalar app.routes'tan gelir;
#: burasi yalnizca iki arac ucunun otomatik uretilen BOS govdesi yerine gercek bir hafiza
#: erisimi denemesi tasimasi icindir (bos tool_calls listesi hicbir kapiyi yoklamaz).
#: Ortulmeyen her rota otomatik govde ile yine de denenir -> kapsam duser DEGIL.
BODY_OVERRIDES = {
    "/v1/execute_tool": {"tool_calls": [{"tool_name": "profile_read",
                                         "parameters": {"scope": "user.name"}}]},
    "/v1/ingest": {"tool": "event_ingest",
                   "params": {"source": "door-inventory", "type": "probe",
                              "content": {"text": "door-inventory-probe"}, "ttl_days": 5}},
}
# NOT: govdelerde agent_id BEYAN EDILMEZ. Beyan edilseydi kimlik kapisi (bound identity
# uyusmazligi) 403 verirdi ve olctugumuz sey IZIN kapisi degil, kimlik kapisi olurdu.


#: Govde uretiminde yasanan sessiz arizalar buraya yazilir -> `errors`e girer.
_BODY_WARNINGS: list = []


# ------------------------------------------------------------- rota envanteri (programatik)
def collect_routes(app):
    """app.routes -> [{path, methods, kind, endpoint, deps, body}]  (ELLE LISTE YOK)."""
    from fastapi.routing import APIRoute
    from starlette.routing import Mount, Route

    def _deps_of(route):
        """FastAPI dependant agacindan bagimlilik adlarini toplar (CODE-STRUCTURE kanit)."""
        names = []
        dep = getattr(route, "dependant", None)
        if dep is None:
            return names
        stack = [dep]
        seen = 0
        while stack and seen < 200:
            d = stack.pop()
            seen += 1
            call = getattr(d, "call", None)
            if call is not None and getattr(call, "__name__", None):
                names.append(call.__name__)
            stack.extend(getattr(d, "dependencies", []) or [])
            for sd in getattr(d, "security_requirements", []) or []:
                sec = getattr(sd, "security_scheme", None)
                if sec is not None:
                    names.append(type(sec).__name__)
        # ilk isim rotanin kendi endpoint'i -> bagimlilik degil
        return sorted(set(names[1:])) if len(names) > 1 else []

    items = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            methods = sorted(m for m in (route.methods or []) if m not in ("HEAD", "OPTIONS"))
            # Govde modeli dependant.body_params'tan okunur. (route.body_field.type_ bu
            # FastAPI surumunde None doner -> sessizce {} govde uretiyordu; yani "422 aldik"
            # sonucu savunmayi degil BIZIM govdemizi olcuyordu. Sessiz arizanin tam ornegi.)
            body = None
            bparams = list(getattr(getattr(route, "dependant", None), "body_params", []) or [])
            if bparams:
                try:
                    if len(bparams) == 1:
                        body = _placeholder(bparams[0].field_info.annotation)
                    else:
                        body = {p.name: _placeholder(p.field_info.annotation) for p in bparams}
                except Exception as ex:
                    body = {}
                    _BODY_WARNINGS.append(f"{route.path}: govde uretilemedi: {ex}")
                if not isinstance(body, (dict, list)):
                    body = {}
            src = "auto"
            if route.path in BODY_OVERRIDES:
                body, src = BODY_OVERRIDES[route.path], "override"
            items.append({"path": route.path, "methods": methods, "kind": "api",
                          "endpoint": getattr(route.endpoint, "__qualname__", str(route.endpoint)),
                          "endpoint_module": getattr(route.endpoint, "__module__", "?"),
                          "deps": _deps_of(route), "body": body, "body_source": src})
        elif isinstance(route, Mount):
            # StaticFiles mount: montaj yolunun KENDISI ve dizindeki ILK gercek dosya denenir.
            sub = None
            d = getattr(getattr(route, "app", None), "directory", None)
            if d:
                try:
                    for p in sorted(pathlib.Path(d).rglob("*")):
                        if p.is_file():
                            sub = route.path.rstrip("/") + "/" + p.relative_to(d).as_posix()
                            break
                except Exception:
                    sub = None
            items.append({"path": route.path, "methods": ["GET"], "kind": "mount",
                          "endpoint": type(getattr(route, "app", None)).__name__,
                          "endpoint_module": "starlette.mount", "deps": [],
                          "body": None, "body_source": "none", "mount_sample": sub})
            if sub:
                items.append({"path": sub, "methods": ["GET"], "kind": "mount-file",
                              "endpoint": type(getattr(route, "app", None)).__name__,
                              "endpoint_module": "starlette.mount", "deps": [],
                              "body": None, "body_source": "none"})
        elif isinstance(route, Route):
            methods = sorted(m for m in (route.methods or ["GET"]) if m not in ("HEAD", "OPTIONS"))
            items.append({"path": route.path, "methods": methods, "kind": "starlette",
                          "endpoint": getattr(route.endpoint, "__qualname__", str(route.endpoint)),
                          "endpoint_module": getattr(route.endpoint, "__module__", "?"),
                          "deps": [], "body": None, "body_source": "none"})
        else:
            items.append({"path": getattr(route, "path", str(route)), "methods": [],
                          "kind": type(route).__name__, "endpoint": "?",
                          "endpoint_module": "?", "deps": [], "body": None,
                          "body_source": "none"})
    return items


# ------------------------------------------------------------------- siniflandirma
_HTML_CT = ("text/html", "javascript", "text/css", "image/", "font/", "text/plain")


def _is_2xx(c):
    return c is not None and 200 <= c < 300


def classify(no_tok, agent, owner, ctype, leaks_secret):
    """Olculen UC koddan sinif uretir. Uydurma yok — girdi yalnizca olculen kodlardir."""
    if no_tok["error"] or agent["error"] or owner["error"]:
        return "OLCULEMEDI"
    n, a, o = no_tok["code"], agent["code"], owner["code"]
    if _is_2xx(n):
        if leaks_secret:
            return "ACIK-SIR-SIZDIRAN"
        if any(m in (ctype or "").lower() for m in _HTML_CT):
            return "STATIK/UI"
        return "ACIK"
    if n in (401, 403):
        if _is_2xx(a) and _is_2xx(o):
            return "KIMLIK-DOGRULAMA"      # gecerli HERHANGI token yeter
        if a == 403 and _is_2xx(o):
            return "SAHIP-OZEL"
        if a == 403 and o == 403:
            return "BROKERLI"              # izin kapisi her iki kimligi de reddetti
        if a == 403:
            return "SAHIP-OZEL(islev-denenmedi)"   # kapi tuttu; ardindaki islev 2xx vermedi
        if _is_2xx(a) and not _is_2xx(o):
            return "AJAN-ERISIMLI"
        return f"BELIRSIZ(n={n},a={a},o={o})"
    # Uc profil de ayni 404/405 aliyorsa ortada KAPI degil, servis edilen bir sey YOK.
    if n == a == o == 404:
        return "KAYNAK-YOK(404)"
    if n == a == o == 405:
        return "METOT-YOK(405)"
    return f"BELIRSIZ(n={n},a={a},o={o})"


# -------------------------------------------------------------------------- kosum
def run():
    print(BOLD("\n=== KASA KAPI ENVANTERI — canli, programatik rota taramasi ===\n"))
    errors = []

    # Kardes modul: izole sunucuyu ve bagli-token uretimini TEKRAR YAZMA, ONU KULLAN.
    sys.path.insert(0, str(HERE))
    from live_mcp_attack import start_isolated_server, token_for

    base, owner_token, home, server, S = start_isolated_server()
    print(DIM(f"  izole sunucu : {base}"))
    print(DIM(f"  izole vault  : {home}"))
    print(DIM("  (gercek vault'a DOKUNULMADI)\n"))

    # IZOLASYON: ajan koprusu normalde 127.0.0.1:11434'teki yerel model servisine gider.
    # Bu olcumun konusu KAPI'dir, model degil; makinedeki gercek servisi mesgul etmemek icin
    # koprunun ucunu olu bir loopback portuna cevirdik. Kapi olcumu etkilenmez (kapi
    # handler'dan ONCE calisir), ama /v1/agent/* icin 2xx islev SONUCU alinamaz -> raporda soyle.
    isolation_notes = []
    try:
        from src.agent import harness as _harness
        _harness.OLLAMA_BASE = "http://127.0.0.1:1"     # kapali port
        isolation_notes.append("agent.harness.OLLAMA_BASE -> http://127.0.0.1:1 "
                               "(yerel model servisi mesgul edilmesin; kapi olcumu etkilenmez, "
                               "/v1/agent/* islev sonucu OLCULMEDI)")
    except Exception as ex:
        errors.append(f"harness izolasyonu kurulamadi: {ex}")

    routes = collect_routes(S.app)
    print(DIM(f"  app.routes uzerinden bulunan rota kaydi: {len(routes)}\n"))

    # dusuk-yetkili bagli ajan: agent_tokens'ta VAR, permissions'ta HIC YOK.
    low_agent = "door-probe-lowpriv"
    agent_token = token_for(low_agent)
    if not agent_token:
        errors.append("dusuk-yetkili ajan token'i uretilemedi")

    results = []
    for r in routes:
        methods = r["methods"] or ["GET"]
        method = "POST" if "POST" in methods else methods[0]
        url = base + r["path"]
        body = r["body"] if method in ("POST", "PUT", "PATCH") else None

        probes = {}
        for label, tok in (("no_token", None), ("agent_token", agent_token),
                           ("owner_token", owner_token)):
            res = _request(method, url, tok, body)
            probes[label] = res
            if res["error"]:
                errors.append(f"{method} {r['path']} [{label}]: {res['error']}")

        # SIR SIZINTISI: cevap govdesinde sahip bearer'i gecerse (ozellikle token'siz istekte)
        leaks = {k: (owner_token in (v["text"] or "")) for k, v in probes.items()}
        leaks_unauth = leaks["no_token"] or leaks["agent_token"]

        cls = classify(probes["no_token"], probes["agent_token"], probes["owner_token"],
                       probes["no_token"]["ctype"], leaks_unauth)

        rec = {"path": r["path"], "methods": r["methods"], "kind": r["kind"],
               "probed_method": method, "endpoint": r["endpoint"],
               "endpoint_module": r["endpoint_module"], "deps": r["deps"],
               "body_source": r["body_source"], "body_sent": body,
               "no_token": probes["no_token"]["code"],
               "agent_token": probes["agent_token"]["code"],
               "owner_token": probes["owner_token"]["code"],
               "no_token_error": probes["no_token"]["error"],
               "agent_token_error": probes["agent_token"]["error"],
               "owner_token_error": probes["owner_token"]["error"],
               "content_type_no_token": probes["no_token"]["ctype"],
               "owner_token_leaked_to": [k for k, v in leaks.items() if v],
               "classification": cls,
               "snippet_no_token": (probes["no_token"]["text"] or "")[:160],
               # 403'un HANGI kapidan geldigini gorunur kilar: izin brokeri mi ("izni yok"),
               # sahip kapisi mi ("yalnizca sahip"), yoksa kimlik kapisi mi ("kimlikle
               # uyusmuyor")? Kimlik kapisi 403'u ULASILAMADI demektir -- olculen sey hedef
               # kapi DEGILDIR. (Bu envanterde govdede agent_id BEYAN EDILMEDIGI icin kimlik
               # kapisi tetiklenmemeli; snippet bunu KANITLAR, varsaymaz.)
               "snippet_agent_token": (probes["agent_token"]["text"] or "")[:160]
               if not _is_2xx(probes["agent_token"]["code"]) else "",
               "identity_gate_hit": "kimlikle uyu" in (probes["agent_token"]["text"] or "")}
        results.append(rec)

    # --------------------------------------------------------- ZORUNLU POZITIF KONTROLLER
    # Hepsini reddeden bir sunucu butun negatif testleri "gecer". Bu iki kontrol tutmazsa
    # olculen sey savunma degil, KIRIK SUNUCU'dur.
    pos = {}

    # PK1: sahip bearer'i ile bir SAHIP-OZEL rota 2xx donmeli.
    owner_2xx = [r for r in results
                 if r["classification"].startswith("SAHIP-OZEL") and _is_2xx(r["owner_token"])]
    pk1_probe = _request("GET", base + "/v1/dashboard/stats", owner_token)
    pos["owner_reaches_owner_route"] = {
        "probe": "GET /v1/dashboard/stats (sahip bearer'i)",
        "http": pk1_probe["code"], "error": pk1_probe["error"],
        "passed": _is_2xx(pk1_probe["code"]),
        "other_owner_2xx_routes": [r["path"] for r in owner_2xx],
    }
    if pk1_probe["error"]:
        errors.append(f"PK1 tasima hatasi: {pk1_probe['error']}")

    # PK2: izin VERILEN bir ajan token'i brokerli bir arac cagrisinda 2xx almali.
    # (events:write veriliyor -> /v1/ingest event_ingest.) Ayni ajan izin ONCESI 403 almali:
    # pozitif kontrolun kendi NEGATIF esi — kapinin gercekten izne bakip bakmadigini gosterir.
    writer = "door-probe-writer"
    writer_token = token_for(writer)
    ingest_body = BODY_OVERRIDES["/v1/ingest"]
    before = _request("POST", base + "/v1/ingest", writer_token, ingest_body)
    granted = False
    try:
        import sqlite3
        conn = sqlite3.connect(S.VAULT_INSTANCE.db_path, timeout=5.0)
        try:
            conn.execute("INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) "
                         "VALUES (?,?,?)", (writer, "events:write", time.time()))
            conn.commit()
            granted = True
        finally:
            conn.close()
    except Exception as ex:
        errors.append(f"PK2 izin verilemedi: {ex}")
    after = _request("POST", base + "/v1/ingest", writer_token, ingest_body) if granted \
        else {"code": None, "error": "izin verilemedi", "text": "", "ctype": ""}
    pos["granted_agent_reaches_tool"] = {
        "probe": "POST /v1/ingest event_ingest (bagli ajan token'i)",
        "before_grant_http": before["code"], "after_grant_http": after["code"],
        "scope_granted": "events:write" if granted else None,
        "error": before["error"] or after["error"],
        "passed": (before["code"] == 403 and _is_2xx(after["code"])),
        "note": "izin ONCESI 403 + SONRASI 2xx = broker gercekten izne bakiyor "
                "(pozitif + negatif kontrol ayni olcumde)",
    }
    if before["error"]:
        errors.append(f"PK2 (izin oncesi) tasima hatasi: {before['error']}")
    if after.get("error") and granted:
        errors.append(f"PK2 (izin sonrasi) tasima hatasi: {after['error']}")

    # PK3: SIR-SIZINTISI SENTINELININ KENDI POZITIF KONTROLU. Hic ates etmeyen bir dedektor
    # "sizinti yok" KANITI DEGILDIR. Owner UI sayfasi bearer'i YALNIZCA gecerli launch
    # nonce'u tasiyan istege gomer (F-DASH). Nonce ILE token'siz istek atarsak sentinel
    # ATES ETMELI (=dedektor calisiyor); nonce'suz istek atarsak SUSMALI (=kapi tutuyor).
    nonce = getattr(S, "_LAUNCH_NONCE", "")
    with_nonce = _request("GET", base + f"/dashboard?k={nonce}", None)
    without_nonce = _request("GET", base + "/dashboard", None)
    pos["leak_sentinel_works"] = {
        "probe": "GET /dashboard?k=<launch_nonce> (token YOK) vs GET /dashboard (nonce YOK)",
        "with_nonce_http": with_nonce["code"],
        "with_nonce_contains_owner_token": owner_token in (with_nonce["text"] or ""),
        "without_nonce_http": without_nonce["code"],
        "without_nonce_contains_owner_token": owner_token in (without_nonce["text"] or ""),
        "error": with_nonce["error"] or without_nonce["error"],
        "passed": (owner_token in (with_nonce["text"] or ""))
                  and (owner_token not in (without_nonce["text"] or "")),
        "note": "nonce ILE sizdirmasi TASARIM (launch.py sirri); onemli olan sentinel'in "
                "ates edebildigi (yani 'sizinti yok' sonucunun bos bir dedektorden gelmedigi) "
                "ve nonce'suz istekte token'in GOMULMEDIGI.",
    }
    if with_nonce["error"] or without_nonce["error"]:
        errors.append(f"PK3 tasima hatasi: {with_nonce['error'] or without_nonce['error']}")

    # ---------------------------------------------------------------------- bulgular
    findings = []
    for r in results:
        if r["classification"] in ("ACIK", "ACIK-SIR-SIZDIRAN"):
            findings.append({"path": r["path"], "method": r["probed_method"],
                             "classification": r["classification"],
                             "no_token_http": r["no_token"],
                             "touches_vault": "get_vault" in r["deps"],
                             "deps": r["deps"],
                             "owner_token_leaked_to": r["owner_token_leaked_to"],
                             "snippet": r["snippet_no_token"]})
        elif r["owner_token_leaked_to"] and set(r["owner_token_leaked_to"]) - {"owner_token"}:
            findings.append({"path": r["path"], "method": r["probed_method"],
                             "classification": r["classification"],
                             "issue": "sahip bearer'i yetkisiz cevap govdesinde gorundu",
                             "owner_token_leaked_to": r["owner_token_leaked_to"]})

    # ------------------------------------------------------------- git + ozet + yazim
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
                                capture_output=True, text=True, timeout=15).stdout.strip() or None
    except Exception as ex:
        commit = None
        errors.append(f"git rev-parse: {ex}")

    dist = {}
    for r in results:
        dist[r["classification"]] = dist.get(r["classification"], 0) + 1

    # Iddianin dogrudan cevabi: TOKEN'SIZ 2xx donen HER rota + hafizaya deger mi.
    # (STATIK/UI dahil — sinif etiketi bir rotayi bu listeden GIZLEMEZ.)
    unauth = [{"path": r["path"], "method": r["probed_method"],
               "http": r["no_token"], "classification": r["classification"],
               "content_type": r["content_type_no_token"],
               "vault_dependency": "get_vault" in r["deps"],
               "endpoint": f"{r['endpoint_module']}.{r['endpoint']}"}
              for r in results if _is_2xx(r["no_token"])]
    errors.extend(_BODY_WARNINGS)
    # Kimlik kapisi tetiklendiyse o rotanin 403'u "izin reddi" DEGILDIR -> hukum yazilmaz.
    for r in results:
        if r.get("identity_gate_hit"):
            errors.append(f"{r['path']}: 403 KIMLIK kapisindan geldi (hedef kapi denenmedi) "
                          f"-> siniflandirma gecersiz")

    out = {
        "measured_by_model": MEASURED_BY_MODEL,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "git_commit": commit,
        "measurement_level": "RAN-LIVE (gercek uvicorn + gercek HTTP); 'deps' alani CODE-STRUCTURE",
        "claim_under_test": "hafizaya (profile/events/audit) ulasan her AG YOLU kimlik "
                            "dogrulamasi, izin brokeri veya sahip kapisiyla korunuyor; "
                            "korunmayan yol YOK",
        "method": "rotalar FastAPI app.routes'tan PROGRAMATIK cikarildi (elle liste yok); "
                  "her rota 3 kimlik-bilgisi profiliyle denendi",
        "isolation": {"vault_home": home, "notes": isolation_notes},
        "credential_profiles": {
            "no_token": "Authorization basligi YOK",
            "agent_token": f"agent_tokens'a bagli '{low_agent}' — permissions tablosunda HIC kaydi yok",
            "owner_token": "server._BEARER_TOKEN (sahip bearer'i; LEGACY_AGENT_ID kimligine cozulur)",
        },
        "route_count": len(results),
        "classification_distribution": dist,
        "routes": results,
        "unauthenticated_2xx": unauth,
        "unauthenticated_2xx_with_vault_dependency": [u for u in unauth if u["vault_dependency"]],
        "positive_controls": pos,
        "findings": findings,
        "not_a_network_route": {
            "path": "src/distill/engine.py",
            "statement": "Damitici bir AG ROTASI DEGILDIR. Surec-ici calisir, kendi "
                         "sqlite3 baglantisiyla events okur ve profile_quarantine'a yazar; "
                         "VaultTools/_check_permission izin brokerinden GECMEZ.",
            "tested": False,
            "why_not_tested": "HTTP yuzeyi yok -> bu envanterin kapsami disinda. "
                              "Kusur degil, tasarim gercegi; ama envanterde GORUNMELI: "
                              "brokersiz surec-ici yazma yolu.",
            "actor": "A1 (prompt-zehirli model) icin dolayli ilgi: damitici zehirli olay "
                     "metnini okur; yazimi karantinaya duser (ayri olcum konusu).",
        },
        "limits": [
            "Yalniz HTTP yuzeyi olculdu; surec-ici yollar (damitici, MCP stdio adaptoru, "
            "dogrudan SQLite erisimi) KAPSAM DISI.",
            "A4 (ayni-OS kullanici) KAPSAM DISI: token dosyasi zaten okunabilir.",
            "Her rota icin TEK metot denendi (POST varsa POST); ayni yolun diger metotlari "
            "ayri olculmedi.",
            "/v1/agent/* icin yerel model servisi bilerek erisilemez kilindi -> o rotalarda "
            "KAPI olculdu, ISLEV olculmedi.",
        ],
        "errors": errors,
    }

    out_path = HERE / "door_inventory_result.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------- terminal tablo
    def _fmt(c, err):
        if err:
            return YELLOW("HATA")
        if c is None:
            return YELLOW("  ? ")
        s = f"{c:>4}"
        if 200 <= c < 300:
            return GREEN(s)
        if c in (401, 403):
            return CYAN(s)
        return DIM(s)

    print(BOLD(f"{'ROTA':<34}{'MET':<6}{'yok':>6}{'ajan':>7}{'sahip':>7}  SINIF"))
    print(DIM("-" * 96))
    for r in sorted(results, key=lambda x: x["path"]):
        cls = r["classification"]
        cls_s = RED(cls) if cls.startswith("ACIK") else (
            YELLOW(cls) if cls.startswith(("BELIRSIZ", "OLCULEMEDI", "STATIK")) else GREEN(cls))
        print(f"{r['path'][:33]:<34}{r['probed_method']:<6}"
              f"{_fmt(r['no_token'], r['no_token_error']):>6}"
              f"{_fmt(r['agent_token'], r['agent_token_error']):>7}"
              f"{_fmt(r['owner_token'], r['owner_token_error']):>7}  {cls_s}")

    print(BOLD("\n=== SINIF DAGILIMI ==="))
    for k, v in sorted(dist.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<28} {v}")

    print(BOLD("\n=== POZITIF KONTROLLER (bunlar tutmazsa olcum GECERSIZ) ==="))
    pk1, pk2 = pos["owner_reaches_owner_route"], pos["granted_agent_reaches_tool"]
    print(f"  PK1 {pk1['probe']}: HTTP {pk1['http']}  -> "
          + (GREEN("TUTTU") if pk1["passed"] else RED("TUTMADI")))
    print(f"  PK2 {pk2['probe']}: izin oncesi {pk2['before_grant_http']} -> "
          f"izin sonrasi {pk2['after_grant_http']}  -> "
          + (GREEN("TUTTU") if pk2["passed"] else RED("TUTMADI")))
    pk3 = pos["leak_sentinel_works"]
    print(f"  PK3 sir-sizintisi sentineli: nonce ile token gomulu="
          f"{pk3['with_nonce_contains_owner_token']}, nonce'suz gomulu="
          f"{pk3['without_nonce_contains_owner_token']}  -> "
          + (GREEN("SENTINEL CALISIYOR") if pk3["passed"] else RED("SENTINEL DOGRULANMADI")))
    if not pk3["passed"]:
        print(YELLOW("      -> sentinel dogrulanmadan 'sizinti yok' bir KANIT DEGILDIR."))
    if not (pk1["passed"] and pk2["passed"]):
        print(RED("  !!! POZITIF KONTROL TUTMADI: 'her sey reddedildi' bir SAVUNMA DEGIL, "
                  "KIRIK SUNUCU olabilir. Negatif sonuclara hukum yazma."))

    print(BOLD("\n=== TOKEN'SIZ 2xx DONEN ROTALAR (iddianin dogrudan cevabi) ==="))
    if unauth:
        for u in unauth:
            mark = RED("VAULT BAGIMLILIGI VAR") if u["vault_dependency"] else DIM("vault bagimliligi yok")
            print(f"  {u['method']:<5}{u['path']:<32} {u['http']}  {u['classification']:<18} {mark}")
        print(("  -> " + RED("hafizaya deger token'siz rota VAR")) if
              out["unauthenticated_2xx_with_vault_dependency"] else
              ("  -> " + GREEN("hicbiri get_vault bagimliligi tasimiyor "
                               "(hafiza tablolarina bu rotalardan ulasilmiyor)")))
    else:
        print(GREEN("  yok"))

    print(BOLD("\n=== BULGULAR ==="))
    if findings:
        for f in findings:
            print(RED(f"  {f['method']} {f['path']}  {f.get('classification','')} "
                      f"{f.get('issue','')}"))
            if "touches_vault" in f:
                print(DIM(f"      token'siz HTTP {f['no_token_http']}  "
                          f"vault bagimliligi: {f['touches_vault']}  deps={f['deps']}"))
    else:
        print(GREEN("  ACIK siniflandirmasi alan veya sir sizdiran rota YOK."))

    print(BOLD("\n=== AG ROTASI OLMAYAN YOL ==="))
    print(DIM("  src/distill/engine.py — surec-ici; izin brokerinden GECMEZ; "
              "ag yuzeyinde YOK (test edilmedi, kapsam disi)."))

    print(BOLD("\n=== ERRORS ==="))
    if errors:
        for e in errors:
            print(RED("  " + e))
        print(RED("  -> `errors` bos degil: etkilenen rotalara HUKUM YAZILMAZ (cikis kodu 2)."))
    else:
        print(GREEN("  bos"))

    print(DIM(f"\n  betik : {pathlib.Path(__file__).resolve()}"))
    print(DIM(f"  sonuc : {out_path}\n"))

    try:
        server.should_exit = True
    except Exception:
        pass

    if errors:
        return 2
    return 0 if (pk1["passed"] and pk2["passed"] and not findings) else 1


if __name__ == "__main__":
    raise SystemExit(run())
