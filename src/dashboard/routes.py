# kasa/src/dashboard/routes.py

"""
Dashboard FastAPI uclari (read-only). Var olan MCP sunucusuna baglanir; paralel ikinci
API kurulmaz (docs/UI_UX_STANDARD.md §3). JSON uclari bearer korumali, yalniz GET.

NOT (ortam): bu kurulumda starlette 1.1.0 var ve FastAPI'nin include_router'i route'lari
app'e SESSIZCE kopyalamiyor (dogrulandi). Bu yuzden mevcut server.py ile AYNI calisan yolu
kullaniyoruz: app.add_api_route. register() app + deps alir (dairesel import yok).

Owner UI (/dashboard): tarayici token olmadan yukleyebilmeli -> sayfa localhost-only servis
edilir ve bearer sunucu tarafinda enjekte edilir. Tehdit modeli: local surec ZATEN guvenilir
(bearer kasa.toml'da duz metin); dolayisiyla bu, kabul edilmis modelle tutarli (v1). v2:
oturum cerezi. Maskesiz gorunum/anahtar-yonetimi HALA yok (aggregate + read-through-redact).
"""

import pathlib
import secrets
import sys

from fastapi import Depends, Security
from fastapi.responses import HTMLResponse, Response

from . import stats, auditor

# Dashboard UI kaynaklari artik PAKET VERISI: src/dashboard/ui/{index.html,app.js,terms.html}
# (2026-08-21, ChatGPT operator karari). TEK kaynak; kaynak-run ve wheel'de ayni yerden
# importlib.resources ile okunur. Eski __file__/../../.. -> dashboard_ui hesabi ANA mekanizma
# DEGIL (wheel kurulunca site-packages'ta o dizin yoktu -> dashboard packaged kurulumda
# kiriliyordu). Nuitka icin fallback KORUNUR (build bundle'i eski dashboard_ui/ konumuna
# kopyalar). Kaynak bulunamazsa SESSIZCE bos/404/fallback-HTML DEGIL -> ACIK hata
# (packaging kusuru gizlenmemeli; ChatGPT P1a #6).
def _read_ui(name: str) -> str:
    # 1) Paket verisi (kaynak + wheel): importlib.resources
    try:
        from importlib.resources import files
        res = files("src.dashboard").joinpath("ui", name)
        if res.is_file():
            return res.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, AttributeError, TypeError):
        pass
    # 2) Nuitka fallback: ikilinin yanindaki dashboard_ui/ (build scripti oraya kopyalar)
    bases: list[pathlib.Path] = []
    comp = globals().get("__compiled__")
    if comp is not None and getattr(comp, "containing_dir", None):
        bases.append(pathlib.Path(comp.containing_dir) / "dashboard_ui")
    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        bases.append(pathlib.Path(sys.executable).resolve().parent / "dashboard_ui")
    for base in bases:
        p = base / name
        if p.is_file():
            return p.read_text(encoding="utf-8")
    # 3) ACIK, teshis edilebilir hata
    raise RuntimeError(
        "dashboard UI kaynagi bulunamadi: %s -- importlib.resources('src.dashboard'/ui) ve "
        "Nuitka fallback ikisi de bos. Paketleme (package-data) kirik olabilir." % name)


def register(app, get_vault, bearer_token: str, require_owner, launch_nonce: str) -> None:
    """Dashboard read-only uclarini + owner UI'yi app uzerine dogrudan kaydeder.

    Turkce not (imza degisti - guvenlik): eskiden `verify_token` (HERHANGI gecerli bearer)
    aliniyordu; artik `require_owner` (SAHIP bearer'i) aliniyor -> F-OWNER-SCOPE. Ayrica
    `launch_nonce` eklendi: owner token'i HTML'e YALNIZCA gecerli nonce ile gomulur (F-DASH).
    """

    def _nonce_ok(k: str) -> bool:
        # Sabit-zamanli; nonce yoksa (yapilandirilmamis) hicbir istek gecemez -> fail-closed.
        return bool(launch_nonce) and secrets.compare_digest(k or "", launch_nonce)

    # --- JSON API (SAHIP korumali) ---
    # async def SART: SQLite baglantisi event-loop thread'inde (lifespan) olusturuldu;
    # sync def endpoint threadpool'da kosar -> cross-thread ProgrammingError. Mevcut
    # execute_tool/ingest de async; ayni desen. (E2E smoke bunu yakaladi; birim test
    # compute_stats'i dogrudan cagirdigi icin gormemisti -> muhur = olcum.)
    async def dashboard_stats(vault=Depends(get_vault), _=Security(require_owner)):
        """Ozet metrikler (aggregate). Ham icerik donmez."""
        return stats.compute_stats(vault)

    async def dashboard_events(limit: int = 20, vault=Depends(get_vault), _=Security(require_owner)):
        """Son olaylarin maskeli yapisal ozeti (content yok)."""
        return {"events": stats.recent_events(vault, limit)}

    async def dashboard_profile(vault=Depends(get_vault), _=Security(require_owner)):
        """Kalici profilin maskeli okumasi (read-through-redact)."""
        return {"profile": stats.profile_entries(vault)}

    app.add_api_route("/v1/dashboard/stats", dashboard_stats, methods=["GET"], tags=["dashboard"])
    app.add_api_route("/v1/dashboard/events", dashboard_events, methods=["GET"], tags=["dashboard"])
    app.add_api_route("/v1/dashboard/profile", dashboard_profile, methods=["GET"], tags=["dashboard"])

    async def dashboard_audit(vault=Depends(get_vault), target_layer: str = "all", _=Security(require_owner)):
        """Guvenlik testlerini (Auditor) calistirir ve sonuclari doner."""
        return {"tests": auditor.run_all_tests(vault, target_layer)}

    app.add_api_route("/v1/dashboard/audit/run", dashboard_audit, methods=["GET"], tags=["dashboard"])

    async def dashboard_audit_report(vault=Depends(get_vault), target_layer: str = "all", _=Security(require_owner)):
        """Detayli diagnostik ve performans raporunu indirir."""
        report = auditor.generate_diagnostic_report(vault, target_layer)
        import json
        return Response(
            content=json.dumps(report, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=kasa_audit_report_{target_layer}.json"}
        )

    app.add_api_route("/v1/dashboard/audit/report", dashboard_audit_report, methods=["GET"], tags=["dashboard"])

    # --- Owner UI (localhost-only; bearer YALNIZCA gecerli launch nonce ile enjekte) ---
    # F-DASH fix: eskiden bu iki sayfa (index/terms) owner bearer'ini KOSULSUZ gomuyordu ->
    # tokensiz GET /dashboard owner token'i sizdiriyordu (canli lab: sifir kimlik -> tam
    # owner kontrolu). Artik token yalnizca launch.py'nin verdigi nonce'u tasiyan istege
    # gomulur; nonce'suz istek TOKENSIZ sayfa alir (sizinti yok, ama sayfa da calismaz).
    def dashboard_index(k: str = ""):
        html = _read_ui("index.html")
        html = html.replace("__KASA_TOKEN__", bearer_token if _nonce_ok(k) else "")
        return HTMLResponse(html)

    def dashboard_appjs():
        js = _read_ui("app.js")
        return Response(content=js, media_type="application/javascript")

    app.add_api_route("/dashboard", dashboard_index, methods=["GET"], include_in_schema=False)
    app.add_api_route("/dashboard/app.js", dashboard_appjs, methods=["GET"], include_in_schema=False)

    # --- Kullanim sartlari (Terms of Use) kapisi ---
    # /terms owner UI'dir (token enjekte, sayfa localhost'ta bearer'siz yuklenir). Kabul/durum
    # uclari bearer korumali. Kabul kaydi sir icermez -> redact/aggregate siniri disinda.
    # Turkce not: bu satir eskiden `from ..desktop import consent` idi ve yanindaki yorum
    # "opsiyonel modul" diyordu -- DEGILDI. try/except yoktu ve _register_dashboard modul
    # seviyesinde cagriliyor, yani `desktop` silindiginde sunucu IMPORT ANINDA oluyordu.
    # "Cekirdek ayrilabilir" iddiasi tek basina bu satir yuzunden yanlisti.
    # Cozum sarmalamak DEGIL, tasimak: consent saf bir politika kaydidir (json/os/pathlib),
    # arayuze ya da masaustune ait hicbir seye dokunmaz -> cekirdege ait. Sarmalasaydik
    # kacak gizlenirdi (sartlar ucu sessizce kaybolurdu); tasiyinca kacak KALKTI.
    from .. import consent

    def terms_index(k: str = ""):
        html = _read_ui("terms.html")
        html = html.replace("__KASA_TOKEN__", bearer_token if _nonce_ok(k) else "")
        return HTMLResponse(html)

    async def terms_status(_=Security(require_owner)):
        return consent.status()

    async def terms_accept(_=Security(require_owner)):
        return {"ok": True, "record": consent.record_acceptance()}

    app.add_api_route("/terms", terms_index, methods=["GET"], include_in_schema=False)
    app.add_api_route("/v1/terms/status", terms_status, methods=["GET"], tags=["terms"])
    app.add_api_route("/v1/terms/accept", terms_accept, methods=["POST"], tags=["terms"])
