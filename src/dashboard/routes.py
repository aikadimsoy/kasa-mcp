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

# dashboard_ui veri dizinini calisma-zamani cozer. Uc mod var:
#   - kaynak-run: repo koku (__file__/../../..).
#   - Nuitka --standalone: veri exe'nin YANINDA (<dist>/dashboard_ui).
#   - Nuitka --onefile: bootstrap kendini gecici bir dizine acar; veri ORADA durur,
#     sys.executable ise ORIJINAL exe'yi gosterir (temp'i DEGIL) -> sys.executable KIRILIR.
# Nuitka'nin kanonik yolu __compiled__.containing_dir'dir (her iki modda ikilinin bulundugu
# dizin = onefile'da temp agac koku). Yine de tek bir mekanizmaya guvenmeyip aday listesinden
# index.html'i ILK bulunan koku seceriz (mühür = ölçüm: yanlis-yolu sessizce yutmaz).
def _resolve_ui_dir() -> pathlib.Path:
    candidates: list[pathlib.Path] = []
    comp = globals().get("__compiled__")
    if comp is not None and getattr(comp, "containing_dir", None):
        candidates.append(pathlib.Path(comp.containing_dir))          # Nuitka (standalone+onefile)
    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        candidates.append(pathlib.Path(sys.executable).resolve().parent)   # standalone yedegi
    candidates.append(pathlib.Path(__file__).resolve().parent.parent.parent)  # kaynak-run + onefile yedegi
    for base in candidates:
        if (base / "dashboard_ui" / "index.html").is_file():
            return base / "dashboard_ui"
    return candidates[0] / "dashboard_ui"  # bulunamadi: anlamli hata icin ilk aday


_UI_DIR = _resolve_ui_dir()


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
        html = (_UI_DIR / "index.html").read_text(encoding="utf-8")
        html = html.replace("__KASA_TOKEN__", bearer_token if _nonce_ok(k) else "")
        return HTMLResponse(html)

    def dashboard_appjs():
        js = (_UI_DIR / "app.js").read_text(encoding="utf-8")
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
        html = (_UI_DIR / "terms.html").read_text(encoding="utf-8")
        html = html.replace("__KASA_TOKEN__", bearer_token if _nonce_ok(k) else "")
        return HTMLResponse(html)

    async def terms_status(_=Security(require_owner)):
        return consent.status()

    async def terms_accept(_=Security(require_owner)):
        return {"ok": True, "record": consent.record_acceptance()}

    app.add_api_route("/terms", terms_index, methods=["GET"], include_in_schema=False)
    app.add_api_route("/v1/terms/status", terms_status, methods=["GET"], tags=["terms"])
    app.add_api_route("/v1/terms/accept", terms_accept, methods=["POST"], tags=["terms"])
