
import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (2 ust dizin = depo koku). Sabit yol, depoyu klonlayan herkeste ve CI
# kosucusunda bu araci calismaz kilardi.
_KASA_ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", ".."))

# ===== Host-guard: benchin isteklerinin YETKILENDIRME KODUNA ULASMASI icin sart =====
# Turkce not (ne/neden): G2 Host-guard (server.py) loopback disi Host'u, herhangi bir
# yetkilendirme kodu calismadan 400 ile reddeder. TestClient 'Host: testserver' yollar.
# Bu degisken YALNIZCA tests/conftest.py'de ayarliydi; bench `python -m tools.security_bench`
# ile kostugundan conftest CALISMAZ -> her istek 400 donerdi. AUTHZ-DENY gibi kontrollerin
# PASS kosulu `status != 200` oldugu icin 400 de PASS sayilir ve kontrol, olctugunu iddia
# ettigi kapiya HIC ugramadan yesil yanardi. Yani YANLIS-PASS ureteci. Olculen 2026-08-04:
# bench kosullarinda 3/3 istek 400 dondu. Bunu ayarlamak dogru olcumu geri getirir;
# Host-guard'in kendisi ayrica sinanmalidir (bkz. AUTHZ-HOSTGUARD).
_os.environ.setdefault("KASA_ALLOWED_HOSTS", "testserver")
import sys
import os
import platform
import socket
import datetime
import json
import hashlib
import subprocess
from tools.security_bench.checks import authz, crypto, audit, scan, fuzz
from tools.security_bench.report import render


# ===== v2 DAMGA (reprodusibilite/seffaflik) — SPEC CPU metodoloji disiplini =====
# Rapor tek-basina denetlenebilir olsun diye her kosuya commit + config + WebView2 +
# OS build + katman (base/peak) damgasi basilir. Windows/git-ozgu oldugu icin Controller elle yazdi.
def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "-C", _KASA_ROOT, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _config_hash() -> str:
    # browser_config.json + requirements.txt -> tek config-hash (ayni girdi = ayni hash = reprodusibilite)
    h = hashlib.sha256()
    for p in (_os.path.join(_KASA_ROOT, "browser_config.json"), _os.path.join(_KASA_ROOT, "requirements.txt")):
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except FileNotFoundError:
            h.update(b"<missing>")
    return h.hexdigest()[:12]


def _webview2_version() -> str:
    # Windows-only: Evergreen WebView2 Runtime surumu (registry 'pv'); yoksa 'n/a'.
    try:
        import winreg
        guid = r"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
        for hive, key in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\\" + guid),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\\" + guid),
        ):
            try:
                with winreg.OpenKey(hive, key) as k:
                    v, _ = winreg.QueryValueEx(k, "pv")
                    if v:
                        return v
            except OSError:
                continue
    except Exception:
        pass
    return "n/a"


#: Bu tezgahin KOSMASI GEREKEN kontrolleri. Bir SOZLESMEDIR, kozmetik degil.
#:
#: Turkce not — NEDEN VAR: bir raporun eksik bir kontrolu fark edebilmesi icin, o kontrolun
#: BEKLENDIGINI bilmesi gerekir. Bu liste olmadan tezgah 21 satir yerine 15 satir uretir ve
#: hem kendisi hem okuyucusu bunu "temiz" diye okur -- kaybolan yedi AUTHZ kontrolu hicbir
#: yerde iz birakmaz. Yeni bir kontrol eklerken ID'sini BURAYA da eklemek zorunludur; bu bir
#: yuk degil, kapinin ta kendisidir.
EXPECTED_CHECK_IDS = frozenset({
    "AUTHZ-TOKEN-MISSING", "AUTHZ-TOKEN-WRONG", "AUTHZ-C5", "AUTHZ-C7", "AUTHZ-C8",
    "AUTHZ-DENY", "AUTHZ-BIND",
    "CRYPTO-EXPORT", "CRYPTO-KDF", "CRYPTO-ATREST", "CRYPTO-DPAPI",
    "AUDIT-VERIFY", "AUDIT-TAMPER-MODIFY", "AUDIT-TAMPER-DELETE",
    "SCAN-BANDIT", "SCAN-PIPAUDIT", "SCAN-SECRETS", "SCAN-BAK-HYGIENE",
    "FUZZ-NOAUTH", "FUZZ-EXECUTE",
})

_CATEGORY_OF = {"AUTHZ": "authz", "CRYPTO": "crypto", "AUDIT": "audit",
                "SCAN": "scan", "FUZZ": "fuzz"}


def loader_error_row(checker_name: str, exc: BaseException) -> dict:
    """Bir kontrol MODULU cokerse uretilen satir.

    Turkce not — OLCULDU 2026-08-05 (SECBENCH-SILENT-SKIP): bu satir eskiden
    status="SKIP", severity="info" tasiyordu. verdict()'teki `unmeasured` suzgeci ise
    status=="ERROR" + high/critical arar -> bir kontrol modulunun TAMAMEN cokmesi
    hukmu hic degistirmiyordu: rapor "PASS", cikis kodu 0. Yani "yedi AUTHZ kontrolunun
    hicbiri kosmadi" ile "yedisi de gecti" ayni ekrani uretiyordu.
    Bir kategoriyi butunuyle kaybetmek "info" degildir; o kategoride HICBIR SEY olculmemistir.
    """
    return {
        "id": f"{checker_name}-LOADER",
        "category": ("audit" if checker_name.endswith("audit")
                     else "authz" if checker_name.endswith("authz")
                     else "crypto" if checker_name.endswith("crypto")
                     else "fuzz" if checker_name.endswith("fuzz")
                     else "scan"),
        "title": "check module failed to load - NOTHING in this category was measured",
        "status": "ERROR",
        "severity": "critical",
        "evidence": f"{type(exc).__name__}: {exc}",
        "remediation": "fix module import; until then this category is UNMEASURED, not clean",
    }


def _coverage_gaps(results: list) -> list:
    """Beklenip de KOSMAYAN kontroller icin ERROR satirlari uret.

    ERROR/critical secilmesi bilerekdir: `unmeasured` suzgeci tam olarak bunu arar ve
    cikis kodunu 3'e (kapsam eksik) cevirir. FAIL demedik cunku bir delik BULMADIK --
    BAKAMADIK. Ikisini ayirmak bu tezgahin varlik sebebi.
    """
    seen = {r.get("id") for r in results}
    gaps = []
    for missing in sorted(EXPECTED_CHECK_IDS - seen):
        gaps.append({
            "id": missing,
            "category": _CATEGORY_OF.get(missing.split("-", 1)[0], "scan"),
            "title": "expected check did not run",
            "status": "ERROR",
            "severity": "critical",
            "evidence": ("Bu kontrol EXPECTED_CHECK_IDS'te var ama sonuclarda YOK. "
                         "Bir delik bulunmadi; BAKILAMADI."),
            "remediation": "Kontrolun neden kaybolduğunu bul; ya da bilerek kaldirildiysa "
                           "EXPECTED_CHECK_IDS'ten gerekcesiyle cikar.",
        })
    return gaps


def verdict(results: list) -> tuple:
    """(state, exit_code, blocking, unmeasured) -- main()'den ayrildi ki TEST EDILEBILSIN.

    Turkce not: bu mantik eskiden main() icinde gomuluydu ve bu yuzden yalnizca tam bir
    tezgah kosumuyla (~5 dakika, ag bagimli) sinanabiliyordu. Pratikte hic sinanmadi --
    yukaridaki sessiz-SKIP hatasi da tam bu yuzden iki gun yasadi.
    """
    blocking = [r for r in results
                if r.get('status') == 'FAIL' and r.get('severity') in ('critical', 'high')]
    unmeasured = [r for r in results
                  if r.get('status') == 'ERROR' and r.get('severity') in ('critical', 'high')]
    state = ('FAIL' if blocking else 'UNVERIFIED' if unmeasured else 'PASS')
    code = 1 if blocking else (3 if unmeasured else 0)
    return state, code, blocking, unmeasured


def main() -> int:
    try:
        if _KASA_ROOT not in sys.path:
            sys.path.insert(0, _KASA_ROOT)

        meta = {
            "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "os": platform.platform(),
            "os_build": platform.version(),
            "python": platform.python_version(),
            "host": socket.gethostname(),
            "commit": _git_commit(),
            "config_hash": _config_hash(),
            "webview2": _webview2_version(),
            # base = varsayilan gizlilik, peak = gelismis-kilitli kademe; ortam degiskeniyle secilir
            "tier": os.environ.get("KASA_BENCH_TIER", "base"),
        }
        
        results = []
        for checker in [authz, crypto, audit, scan, fuzz]:
            try:
                module_results = checker.run()
                if isinstance(module_results, list):
                    results.extend(module_results)
            except Exception as e:
                # OLCULDU 2026-08-05 (SECBENCH-SILENT-SKIP): burasi eskiden
                # status="SKIP", severity="info" yaziyordu. Asagidaki `unmeasured`
                # suzgeci ise status=="ERROR" + high/critical ariyor -> bir kontrol
                # MODULU tamamen cokerse rapor TEMIZ gorunuyor ve cikis kodu 0 donuyordu.
                # Yani "yedi AUTHZ kontrolunun hicbiri kosmadi" ile "hepsi gecti" ayni
                # ekrani uretiyordu. Bir kategoriyi tamamen kaybetmek info degil, kritik:
                # o kategoride HICBIR SEY olculmedi.
                results.append(loader_error_row(checker.__name__, e))

        # KAPSAM KAPISI: yukaridaki duzeltme yalnizca modul CAGRISI patlarsa calisir.
        # Bir kontrol modulun ICINDE sessizce dusebilir (or. bir except blogu satiri
        # hic eklemezse) ve o zaman satir sayisi 21'den 15'e duser, hicbir hata gorunmez.
        # Rapor bir kontrolun BEKLENDIGINI bilmiyorsa, yoklugunu de bilemez.
        results.extend(_coverage_gaps(results))

        docs = _os.path.join(_KASA_ROOT, "docs")
        os.makedirs(docs, exist_ok=True)
        md, js = render(results, meta)
        
        with open(os.path.join(docs, "SECURITY_BENCHMARK.md"), "w", encoding="utf-8") as md_file:
            md_file.write(md)
        
        with open(os.path.join(docs, "security_bench_result.json"), "w", encoding="utf-8") as json_file:
            json_file.write(js)
        
        # Cikis kodu UC durumu ayirir; ikisine indirgemek iki ayri yalandan birini uretir:
        #   0 dersek  -> "olcemedik"i "temiz" gibi gosteririz  (sahte yesil; otomasyon gecer)
        #   1 dersek  -> "olcemedik"i "acik bulduk" gibi gosteririz (sahte kirmizi; kurt masali)
        # Ikisi de yanlis. Ayri bir kod, otomasyonun "delik var" ile "bakamadik"i ayirt
        # etmesini saglar -- rapor metnindeki ayrimin makine tarafindaki karsiligidir.
        #   0 = temiz | 1 = gercek bulgu | 2 = beklenmedik hata | 3 = kapsam eksik
        state, code, blocking, unmeasured = verdict(results)
        issues = len([r for r in results if r['status'] != 'PASS'])
        summary = (f"SECURITY BENCHMARK: {state} - {issues} issues found."
                   + (f" NOT MEASURED: {', '.join(r['id'] for r in unmeasured)}." if unmeasured else "")
                   + f" ({len(results)} kontrol satiri; beklenen en az {len(EXPECTED_CHECK_IDS)} kimlik)"
                   + " Report saved at docs/SECURITY_BENCHMARK.md and docs/security_bench_result.json")
        print(summary)
        return code
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())


# ===== NEDEN -> SONUC / CAUSE -> EFFECT (yerel model, sifir-token) =====
# Purpose: The main function of this script is to run a series of security checks and generate reports.
# Why (cause -> effect): By executing various security modules, it identifies vulnerabilities and generates both Markdown and JSON reports for documentation.
# Amac: Bu betiğin ana işlevi, bir dizi güvenlik kontrolünü çalıştırmak ve raporlar oluşturmak.
# Neden -> Sonuc: Farklı güvenlik modüllerini çalıştırarak açıkları belirler ve hem Markdown hem de JSON raporları için belgeleme yapar.
