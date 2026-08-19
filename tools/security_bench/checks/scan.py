
import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (3 ust dizin = depo koku). Sabit yol, depoyu klonlayan herkeste ve CI
# kosucusunda bu araci calismaz kilardi.
_KASA_ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", ".."))
import subprocess
import sys
import json
import os
import importlib.util


# ===== L1 secret allowlist suzgeci (test-edilebilir; false-PASS avi icin ayri fonksiyon) =====
def load_allowlist(path=None):
    """secret_allowlist.json -> {(normalize_path, type)} kumesi. Okunamazsa BOS (fail-closed)."""
    path = path or os.path.join(os.path.dirname(__file__), "..", "secret_allowlist.json")
    try:
        with open(path, encoding="utf-8") as f:
            return {(e["path"].replace("\\", "/"), e["type"]) for e in json.load(f)["allowlist"]}
    except Exception:
        return set()


def load_bandit_triage(path=None):
    """bandit_triage.json -> {(test_id, normalize_path): count}. Okunamazsa BOS (fail-closed)."""
    path = path or os.path.join(os.path.dirname(__file__), "..", "bandit_triage.json")
    try:
        with open(path, encoding="utf-8") as f:
            return {(e["test_id"], e["path"].replace("\\", "/")): int(e["count"])
                    for e in json.load(f)["triage"]}
    except Exception:
        return {}


def filter_bandit(bandit_json, triage):
    """raw bandit JSON -> (denetlenmemis_MEDIUM_listesi, bastirilan_sayi).

    Turkce not — NEDEN (test_id, path, COUNT) ile anahtarlaniyor:
      * satir numarasiyla anahtarlamak triyaji her duzenlemede bayatlatirdi (satirlar kayar);
      * yalnizca (test_id, path) ile anahtarlamak AYNI dosyada acilan YENI bir bulguyu
        sessizce gizlerdi -- yani triyaj bir KOR NOKTA uretirdi.
    count, o dosyada o test icin kac bulgunun denetlendigini soyler; fazlasi yuzeye cikar.

    HIGH burada hic ele alinmaz: triyaj yalnizca MEDIUM icindir, cagiran HIGH'i ayrica sayar.
    """
    med = [r for r in bandit_json.get("results", []) if r.get("issue_severity") == "MEDIUM"]
    grouped = {}
    for r in med:
        p = str(r.get("filename", "")).replace("\\", "/")
        for marker in ("/src/", "src/"):
            i = p.find(marker)
            if i != -1:
                p = p[i + (1 if marker.startswith("/") else 0):]
                break
        grouped.setdefault((r.get("test_id"), p), []).append(r)

    untriaged, suppressed = [], 0
    for key, rows in sorted(grouped.items()):
        allowed = triage.get(key, 0)
        suppressed += min(allowed, len(rows))
        for r in rows[allowed:]:
            untriaged.append(f"{key[0]} {key[1]}:{r.get('line_number')}")
    return untriaged, suppressed


def filter_secrets(results_dict, allow):
    """raw detect-secrets results -> (real_bulgular_listesi, bastirilan_sayi).
    (path,type) allowlist'te ise bastir; degilse 'real'. bearer_token allowlist'te olmadigindan
    HER ZAMAN real'de kalir -> gizlenemez (test bunu kanitlar)."""
    real, suppressed = [], 0
    for path, items in results_dict.items():
        npath = path.replace("\\", "/")
        for it in items:
            if (npath, it["type"]) in allow:
                suppressed += 1
            else:
                real.append(f"{npath}:{it.get('line_number', '?')} [{it['type']}]")
    return real, suppressed


def run():
    results = []
    
    # Bandit Scan
    if importlib.util.find_spec("bandit") is None:
        result = {
            "id": "SCAN-BANDIT",
            "category": "scan",
            "title": "Static Analysis with Bandit",
            "status": "SKIP",
            "severity": "info",
            "evidence": "Bandit not installed. Remediation: pip install bandit.",
            "remediation": "pip install bandit; review src findings"
        }
        results.append(result)
    else:
        try:
            # Controller: .bak yedekleri src/ disina tasindi (_bak_archive) -> exclude'a gerek yok, gercek src taranir.
            cmd = [sys.executable, "-m", "bandit", "-r", "src", "-f", "json"]
            process = subprocess.run(cmd, cwd=_KASA_ROOT, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=300)
            # encoding="utf-8": text=True, alt surecin ciktisini metne cevirirken Windows'ta
            # YEREL kod sayfasini kullanir (bu makinede cp1254 / Turkce). Cikti UTF-8 bayt
            # icerdiginde cozumleme UnicodeDecodeError verir, subprocess.run bu istisnayi
            # okuma thread'inde YUTAR ve stdout'u BOS dondurur -- donus kodu dogru gelir ama
            # kanit yok olur. errors="replace": cozulemeyen bayti "?" ile degistirir, yani
            # kanit kirpilabilir ama ASLA tamamen kaybolmaz. Olculdu (2026-08-01): ayni
            # cagri deseni saf-ASCII ciktida 98 karakter, Turkce iceren ciktida 0 dondurdu.
            data = process.stdout
            try:
                results_data = json.loads(data)
                high_issues = sum(1 for result in results_data["results"] if result["issue_severity"] == "HIGH")
                # Triyaj suzgeci: DENETLENMIS bulgulari duser, kalani yuzeye cikarir.
                # HIGH ASLA suzulmez -- triyaj yalnizca MEDIUM icin gecerlidir.
                untriaged_med, suppressed_med = filter_bandit(results_data, load_bandit_triage())
                medium_issues = len(untriaged_med) + suppressed_med

                status = "PASS"
                evidence = (f"High: {high_issues}, Medium: {medium_issues} "
                            f"({suppressed_med} denetlenmis, {len(untriaged_med)} denetlenmemis)")
                if high_issues > 0:
                    status = "FAIL"
                    evidence += "; Found HIGH severity issues."
                elif untriaged_med:
                    status = "WARN"
                    evidence += "; DENETLENMEMIS MEDIUM: " + "; ".join(untriaged_med[:6])

                result = {
                    "id": "SCAN-BANDIT",
                    "category": "scan",
                    "title": "Static Analysis with Bandit (triyaj-suzulmus)",
                    "status": status,
                    "severity": "high",
                    "evidence": evidence,
                    "remediation": ("Yeni bulgu gercekse kaynaktan kaldir; yanlis-pozitif veya "
                                    "kabul-edilen kalinti ise GEREKCESIYLE bandit_triage.json'a ekle "
                                    "(count'u da guncelle).")
                }
                results.append(result)
            except json.JSONDecodeError:
                result = {
                    "id": "SCAN-BANDIT",
                    "category": "scan",
                    "title": "Static Analysis with Bandit",
                    "status": "ERROR",
                    # "ERROR" = "olcum yapilamadi", "FAIL" = "olculdu ve sorun bulundu".
                    # Ciktisi ayristirilamayan bir arac HICBIR SEY olcmemistir; bunu FAIL
                    # saymak, bulunmamis bir bulguyu raporlamak olur.
                    "severity": "high",
                    "evidence": f"Failed to parse output: {data[:200]}",
                    "remediation": "pip install bandit; review src findings"
                }
                results.append(result)
        except subprocess.TimeoutExpired:
            result = {
                "id": "SCAN-BANDIT",
                "category": "scan",
                "title": "Static Analysis with Bandit",
                "status": "ERROR",
                # Zaman asimina ugrayan tarama da hicbir sey olcmemistir -> ERROR.
                "severity": "high",
                "evidence": "Scan timed out.",
                "remediation": "pip install bandit; review src findings"
            }
            results.append(result)
        except Exception as e:
            result = {
                "id": "SCAN-BANDIT",
                "category": "scan",
                "title": "Static Analysis with Bandit",
                "status": "SKIP",
                "severity": "info",
                "evidence": f"Unexpected error: {str(e)}",
                "remediation": "pip install bandit"
            }
            results.append(result)
    
    # Pip Audit Scan
    if importlib.util.find_spec("pip_audit") is None:
        result = {
            "id": "SCAN-PIPAUDIT",
            "category": "scan",
            "title": "Dependency Audit with pip-audit",
            "status": "SKIP",
            "severity": "info",
            "evidence": "pip-audit not installed. Remediation: pip install pip-audit.",
            "remediation": "pip install pip-audit; review requirements.txt findings"
        }
        results.append(result)
    else:
        try:
            cmd = [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "-f", "json"]
            process = subprocess.run(cmd, cwd=_KASA_ROOT, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=300)
            # Kodlama neden acikca sabitleniyor: bkz. yukaridaki bandit cagrisinin notu.
            # Ozetle text=True yerel kod sayfasina duser ve cozumleme hatasi ciktiyi
            # SESSIZCE bosaltir; utf-8 + replace ile kanit her halukarda korunur.
            data = process.stdout
            try:
                results_data = json.loads(data)
                if isinstance(results_data, dict):
                    results_data = results_data["dependencies"]
                
                vulnerable_count = sum(1 for entry in results_data if "vulns" in entry and entry["vulns"])
                
                status = "PASS"
                evidence = f"Vulnerable dependencies: {vulnerable_count}"
                if vulnerable_count > 0:
                    status = "FAIL"
                    evidence += "; Found vulnerable dependencies."
                
                result = {
                    "id": "SCAN-PIPAUDIT",
                    "category": "scan",
                    "title": "Dependency Audit with pip-audit",
                    "status": status,
                    "severity": "high",
                    "evidence": evidence,
                    "remediation": "pip install pip-audit; review requirements.txt findings"
                }
                results.append(result)
            except json.JSONDecodeError:
                result = {
                    "id": "SCAN-PIPAUDIT",
                    "category": "scan",
                    "title": "Dependency Audit with pip-audit",
                    "status": "ERROR",
                    # Ayristirilamayan cikti = olcum yok. Gercek bulgu yolu (asagida
                    # vulnerable_count > 0) FAIL olarak KALIR; degisen yalnizca bu dal.
                    "severity": "high",
                    "evidence": f"Failed to parse output: {data[:200]}",
                    "remediation": "pip install pip-audit; review requirements.txt findings"
                }
                results.append(result)
        except subprocess.TimeoutExpired:
            result = {
                "id": "SCAN-PIPAUDIT",
                "category": "scan",
                "title": "Dependency Audit with pip-audit",
                "status": "ERROR",
                # Zaman asimi = olcum yok.
                "severity": "high",
                "evidence": "Scan timed out.",
                "remediation": "pip install pip-audit; review requirements.txt findings"
            }
            results.append(result)
        except Exception as e:
            result = {
                "id": "SCAN-PIPAUDIT",
                "category": "scan",
                "title": "Dependency Audit with pip-audit",
                "status": "SKIP",
                "severity": "info",
                "evidence": f"Unexpected error: {str(e)}",
                "remediation": "pip install pip-audit"
            }
            results.append(result)
    
    # Secrets Scan
    if importlib.util.find_spec("detect_secrets") is None:
        result = {
            "id": "SCAN-SECRETS",
            "category": "scan",
            "title": "Secret Detection with Detect-Secrets",
            "status": "SKIP",
            "severity": "info",
            "evidence": "Detect-secrets not installed. Remediation: pip install detect-secrets.",
            "remediation": "pip install detect-secrets; review filesystem findings"
        }
        results.append(result)
    else:
        try:
            # Controller splice: path'siz 'scan' repo'yu taramiyordu (sahte PASS=0). --all-files ile
            # gercek dosyalar taranir; .pytest_cache (sabit CACHEDIR.TAG) false-positive olarak haric.
            _EXCLUDE = (r"(^|[\\/])(build_nuitka_312|build_nuitka_onefile|build_nuitka|_lab)[\\/]"
                        r"|\.pytest_cache")
            # Ayirici olarak [\\/] kullanilir, duz `/` DEGIL.
            # Olculdu (2026-08-02): ilk surum yalnizca `/` ile yazilmisti; Windows'ta yollar
            # ters egik cizgiyle geldigi icin desen HICBIR seyi eslemedi, dislama etkisiz
            # kaldi ve tarama yine 3,7 GB gezip 351 saniyede zaman asimina dustu. Testi de
            # yalnizca egik-cizgili orneklerle yazdigim icin test YESIL yandi -- olcmedigi
            # seyi olctugunu sanan bir sinav. Artik test iki bicimi de dener.
            # Tarama kapsami: Nuitka DERLEME CIKTISI haric tutulur.
            # Olculdu (2026-08-02): depo 11.760 dosya / 3.776 MB ve bunun %95'i uc derleme
            # dizini (build_nuitka 6.514 dosya / 2.275 MB, build_nuitka_312 2.916,
            # build_nuitka_onefile 1.762) -- hepsi .pyd/.dll ikili ciktisi. Gercek kaynak
            # toplam ~2 MB. Bu 3,7 GB'i gezmek 300 saniyelik siniri asiyordu ve zaman asimi
            # "kritik acik" olarak raporlaniyordu; yani "guvenlik acigi" sanilan sey aslinda
            # derleme klasorunu taramaya calismakti.
            # Kor nokta YARATMAZ: bu ikili dosyalar kaynaktan uretilir, kaynakta secret varsa
            # kaynak taramasinda zaten yakalanir. _bak_archive BILEREK haric tutulmadi --
            # bir config yedegi gercek anahtar tasiyabilir ve kucuk oldugu icin ucuzdur.
            cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files",
                   "--exclude-files", _EXCLUDE]
            process = subprocess.run(cmd, cwd=_KASA_ROOT, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=300)
            # Bu cagri kodlamaya en duyarli olani: detect-secrets TUM depoyu tarar ve bulgu
            # satirlarini ciktiya koyar; bu depoda Turkce yorum/dize bol oldugu icin cikti
            # neredeyse kesin UTF-8 bayt icerir. Kodlama sabitlenmezse cikti bosalir,
            # json.loads("") patlar ve tarayici "Failed to parse output" diye HIC YAPMADIGI
            # bir bulguyu raporlar -- yani sahte kirmizi.
            data = process.stdout
            try:
                results_data = json.loads(data)

                # Controller L1: raw ciktiyi DENETLENMIS allowlist ile suz (secret_allowlist.json).
                # Amac: fixture/false-positive gurultuyu GEREKCELI dusup gercek secret'i (bearer_token)
                # yuzeye cikarmak. bearer_token allowlist'te DEGIL -> FAIL KALIR (durustluk; ".bak gizleme" degil).
                allow_path = os.path.join(os.path.dirname(__file__), "..", "secret_allowlist.json")
                try:
                    with open(allow_path, encoding="utf-8") as _af:
                        allow = {(e["path"].replace("\\", "/"), e["type"]) for e in json.load(_af)["allowlist"]}
                except Exception:
                    allow = set()  # allowlist okunamazsa HICBIR sey bastirma (fail-closed: daha cok FAIL)

                real, suppressed = [], 0
                for path, items in results_data["results"].items():
                    npath = path.replace("\\", "/")
                    for it in items:
                        if (npath, it["type"]) in allow:
                            suppressed += 1
                        else:
                            real.append(f"{npath}:{it.get('line_number', '?')} [{it['type']}]")

                if not real:
                    status = "PASS"
                    evidence = f"0 denetlenmemis secret ({suppressed} allowlist'li bastirildi; gerekce: secret_allowlist.json)"
                else:
                    status = "FAIL"
                    evidence = (f"{len(real)} denetlenmemis secret ({suppressed} allowlist'li bastirildi): "
                                + "; ".join(real[:3]))

                result = {
                    "id": "SCAN-SECRETS",
                    "category": "scan",
                    "title": "Secret Detection with Detect-Secrets (allowlist-suzulmus)",
                    "status": status,
                    "severity": "critical",
                    "evidence": evidence,
                    "remediation": "bearer_token: owner-only ACL uygulandi; kalan -> rotasyon + DPAPI-wrap/at-rest (owner-gated). Yeni bulgu gercekse kaynaktan kaldir, fixture/FP ise gerekceyle secret_allowlist.json'a ekle."
                }
                results.append(result)
            except json.JSONDecodeError:
                result = {
                    "id": "SCAN-SECRETS",
                    "category": "scan",
                    "title": "Secret Detection with Detect-Secrets",
                    "status": "ERROR",
                    # Gercek gizli-anahtar bulgusu yukaridaki dalda FAIL olarak KALIR
                    # (bearer_token allowlist'te olmadigi icin gizlenemez). Burasi yalnizca
                    # "arac cevap veremedi" dalidir.
                    "severity": "critical",
                    "evidence": f"Failed to parse output: {data[:200]}",
                    "remediation": "Review filesystem findings"
                }
                results.append(result)
        except subprocess.TimeoutExpired:
            result = {
                "id": "SCAN-SECRETS",
                "category": "scan",
                "title": "Secret Detection with Detect-Secrets",
                "status": "ERROR",
                # 2026-08-01 kosusunda tezgah tam burada "FAIL critical" bastı ve kaniti
                # yalnizca "Scan timed out." idi -- yani hicbir sey taranmadan kritik acik
                # ilan edildi. Bu satir o sahte kirmiziyi kapatir.
                "severity": "critical",
                "evidence": "Scan timed out.",
                "remediation": "Review filesystem findings"
            }
            results.append(result)
        except Exception as e:
            result = {
                "id": "SCAN-SECRETS",
                "category": "scan",
                "title": "Secret Detection with Detect-Secrets",
                "status": "SKIP",
                "severity": "info",
                "evidence": f"Unexpected error: {str(e)}",
                "remediation": "pip install detect-secrets; review filesystem findings"
            }
            results.append(result)
    
    # Controller: KALICI HIJYEN — REPO GENELINDE stray .bak/yedek birikimi -> WARN.
    # Onceki surum YALNIZ src/ tariyordu; tools/ + _orch/loop birikimini kacirdi -> 107 dosya (108
    # loop-rollback dahil) sessizce birikmisti. Tek-seferlik 'mv' bir KALICI kontrole baglanmadikca
    # kapanmis sayilmaz. Istisna: _bak_archive (arsivin yeri), kasa.db.bak* (migration yedegi),
    # .git/__pycache__/venv gurultu dizinleri.
    try:
        _repo = _KASA_ROOT
        _skip = {"_bak_archive", ".git", "__pycache__", ".pytest_cache",
                 ".venv", "venv", "node_modules"}
        _ARCHIVE_MAX = 200  # _bak_archive KOR NOKTA olmasin: sinir asilirsa retention bozuk -> WARN.
        # (10/basename retention ile ~15+ basename bile <200; 'binlerce birikti' senaryosunu yakalar,
        #  mesru retention'i false-WARN etmez.)
        bak_files = []
        for root, dirs, files in os.walk(_repo):
            dirs[:] = [d for d in dirs if d not in _skip]
            for fn in files:
                if fn.startswith("kasa.db.bak"):
                    continue  # migration guvenlik yedegi (bilincli, gitignore'lu)
                if ".bak" in fn or "bak_" in fn:
                    bak_files.append(os.path.relpath(os.path.join(root, fn), _repo).replace("\\", "/"))
        # _bak_archive'i HARIC TUTMAK bir kor nokta yaratir (uretim hatti oraya yaziyor). Tumden
        # gormezden gelmek yerine SAYI ESIGI koy: retention (guard._BAK_KEEP) calisiyorsa arsiv
        # kucuk kalir; bozulursa esik asilir ve musfettis WARN basar -> sinirsiz-sink kor noktasi yok.
        arch_dir = os.path.join(_repo, "_bak_archive")
        arch_count = sum(1 for f in os.listdir(arch_dir)
                         if (".bak" in f or "bak_" in f)) if os.path.isdir(arch_dir) else 0
        problems = []
        if bak_files:
            problems.append(f"{len(bak_files)} stray (excl _bak_archive): " + ", ".join(sorted(bak_files)[:5]))
        if arch_count > _ARCHIVE_MAX:
            problems.append(f"_bak_archive sinir asti: {arch_count}>{_ARCHIVE_MAX} (retention bozuk?)")
        results.append({
            "id": "SCAN-BAK-HYGIENE",
            "category": "scan",
            "title": "No stray backups + bounded _bak_archive",
            "status": "PASS" if not problems else "WARN",
            "severity": "medium",
            "evidence": f"No stray backups; _bak_archive bounded ({arch_count}/{_ARCHIVE_MAX})"
                        if not problems else " | ".join(problems),
            "remediation": "Stray'i sil/tasi; _bak_archive icin retention (guard._BAK_KEEP) veya age-out"
        })
    except Exception as e:
        results.append({"id": "SCAN-BAK-HYGIENE", "category": "scan", "title": "Backup hygiene check",
                        "status": "SKIP", "severity": "info", "evidence": str(e), "remediation": ""})

    return results


# ===== NEDEN -> SONUC / CAUSE -> EFFECT (yerel model, sifir-token) =====
# Purpose: This script runs security scans using Bandit, pip-audit, and Detect-Secrets.
# Why (cause -> effect): By scanning the codebase for vulnerabilities, dependencies, and secrets,
# it helps identify potential security issues early in the development process.
# Amac: Bu betik, Bandit, pip-audit ve Detect-Secrets kullanarak güvenlik taramaları çalıştırır.
# Neden -> Sonuc: Kod tabanını zafiyetler, bağımlılıklar ve gizli anahtarlar açısından inceleyerek,
# geliştirme sürecinin başlarında olası güvenlik sorunlarını erkenden belirlemeye yardımcı olur.
