# -*- coding: utf-8 -*-
"""Tezgahin KAPSAM KAPISI — pozitif ve negatif kontrollerle.

NE OLCULDU VE NEDEN BU DOSYA VAR
--------------------------------
2026-08-05, SECBENCH-SILENT-SKIP. Guvenlik tezgahinda ucuncu bir sahte-PASS kok nedeni
bulundu ve oncekilerle ayni aileden:

  * `run.py` bir kontrol MODULU cokerse `status="SKIP", severity="info"` satiri yaziyordu.
  * Hukum suzgeci ise `status=="ERROR"` + high/critical ariyordu.
  * Sonuc: yedi AUTHZ kontrolunun hicbiri kosmasa bile rapor **PASS**, cikis kodu **0**.
    "Hicbirine bakmadik" ile "hepsi gecti" AYNI ekrani uretiyordu.

Daha derin acik ise sudur: tezgahin hangi kontrollerin kosmasi GEREKTIGINE dair bir
sozlesmesi yoktu. Bir kontrol modulun ICINDE sessizce dusseydi (bir except blogu satir
eklemeyi unutursa), 21 satir 15 olur ve hicbir yerde iz kalmazdi. Bir rapor, bir kontrolun
BEKLENDIGINI bilmiyorsa yoklugunu da bilemez.

BU DOSYANIN TUTTUGU SEY
-----------------------
Uc yon birlikte, cunku biri tek basina yaniltir:
  * POZITIF: tam ve temiz bir sonuc kumesi PASS + cikis 0 uretmeli. (Her seye ERROR diyen
    bir kapi butun negatif testleri gecer ve hicbir ise yaramaz.)
  * NEGATIF-A: modul cokmesi -> ERROR/critical -> UNVERIFIED + cikis 3.
  * NEGATIF-B: **sessiz kaybolma** -> kapsam kapisi eksik ID'yi yakalar. Eski kod bu vakayi
    hic goremiyordu; testin asil degeri burada.
Ayrica: gercek bir BULGU (FAIL) kapsam eksikligini bastirmali -- delik bulmak, bakamamaktan
daha yuksek onceliklidir.
"""
import os as _os
import sys

_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from tools.security_bench.run import (
    EXPECTED_CHECK_IDS,
    _coverage_gaps,
    loader_error_row,
    verdict,
)


def _complete_clean_results():
    """Beklenen her kontrolun PASS dondugu tam bir sonuc kumesi."""
    return [{"id": cid, "category": "x", "title": cid, "status": "PASS",
             "severity": "info", "evidence": "ok", "remediation": ""}
            for cid in sorted(EXPECTED_CHECK_IDS)]


# --- POZITIF KONTROL: kapi kor bir ret degil -------------------------------

def test_POSITIVE_complete_clean_run_is_pass_and_exit_zero():
    results = _complete_clean_results()
    assert _coverage_gaps(results) == [], "eksik olmayan kosumda kapsam bosluğu uretildi"
    state, code, blocking, unmeasured = verdict(results)
    assert (state, code) == ("PASS", 0), f"temiz kosum PASS/0 vermedi: {state}/{code}"
    assert not blocking and not unmeasured


def test_POSITIVE_extra_new_check_is_not_an_error():
    """Yeni bir kontrol eklemek hata degildir; yalnizca EKSIK olan hatadir."""
    results = _complete_clean_results()
    results.append({"id": "SCAN-BRAND-NEW", "category": "scan", "title": "yeni",
                    "status": "PASS", "severity": "info", "evidence": "", "remediation": ""})
    assert _coverage_gaps(results) == []
    assert verdict(results)[1] == 0


# --- NEGATIF-A: modul cokmesi ----------------------------------------------

def test_NEGATIVE_module_crash_row_is_error_critical_not_skip_info():
    """Duzeltilen hatanin ta kendisi: bu satir SKIP/info olsaydi hukum degismezdi."""
    row = loader_error_row("tools.security_bench.checks.authz", RuntimeError("import patladi"))
    assert row["status"] == "ERROR", "modul cokmesi hala ERROR disi bir durum yaziyor"
    assert row["severity"] == "critical"
    assert "import patladi" in row["evidence"]


def test_NEGATIVE_module_crash_drives_unverified_and_exit_three():
    """AUTHZ modulu tamamen cokmus bir kosum: PASS/0 DEGIL, UNVERIFIED/3 olmali."""
    survived = [r for r in _complete_clean_results() if not r["id"].startswith("AUTHZ-")]
    survived.append(loader_error_row("tools.security_bench.checks.authz", RuntimeError("boom")))
    state, code, _, unmeasured = verdict(survived + _coverage_gaps(survived))
    assert (state, code) == ("UNVERIFIED", 3), f"modul cokmesi hukmu degistirmedi: {state}/{code}"
    assert any(u["id"].startswith("AUTHZ-") for u in unmeasured)


def test_NEGATIVE_the_old_skip_info_shape_would_have_slipped_through():
    """Regresyon capasi: eski satir bicimi tek basina hukmu DEGISTIRMEZ.

    Turkce not: bu test hatayi 'yeniden uretir' -- eger biri ileride satiri SKIP/info'ya
    geri cevirirse, yukaridaki test kirilir ve bu test NEDEN kirildigini anlatir.
    """
    old_shape = {"id": "authz-LOADER", "category": "authz", "title": "check module failed to load",
                 "status": "SKIP", "severity": "info", "evidence": "boom", "remediation": ""}
    state, code, _, unmeasured = verdict([old_shape])
    assert (state, code) == ("PASS", 0)
    assert unmeasured == []


# --- NEGATIF-B: sessiz kaybolma (eski kodun HIC goremedigi vaka) -----------

def test_NEGATIVE_silently_missing_check_is_caught_by_coverage_gate():
    results = [r for r in _complete_clean_results() if r["id"] != "CRYPTO-ATREST"]
    gaps = _coverage_gaps(results)
    assert len(gaps) == 1 and gaps[0]["id"] == "CRYPTO-ATREST"
    assert gaps[0]["status"] == "ERROR" and gaps[0]["severity"] == "critical"
    state, code, _, _ = verdict(results + gaps)
    assert (state, code) == ("UNVERIFIED", 3), \
        "sessizce kaybolan kontrol hukmu degistirmedi -- kapsam kapisi calismiyor"


def test_NEGATIVE_missing_check_is_ERROR_not_FAIL():
    """Bakamamak, delik bulmak DEGILDIR. Ikisini karistirmak kurt masali uretir."""
    gaps = _coverage_gaps([])
    assert gaps, "hic sonuc yokken kapsam kapisi sessiz kaldi"
    assert all(g["status"] == "ERROR" for g in gaps)
    assert not any(g["status"] == "FAIL" for g in gaps)
    assert len(gaps) == len(EXPECTED_CHECK_IDS)


# --- Oncelik: gercek bulgu, kapsam eksikligini bastirir --------------------

def test_real_finding_outranks_missing_coverage():
    results = [r for r in _complete_clean_results() if r["id"] != "SCAN-SECRETS"]
    results.append({"id": "AUTHZ-C5", "category": "authz", "title": "x", "status": "FAIL",
                    "severity": "critical", "evidence": "403 bekleniyordu, 200 geldi",
                    "remediation": ""})
    state, code, blocking, unmeasured = verdict(results + _coverage_gaps(results))
    assert (state, code) == ("FAIL", 1), "gercek bulgu varken hukum FAIL/1 olmali"
    assert blocking and unmeasured, "ikisi de raporda gorunmeli, biri otekini silmemeli"
