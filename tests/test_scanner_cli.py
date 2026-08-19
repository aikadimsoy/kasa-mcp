"""
kasa-scan olcum cihazinin IKI YONLU testi (D24).

Turkce not: Bu tarayici bir OLCUM CIHAZIDIR. Bir olcum cihazi ana koseye
girmeden once iki yonlu sinanir:
    - ATESLEMELI girdide ateslemeli  (guvensiz sunucu -> FAIL)
    - SUSMALI girdide susmali        (uygulanamaz hedef -> SKIP, PASS DEGIL)

Bu dosyanin var olma sebebi olculmus bir arizadir (2026-08-19): tarayicinin
onceki surumu, her istege 404 donen ve HICBIR guvenligi olmayan bir sunucuya
%60 guvenlik skoru ve 3/5 PASS verdi. Sebepleri:
    1. HTTP 404 PASS sayiliyordu (rota yok != saldiri engellendi).
    2. EGRESS kontrolu hedefe hic istek atmadan KASA'nin kendi yerel
       fonksiyonunu cagirip sonucu HEDEFIN karnesine yaziyordu.

Fixture'lar hedefe dusen istekleri SAYAR; boylece "bu kontrol hedefe bakti mi"
sorusu kod okumasindan bagimsiz, ag seviyesinde yanitlanir.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tools.scanner.cli import (
    FAIL,
    PASS,
    SKIP,
    AgentSecurityScanner,
    format_markdown_report,
    format_terminal_report,
    main,
    score_of,
)


# ----------------------------------------------------------------------
# Fixture sunuculari
# ----------------------------------------------------------------------
class _CountingHandler(BaseHTTPRequestHandler):
    """Turkce not: Gelen her istegi sayar; alt siniflar yalniz yaniti belirler."""

    mode = "404"

    def _respond(self, code: int, payload: dict):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.server.request_count += 1  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

        if self.server.mode == "404":  # type: ignore[attr-defined]
            # Rotasi olmayan sunucu: guvenlik yok, uc nokta da yok.
            self._respond(404, {"detail": "not found"})
        elif self.server.mode == "obedient":  # type: ignore[attr-defined]
            # En kotu durum: ne sorulursa yapar. Kimlik dogrulamasi yok,
            # yetki kontrolu yok, karantina yok.
            self._respond(200, {"result": {"status": "ok", "written": True}})
        elif self.server.mode == "secure":  # type: ignore[attr-defined]
            # Iyi davranan sunucu: token yok/yetki yok -> 401.
            if not self.headers.get("Authorization"):
                self._respond(401, {"detail": "unauthorized"})
            else:
                self._respond(403, {"detail": "forbidden"})

    def log_message(self, *args):
        pass


def _start_server(mode: str):
    srv = HTTPServer(("127.0.0.1", 0), _CountingHandler)
    srv.mode = mode  # type: ignore[attr-defined]
    srv.request_count = 0  # type: ignore[attr-defined]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


@pytest.fixture
def server_404():
    srv, url = _start_server("404")
    yield srv, url
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def server_obedient():
    srv, url = _start_server("obedient")
    yield srv, url
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def server_secure():
    srv, url = _start_server("secure")
    yield srv, url
    srv.shutdown()
    srv.server_close()


# ----------------------------------------------------------------------
# NEGATIF YON: susmasi gereken girdide susuyor mu?
# ----------------------------------------------------------------------
def test_404_target_yields_no_pass_at_all(server_404):
    """Rotasi olmayan sunucu HICBIR kontrolden gecmemeli (regresyon: %60 verdi)."""
    _srv, url = server_404
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    passed = [r.check_id for r in results if r.status == PASS]
    assert passed == [], "Guvenligi olmayan hedef PASS aldi: %s" % passed


def test_404_target_has_no_score(server_404):
    """Hicbir sey olculemediyse skor uretilmemeli (sifir da yuzde yuz de degil)."""
    _srv, url = server_404
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    assert score_of(results) is None


def test_404_target_report_says_not_measured(server_404):
    _srv, url = server_404
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    assert "OLCULEMEDI" in format_terminal_report(results, lang="tr")
    assert "NOT MEASURED" in format_terminal_report(results, lang="en")


def test_unreachable_target_is_skip_not_pass():
    """Kapali port: baglanti yok. Bu da PASS degil."""
    # Turkce not: 9 nolu port (discard) kapalidir; baglanti reddedilir.
    results = AgentSecurityScanner(base_url="http://127.0.0.1:9", timeout=1.0).run_all_checks()
    assert all(r.status == SKIP for r in results)
    assert score_of(results) is None


# ----------------------------------------------------------------------
# POZITIF YON: ateslemesi gereken girdide atesliyor mu? (D22 pozitif kontrol)
# ----------------------------------------------------------------------
def test_obedient_server_is_flagged_insecure(server_obedient):
    """Her istege 'tamam' diyen sunucu FAIL almali; alet olu olmamali."""
    _srv, url = server_obedient
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    failed = {r.check_id for r in results if r.status == FAIL}
    assert "AUTHZ-NO-TOKEN" in failed
    assert "AUTHZ-C5-IMPERSONATION" in failed
    assert "AUTHZ-DENY-BY-DEFAULT" in failed
    assert "POISON-QUARANTINE" in failed


def test_obedient_server_score_is_zero(server_obedient):
    _srv, url = server_obedient
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    assert score_of(results) == 0


def test_secure_server_passes_authz_checks(server_secure):
    """401/403 donen sunucu yetki kontrollerinden gecmeli."""
    _srv, url = server_secure
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    by_id = {r.check_id: r.status for r in results}
    assert by_id["AUTHZ-NO-TOKEN"] == PASS
    assert by_id["AUTHZ-C5-IMPERSONATION"] == PASS
    assert by_id["AUTHZ-DENY-BY-DEFAULT"] == PASS


def test_secure_server_quarantine_is_skip_not_pass(server_secure):
    """
    Yetki kapisinda duran istek KARANTINA KANITI DEGILDIR.
    Karantina motoruna hic ulasilmadi -> SKIP.
    """
    _srv, url = server_secure
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    by_id = {r.check_id: r.status for r in results}
    assert by_id["POISON-QUARANTINE"] == SKIP


# ----------------------------------------------------------------------
# EGRESS: hedefe bakiyor mu? (ag seviyesi kanit, kod okumasindan bagimsiz)
# ----------------------------------------------------------------------
def test_egress_check_is_skip_by_default(server_secure):
    _srv, url = server_secure
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    egress = [r for r in results if r.check_id.startswith("EGRESS")]
    assert len(egress) == 1
    assert egress[0].status == SKIP
    assert "OLCULEMEDI" in egress[0].evidence


def test_egress_selftest_is_labelled_as_local(server_secure):
    """--self-test sonucu HEDEFIN degil YEREL kurulumun karnesidir; etiketi tasimali."""
    _srv, url = server_secure
    results = AgentSecurityScanner(base_url=url).run_all_checks(self_test=True)
    egress = [r for r in results if r.check_id.startswith("EGRESS")][0]
    assert egress.check_id.endswith("-SELFTEST")
    assert "YEREL" in egress.title or "LOCAL" in egress.title_en


def test_scanner_sends_no_extra_requests_for_egress(server_secure):
    """
    Turkce not: Hedefe dusen istek sayisi, hedefi olcen kontrol sayisina esit
    olmali. EGRESS hedefi olcmedigini kendisi soyluyor; sessizce istek de atmiyor.
    """
    srv, url = server_secure
    AgentSecurityScanner(base_url=url).run_all_checks()
    # 4 kontrol hedefe istek atar (authz x3 + poison); egress atmaz.
    assert srv.request_count == 4  # type: ignore[attr-defined]


# ----------------------------------------------------------------------
# Cikis kodlari: CI "hicbir sey olculemedi"yi yesil okumamali
# ----------------------------------------------------------------------
def test_exit_code_2_when_nothing_measured(server_404, capsys):
    _srv, url = server_404
    code = main(["--url", url, "--lang", "tr"])
    capsys.readouterr()
    assert code == 2


def test_exit_code_1_when_failures(server_obedient, capsys):
    _srv, url = server_obedient
    code = main(["--url", url, "--lang", "tr"])
    capsys.readouterr()
    assert code == 1


def test_markdown_report_never_prints_score_when_unmeasured(server_404):
    _srv, url = server_404
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    md = format_markdown_report(results, lang="tr")
    assert "OLCULEMEDI" in md
    assert "%100" not in md
    assert "%0" not in md
