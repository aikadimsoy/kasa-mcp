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
    ScanProfile,
    PASS,
    SKIP,
    AgentSecurityScanner,
    format_markdown_report,
    format_terminal_report,
    main,
    positive_control_ok,
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
        self._last_body = self.rfile.read(length).decode("utf-8") if length else ""

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
        elif self.server.mode == "deny_all":  # type: ignore[attr-defined]
            # Turkce not: HER istege 403. Guvensiz degil -- ISLEVSIZ. Hicbir mesru
            # kullanima da izin vermiyor. Saldiri-bicimli her testten gecer.
            self._respond(403, {"detail": "forbidden"})
        elif self.server.mode == "discriminating":  # type: ignore[attr-defined]
            # Turkce not: Dogru yapilandirilmis sunucu. Mesru istegi KABUL eder,
            # saldiri bicimindekileri reddeder. deny_all'dan tek farki budur ve
            # pozitif kontrolun olcmesi gereken sey tam olarak o fark.
            if not self.headers.get("Authorization"):
                self._respond(401, {"detail": "unauthorized"})
                return
            body = {}
            try:
                body = json.loads(self._last_body or "{}")
            except Exception:
                pass
            if body.get("agent_id") in ("system", "kasa_scan_unknown_agent"):
                self._respond(403, {"detail": "forbidden"})
            elif body.get("tool") == "profile_write":
                self._respond(200, {"result": {"status": "quarantined"}})
            else:
                self._respond(200, {"result": {"status": "ok"}})

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


@pytest.fixture
def server_deny_all():
    srv, url = _start_server("deny_all")
    yield srv, url
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def server_discriminating():
    srv, url = _start_server("discriminating")
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
# POZITIF KONTROL: "her seyi reddeden kapi her negatif testi gecer"
#
# Turkce not: Bu blogun var olma sebebi olculmus bir bosluktur. Tarayici hedefe
# yalniz SALDIRI bicimli istek gonderiyordu; her istegi reddeden -- yani hicbir
# mesru kullanima izin vermeyen, ISLEVSIZ -- bir sunucu hepsinden geciyor ve
# %100 aliyordu (olculdu 2026-08-19). Bulguya yerel bir modelin denetimi
# sirasinda ulasildi; sonra bu makinede yeniden uretildi.
# ----------------------------------------------------------------------
def test_deny_all_server_still_scores_high(server_deny_all):
    """
    Kusurun KENDISI burada dondurulur: her seye 403 donen sunucu, saldiri
    bicimli kontrollerin hepsinden gecer. Bu beklenen davranistir -- kontroller
    dogru calisiyor. Tehlike skorda degil, skorun YORUMUNDA.
    """
    _srv, url = server_deny_all
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    assert score_of(results) == 100


def test_deny_all_server_report_carries_the_caveat(server_deny_all):
    """...ve bu yuzden rapor, skorun yaninda uyariyi TASIMAK ZORUNDA."""
    _srv, url = server_deny_all
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    assert not positive_control_ok(results)
    tr = format_terminal_report(results, lang="tr")
    en = format_terminal_report(results, lang="en")
    assert "POZITIF KONTROL YOK" in tr
    assert "NO POSITIVE CONTROL" in en
    md = format_markdown_report(results, lang="tr")
    assert "pozitif kontrol yok" in md.lower()


def test_positive_control_is_skip_without_token(server_discriminating):
    """Token yoksa ayirt etme OLCULEMEZ; bu bir gecis degildir."""
    _srv, url = server_discriminating
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    pc = [r for r in results if r.check_id == "POSITIVE-CONTROL"][0]
    assert pc.status == SKIP
    assert not positive_control_ok(results)


def test_positive_control_passes_on_discriminating_server(server_discriminating):
    """Token varsa ve hedef mesru istegi KABUL ediyorsa: PASS (pozitif yon)."""
    _srv, url = server_discriminating
    results = AgentSecurityScanner(base_url=url, token="valid-token").run_all_checks()
    pc = [r for r in results if r.check_id == "POSITIVE-CONTROL"][0]
    assert pc.status == PASS
    assert positive_control_ok(results)


def test_positive_control_fails_on_deny_all_server(server_deny_all):
    """
    Token varsa ve hedef MESRU istegi de reddediyorsa: FAIL (negatif yon).
    Iki fixture'in tek farki bu; pozitif kontrolun olcmesi gereken sey de o.
    """
    _srv, url = server_deny_all
    results = AgentSecurityScanner(base_url=url, token="valid-token").run_all_checks()
    pc = [r for r in results if r.check_id == "POSITIVE-CONTROL"][0]
    assert pc.status == FAIL
    assert not positive_control_ok(results)


def test_discriminating_server_with_token_gets_clean_report(server_discriminating):
    """Dogru yapilandirilmis sunucu, token ile: uyari YOK, karantina olculur."""
    _srv, url = server_discriminating
    results = AgentSecurityScanner(base_url=url, token="valid-token").run_all_checks()
    by_id = {r.check_id: r.status for r in results}
    assert by_id["POSITIVE-CONTROL"] == PASS
    assert by_id["POISON-QUARANTINE"] == PASS  # 200 + status=quarantined
    assert "POZITIF KONTROL YOK" not in format_terminal_report(results, lang="tr")


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
# PROFIL: alet KASA'ya bagli mi?
#
# Turkce not: Tarayici bastan KASA'ya gore yazilmisti; uc nokta ve alan adlari
# koda gomuluydu. Bu blok, aletin BASKA bir sunucu bicimini de olcebildigini
# gosterir -- ve o iddiayi kod okuyarak degil, farkli bicimde konusan gercek bir
# fixture'a istek gondererek kanitlar.
# ----------------------------------------------------------------------
class _GenericHandler(BaseHTTPRequestHandler):
    """Tamamen farkli bir bicim: /api/tools/invoke, name/input/actor alanlari."""

    def do_POST(self):
        self.server.request_count += 1  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        self.server.last_bodies.append(raw)  # type: ignore[attr-defined]

        if self.path != "/api/tools/invoke":
            self._send(404, {"detail": "no such route"})
            return
        body = json.loads(raw or "{}")
        if not self.headers.get("Authorization"):
            self._send(401, {"detail": "unauthorized"})
        elif body.get("actor") in ("root", "scan_probe_agent"):
            self._send(403, {"detail": "forbidden"})
        elif body.get("name") == "memory.put":
            self._send(200, {"data": {"state": "held"}})
        else:
            self._send(200, {"data": {"state": "ok"}})

    def _send(self, code, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture
def server_generic():
    srv = HTTPServer(("127.0.0.1", 0), _GenericHandler)
    srv.request_count = 0  # type: ignore[attr-defined]
    srv.last_bodies = []  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


GENERIC_PROFILE = ScanProfile(
    name="example-generic",
    endpoint="/api/tools/invoke",
    tool_field="name",
    args_field="input",
    agent_field="actor",
    read_tool="memory.get",
    write_tool="memory.put",
    read_args={"key": "*"},
    write_key="policy.note",
    quarantine_path=["data", "state"],
    quarantine_value="held",
    reserved_agent_id="root",
    unknown_agent_id="scan_probe_agent",
    deny_statuses=[401, 403],
)


def test_default_profile_finds_nothing_on_a_generic_server(server_generic):
    """Varsayilan (KASA) profil bu sunucuyu OLCEMEZ -- ve bunu PASS diye degil SKIP diye der."""
    _srv, url = server_generic
    results = AgentSecurityScanner(base_url=url, token="t").run_all_checks()
    assert all(r.status == SKIP for r in results)
    assert score_of(results) is None


def test_generic_profile_actually_measures_the_generic_server(server_generic):
    """Dogru profil ile ayni alet ayni sunucuyu OLCER. 'KASA'ya bagli degil' iddiasinin kaniti."""
    _srv, url = server_generic
    results = AgentSecurityScanner(base_url=url, token="t",
                                   profile=GENERIC_PROFILE).run_all_checks()
    by_id = {r.check_id: r.status for r in results}
    assert by_id["POSITIVE-CONTROL"] == PASS
    assert by_id["AUTHZ-NO-TOKEN"] == PASS
    assert by_id["AUTHZ-C5-IMPERSONATION"] == PASS
    assert by_id["AUTHZ-DENY-BY-DEFAULT"] == PASS
    assert by_id["POISON-QUARANTINE"] == PASS  # quarantine_path/value profilden okundu
    assert score_of(results) == 100


def test_profile_fields_really_reach_the_wire(server_generic):
    """Profil alan adlari GERCEKTEN istege giriyor mu -- govdeyi sunucudan okuyoruz."""
    srv, url = server_generic
    AgentSecurityScanner(base_url=url, token="t", profile=GENERIC_PROFILE).run_all_checks()
    bodies = [json.loads(b) for b in srv.last_bodies]  # type: ignore[attr-defined]
    assert any("name" in b and "input" in b for b in bodies), "tool/args alan adlari uygulanmamis"
    assert any(b.get("actor") == "root" for b in bodies), "agent alan adi uygulanmamis"
    assert not any("tool" in b or "arguments" in b for b in bodies), "KASA alan adlari sizmis"


def test_profile_file_roundtrip(tmp_path):
    p = tmp_path / "prof.json"
    p.write_text(json.dumps(GENERIC_PROFILE.to_dict()), encoding="utf-8")
    loaded = ScanProfile.from_file(str(p))
    assert loaded.endpoint == "/api/tools/invoke"
    assert loaded.deny_statuses == (401, 403)


def test_profile_rejects_unknown_field_loudly(tmp_path):
    """Sessizce yok saymak, kullanicinin ayarladigini sanmasina yol acar."""
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"endpoint": "/x", "endpiont": "/typo"}), encoding="utf-8")
    with pytest.raises(ValueError) as e:
        ScanProfile.from_file(str(p))
    assert "endpiont" in str(e.value)


def test_shipped_profiles_are_loadable():
    """Depoda duran ornek profiller gercekten yukleniyor mu?"""
    for name in ("kasa", "example-generic"):
        prof = ScanProfile.from_file("tools/scanner/profiles/%s.json" % name)
        assert prof.name == name


def test_only_marks_others_skip_not_absent(server_discriminating):
    """Daraltilmis tarama, tam tarama gibi gorunmemeli: dislananlar SKIP olarak DURUR."""
    _srv, url = server_discriminating
    results = AgentSecurityScanner(base_url=url, token="t").run_all_checks(
        only=["AUTHZ-NO-TOKEN"])
    assert len(results) == len(AgentSecurityScanner.CHECKS)
    by_id = {r.check_id: r.status for r in results}
    assert by_id["AUTHZ-NO-TOKEN"] == PASS
    assert by_id["AUTHZ-C5-IMPERSONATION"] == SKIP
    assert "--only" in [r for r in results if r.check_id == "AUTHZ-C5-IMPERSONATION"][0].evidence


def test_skip_checks_marks_skipped_with_reason(server_discriminating):
    _srv, url = server_discriminating
    results = AgentSecurityScanner(base_url=url, token="t").run_all_checks(
        skip=["POISON-QUARANTINE"])
    r = [x for x in results if x.check_id == "POISON-QUARANTINE"][0]
    assert r.status == SKIP
    assert "--skip-checks" in r.evidence


def test_unknown_check_name_is_an_error(server_discriminating):
    _srv, url = server_discriminating
    with pytest.raises(ValueError) as e:
        AgentSecurityScanner(base_url=url).run_all_checks(only=["NO-SUCH-CHECK"])
    assert "NO-SUCH-CHECK" in str(e.value)


def test_list_checks_exits_zero(capsys):
    assert main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    for cid, _m, _d in AgentSecurityScanner.CHECKS:
        assert cid in out


def test_print_profile_shows_what_will_be_sent(capsys):
    assert main(["--print-profile"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["endpoint"] == "/v1/execute_tool"


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
    """
    Turkce not: Bu test once tum belgede "%100" arıyordu ve pozitif kontrolun
    ACIKLAMA metnindeki olculmus sayiya takildi. Iddia "belgede su dizge gecmesin"
    degil, "SKOR SATIRI bir yuzde basmasin" -- o yuzden yalniz skor satirina bakar.
    """
    _srv, url = server_404
    results = AgentSecurityScanner(base_url=url).run_all_checks()
    md = format_markdown_report(results, lang="tr")
    score_lines = [l for l in md.splitlines() if "Genel Guvenlik Skoru" in l]
    assert len(score_lines) == 1
    assert "OLCULEMEDI" in score_lines[0]
    assert "%" not in score_lines[0].replace("Skoru:", "")
