"""
KASA — MCP sunucu yetkilendirme (authz) regresyon testleri.
Kanitlanmis acikari (C5/C7/C8) kilitler; GUVENLI son-durumu iddia eder:
fix'ten ONCE FAIL, fix'ten SONRA PASS. server_client fixture'i conftest.py'den gelir.
"""


def test_c5_network_cannot_claim_system(server_client):
    """C5: govdeden agent_id='system' gelen istek TUM izinleri baypaslamamali."""
    c, h = server_client["client"], server_client["headers"]
    r = c.post("/v1/execute_tool", headers=h, json={
        "agent_id": "system",
        "tool_calls": [{"tool_name": "profile_write",
                        "parameters": {"key": "user.x", "value": 1, "provenance": []}}]})
    assert r.status_code in (400, 403), \
        f"C5 ACIK: system baypasi kabul edildi -> {r.status_code} {r.text[:200]}"


def test_c7_grant_permission_not_callable(server_client):
    """C7: grant_permission ag disindan cagrilamamali (izin yukseltme)."""
    c, h = server_client["client"], server_client["headers"]
    r = c.post("/v1/ingest", headers=h, json={
        "tool": "grant_permission", "agent_id": "attacker",
        "params": {"scope": "profile:write"}})
    assert r.status_code in (403, 404), \
        f"C7 ACIK: grant_permission cagrilabildi -> {r.status_code} {r.text[:200]}"


def test_c8_private_methods_not_callable(server_client):
    """C8: _check_permission gibi private/allow-list disi metodlar isimle cagrilamamali."""
    c, h = server_client["client"], server_client["headers"]
    for name in ("_check_permission", "_db", "grant_permission"):
        # agent_id BEYAN EDILMIYOR: kimlik baglamadan sonra uyusmayan bir beyan istegi
        # 403 ile kimlik kapisinda durdurur ve arac gonderimine HIC ULASMAZ -- yani bu
        # test olcmek istedigi seyi (allow-list disi isim cagirilamaz) olcemez olurdu.
        # Beyansiz cagri, token'a bagli kimlikle gecer ve gercekten gonderim katmanini dener.
        r = c.post("/v1/ingest", headers=h, json={
            "tool": name, "params": {}})
        assert r.status_code == 404, \
            f"C8 ACIK: '{name}' cagrilabildi -> {r.status_code} {r.text[:200]}"
