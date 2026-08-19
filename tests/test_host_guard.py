# EN: G2 Host-header guard — reject non-loopback Host (DNS-rebinding defense).
# Turkce not: loopback Host'lar (127.0.0.1/localhost) gecer; loopback-disi (attacker) 400 alir;
# KASA_ALLOWED_HOSTS ile acik opt-in edilen ekstra host gecer, listede olmayan reddedilir.
import importlib
import os

from fastapi.testclient import TestClient


def _client(tmp_vault, host):
    os.environ["KASA_VAULT_PATH"] = tmp_vault
    srv = importlib.import_module("src.mcp_server.server")
    importlib.reload(srv)
    # base_url'in host'u -> istegin Host basligi
    return TestClient(srv.app, base_url=f"http://{host}", raise_server_exceptions=False)


def test_loopback_host_allowed(tmp_vault):
    for host in ("127.0.0.1", "localhost", "127.0.0.1:8780"):
        with _client(tmp_vault, host) as c:
            r = c.get("/")
            assert r.status_code == 200, (host, r.status_code, r.text)


def test_nonloopback_host_rejected(tmp_vault):
    # DNS-rebinding: rebound sayfa 127.0.0.1'e baglanir ama saldirganin Host'unu yollar.
    with _client(tmp_vault, "127.0.0.1.evil.example") as c:
        r = c.get("/")
        assert r.status_code == 400, r.text
        assert "Host" in r.json().get("detail", "")
    with _client(tmp_vault, "attacker.example") as c:
        assert c.get("/").status_code == 400


def test_extra_allowed_host_via_env(tmp_vault, monkeypatch):
    # Reverse-proxy/Tailscale icin acik opt-in; wildcard yok.
    monkeypatch.setenv("KASA_ALLOWED_HOSTS", "myproxy.local")
    with _client(tmp_vault, "myproxy.local") as c:
        assert c.get("/").status_code == 200
    with _client(tmp_vault, "other.example") as c:
        assert c.get("/").status_code == 400
