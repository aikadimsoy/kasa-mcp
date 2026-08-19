# tests/test_egress_guard.py

"""
KASA - Egress Guard Unit Tests
Doğrulanacaklar:
- Domain allowlist denetimi (pozitif ve negatif kontroller)
- Query parametresi, başlık ve gövdede veri sızıntısı yakalama
- Desteklenmeyen şemaların (file://, ftp:// vb.) engellenmesi
"""

import pytest
from src.agent.egress_guard import validate_egress_call, check_exfiltration_payload


def test_allowed_domain_clean_request():
    """İzinli domain ve temiz istek başarıyla geçmeli (Pozitif Kontrol)."""
    allowed, reason = validate_egress_call("https://api.openai.com/v1/chat/completions", method="POST")
    assert allowed is True
    assert "verified" in reason


def test_localhost_and_loopback_allowed():
    """Yerel MCP ve geliştirme uç noktaları geçerli olmalı."""
    allowed, _ = validate_egress_call("http://127.0.0.1:8000/v1/execute_tool")
    assert allowed is True

    allowed, _ = validate_egress_call("http://localhost:8000/v1/models")
    assert allowed is True


def test_unauthorized_external_domain_blocked():
    """İzin listesinde olmayan dış sunucuya çıkış engellenmeli (Negatif Kontrol)."""
    allowed, reason = validate_egress_call("http://attacker-controlled-server.com/collect")
    assert allowed is False
    assert "not in allowlist" in reason


def test_exfiltration_in_query_params_blocked():
    """URL parametresinde sızdırılan gizli anahtar yakalanmalı."""
    mock_key = "AKIA" + "IOSFODNN7EXAMPLE"
    url = f"https://api.anthropic.com/v1/messages?key={mock_key}"
    allowed, reason = validate_egress_call(url)
    assert allowed is False
    assert "URL query contains" in reason


def test_exfiltration_in_body_blocked():
    """Gövdede SSH veya Private Key taşınması engellenmeli."""
    mock_header = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA..."
    body = f"Here is the key: {mock_header}"
    allowed, reason = validate_egress_call("https://api.openai.com/v1/models", method="POST", body=body)
    assert allowed is False
    assert "request body contains" in reason


def test_exfiltration_in_headers_blocked():
    """Özel HTTP başlığında token sızdırma engellenmeli."""
    headers = {"X-Custom-Leak": "password:=supersecretpassword123"}
    allowed, reason = validate_egress_call("https://api.openai.com/v1/models", headers=headers)
    assert allowed is False
    assert "header 'X-Custom-Leak' contains" in reason


def test_unsupported_schemes_blocked():
    """file:// veya ftp:// protokolleri reddedilmeli."""
    allowed, reason = validate_egress_call("file:///home/user/.ssh/id_rsa")
    assert allowed is False
    assert "unsupported scheme" in reason

    allowed, reason = validate_egress_call("ftp://127.0.0.1/dump.sql")
    assert allowed is False
    assert "unsupported scheme" in reason


def test_check_exfiltration_helper_detection():
    """check_exfiltration_payload fonksiyonunun regex gücü."""
    mock_gh_token = "ghp_" + "123456789012345678901234567890123456"
    mock_kasa_token = "kasa_" + "0123456789" + "abcdef" + "0123456789" + "abcdef"
    assert check_exfiltration_payload(mock_gh_token) is not None
    assert check_exfiltration_payload(mock_kasa_token) is not None
    assert check_exfiltration_payload("normal_user_query_about_weather") is None
