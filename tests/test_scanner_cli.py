# tests/test_scanner_cli.py

"""
KASA - Scanner CLI Unit Tests
Doğrulanacaklar:
- Tarayıcının HTTP yanıtlarına göre PASS/FAIL ayrımı yapması
- JSON ve Markdown formatlarının hatasız üretilmesi
"""

import pytest
from unittest.mock import patch, MagicMock
from tools.scanner.cli import AgentSecurityScanner, format_markdown_report, format_terminal_report


def test_scanner_detects_vulnerable_unauth():
    """Token kontrolü yapmayan (açık) sunucuyu FAIL olarak işaretlemeli."""
    scanner = AgentSecurityScanner(base_url="http://mock-server:8000")
    
    with patch.object(scanner, "_post") as mock_post:
        # Yetkisiz isteğe 200 dönen korumasız sunucu
        mock_post.return_value = (200, {"status": "success", "data": "leaked"}, "")
        
        scanner._check_unauthenticated_access()
        assert len(scanner.results) == 1
        assert scanner.results[0].status == "FAIL"
        assert "AUTHZ-NO-TOKEN" == scanner.results[0].check_id


def test_scanner_detects_protected_auth():
    """Token kontrolü yapan sunucuyu PASS olarak işaretlemeli."""
    scanner = AgentSecurityScanner(base_url="http://mock-server:8000")
    
    with patch.object(scanner, "_post") as mock_post:
        # Yetkisiz isteğe 401 dönen korumalı sunucu
        mock_post.return_value = (401, {"error": "Unauthorized"}, "")
        
        scanner._check_unauthenticated_access()
        assert len(scanner.results) == 1
        assert scanner.results[0].status == "PASS"


def test_report_formatting():
    """Markdown ve Terminal raporlarının çökmeden üretilmesi."""
    scanner = AgentSecurityScanner(base_url="http://mock-server:8000")
    scanner.results = []
    scanner._check_egress_and_secret_leak()
    
    md_text = format_markdown_report(scanner.results)
    assert "KASA AI Agent Security Benchmark Raporu" in md_text
    assert "EGRESS-DATA-LEAK" in md_text

    term_text = format_terminal_report(scanner.results)
    assert "KASA AI AGENT & MCP SECURITY BENCHMARK REPORT" in term_text
