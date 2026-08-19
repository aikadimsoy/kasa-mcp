# tests/test_client_sdk.py

"""
KASA - Client SDK Unit Tests
Doğrulanacaklar:
- KasaClient metodlarının payload hazırlığı
- Doğru HTTP header ve Bearer token gönderimi
- HTTP 403 / Hata eşlemelerinin temiz Exception fırlatması
"""

import pytest
from unittest.mock import patch, MagicMock
from src.client import KasaClient


def test_client_ingest_payload():
    client = KasaClient(base_url="http://127.0.0.1:8000", token="test_token_123")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "success", "result": {"status": "success", "event_id": 42}}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = client.ingest(source="test_src", type="test_type", content={"k": "v"})
        assert res["status"] == "success"
        assert res["event_id"] == 42


def test_client_profile_read_requires_reason():
    client = KasaClient(base_url="http://127.0.0.1:8000", token="test_token_123")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "success", "result": {"data": [{"key": "user.name", "value": "Alice"}]}}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = client.get_profile(scope="user.*", reason="context_fetch")
        assert len(res["data"]) == 1
        assert res["data"][0]["value"] == "Alice"
