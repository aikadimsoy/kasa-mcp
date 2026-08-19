# -*- coding: utf-8 -*-
"""mcp_adapter loopback URL guard — startswith bypass regresyonu.

OLCULDU (sahip red-team notu): eski kontrol `base_url.startswith("http://127.0.0.1")` idi
ve alt-alan (`http://127.0.0.1.evil.example`) ile userinfo (`http://127.0.0.1@evil.example`)
hilelerini GECIRIYORDU -> "air-gap" iddiasi yaniltici. Guard artik URL'yi ayristirip
`hostname`i tam-eslesme ile denetler. Bu dosya hem gecmesi hem ELENMESI gerekenleri pinler.
"""
import os
import sys

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

import pytest

from src.mcp_adapter.proxy import _is_loopback_url


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8000/v1/execute_tool",
    "http://localhost:8000",
    "https://localhost",
    "http://[::1]:8000",
])
def test_genuine_loopback_allowed(url):
    assert _is_loopback_url(url) is True, f"mesru loopback reddedildi: {url}"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1.evil.example",       # alt-alan hilesi (eski startswith GECIRIYORDU)
    "http://127.0.0.1.evil.example/x",
    "http://127.0.0.1@evil.example",       # userinfo hilesi (eski startswith GECIRIYORDU)
    "http://localhost.evil.example",
    "http://evil.example/127.0.0.1",       # yol icinde loopback
    "http://10.0.0.5:8000",                # LAN
    "http://0.0.0.0:8000",                 # tum arayuzler
    "ftp://127.0.0.1",                     # yanlis sema
    "file:///etc/passwd",
])
def test_impostor_urls_rejected(url):
    assert _is_loopback_url(url) is False, f"loopback taklitcisi GECTI: {url}"
