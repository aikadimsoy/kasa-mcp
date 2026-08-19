# kasa/src/agent/egress_guard.py

"""
KASA - Egress Guard & Outbound Network Gate

Denetimli giden trafik (outbound egress) filtresi.
Ajanların dış dünyaya (internet) veri sızdırmasını (data exfiltration),
bilinmeyen alan adlarına bağlanmasını ve hassas anahtar/kimlik bilgilerini
HTTP parametrelerinde veya gövdesinde dışarı kaçırmasını deterministik olarak engeller.

Mimari Kurallar:
- Model sınır değildir; denetim deterministik regex ve allowlist ile yapılır.
- Varsayılan olarak reddet (deny-by-default): Yalnızca izinli alan adlarına geçit verilir.
- Hassas veri sızıntı kalıpları (AWS, SSH, Bearer, Secret) engellenir.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, Optional, Set, Tuple

# Varsayılan İzin Verilen Alan Adları (Niyet Bazlı Domain Allowlist)
DEFAULT_ALLOWED_DOMAINS: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "api.anthropic.com",
    "api.openai.com",
    "scholar.google.com",
    "arxiv.org",
    "huggingface.co",
}

# Veri Sızıntısı (Exfiltration) Şüphesi Yaratan Regex Kalıpları
_EXFIL_PATTERNS = [
    re.compile(r"(?:bearer|token|key|pwd|password|secret|auth|apikey|api_key)[\s:=]+[\w\-\.]{12,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),  # AWS Access Key
    re.compile(r"ghp_[A-Za-z0-9_]{36}", re.IGNORECASE),  # GitHub Token
    re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),  # SSH / Private Key
    re.compile(r"kasa_[a-f0-9]{32,}", re.IGNORECASE),  # KASA Vault Tokens / Signatures
]


def check_exfiltration_payload(text: str) -> Optional[str]:
    """
    Metin içinde (URL sorgusu, başlık veya gövde) hassas veri veya sızıntı deseni arar.
    Tespit edilirse nedenini döner, temizse None döner.
    """
    if not text:
        return None
    for pattern in _EXFIL_PATTERNS:
        if pattern.search(text):
            return f"potential data exfiltration detected: matches pattern '{pattern.pattern[:30]}...'"
    return None


def validate_egress_call(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    allowed_domains: Optional[Set[str]] = None,
) -> Tuple[bool, str]:
    """
    Ajanın yapacağı giden HTTP/HTTPS isteğini doğrular.

    Returns:
        (is_allowed: bool, reason: str)
    """
    if not url:
        return False, "Egress blocked: empty URL"

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Egress blocked: malformed URL ({e})"

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False, f"Egress blocked: unsupported scheme '{scheme}' (only http/https allowed)"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Egress blocked: missing hostname"

    # 1. Domain Allowlist Denetimi
    domains = allowed_domains if allowed_domains is not None else DEFAULT_ALLOWED_DOMAINS
    if hostname not in domains:
        return False, f"Egress blocked: domain '{hostname}' is not in allowlist"

    # 2. URL Query Parametrelerinde Sızıntı Denetimi
    if parsed.query:
        exfil_reason = check_exfiltration_payload(parsed.query)
        if exfil_reason:
            return False, f"Egress blocked: URL query contains {exfil_reason}"

    # 3. HTTP Header Sızıntı Denetimi
    if headers:
        for header_name, header_value in headers.items():
            # Standart izinli Authorization dışındaki kaçak başlıkları tara
            if header_name.lower() not in {"authorization", "host", "user-agent", "accept", "content-type"}:
                exfil_reason = check_exfiltration_payload(f"{header_name}={header_value}")
                if exfil_reason:
                    return False, f"Egress blocked: header '{header_name}' contains {exfil_reason}"

    # 4. Request Body Sızıntı Denetimi
    if body:
        body_text = str(body) if not isinstance(body, (bytes, bytearray)) else body.decode("utf-8", errors="ignore")
        exfil_reason = check_exfiltration_payload(body_text)
        if exfil_reason:
            return False, f"Egress blocked: request body contains {exfil_reason}"

    return True, "Egress allowed: destination verified and payload clean"
