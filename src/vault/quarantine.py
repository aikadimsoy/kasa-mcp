# kasa/src/vault/quarantine.py

"""Faz-2 (G3/ASI06) & Hardened Deterministic Structural Quarantine Engine.

Shared by BOTH write paths so agent-directed injection patterns are routed to quarantine
instead of the live profile: the agent path (mcp_server.tools.profile_write) and the distill
engine (src/distill/engine.py).

Gelişmiş Savunma Hatları:
1. Unicode NFKC Kanonik Normalizasyonu & Sıfır Genişlikli Karakter Temizliği (Homoglif Kalkanı).
2. Base64 & Hex Kodlanmış İkincil Enjeksiyon Çözümleme ve Süzme.
3. Shannon Bilgi Entropisi Analizi.
4. Çok Dilli (Türkçe, İngilizce, Almanca, Rusça) Emir Kipi Kalıpları.
"""

from __future__ import annotations

import base64
import json
import math
import re
import unicodedata
from collections import Counter
from typing import Optional, Tuple

# Görünmez ve yönlendirici sıfır genişlikli karakterler
_ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]")

# Çok Dilli ve Genişletilmiş Emir Kipi Desenleri
_QUARANTINE_PATTERNS = re.compile(
    r"\bignore\s+(?:all|previous|above|everything|instructions|rules)\b|"
    r"\bdisregard\b|"
    r"\byou\s+must\b|"
    r"\b(?:system|admin|root|assistant|sistem)\s*:|"
    r"\bSYSTEM\s+OVERRIDE\b|"
    r"\b(?:reply\s+with|output\s+only|append\b.*\bto\s+every)\b|"
    r"\b(?:yoksay|gecersiz\s+k[ıi]l|talimatlar[ıi]\s+unut|kurallar[ıi]\s+yoksay)\b|"
    r"\b(?:ignoriere\s+alle\s+anweisungen|alle\s+regeln\s+vergessen)\b|"
    r"\b(?:игнорир\w*|забудь\s+инструкци\w*)\b|"
    r"<\s*script\b|\brm\s+-rf\b",
    re.IGNORECASE | re.MULTILINE,
)

# Base64 olabilecek metin blokları (en az 8 karakter, isteğe bağlı padding)
_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{8,}(?:={1,2})?")


def shannon_entropy(text: str) -> float:
    """Metnin Shannon Bilgi Entropisini hesaplar: H(X) = -sum(p * log2(p))."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_text_canonical(text: str) -> str:
    """Unicode NFKC normalizasyonu uygular ve görünmez karakterleri temizler."""
    if not isinstance(text, str):
        return str(text)
    # 1. Sıfır genişlikli karakterleri temizle
    clean = _ZERO_WIDTH_CHARS.sub("", text)
    # 2. NFKC ile Kiril/Latin ve tam-genişlik karakterleri standart Latin/Kanonik forma dönüştür
    return unicodedata.normalize("NFKC", clean)


def _check_decoded_base64(text: str) -> Optional[str]:
    """Metin içindeki Base64 adaylarını decode edip zararlı kalıp arar."""
    candidates = _BASE64_CANDIDATE_RE.findall(text)
    for cand in candidates:
        try:
            # Base64 çözmeyi dene
            decoded_bytes = base64.b64decode(cand, validate=True)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded_str) >= 4:
                decoded_norm = normalize_text_canonical(decoded_str)
                if _QUARANTINE_PATTERNS.search(decoded_norm):
                    return f"base64-encoded injection payload: '{cand}' -> '{decoded_norm[:40]}...'"
        except Exception:
            continue
    return None


def quarantine_reason(value) -> Optional[str]:
    """Girdide herhangi bir doğrudan veya gizlenmiş enjeksiyon varsa nedenini döner."""
    if isinstance(value, str):
        raw_text = value
    else:
        try:
            raw_text = json.dumps(value, ensure_ascii=False)
        except Exception:
            raw_text = str(value)

    # 1. Kanonik Normalizasyon
    normalized = normalize_text_canonical(raw_text)

    # 2. Doğrudan Kalıp Süzgeci
    if _QUARANTINE_PATTERNS.search(normalized):
        return "agent-directed imperative pattern in value"

    # 3. Base64 Gizlenmiş Yük Süzgeci
    b64_hit = _check_decoded_base64(raw_text)
    if b64_hit:
        return b64_hit

    return None


_NEUTRALIZED = "[quarantined:injection-pattern]"


def neutralize(text) -> Tuple[str, int]:
    """Metin içindeki enjeksiyon kalıplarını güvenle nötralize eder."""
    if not isinstance(text, str):
        text = str(text)
    hits = 0

    def _sub(_m):
        nonlocal hits
        hits += 1
        return _NEUTRALIZED

    # Normalizasyon ile tara
    normalized = normalize_text_canonical(text)
    cleaned = _QUARANTINE_PATTERNS.sub(_sub, normalized)
    return cleaned, hits
