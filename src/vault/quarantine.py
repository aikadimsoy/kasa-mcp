# kasa/src/vault/quarantine.py

"""Faz-2 (G3/ASI06) deterministic STRUCTURAL quarantine flag.

Shared by BOTH write paths so agent-directed injection patterns are routed to quarantine
instead of the live profile: the agent path (mcp_server.tools.profile_write) and the distill
engine (src/distill/engine.py).

Turkce not: yapisal bayrak (model-yargisi DEGIL) -> adaptif atlatmaya kapali, tekrar-uretilebilir;
secim arastirmadan "learn/flag on structural features, not model judgment". Hit -> KARANTINA
(reddetme degil): sahip inceler. Kelime-kalibi obfuscated zehri kacirabilir = tespit, ISPAT degil.
"""

import json
import re

_QUARANTINE_PATTERNS = re.compile(
    r"ignore\s+(all|previous|above)|disregard\b|you\s+must\b|system\s*:|"
    r"reply\s+with\b|output\s+only\b|append\b.*\bto\s+every\b|\brm\s+-rf\b",
    re.IGNORECASE,
)


def quarantine_reason(value) -> str:
    """Return a reason string if `value` looks like an agent-directed injection, else None."""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False)
        except Exception:
            text = str(value)
            
    # Structural Deterministic Guard
    if _QUARANTINE_PATTERNS.search(text):
        return "agent-directed imperative pattern in value"
        
    return None


_NEUTRALIZED = "[quarantined:injection-pattern]"


def neutralize(text) -> tuple:
    """Faz-3: replace agent-directed injection spans in UNTRUSTED FREE-TEXT with a placeholder,
    so a tool-authorized reasoning step (agent bridge harness) never reads a verbatim imperative
    that came out of the vault. Deterministic (same structural pattern as quarantine_reason),
    NOT model-judgment. Returns (clean_text, hit_count).

    Turkce not: bu, EYLEM kapisi DEGILDIR -- gate zaten her yetkili eylemi deterministik keser.
    Bu adim yalniz CEVAP-butunlugunu korur: vault'tan gelen enjeksiyon-kalibi metin, ozetleyen
    modele KELIMESI KELIMESINE ulasmaz. Durust kalinti/tradeoff: kalip muhafazakar oldugu icin
    kullanicinin KENDI notundaki mesru "you must ..." gibi ifadeler de maskelenebilir (asiri-
    cevreleme) -> modelin cevabi baglamdan biraz yoksun kalabilir; ama hicbir yetkili eylem bundan
    etkilenmez. Depoda saklanan veri DEGISMEZ; yalniz modele-beslenen kopya notrlenir."""
    if not isinstance(text, str):
        text = str(text)
    hits = 0

    def _sub(_m):
        nonlocal hits
        hits += 1
        return _NEUTRALIZED

    return _QUARANTINE_PATTERNS.sub(_sub, text), hits
