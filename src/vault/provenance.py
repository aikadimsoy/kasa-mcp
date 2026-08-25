# kasa/src/vault/provenance.py

"""
Matematiksel Veri Kökeni ve Güven Bozunumu Modülü (Data Provenance & Trust Decay).

Felsefi Prensip:
"Veri doğru veya yanlış değildir; bir kökene (Provenance) ve zamansal güven katsayısına sahiptir."

Matematiksel Model:
T(t, source) = T_0(source) * exp(-lambda * delta_t) * (1 - Entropy_Penalty)

Burada:
- T_0(source): Başlangıç güven katsayısı (System: 1.0, User: 0.9, Tool: 0.8, Web: 0.3, Unknown: 0.1)
- lambda = ln(2) / Half_Life_Days (Zamansal yarılanma ömrü)
- delta_t: Verinin yazılmasından bu yana geçen gün sayısı
- Entropy_Penalty: Yüksek düzensizlik / karmaşıklık cezası
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Optional

from .quarantine import shannon_entropy

# Başlangıç Güven Katsayıları T_0
SOURCE_BASE_TRUST = {
    "system": 1.0,
    "owner": 1.0,
    "user": 0.9,
    "verified_tool": 0.8,
    "agent": 0.6,
    "distill_web": 0.3,
    "unknown_external": 0.1,
}

# Yarılanma Ömürleri (Gün Cinsinden)
SOURCE_HALF_LIFE_DAYS = {
    "system": 3650.0,      # 10 yıl (Kalıcı kural)
    "owner": 3650.0,       # 10 yıl
    "user": 365.0,         # 1 yıl
    "verified_tool": 90.0, # 3 ay
    "agent": 30.0,         # 1 ay
    "distill_web": 7.0,    # 7 gün (Hızlı bozunma)
    "unknown_external": 1.0# 1 gün
}


@dataclass(frozen=True)
class ProvenanceMetadata:
    source: str
    created_at: float
    base_trust: float
    current_trust: float
    age_days: float
    entropy: float
    is_high_trust: bool


def calculate_trust_score(
    source: str,
    created_at: float,
    content_sample: Optional[str] = None,
    current_time: Optional[float] = None,
) -> ProvenanceMetadata:
    """Verinin kökenine, yaşına ve entropisine göre dinamik güven skoru T(t) hesaplar."""
    now = current_time if current_time is not None else time.time()
    source_key = source.lower() if source else "unknown_external"

    base_t0 = SOURCE_BASE_TRUST.get(source_key, 0.2)
    half_life = SOURCE_HALF_LIFE_DAYS.get(source_key, 7.0)

    # 1. Yaş hesabı (Gün cinsinden)
    delta_seconds = max(0.0, now - created_at)
    delta_days = delta_seconds / 86400.0

    # 2. Üstel Bozunma (Exponential Decay): exp(-lambda * delta_t)
    decay_constant = math.log(2.0) / max(0.1, half_life)
    temporal_factor = math.exp(-decay_constant * delta_days)

    # 3. Entropi Düzensizlik Cezası
    entropy_val = 0.0
    entropy_multiplier = 1.0
    if content_sample:
        entropy_val = shannon_entropy(content_sample)
        # Doğal metin ~4.0; şüpheli karmaşık metin > 5.5
        if entropy_val > 5.5:
            penalty = min(0.5, (entropy_val - 5.5) * 0.25)
            entropy_multiplier = max(0.1, 1.0 - penalty)

    # Nihai Güven Skoru T(t) [0.0 - 1.0]
    final_trust = round(base_t0 * temporal_factor * entropy_multiplier, 4)
    is_high = final_trust >= 0.7

    return ProvenanceMetadata(
        source=source_key,
        created_at=created_at,
        base_trust=base_t0,
        current_trust=final_trust,
        age_days=round(delta_days, 2),
        entropy=round(entropy_val, 2),
        is_high_trust=is_high,
    )
