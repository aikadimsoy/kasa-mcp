# kasa/src/distill/sensory_filter.py

"""
Sensory Filter (Duyusal Filtre):
Web tarayıcısından veya işletim sisteminden gelen devasa boyuttaki,
düşük seviyeli telemetri ve çerez (cookie) davranışlarını ana bilince (LLM'e)
gitmeden önce süzen, kural tabanlı bir ön-işlemcidir.

Amacı: "Sıfır bilgi kazancı" olan gürültüyü (noise) silmek ve
yalnızca potansiyel güvenlik riskleri veya belirgin insan davranışlarını
Kasa'ya (Vault) kaydetmektir.
"""

import json
import re

# Ana bilinci yormaması gereken gürültü kalıpları
NOISE_PATTERNS = [
    re.compile(r"cookie.*(tracking|analytics|pixel)", re.IGNORECASE),
    re.compile(r"scroll_\d+px", re.IGNORECASE),
    re.compile(r"mouse_move_.*", re.IGNORECASE),
    re.compile(r"(ads|metrics|telemetry)\.example\.com", re.IGNORECASE),
]

# Ana bilinci uyaracak kırmızı alarm kalıpları (Şüpheli davranışlar)
ALERT_PATTERNS = [
    re.compile(r"request_permission.*(camera|microphone|location)", re.IGNORECASE),
    re.compile(r"keylogger.*detected", re.IGNORECASE),
    re.compile(r"clipboard_read.*", re.IGNORECASE),
]

def process_telemetry(raw_event: dict) -> dict:
    """
    Ham bir web/telemetri olayını analiz eder.
    
    Returns:
        dict: Eğer veri gürültü ise {"status": "discarded"} döner.
              Eğer alarm ise {"status": "alert", "data": ...} döner.
              Eğer normal, saklanabilir bir davranışsa {"status": "keep", "data": ...} döner.
    """
    content = json.dumps(raw_event)
    
    # Kırmızı Alarmlar (Anında raporlanmalı)
    for pattern in ALERT_PATTERNS:
        if pattern.search(content):
            return {
                "status": "alert",
                "reason": f"Suspicious behavior matched pattern: {pattern.pattern}",
                "data": raw_event
            }
            
    # Gürültü (Diske veya modele gitmeden önce yok edilir)
    for pattern in NOISE_PATTERNS:
        if pattern.search(content):
            return {
                "status": "discarded",
                "reason": "Matched noise pattern"
            }
            
    # Eğer ne gürültü ne de alarmsa, normal veri olarak sakla
    return {
        "status": "keep",
        "data": raw_event
    }

if __name__ == '__main__':
    # Test
    test_noise = {"action": "cookie_set", "value": "tracking_id=123"}
    test_alert = {"action": "request_permission", "type": "camera"}
    test_normal = {"action": "user_clicked_buy", "item": "laptop"}
    
    print("Noise:", process_telemetry(test_noise))
    print("Alert:", process_telemetry(test_alert))
    print("Normal:", process_telemetry(test_normal))
