# kasa/src/vault/decay.py

"""
Faz 3 - Asenkron Çürüme (Decay) Mekanizması: KORTEX Destekli Uyumsuzluk Taraması
Bu script, KASA'nın profile tablosundaki bilgileri tarar ve aralarındaki
mantıksal çelişkileri (F-POISON, yani sonradan enjekte edilen yalan bilgileri)
LLM (KORTEX Hakem) yardımıyla tespit eder.

Tespit edilen çelişkili veya manipülatif verilerin 'weight' (güven) skoru düşürülür.
Ağırlığı 0'a düşen veriler ölü (dead) kabul edilir.
"""

import sqlite3
import os
import json
import urllib.request
import time
import logging

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "kasa_decay.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def check_contradiction(fact_a: str, fact_b: str) -> bool:
    """
    KORTEX Yargıcı: İki profil verisi arasında bir çelişki olup olmadığını sorar.
    Örnek: "Kullanıcı çay sever" vs "Kullanıcı sadece kahve içer, çaydan nefret eder".
    """
    prompt = f"Analyze these two statements. Do they logically contradict each other? Reply ONLY with 'CONTRADICTION' or 'SAFE'.\n\nStatement A: {fact_a}\nStatement B: {fact_b}"
    
    payload = {
        "model": "qwen2.5:7b",
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 10}
    }
    
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
            if "CONTRADICTION" in result.get("response", "").upper():
                return True
    except Exception as e:
        logging.error(f"[KORTEX DECAY] LLM bağlantı hatası: {e}")
    return False

def run_decay_scan(db_path: str):
    """
    Veritabanındaki profilleri tarar, çelişkili olanları bulur ve weight (güven) 
    skorlarını %50 oranında düşürür (Decay).
    """
    logging.info("[KORTEX DECAY] Çürüme taraması başlatıldı.")
    if not os.path.exists(db_path):
        logging.error(f"Veritabanı bulunamadı: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Weight kolonu migration ile gelmediyse güvenli ekle
    try:
        cursor.execute("ALTER TABLE profile ADD COLUMN weight REAL DEFAULT 1.0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    cursor.execute("SELECT id, key, value, weight FROM profile WHERE weight > 0")
    profiles = cursor.fetchall()

    decay_applied = 0

    # Basit N^2 karşılaştırma (gerçek sistemlerde embedding / RAG ile yapılır)
    for i in range(len(profiles)):
        for j in range(i + 1, len(profiles)):
            p1 = profiles[i]
            p2 = profiles[j]
            
            # Yalnızca aynı üst key grubunda olanları (örn: user.preferences) karşılaştır
            # Optimizasyon için
            prefix1 = p1['key'].split('.')[1] if len(p1['key'].split('.')) > 1 else ""
            prefix2 = p2['key'].split('.')[1] if len(p2['key'].split('.')) > 1 else ""
            
            if prefix1 == prefix2 and prefix1:
                is_contradiction = check_contradiction(p1['value'], p2['value'])
                if is_contradiction:
                    logging.warning(f"[KORTEX DECAY] Çelişki tespit edildi! ID1={p1['id']} ID2={p2['id']}")
                    
                    # Güven skorlarını yarıya indir (Asenkron Çürüme)
                    new_w1 = p1['weight'] * 0.5
                    new_w2 = p2['weight'] * 0.5
                    
                    cursor.execute("UPDATE profile SET weight = ? WHERE id = ?", (new_w1, p1['id']))
                    cursor.execute("UPDATE profile SET weight = ? WHERE id = ?", (new_w2, p2['id']))
                    decay_applied += 2

    conn.commit()
    conn.close()
    logging.info(f"[KORTEX DECAY] Tarama bitti. Çürütülen fakt sayısı: {decay_applied}")

if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "kasa.db")
    run_decay_scan(db_path)
