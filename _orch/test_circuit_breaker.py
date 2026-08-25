# _orch/test_circuit_breaker.py
# -*- coding: utf-8 -*-

"""
KASA Circuit Breaker & Schema Length Enforcer Testi.

Bu betik şunları test eder:
1. Devasa boyutlu yüklerin (DoS payload) yapısal olarak KASA çekirdeğinde reddedilmesi.
2. Saniyede aşırı sayıda istek atan bir ajanın KASA tarafından kilitlenmesi (Hız Sınırı).
"""

import sys
import os
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vault.database import Vault
from src.mcp_server.tools import VaultTools
from src.vault.schema import ALL_TABLES, ALL_INDEXES

def test_circuit_breaker():
    test_db = f"test_cb_{os.getpid()}.sqlite"
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass
        
    vault = Vault(test_db)
    vault.connect()
    
    for sql in ALL_TABLES + ALL_INDEXES:
        vault.get_connection().execute(sql)
        
    vault.get_connection().execute("INSERT INTO permissions (agent_id, scope, granted_at) VALUES ('spam_agent', 'profile:write', 1000)")
    vault.get_connection().commit()
    
    tools = VaultTools(vault, agent_id="spam_agent")
    
    print("\n--- TEST 1: BOYUT SINIRI (DoS KALKANI) ---")
    huge_payload = "A" * 15000  # 15KB (KASA limit is 10KB)
    try:
        tools.profile_write(key="user.note", value=huge_payload, provenance=[1])
        print("❌ HATA: Dev yük kabul edildi! (DoS Başarılı)")
    except ValueError as e:
        print(f"✅ BAŞARILI: Boyut kalkanı çalıştı.\n  -> Hata Mesajı: {e}")

    print("\n--- TEST 2: HIZ SINIRI (CIRCUIT BREAKER) ---")
    # limit = 50 requests in 60 secs.
    successful_writes = 0
    spam_detected = False
    
    for i in range(1, 60):
        try:
            tools.profile_write(key=f"user.spam.{i}", value="junk data", provenance=[1])
            successful_writes += 1
            # print(f"Yazıldı: {i}")
        except PermissionError as e:
            spam_detected = True
            print(f"✅ BAŞARILI: Kalkan devreye girdi! {successful_writes} işlemden sonra sigorta attı.")
            print(f"  -> Hata Mesajı: {e}")
            break
            
    if not spam_detected:
        print(f"❌ HATA: {successful_writes} işlem yapıldı ama kalkan devreye girmedi!")

    vault.close()
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass

if __name__ == "__main__":
    test_circuit_breaker()
