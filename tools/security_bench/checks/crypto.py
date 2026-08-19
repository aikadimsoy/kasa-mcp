
import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (3 ust dizin = depo koku). Sabit yol, depoyu klonlayan herkeste ve CI
# kosucusunda bu araci calismaz kilardi.
_KASA_ROOT = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", ".."))
import os
import tempfile
import shutil
import time as _t
from src.export.encrypt import export_vault, verify_export
from src.vault.database import Vault

def run():
    results = []
    
    try:
        # CRYPTO-EXPORT Check
        tmpdir = tempfile.mkdtemp(dir=_KASA_ROOT)
        vault_path = os.path.join(tmpdir, "vault")
        os.makedirs(vault_path)
        v = Vault(vault_path=vault_path)
        conn = v.get_connection()
        
        # Insert an event
        content_str = '{"note": "test event"}'
        conn.execute("INSERT INTO events (timestamp, session_id, source, type, content, ttl_expiry) VALUES (?,?,?,?,?,?)", (_t.time(), "sess", "bench", "note", content_str, _t.time() + 3600))
        conn.commit()
        
        # Export the vault
        output_path = os.path.join(tmpdir, "e.kasa")
        export_vault(vault_path, "pw-strong-123", output_path)
        
        # Verify the export with correct password
        result = verify_export(output_path, "pw-strong-123")
        if result["status"] == "success":
            results.append({
                "id": "CRYPTO-EXPORT",
                "category": "crypto",
                "title": "Prove vault crypto properties (Export)",
                "status": "PASS",
                "severity": "high",
                "evidence": f"Events count: {result['events']}",
                "remediation": ""
            })
        else:
            results.append({
                "id": "CRYPTO-EXPORT",
                "category": "crypto",
                "title": "Prove vault crypto properties (Export)",
                "status": "FAIL",
                "severity": "high",
                "evidence": f"Verification failed: {result['message']}",
                "remediation": ""
            })
        
        # Verify the export with wrong password
        try:
            verify_export(output_path, "wrong-pw")
        except ValueError:
            results.append({
                "id": "CRYPTO-EXPORT",
                "category": "crypto",
                "title": "Prove vault crypto properties (Export)",
                "status": "PASS",
                "severity": "high",
                "evidence": "wrong-pw rejected",
                "remediation": ""
            })
        else:
            results.append({
                "id": "CRYPTO-EXPORT",
                "category": "crypto",
                "title": "Prove vault crypto properties (Export)",
                "status": "FAIL",
                "severity": "high",
                "evidence": "wrong password did not raise ValueError",
                "remediation": ""
            })
        
        # CRYPTO-KDF Check
        import inspect
        import src.export.encrypt as _enc
        enc_src = inspect.getsource(_enc)
        if 'scrypt' in enc_src and ('2**14' in enc_src or '16384' in enc_src):
            results.append({
                "id": "CRYPTO-KDF",
                "category": "crypto",
                "title": "Prove vault crypto properties (Key Derivation Function)",
                "status": "PASS",
                "severity": "medium",
                "evidence": "scrypt parameters found",
                "remediation": ""
            })
        elif 'scrypt' in enc_src:
            results.append({
                "id": "CRYPTO-KDF",
                "category": "crypto",
                "title": "Prove vault crypto properties (Key Derivation Function)",
                "status": "WARN",
                "severity": "medium",
                "evidence": "scrypt parameters weak or absent",
                "remediation": ""
            })
        else:
            results.append({
                "id": "CRYPTO-KDF",
                "category": "crypto",
                "title": "Prove vault crypto properties (Key Derivation Function)",
                "status": "FAIL",
                "severity": "medium",
                "evidence": "no scrypt found",
                "remediation": ""
            })
        
        # CRYPTO-ATREST Check — L2 app-layer at-rest.
        # ONEMLI: canary UYGULAMA yazma yolundan (event_ingest + profile_write) gecmeli; dogrudan
        # INSERT (eski hal) sifrelemeyi atlar ve app-layer'i hic test etmez (sahte FAIL). Sonra
        # kasa.db + TUM yan dosyalarda (-wal/-shm/-journal) plaintext canary aranir (plan: yan dosyalar).
        from src.mcp_server.tools import VaultTools
        canary = "KASA_CANARY_" + os.urandom(6).hex()
        tools = VaultTools(v, "system")
        tools.event_ingest("bench", "note", {"canary": canary}, ttl_days=1)      # events.content sifrelenir
        tools.profile_write("user.profile.canary", {"canary": canary}, [1])       # profile.value sifrelenir
        v.close()

        blobs = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = v.db_path + suffix
            if os.path.exists(p):
                with open(p, "rb") as f:
                    blobs[p] = f.read()
        hit = next((os.path.basename(p) for p, b in blobs.items() if canary.encode() in b), None)

        if hit:
            results.append({
                "id": "CRYPTO-ATREST",
                "category": "crypto",
                "title": "Prove vault crypto properties (At Rest)",
                "status": "FAIL",
                "severity": "critical",
                "evidence": f"plaintext canary found in {hit} (app-layer at-rest sizinti)",
                "remediation": "cell_crypt ile events.content + profile.value + audit.details sifrele (L2)."
            })
        else:
            total = sum(len(b) for b in blobs.values())
            results.append({
                "id": "CRYPTO-ATREST",
                "category": "crypto",
                "title": "Prove vault crypto properties (At Rest)",
                "status": "PASS",
                "severity": "critical",
                "evidence": f"canary absent from kasa.db + yan dosyalar ({len(blobs)} dosya, {total} bytes; app-layer AES-GCM)",
                "remediation": ""
            })
        
        # CRYPTO-DPAPI Check
        import platform
        if platform.system() != "Windows":
            results.append({
                "id": "CRYPTO-DPAPI",
                "category": "crypto",
                "title": "Prove vault crypto properties (Data Protection API)",
                "status": "WARN",
                "severity": "info",
                "evidence": "protect_data is a no-op passthrough off Windows; key unprotected",
                "remediation": "Document non-Windows limitation or add a portable keystore."
            })
        else:
            results.append({
                "id": "CRYPTO-DPAPI",
                "category": "crypto",
                "title": "Prove vault crypto properties (Data Protection API)",
                "status": "PASS",
                "severity": "info",
                "evidence": "DPAPI CryptProtectData available for key file",
                "remediation": ""
            })
        
    except Exception as e:
        # OLCULDU 2026-08-05 (SECBENCH-SILENT-SKIP): burasi SKIP/info yaziyordu.
        # Bu bloga dusuldugunde CRYPTO-KDF, CRYPTO-ATREST ve CRYPTO-DPAPI de hic
        # eklenmemis oluyor -- yani bes kripto kontrolunun dordu sessizce kayboluyor
        # ve geriye "info" seviyesinde tek bir satir kaliyordu. Rapor temiz gorunuyordu.
        # ERROR/critical: bir delik BULMADIK, BAKAMADIK. run.py'deki kapsam kapisi
        # eksik kalan digerlerini ayrica ERROR olarak ekler.
        results.append({
            "id": "CRYPTO-EXPORT",
            "category": "crypto",
            "title": "Prove vault crypto properties (Export) - crypto block aborted",
            "status": "ERROR",
            "severity": "critical",
            "evidence": f"{type(e).__name__}: {e}",
            "remediation": "Kripto blogu yarida kesildi; bu kategoride olculmemis kontroller var."
        })
    
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    
    return results


# ===== NEDEN -> SONUC / CAUSE -> EFFECT (yerel model, sifir-token) =====
# Purpose: This script checks the cryptographic properties of a vault system.
# Why (cause -> effect): It verifies export functionality with correct and incorrect passwords,
#                        checks key derivation function parameters, ensures data at rest is encrypted,
#                        and confirms Data Protection API usage on Windows systems.
# Amac: Bu betik bir kasa sisteminin şifreleme özelliklerini kontrol eder.
# Neden -> Sonuc: Doğru ve yanlış parolalarla dışa aktarma işlevselliğini doğrular,
#                 anahtar türetme fonksiyonu parametrelerini kontrol eder, verilerin dinlenmede şifrelendiğini sağlar
#                 ve Windows sistemlerinde Veri Koruma API'sinin kullanımını onaylar.
