# KASA Guvenlik Katmani — Tehdit Modeli (THREAT_MODEL v1)

## AMAC & KAPSAM:
KASA = local-first sifreli hafiza kasasi + MCP server + gizlilik-tarayicisi + yerel modeller.  
Bu belge guvenlik-katmani projesinin (L0–L4) dusman tanimidir; tum kontroller buradan gerekcelenir.

## DORT DUSMAN SINIFI:

### A) Ayni-kullanici yerel malware:
#### Yetenekleri:
Kullanicinin kendi OS oturumunda calisan kotu yazilim. DPAPI'yi cagirabilir (ayni kullanici baglami oldugu icin).
#### Hedefi:
KASA'nin verilerine erismek.
#### KASA'nin Savunmasi:
Savunma sinirlidir; bu bilincli bir REZIDUEL risktir, gizlenmez.

### B) Diger OS hesaplari:
#### Yetenekleri:
Ayni makinedeki baska kullanicilar.
#### Hedefi:
KASA'nin verilerine erismek.
#### KASA'nin Savunmasi:
Owner-only ACL + DPAPI (anahtar makine+kullaniciya bagli) onlari durdurur.

### C) Bulut-sync / OneDrive:
#### Yetenekleri:
Kasa.db bulut klasorundeyse duz metin kopyalanir.
#### Hedefi:
KASA'nin verilerinin disarida acilmasini saglamak.
#### KASA'nin Savunmasi:
At-rest sifreleme (L2) bunu kapatir: DPAPI anahtari makine+kullaniciya bagli oldugundan bulut kopya baska yerde ACILAMAZ.

### D) Sayfa enjeksiyonu / kotu web icerigi:
#### Yetenekleri:
Tarayiciya enjekte olan JS, fingerprint sizintisi, veri/komut karismasi.
#### Hedefi:
KASA'nin verilerine erismek veya manipule etmek.
#### KASA'nin Savunmasi:
Savunma: fingerprint tutarliligi (L3 B1/B4) + veri-komut ayrimi.

## REZIDUEL RISKLER:
- Ayni-kullanici malware DPAPI'yi cagirabilir (dusman A ile ortusen bilincli sinir).
- Bellekteki duz metin swap/hibernate ile pagefile'a dusebilir — Python'da pratik mitigasyon yok.
- profile.provenance (event-ID referanslari) L2'de plaintext kalir → hangi olaylardan turedigi gorulebilir (linkage sizintisi); dusuk hassasiyet + sicak-yol maliyeti gerekcesiyle kabul.
- Sorgulanan metadata kolonlari (profile.key, events.ttl_expiry/distilled/source, audit.timestamp/agent_id/action/*_hash, permissions.*) L2'de plaintext kalir — sorgu/indeks/ hash-zinciri bunlara bagli; bilincli sinir.
- ~~(L1 tasarim notu) `agent_id` hala client-asserted~~ — **KAPANDI 2026-08-05.** Adi konan kalici cozum (per-agent token / token->agent_id baglama) kuruldu: kimlik `agent_tokens` uzerinden token'dan cozuluyor, govdedeki beyan yalnizca iddia, celisirse 403. Gercek sunucuya karsi 7/7 kontrol, pozitif ve negatif (`_orch/redteam/fimp_live_verify.py`). **Kalan reziduel bu satirin ustundeki A-sinifiyla ayni:** kimlik token'a baglidir, dolayisiyla vault dosyasini okuyabilen ayni-kullanici malware token uretebilir — yani bu, ayri bir aciklik degil, DPAPI satiriyla ayni bilincli sinirin bir baska yuzudur.

## L2 AT-REST KARARI OZETI:
Neden hibrit app-layer AES-GCM, neden SQLCipher DEGIL: bu makinede SQLCipher wheel yok + C derleyici yok (infeasible) ve ampirik olarak gereksiz (icerik kolonunda tek yapisal filtre forget()'in soguk-yol LIKE'i). Sifrelenen kolonlar: profile.value, events.content, audit.details. forget() decrypt-scan'e, audit encrypt-then-hash'e yeniden tasarlanir.

## SQLCIPHER TRIPWIRE:
Ileride herhangi bir sorgu content kolonu uzerinde WHERE/LIKE/FTS gerektirirse, app-layer karari yeniden acilir (SQLCipher veya blind-index masaya doner). Karar kapali, kapi isaretli.

## DPAPI TASINABILIRLIK:
DPAPI Windows-only. Anahtar temini KeyProvider dikisi arkasinda; macOS portunda Keychain provider gerekir (simdi yazilmaz, YAGNI).

## ILKE: "SIFRELEMEDEN ONCE SORGUYU LISTELE":
Bir kolonu sifrelemek depolama degil erisim-deseni karardir; kolona dokunan HER SQL ifadesi (WHERE/LIKE/JOIN/ORDER/hash-zinciri/audit-log) once listelenmeli. Bu ilke, forget() ve audit yan-kanalinin nasil kacirildiginin dersidir.

## KAPSAM DISI:
Ag MITM, fiziksel erisim, Guardian G1 action-layer (asagi-akis).

---
<!-- Uretim damgasi (seffaflik): prose'u YEREL modeller yazdi (sifir-token) —
     deepseek-coder-v2:16b taslak (99s) -> qwen2.5-coder:14b inceleme (250s);
     faktuel iskelet ve denetim Controller (opus), koda karsi dogrulandi
     (tools.py:159 forget LIKE, encrypt kolonlari, olu DPAPI _db_key). Tarih: 2026-07-09. -->

