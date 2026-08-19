# kasa/src/desktop/consent.py

"""
Kullanim sartlari (Terms of Use) kabul kaydi.

Kabul, KASA veri dizininde (`<DATA_DIR>/acceptance.json`) saklanir. DATA_DIR, launch.py'nin
hazirladigi KASA_CONFIG'in bulundugu dizindir (%APPDATA%\\KASA veya dev override). Boylece
launch.py (baslangic-URL karari) ve server (kabul ucu) AYNI dosyaya bakar.

Surum takibi: sartlar guncellenirse TERMS_VERSION artar -> eski kabul gecersiz sayilir, kullaniciya
yeni sartlar tekrar gosterilir. Bu bir hukuki/politika siniridir; iceriginde sir yoktur (redact
gerekmez), yalniz kabul-durumu tutulur.
"""

from __future__ import annotations

import json
import os
import pathlib
import time

# Kullanim sartlarinin gecerli surumu. TERMS_OF_USE.md ile ESLESMELI (surum satiri).
TERMS_VERSION = "1.0"


def _data_dir() -> pathlib.Path:
    """Kabul dosyasinin bulunacagi kalici veri dizini (launch.py ile ayni kaynak)."""
    cfg = os.environ.get("KASA_CONFIG")
    if cfg:
        return pathlib.Path(cfg).resolve().parent
    base = os.environ.get("KASA_HOME") or os.path.join(
        os.environ.get("APPDATA") or str(pathlib.Path.home()), "KASA")
    return pathlib.Path(base)


def acceptance_path() -> pathlib.Path:
    return _data_dir() / "acceptance.json"


def is_accepted(version: str = TERMS_VERSION) -> bool:
    """Kullanici GECERLI surumun sartlarini kabul etti mi?"""
    path = acceptance_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return False
    return bool(data.get("accepted")) and str(data.get("version")) == str(version)


def record_acceptance(version: str = TERMS_VERSION) -> dict:
    """Kabulu diske yazar (atomik: gecici dosya + replace). Kayit dict'ini dondurur."""
    path = acceptance_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "accepted": True,
        "version": str(version),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    return record


def status(version: str = TERMS_VERSION) -> dict:
    """API icin durum ozeti (ham dosya icerigi degil)."""
    return {"accepted": is_accepted(version), "version": str(version)}
