# kasa/tests/test_config_roundtrip.py

"""`kasa.toml` yazılıp geri okunabilmeli — özellikle **boolean** değerler.

Türkçe not (2026-08-20, ölçülmüş ve gerçekten yaşanmış arıza):

`src/config.py` `_write_toml()` bir değeri `isinstance(value, int)` ile
sınıyordu. Python'da **`bool`, `int`'in alt sınıfıdır**; bu yüzden `False`
o dala düşüyor ve dosyaya **`require_semantic_validation = False`** olarak
yazılıyordu. TOML `true`/`false` ister; `False` **geçersiz TOML**'dur.

Zincir ölçüldü (RAN-LIVE, 2026-08-20):

1. `kasa.toml.example` `require_semantic_validation = false` içeriyor —
   yani yeni kullanıcının kopyaladığı dosyada bir boolean **var**.
2. İlk çalıştırmada `get_or_create_bearer_token()` üretilen token'ı kalıcı
   kılmak için config'i **geri yazıyor** (`src/config.py:173 _write_toml`).
3. Geri yazma sırasında `false` → `False` oluyor.
4. **İkinci çalıştırma** `tomllib.TOMLDecodeError: Invalid value` ile
   çöküyor. Sunucu hiç açılmıyor.

Sahibin kendi `kasa.toml`'unda boolean **yok** — bu yüzden onun makinesinde
hiç patlamadı. Yani arıza yalnız **yeni kullanıcıyı** vuruyordu: örnek
dosyayı kopyala, bir kez çalıştır, ikinci sefer açılmaz.

Ölçüm sırasında bir hipotez de **çürütüldü** ve buraya yazıldı: okuma tarafının
`false`'ı truthy bir *string* olarak döndürdüğünden şüphelenmiştim. Ölçüldü —
`_load_toml` `tomllib` kullanıyor ve gerçek `bool` döndürüyor (`False`,
`bool()` → `False`). Okuma tarafı **sağlam**; kırık olan yalnız yazmaydı.
"""

from __future__ import annotations

import os
import sys

import pytest

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

from src.config import _write_toml, _load_toml  # noqa: E402

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None


# ----------------------------------------------------------------------
# 1. GİDİŞ-DÖNÜŞ — yazılan geri okunabilmeli
# ----------------------------------------------------------------------
@pytest.mark.parametrize("value", [True, False])
def test_boolean_survives_write_then_read(tmp_path, value):
    """POZITIF+NEGATIF: her iki boolean da tipini koruyarak dönmeli."""
    p = tmp_path / "kasa.toml"
    _write_toml({"vault": {"require_semantic_validation": value}}, p)

    back = _load_toml(p)["vault"]["require_semantic_validation"]
    assert isinstance(back, bool), (
        "boolean tipini kaybetti: %r (%s). Yazilan dosya:\n%s"
        % (back, type(back).__name__, p.read_text(encoding="utf-8")))
    assert back is value


@pytest.mark.skipif(tomllib is None, reason="tomllib gerekli (py3.11+)")
@pytest.mark.parametrize("value", [True, False])
def test_written_file_is_valid_toml(tmp_path, value):
    """
    Yazılan dosya **gerçek** bir TOML ayrıştırıcısından geçmeli.

    Gidiş-dönüş testi tek başına yetmez: iki taraf da aynı gevşek
    ayrıştırıcıyı kullanıyorsa aynı yanlış varsayımı paylaşır ve yeşil olur
    (D24 eki 2). Bu test bilerek **dışarıdan** bir ayrıştırıcıya sorar.
    """
    p = tmp_path / "kasa.toml"
    _write_toml({"vault": {"require_semantic_validation": value}}, p)
    with open(p, "rb") as fh:
        tomllib.load(fh)   # gecersiz TOML ise burada patlar


def test_integers_and_strings_still_round_trip(tmp_path):
    """Düzeltme başka tipleri bozmamalı."""
    p = tmp_path / "kasa.toml"
    _write_toml({"server": {"port": 8791, "host": "127.0.0.1",
                            "allowed_origins": ["http://localhost"]}}, p)
    back = _load_toml(p)["server"]
    assert back["port"] == 8791 and isinstance(back["port"], int)
    assert back["host"] == "127.0.0.1"
    assert back["allowed_origins"] == ["http://localhost"]


# ----------------------------------------------------------------------
# 2. GERÇEK DOSYA — örnek config'in kendisi bu yoldan geçiyor
# ----------------------------------------------------------------------
@pytest.mark.skipif(tomllib is None, reason="tomllib gerekli (py3.11+)")
def test_example_config_survives_a_rewrite(tmp_path):
    """
    `kasa.toml.example` kopyalanıp bir kez geri yazıldığında hâlâ okunabilmeli.

    Bu, yeni kullanıcının gerçek yolu: örneği kopyala → ilk çalıştırma token'ı
    yazar → ikinci çalıştırma dosyayı okur. Sentetik bir sözlük değil, **depoda
    duran dosya** kullanılır; çünkü kırılan tam olarak o dosyaydı.
    """
    src = os.path.join(_KASA_ROOT, "kasa.toml.example")
    with open(src, "rb") as fh:
        cfg = tomllib.load(fh)
    assert isinstance(cfg["vault"]["require_semantic_validation"], bool), (
        "ornek config artik boolean icermiyor — bu test bir seyi olcmuyor olabilir")

    p = tmp_path / "kasa.toml"
    _write_toml(cfg, p)
    with open(p, "rb") as fh:
        again = tomllib.load(fh)
    assert again["vault"]["require_semantic_validation"] == \
        cfg["vault"]["require_semantic_validation"]
