from pathlib import Path
import os
import secrets
import re

DEFAULT_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 8000,
        "bearer_token": "",
        "allowed_origins": ["http://localhost", "http://127.0.0.1"],
    },
    "vault": {
        "path": "~/.kasa/vault",
        "ttl_days": 30,
    },
    "distill": {
        "model": "qwen2.5:7b",
        "ollama_url": "http://localhost:11434",
        "schedule_hour": 2,
    },
}

try:
    import tomllib
    def _load_toml(path: Path) -> dict:
        with path.open("rb") as f:
            return tomllib.load(f)
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
        def _load_toml(path: Path) -> dict:
            with path.open("rb") as f:
                return tomllib.load(f)
    except ImportError:
        def _load_toml(path: Path) -> dict:  # type: ignore
            return _parse_toml_simple(path.read_text(encoding="utf-8"))


def _parse_toml_simple(text: str) -> dict:
    data: dict = {}
    section: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\[[\w.]+\]", line):
            section = line[1:-1]
            data.setdefault(section, {})
        elif "=" in line and section is not None:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().split("#")[0].strip()
            if val.startswith("[") and val.endswith("]"):
                inner = val[1:-1]
                data[section][key] = [
                    v.strip().strip('"').strip("'")
                    for v in inner.split(",") if v.strip()
                ]
            elif val.isdigit():
                data[section][key] = int(val)
            else:
                data[section][key] = val.strip('"').strip("'")
    return data


def _write_toml(data: dict, path: Path) -> None:
    lines = []
    for section, values in data.items():
        lines.append(f"[{section}]")
        for key, value in values.items():
            if isinstance(value, list):
                items = ", ".join(f'"{v}"' for v in value)
                lines.append(f'{key} = [{items}]')
            elif isinstance(value, bool):
                # Turkce not (2026-08-20, OLCULDU): bu dal `int` dalindan ONCE
                # gelmek ZORUNDA -- Python'da `bool`, `int`'in ALT SINIFIDIR,
                # yani `isinstance(False, int)` True'dur. Once int dali
                # kosuyordu ve dosyaya `False` yaziliyordu; TOML `false` ister
                # ve `False`u REDDEDER.
                # Yasanan zincir: kasa.toml.example `require_semantic_validation
                # = false` iceriyor -> ilk calistirmada uretilen bearer token'i
                # kalici kilmak icin config GERI YAZILIYOR (asagida satir ~173)
                # -> `false` `False` oluyor -> IKINCI calistirma
                # tomllib.TOMLDecodeError ile coquyor, sunucu hic acilmiyor.
                # Sahibin kendi kasa.toml'unda boolean YOK, o yuzden onun
                # makinesinde hic patlamadi; ariza yalniz YENI kullaniciyi
                # vuruyordu. Test: tests/test_config_roundtrip.py
                lines.append(f"{key} = {'true' if value else 'false'}")
            elif isinstance(value, (int, float)):
                lines.append(f"{key} = {value}")
            else:
                lines.append(f'{key} = "{value}"')
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _deep_merge(base: dict, override: dict) -> dict:
    result = {**base}
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def resolve_config_path() -> Path:
    """Tek dogruluk kaynagi: server ve adapter AYNI config dosyasini cozsun diye
    kullanilan ORTAK cozucu. Precedence (ChatGPT operator karari, 2026-08-21):
      1. KASA_CONFIG env acikca verilmisse -> onu kullan (test izolasyonu da bu)
      2. ~/.kasa/kasa.toml mevcutsa        -> onu kullan
      3. ./kasa.toml mevcutsa              -> kaynak/dev geriye uyumluluk
      4. hicbiri yoksa                     -> ~/.kasa/kasa.toml (olusturma hedefi)

    Turkce not (paketleme, 2026-08-21): server.py eskiden __file__ uzerinden
    repo_root/kasa.toml kuruyordu; wheel kurulunca bu site-packages/kasa.toml'a
    kayiyor ve (a) kullanici secret'i site-packages'a yaziliyor, (b) adapter
    load_config() ~/.kasa'ya bakip AYRI dosya cozuyordu -> "kurulum basarili ama
    MCP kirik". Ortak cozucu bu ikiligi kapatir; server'in urettigi owner token
    ile adapter'in aradigi token ayni dosyadan gelir. site-packages'a ASLA yazilmaz.
    """
    env = os.environ.get("KASA_CONFIG")
    if env:
        return Path(env)
    home_cfg = Path.home() / ".kasa" / "kasa.toml"
    if home_cfg.exists():
        return home_cfg
    local_cfg = Path("./kasa.toml")
    if local_cfg.exists():
        return local_cfg
    return home_cfg


def load_config(config_path: Path = None) -> dict:
    if config_path is None:
        config_path = resolve_config_path()

    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        _write_toml(DEFAULT_CONFIG, config_path)
        return dict(DEFAULT_CONFIG)

    loaded = _load_toml(config_path)
    return _deep_merge(DEFAULT_CONFIG, loaded)


def resolve_vault_path(config: dict = None) -> str:
    """Server ve owner CLI (kasa-admin) AYNI vault'u cozsun diye ORTAK cozucu
    (ChatGPT operator karari, 2026-08-21). Precedence:
      1. KASA_VAULT_PATH env (test/dev override)
      2. (verilmisse) gecirilen config, yoksa load_config() -> ["vault"]["path"]
    Sonuc expanduser'lanir.

    Turkce not: eski owner CLI (tools/grant_agent_scope.py) default vault olarak
    REPO KOKUNU seciyordu -> KASA_VAULT_PATH verilmezse sahibin gercek kasasi
    yerine repo kokune BASARIYLA izin yazardi. Yanlis kasaya sessizce yazmak,
    acikca hata vermekten daha tehlikeli. Bu cozucu server ile owner CLI'yi tek
    vault'a baglar; ikisi de bunu kullanir (invariant testte kilitli)."""
    env = os.environ.get("KASA_VAULT_PATH")
    if env:
        return os.path.expanduser(env)
    cfg = config if config is not None else load_config()
    return os.path.expanduser(cfg["vault"]["path"])


_DPAPI_PREFIX = "dpapi:"
# Bu onekli bearer_token degeri DPAPI ile korunmus (base64) demektir; oneksiz = legacy duz metin.


def _protect_token_value(token: str) -> str | None:
    """Token'i DPAPI ile koruyup TOML'da saklanabilir dizeye cevirir; olmazsa None.
    DPAPI yalniz Windows'ta gercek korur (encryption.protect_data Windows-disi gecislidir);
    basarisizsa cagiran taraf duz metne duser (gelistirme/Windows-disi ortam)."""
    try:
        import base64
        from .vault import encryption
        blob = encryption.protect_data(token.encode("utf-8"))
        return _DPAPI_PREFIX + base64.b64encode(blob).decode("ascii")
    except Exception:
        return None


def resolve_bearer_token(config: dict) -> str:
    """Return the USABLE plaintext bearer from config, or "" if there is none.

    Never mints and never writes. Unwraps a ``dpapi:`` value; passes a legacy plaintext
    value through; returns "" when absent or undecryptable (different user/machine/corrupt).

    Turkce not (2026-08-05, F-MCP-BEARER'in kok-neden fix'i): bu cozucu TEK olsun diye
    ayrildi. Onceden sunucu get_or_create_bearer_token() ile DUZ token'i aliyor, ama
    src/mcp_adapter/proxy.py bearer'i config'ten DOGRUDAN okuyordu -> DPAPI-SARMALI dizeyi
    gonderiyordu (390 karakter, "dpapi:" onekli). Sunucu 43 karakterlik duz token'i bekledigi
    icin karsilastirma HER ZAMAN basarisiz: canli olculdu, adaptorun her cagrisi
    HTTP 401 "Gecersiz token". Ayni sirri iki yerde iki farkli sekilde cozmek hatanin
    kendisiydi; artik tek giris noktasi burasi.
    """
    stored = config.get("server", {}).get("bearer_token", "")
    if stored.startswith(_DPAPI_PREFIX):
        try:
            import base64
            from .vault import encryption
            return encryption.unprotect_data(
                base64.b64decode(stored[len(_DPAPI_PREFIX):])).decode("utf-8")
        except Exception:
            return ""  # cozulemez -> cagiran taraf karar versin (uret / hata ver)
    return stored


def get_or_create_bearer_token(config: dict, config_path: Path) -> str:
    """Bearer token'i dondurur; YENI token uretilirse DPAPI-korumali saklanir (duz metin
    diske yazilmasin). Legacy duz-metin token geriye-uyum icin oldugu gibi okunur ve config
    SESSIZCE degistirilmez (sahibin izlenen kasa.toml'unu surpriz mutasyonla bozmayalim)."""
    stored = resolve_bearer_token(config)
    if stored:
        # Legacy DUZ METIN token: dokunma, oldugu gibi kullan (config'i mutasyona ugratma).
        return stored
    token = secrets.token_urlsafe(32)
    # Mumkunse DPAPI-korumali sakla; degilse (Windows-disi) duz metne dus.
    protected = _protect_token_value(token)
    config["server"]["bearer_token"] = protected if protected else token
    _write_toml(config, config_path)
    return token


write_toml = _write_toml
