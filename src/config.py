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
            elif isinstance(value, int):
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


def load_config(config_path: Path = None) -> dict:
    if config_path is None:
        env = os.environ.get("KASA_CONFIG")
        if env:
            config_path = Path(env)
        else:
            candidates = [
                Path.home() / ".kasa" / "kasa.toml",
                Path("./kasa.toml"),
            ]
            for p in candidates:
                if p.exists():
                    config_path = p
                    break

    if config_path is None or not config_path.exists():
        target = config_path or (Path.home() / ".kasa" / "kasa.toml")
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_toml(DEFAULT_CONFIG, target)
        return dict(DEFAULT_CONFIG)

    loaded = _load_toml(config_path)
    return _deep_merge(DEFAULT_CONFIG, loaded)


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
