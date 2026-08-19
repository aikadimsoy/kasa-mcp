# kasa/src/desktop/launch.py

"""
KASA masaustu launcher — cift-tikla acilan native uygulama.

Mimari (Faz 0 spike ile ampirik kanitlandi, docs/EXE_PACKAGING_LOG.md):
  - ThreadedUvicorn (signal-handler'siz uvicorn.Server) yerel server'i ARKA-thread'de kosar (127.0.0.1).
  - pywebview penceresi (WebView2) ANA-thread'de /dashboard'u gosterir.
  - pystray tray (daemon-thread) Goster/Cikis verir.
Sifir ag: yalniz 127.0.0.1. Veri dizini %APPDATA%\\KASA (ilk acilis vault + DPAPI anahtari + config).

Not (guvenlik): server bearer korumali; pano token'i server-tarafi enjekte edilir (localhost owner UI).
"""

import os
import json
import socket
import sys
import threading
import time
import urllib.request
import pathlib
import webbrowser


def _prepare_env() -> pathlib.Path:
    """Kalici veri dizinini (%APPDATA%\\KASA) kur ve server env'ini ona yonlendir.
    setdefault: disaridan verilen KASA_CONFIG/KASA_VAULT_PATH korunur (dev/test override)."""
    base = os.environ.get("KASA_HOME") or os.path.join(
        os.environ.get("APPDATA") or str(pathlib.Path.home()), "KASA")
    data = pathlib.Path(base)
    (data / "vault").mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("KASA_CONFIG", str(data / "kasa.toml"))
    # Ayarlar > picker ile kaydedilmis vault yolu varsa varsayilan olarak onu kullan;
    # disaridan verilen KASA_VAULT_PATH (dev/test override) yine oncelikli kalir (setdefault).
    default_vault = str(data / "vault")
    settings_path = data / "settings.json"
    if settings_path.is_file():
        try:
            saved = json.loads(settings_path.read_text(encoding="utf-8")).get("vault_path")
            # SEBEP: vault_path DIZIN olmali (Vault.__init__ -> os.makedirs). Kayitli deger var
            # olan bir DOSYAYI gosteriyorsa makedirs FileExistsError atar ve bu, server import'unda
            # (modul seviyesi) patlar -> main() calismaz -> konsolsuz exe SESSIZCE acilmaz.
            # KARAR: dosyaysa yok say, varsayilana dus. Kullanilamaz ayar yuzunden uygulama
            # acilamaz hale GELMEZ (savunma-derinligi; picker._save zaten dizine cevirir).
            if saved and not pathlib.Path(saved).is_file():
                default_vault = saved
        except Exception:
            pass  # bozuk settings.json sessizce yok sayilir; varsayilan vault kullanilir
    os.environ.setdefault("KASA_VAULT_PATH", default_vault)
    return data


# Env, server import'undan ONCE hazirlanmali (server config'i import-zamani okur).
DATA_DIR = _prepare_env()

# Frozen/exe icin d:/kasa gelistirme yolu sys.path'te olmayabilir; kaynak-run icin ekle.
_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import uvicorn  # noqa: E402
from src.mcp_server import server as kasa_server  # noqa: E402


class ThreadedUvicorn(uvicorn.Server):
    """Arka-thread'de kosmak icin signal handler kurulumunu devre disi birakir."""
    def install_signal_handlers(self) -> None:
        pass


def _msgbox(text: str, title: str, flags: int) -> int:
    """Native Win32 mesaj kutusu (konsolsuz GUI exe'de de calisir). Hata olursa stderr'e duser."""
    try:
        import ctypes
        return int(ctypes.windll.user32.MessageBoxW(0, text, title, flags))
    except Exception:
        sys.stderr.write("%s: %s\n" % (title, text))
        return 0


def _preflight_gate() -> bool:
    """Eksik calisma-zamani bagimliliklarini kontrol eder.
    Kritik eksik (WebView2) varsa: kullaniciya sorar, resmi MS indirme baglantisini acar, False
    doner (pencere acilmaz — kurulumdan sonra tekrar acilir). Yalniz tavsiye-niteligi eksikse:
    bilgilendirir, baglantiyi acar, True doner (uygulama devam eder). Tumu varsa sessizce True."""
    from .preflight import missing_dependencies
    missing = missing_dependencies()
    if not missing:
        return True

    lines = "\n".join("- %s\n    %s" % (d.name, d.reason) for d in missing)
    critical = [d for d in missing if d.critical]
    MB_YESNO, MB_OK = 0x4, 0x0
    MB_ICONWARNING, MB_ICONINFO = 0x30, 0x40
    IDYES = 6

    if critical:
        body = ("KASA'nin calismasi icin asagidaki bilesen(ler) eksik:\n\n%s\n\n"
                "Resmi Microsoft indirme sayfalarini simdi acayim mi?" % lines)
        if _msgbox(body, "KASA - Eksik Bilesen", MB_YESNO | MB_ICONWARNING) == IDYES:
            for d in missing:
                webbrowser.open(d.url)
        return False

    body = ("Bilgi: asagidaki onerilen bilesen(ler) eksik olabilir:\n\n%s\n\n"
            "Resmi indirme baglantisi acilacak; kurulum onerilir." % lines)
    _msgbox(body, "KASA - Bilgi", MB_OK | MB_ICONINFO)
    for d in missing:
        webbrowser.open(d.url)
    return True


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_ready(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _start_tray(on_show, on_quit):
    """pystray tray'i daemon-thread'de baslatir. Basarisiz olursa sessizce atlanir
    (tray opsiyonel; pencere yine calisir)."""
    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception:
        return None

    img = Image.new("RGB", (64, 64), "#0D1017")
    d = ImageDraw.Draw(img)
    d.ellipse((18, 18, 46, 46), fill="#E02244")
    menu = pystray.Menu(
        pystray.MenuItem("KASA'yı Göster", lambda icon, item: on_show()),
        pystray.MenuItem("Çıkış", lambda icon, item: on_quit(icon)),
    )
    icon = pystray.Icon("kasa", img, "KASA — Egemen Hafıza", menu)
    threading.Thread(target=icon.run, daemon=True).start()
    return icon


def main() -> int:
    # 1) Bagimlilik on-kontrolu (WebView2 vb.). Kritik eksikse pencere acilamaz -> once cik.
    #    Selftest'te de calisir; bagimliliklar mevcutsa sessizce gecer (diyalog cikmaz).
    if not _preflight_gate():
        sys.stderr.write("KASA: gerekli bilesen(ler) eksik; kurulum sonrasi tekrar deneyin.\n")
        return 3

    port = int(os.environ.get("KASA_UI_PORT") or _free_port())

    config = uvicorn.Config(kasa_server.app, host="127.0.0.1", port=port, log_level="warning")
    server = ThreadedUvicorn(config)
    threading.Thread(target=server.run, daemon=True).start()

    if not _wait_ready(port):
        sys.stderr.write("KASA: yerel server baslatilamadi.\n")
        return 1

    import webview
    from .. import consent   # cekirdege tasindi: dashboard'un desktop'a bagli olmamasi icin
    from .picker import PickerApi

    # Ilk acilis: kullanim sartlari kabul edilmemisse once /terms goster; kabul sonrasi JS
    # /dashboard'a yonlendirir. Kabul edilmisse dogrudan panoya gir.
    start_path = "/dashboard" if consent.is_accepted() else "/terms"
    # F-DASH: owner token'i HTML'e ancak launch nonce'u tasiyan istekte gomulur. Nonce'u
    # sunucu modulu uretti (surec-basina); tarayiciyi onunla aciyoruz. Ag istemcisi bu
    # nonce'u bilemez -> tokensiz sayfa alir. terms.html kabul sonrasi redirect'i query'yi
    # korur (window.location.search), boylece /dashboard'a gecerken nonce kaybolmaz.
    _nonce = getattr(kasa_server, "_LAUNCH_NONCE", "")
    start_path = f"{start_path}?k={_nonce}"

    # Native dosya/klasor secici (Ayarlar). PickerApi window'u SAKLAMAZ (webview.active_window()
    # ile lazy eris) -> pywebview js_api serialize'i WebView2 native grafini taramaz (kararlilik).
    picker_api = PickerApi(DATA_DIR)

    window = webview.create_window(
        "KASA — Egemen Hafıza",
        f"http://127.0.0.1:{port}{start_path}",
        width=1200, height=820, min_size=(900, 600),
        js_api=picker_api,
    )

    def _quit(icon=None):
        try:
            if icon is not None:
                icon.stop()
        except Exception:
            pass
        try:
            window.destroy()
        except Exception:
            pass

    icon = _start_tray(on_show=lambda: window.show(), on_quit=_quit)

    # Self-test kancasi (CI/smoke): pencereyi otomatik kapatip 0 ile cikar.
    if os.environ.get("KASA_SELFTEST"):
        def _selftest():
            time.sleep(float(os.environ.get("KASA_SELFTEST", "4")))
            print("SELFTEST server_ready port=%d" % port, flush=True)
            _quit(icon)
        threading.Thread(target=_selftest, daemon=True).start()

    webview.start()   # ana-thread GUI dongusu; window.destroy() ile doner
    try:
        server.should_exit = True
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
