import sys
import os
from pathlib import Path

# sys.path import'lardan ÖNCE ayarlanmalı
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
import threading
import time
import uvicorn

from src.vault.database import Vault
from src.vault.schema import ALL_TABLES, ALL_INDEXES
from src.distill.scheduler import DistillScheduler

OLLAMA_URL = "http://localhost:11434/api/generate"


def parse_args():
    parser = argparse.ArgumentParser(description="Project KASA — Lokal Hafıza Kasası")
    sub = parser.add_subparsers(dest="command")

    # kasa export
    exp = sub.add_parser("export", help="Vault'u şifreli .kasa dosyasına aktar")
    exp.add_argument("--output", required=True, help="Çıktı dosyası (.kasa)")
    exp.add_argument("--vault-path", type=str, default=None, help="Vault dizini")
    exp.add_argument("--verify", action="store_true", help="Dosyayı şifrele ve hemen doğrula")

    # Kök argümanlar (sunucu modu)
    parser.add_argument('--vault-path', type=str, default='d:/kasa', help='Vault dizin yolu')
    parser.add_argument('--mcp-port', type=int, default=8000, help='MCP sunucu portu')
    parser.add_argument('--no-tray', action='store_true', help='Tray olmadan headless mod')
    parser.add_argument('--distill-now', action='store_true', help='Hemen damıt ve çık')
    return parser.parse_args()


def _run_export(args):
    """Şifreli export alt komutu."""
    import getpass
    from src.export.encrypt import export_vault, verify_export
    from src.config import load_config

    vault_path = args.vault_path
    if not vault_path:
        cfg = load_config(Path(__file__).parent / "kasa.toml")
        vault_path = os.path.expanduser(cfg["vault"]["path"])

    password = getpass.getpass("Şifreleme parolası: ")
    if not password:
        print("[KASA] Parola boş olamaz.")
        sys.exit(1)

    print(f"[KASA] Şifreleniyor: {vault_path} → {args.output}")
    result = export_vault(vault_path, password, args.output)
    print(f"[KASA] Tamamlandı — events: {result['events']}, profile: {result['profile']}")
    print(f"[KASA] Dosya: {result['path']}")

    if args.verify:
        v = verify_export(args.output, password)
        print(f"[KASA] Doğrulama OK — sürüm: {v['version']}, events: {v['events']}, profile: {v['profile']}")


def main():
    args = parse_args()

    # Egress kalkanını devreye al (L2)
    try:
        from src.vault.egress_guard import enable_egress_guard
        enable_egress_guard()
    except ImportError:
        pass

    # Export alt komutu
    if args.command == "export":
        _run_export(args)
        sys.exit(0)

    # Vault başlat ve şemayı kur
    os.environ.setdefault("KASA_VAULT_PATH", args.vault_path)
    vault = Vault(args.vault_path)
    vault.connect()
    conn = vault.get_connection()
    for sql in ALL_TABLES + ALL_INDEXES:
        conn.execute(sql)
    conn.commit()

    # MCP sunucusunu daemon thread'de başlat (ana thread'i bloklamaz)
    from src.mcp_server.server import app as mcp_app
    mcp_thread = threading.Thread(
        target=uvicorn.run,
        kwargs={"app": mcp_app, "host": "127.0.0.1", "port": args.mcp_port,
                "log_level": "warning"},
        daemon=True,
        name="MCPServer"
    )
    mcp_thread.start()

    # Sunucunun ayağa kalkması için kısa bekleme
    time.sleep(1)

    # Damıtma zamanlayıcısını başlat (kendi daemon thread'ini kendi yaratır)
    scheduler = DistillScheduler(
        db_path=str(Path(args.vault_path) / "kasa.db"),
        ollama_url=OLLAMA_URL
    )
    scheduler.start()

    # --distill-now: hemen çalıştır ve çık
    if args.distill_now:
        result = scheduler.run_now()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        vault.close()
        sys.exit(0)

    # --no-tray: tray olmadan çalış (sinyal gelene kadar bekle)
    if args.no_tray:
        print(f"[KASA] Headless mod — MCP: http://127.0.0.1:{args.mcp_port}")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        vault.close()
        sys.exit(0)

    # Tray uygulamasını başlat (Qt main thread'de çalışmalı)
    from PyQt5.QtWidgets import QApplication
    from src.tray.app import KasaTrayApp
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # Tray uygulaması pencere kapansa da devam eder
    tray = KasaTrayApp()
    print(f"[KASA] Başlatıldı — MCP: http://127.0.0.1:{args.mcp_port}")
    exit_code = app.exec_()
    vault.close()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

