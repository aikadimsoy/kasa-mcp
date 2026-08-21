# build_kasa.ps1 — KASA.exe'yi Nuitka ile kaynak-korumali TEK DOSYA olarak derler.
#
# Neden Nuitka: Python -> C -> native makine kodu. OLCULEN sey sudur: src/*.py bundle'da YOK
# (asagidaki saglamalar bunu dogrular) — yani .pyc cikarip geri-derleme yolu kapali.
# DURUST SINIR: bu "geri-decompile EDILEMEZ" demek DEGILDIR. String sabitleri ve mantik izleri
# ikilide kalir, disassembly ile analiz edilebilir; %100 koruma mumkun degildir
# (bkz. docs/SOURCE_PROTECTION_NOTES.md §2 ve §5). Kaynak koruma burada bir FIKRI MULKIYET
# onlemidir, bir guvenlik siniri degil: Kerckhoffs geregi KASA'nin guvenligi zaten kaynak
# gizliligine dayanmaz (sir = DPAPI ile korunan vault anahtari, kod degil).
#
# Neden --onefile: tek cift-tik KASA.exe (yaninda 57 dosya tasimaz). Bootstrap kendini
# {CACHE_DIR}\KASA\{VERSION}'a acar (ilk acilis ~2sn, sonra sicak/aninda). dashboard_ui bu temp
# agacina gomulur; routes.py __compiled__.containing_dir ile orada bulur (onefile-saglam).
#
# HER ZAMAN Python 3.12 (3.14 pywebview'da segfault verir — docs/EXE_PACKAGING_LOG.md).
# Kullanim:  pwsh -File build_kasa.ps1   [-Standalone]  (klasor modu; hata ayiklamak icin)

param(
    [switch]$Standalone   # verilirse --onefile YERINE --standalone (57-dosya klasor; debug)
)

$ErrorActionPreference = "Stop"
$Root = "d:/kasa"
$Version = "0.1.0"

# --- Calisan KASA'yi durdur (yoksa Nuitka eski KASA.exe'yi degistiremez: WinError 5 kilit) ---
$running = Get-Process -Name KASA -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "[build] Calisan KASA.exe kapatiliyor ($($running.Count) surec)" -ForegroundColor Yellow
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 800
}

# --- Python 3.12 dogrula (segfault kalkani) ---
$pyv = (& py -3.12 -c "import sys;print('%d.%d'%sys.version_info[:2])") 2>$null
if ($pyv -ne "3.12") { throw "Python 3.12 gerekli (bulundu: '$pyv'). 3.14 pywebview'da segfault verir." }
Write-Host "[build] Python 3.12 OK" -ForegroundColor Green

if ($Standalone) {
    $ModeFlags = @("--standalone")
    $OutDir = "$Root/build_nuitka_312"
    Write-Host "[build] MOD: --standalone (klasor)" -ForegroundColor Yellow
} else {
    # Onefile: metadata + konsolsuz + ikon + onbellekli acilim dizini.
    $ModeFlags = @(
        "--onefile",
        "--windows-console-mode=disable",
        "--windows-icon-from-ico=$Root/assets/icon.ico",
        "--onefile-tempdir-spec={CACHE_DIR}\KASA\{VERSION}",
        "--company-name=KASA",
        "--product-name=KASA",
        "--product-version=$Version",
        "--file-version=$Version",
        "--file-description=KASA - Egemen Hafiza"
    )
    $OutDir = "$Root/build_nuitka_onefile"
    Write-Host "[build] MOD: --onefile (tek dosya, konsolsuz)" -ForegroundColor Green
}

# --- Kazanan recete (docs/EXE_PACKAGING_LOG.md) ---
# pywebview plugin'i pywebview 6.2.1'e gore eski (win32 modulunu disliyor ama winforms onu
# kosulsuz import ediyor) -> plugin'i kapat, gerekli backend'leri + clr'yi elle dahil et.
$Args = @(
    "-3.12", "-m", "nuitka"
) + $ModeFlags + @(
    "--assume-yes-for-downloads",
    "--nofollow-import-to=PyQt5,PyQt6,PySide2,PySide6,tkinter",
    "--disable-plugin=pywebview",
    "--include-module=webview.platforms.winforms",
    "--include-module=webview.platforms.win32",
    "--include-module=webview.platforms.edgechromium",
    "--include-module=webview.platforms.mshtml",
    "--include-module=clr",
    "--include-module=winreg",
    "--include-package=src.vault",
    "--include-package=src.mcp_server",
    "--include-package=src.dashboard",
    "--include-package=src.agent",
    "--include-package=src.desktop",
    "--include-module=src.config",
    # P1a (2026-08-21): dashboard UI kaynagi src/dashboard/ui/ altina tasindi (TEK kaynak,
    # wheel paket-verisi). Nuitka bundle'i ESKI beklenen dashboard_ui/ konumuna kopyalar ki
    # routes.py'nin Nuitka fallback'i (__compiled__.containing_dir/dashboard_ui) bulsun.
    # Boylece kaynak KOPYASI yok; yalniz runtime uyumluluk. (Kaynak/wheel yolunda
    # importlib.resources kullanilir; Nuitka'da bu fallback.)
    "--include-data-dir=$Root/src/dashboard/ui=dashboard_ui",
    "--include-data-dir=$Root/design_system=design_system",
    "--output-filename=KASA.exe",
    "--output-dir=$OutDir",
    "$Root/kasa_app.py"
)

Write-Host "[build] Nuitka baslatiliyor -> $OutDir/KASA.exe" -ForegroundColor Cyan
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& py @Args
if ($LASTEXITCODE -ne 0) { throw "Nuitka derleme HATASI (exit $LASTEXITCODE)" }
$sw.Stop()

$exe = if ($Standalone) { "$OutDir/kasa_app.dist/KASA.exe" } else { "$OutDir/KASA.exe" }
if (-not (Test-Path $exe)) { throw "Beklenen exe uretilmedi: $exe" }
$mb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "`n[build] TAMAM ($([math]::Round($sw.Elapsed.TotalSeconds))s) -> $exe ($mb MB)" -ForegroundColor Green
