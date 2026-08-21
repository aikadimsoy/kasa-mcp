# KASA Asset Inventory — P1b (2026-08-21)

ChatGPT operator karari geregi **envanter + olcum** (bu tur refactor YOK). Amac:
"dosya var" degil, **"dosya olmazsa ne bozulur"** sorusunu kanitlamak. Yontem:
kod/referans envanteri + RAN-LIVE HTTP gozlemi + fault-injection. Kanit seviyeleri
isaretli (RAN-LIVE > CODE-STRUCTURE > DOCUMENTED). Base commit: 3d50dbd.

## Karar tablosu

| Asset | Kim kullaniyor? | Ne zaman? | Source | Wheel | Onefile | Eksikse GERCEK sonuc | Kanit |
|---|---|---|---|---|---|---|---|
| `assets/icon.ico` | Nuitka `--windows-icon-from-ico` | build-time | /assets ile servis (consumer YOK) | pakette yok (consumer yok) | EXE ikonu olarak gomulu | **onefile build FATAL** ("icon path does not exist", exit 1); runtime: hicbir sey | RAN-LIVE (fault-injection) |
| `assets/fonts/*.woff2` (4) | `src/browser/browser_window.py` `@font-face` | browser runtime (**browser DISABLED ships**) | 200 | **404** (mount yok) | **404** (bundle'da yok) | browser acikken wheel/onefile'da fontlar sistem-fontuna duser (KOZMETIK); dashboard etkilenmez | RAN-LIVE |
| `assets/make_icon.py` | gelistirici (icon.ico uretir) | dev-time | — | pakette yok | pakette yok | yok (dev araci) | CODE-STRUCTURE |
| `design_system/**` (index.html, tokens.css, README) | dashboard HTML yalniz ADINI anar (yorum + footer atif); route/import/fetch YOK | asla (runtime yukleme) | 404 | 404 | **bundle'a gomulu ama YUKLENMIYOR** | yok (dashboard CSS token'lari artik HTML icinde inline; tokens.css fetch edilmiyor) | RAN-LIVE |
| server `/assets` mount | browser (fontlar) | runtime | aktif (200) | atlaniyor (dizin yok) | atlaniyor (dizin yok) | wheel/onefile: browser fontlari 404 (kozmetik, browser disabled) | RAN-LIVE |

## 4 sinif

- **A. REQUIRED-WHEEL:** (yok — dashboard package-data zaten wheel'de; MCP cekirdegi asset'siz calisiyor)
- **B. REQUIRED-ONEFILE (build):** `assets/icon.ico` (Nuitka EXE ikonu; eksikse build FATAL). Runtime REQUIRED **degil**.
- **C. SOURCE/DEV-ONLY:** `assets/make_icon.py` (dev); `assets/fonts/*.woff2` (yalniz source'ta servis; tek consumer = DISABLED browser).
- **D. DEAD / NO OBSERVED CONSUMER:** `design_system/**` (onefile bundle'ina giriyor, runtime consumer yok).

Yuzey-bazli ayrim (tam bir sinifa girmeyen):
```
icon.ico:
  wheel   = NOT REQUIRED
  onefile = BUILD REQUIRED
  runtime = NOT REQUIRED

fonts/*.woff2:
  dashboard = NOT USED (yalniz font-family adi)
  browser   = consumer VAR ama browser DISABLED ships
  source    = servis 200 ; wheel/onefile = 404
```

## RAN-LIVE gozlem ozeti
- Source server: `/assets/fonts/*.woff2`=200, `/assets/icon.ico`=200, `/design_system/*`=404, `/dashboard?k=`=200.
- Onefile (KASA.exe): `/assets/fonts/inter-400.woff2`=404, `/assets/icon.ico`=404, `/dashboard/app.js`=200, selftest exit 0.
- Wheel (kasa-server): `/assets/fonts/inter-400.woff2`=404, `/assets/icon.ico`=404, `/dashboard/app.js`=200.
- Fault-injection: Nuitka missing-icon → `FATAL: icon path does not exist`, exit 1, exe yok.
- Kod: tray ikonu `src/desktop/launch.py`'de PIL ile uretiliyor (icon.ico DEGIL); dashboard `index.html` yalniz font-family ADI kullanir (@font-face/`/assets/fonts` YOK); `design_system/tokens.css` dashboard HTML'de yalniz ADIYLA anilir (satir 8 yorum + satir 422 footer atif) ama `<link>`/`@import`/fetch ile YUKLENMIYOR ve hicbir route/py-open acmiyor -> runtime yukleme yok.

**Olcum durustlugu (D21/D24):** ilk consumer taramasinda `grep -v "design_system/"` filtresi tam da aranan satirlari (path iceren) eledi -> "hicbir referans yok" yanlis sonucuna vardim. Sonradan yazdigim `tests/test_asset_inventory.py` bunu YAKALADI (isim-anmasini consumer sandigi icin kirmizi yandi); filtresiz yeniden tarayinca gercek durum (isim-atif VAR, runtime-yukleme YOK) ortaya cikti. Bulgu (dead payload) degismedi; gerekce netlesti.

## Bes soru — dogrudan cevap
1. **Wheel'de eksik gercek asset var mi?** HAYIR. Dashboard package-data ile wheel'de; MCP cekirdegi + dashboard tam calisiyor (RAN-LIVE 200). Fontlar/icon MCP/dashboard icin gerekli degil; browser disabled.
2. **Onefile'da eksik gercek asset var mi?** HAYIR (MCP+dashboard icin). icon.ico onefile'da EXE ikonu olarak var. Fontlar bundle'da yok ama tek consumer (browser) disabled -> islevsel bozulma yok.
3. **Paketlenmis ama kullanilmayan asset var mi?** EVET: **`design_system/**`** onefile bundle'ina --include-data-dir ile giriyor ama RUNTIME CONSUMER YOK (DEAD BUILD PAYLOAD).
4. **Server'da dead /assets mount var mi?** Wheel/onefile'da mount ATLANIYOR (dizin yok) -> pratikte mount yok. Source'ta mount aktif ama tek consumer'i (browser) disabled ships -> pratikte atil.
5. **Kullanici tarafindan gorulebilen bozulma var mi?** HAYIR. Paketlenen yuzeyler (dashboard owner UI + MCP) wheel ve onefile'da tam calisiyor. Tek acik (fontlar 404) yalniz DISABLED browser'i etkiler ve kozmetiktir (sistem-fontu fallback).

## Sonraki (ChatGPT yetkilendirecek — bu tur DUZELTME YOK)
Muhtemel en-kucuk-duzeltme adaylari (yalniz oneri; henuz onaysiz):
- design_system'i onefile bundle'indan cikar (dead payload) — VEYA gercek bir consumer eklenecekse birak.
- Fontlar: browser bir urun yuzeyi olacaksa wheel/onefile'a package-data; olmayacaksa SOURCE/DEV-ONLY olarak birak.
- /assets mount: browser disabled kaldikca atil; browser etkinlestirilecekse packaging gap.
