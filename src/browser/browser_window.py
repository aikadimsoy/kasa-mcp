import webview
import urllib.request
import json
import pathlib
import threading
import os
import time
import hashlib
import secrets

# Design System v0.1 — CSS token tanımları ve self-host font yükleme
_DESIGN_CSS = r"""
@font-face {
    font-family: 'KasaUI';
    font-weight: 400;
    src: url('http://localhost:8000/assets/fonts/inter-400.woff2') format('woff2');
    font-display: swap;
}
@font-face {
    font-family: 'KasaUI';
    font-weight: 500;
    src: url('http://localhost:8000/assets/fonts/inter-500.woff2') format('woff2');
    font-display: swap;
}
@font-face {
    font-family: 'KasaUI';
    font-weight: 600;
    src: url('http://localhost:8000/assets/fonts/inter-600.woff2') format('woff2');
    font-display: swap;
}
@font-face {
    font-family: 'KasaMono';
    font-weight: 400;
    src: url('http://localhost:8000/assets/fonts/jetbrains-mono-400.woff2') format('woff2');
    font-display: swap;
}
:root {
    --kasa-primary:       #E02244;
    --kasa-primary-hover: #C41E3D;
    --kasa-accent:        #1BA7C2;
    --kasa-n950:          #0D1017;
    --kasa-n900:          #12161F;
    --kasa-n800:          #1A2029;
    --kasa-n700:          #242B37;
    --kasa-n500:          #5B6472;
    --kasa-n300:          #9AA3B2;
    --kasa-n100:          #E4E7EC;
    --kasa-secure:        #2FBF71;
    --kasa-warning:       #E8A13C;
    --kasa-danger:        #E5484D;
    --kasa-private:       #8B5CF6;
    --kasa-e1: 0 1px 2px rgba(0,0,0,.24);
    --kasa-e2: 0 4px 12px rgba(0,0,0,.32);
    --kasa-e3: 0 12px 32px rgba(0,0,0,.40);
    --kasa-t-micro: 120ms;
    --kasa-t-std:   200ms;
    --kasa-ease:    cubic-bezier(0.2,0,0,1);
}
#_kasa_toolbar button:hover {
    background: var(--kasa-n700) !important;
    transition: background var(--kasa-t-micro) var(--kasa-ease);
}
#_kasa_addr_box:focus-within {
    border-color: var(--kasa-accent) !important;
}
"""

# KASA toolbar — her sayfaya enjekte edilir
# deepseek/qwen taslağı; bug düzeltmeleri: CSS token enjeksiyonu, URL giriş handler,
# güvenlik halkası ID'leri, icon boyutları
_TOOLBAR_JS = r"""
(function() {
    if (document.getElementById('_kasa_toolbar')) return;

    // CSS token + font tanımlarını sayfaya enjekte et (var() referanslarından önce zorunlu)
    var _style = document.createElement('style');
    _style.textContent = window.__KASA_DESIGN_CSS__ || '';
    (document.head || document.documentElement).appendChild(_style);

    // Chromium tarzı URL/arama heuristic
    window._kasa_navigate = function(v) {
        v = (v || '').trim();
        if (!v) return;
        // Protokol varsa dogrudan git
        if (/^[a-z][a-z0-9+.\-]*:\/\//i.test(v)) {
            window.location.href = v;
            return;
        }
        // Bosluksuz + domain kalibi -> https ekle
        if (!/\s/.test(v) && /^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}(\/.*)?$/i.test(v)) {
            window.location.href = 'https://' + v;
            return;
        }
        // Aksi halde arama — sidebar'daki secili motor (localStorage._kasa_user_search)
        var engine = 'duckduckgo';
        try { engine = localStorage.getItem('_kasa_user_search') || 'duckduckgo'; } catch (e) {}
        var q = encodeURIComponent(v);
        var url;
        if (engine === 'startpage') {
            url = 'https://www.startpage.com/sp/search?query=' + q;
        } else if (engine === 'brave') {
            url = 'https://search.brave.com/search?q=' + q;
        } else {
            url = 'https://lite.duckduckgo.com/lite?q=' + q;
        }
        window.location.href = url;
    };

    // target="_blank" linkleri yeni sekme yerine aynı pencerede aç
    document.addEventListener('click', function(e) {
        var a = e.target.closest('a');
        if (a && a.target === '_blank' && a.href) {
            e.preventDefault();
            e.stopPropagation();
            window.location.href = a.href;
        }
    }, true);

    // Nav butonları: 48x48 dokunma hedefi (6x8), border-radius 12px (r-md)
    var btnStyle = [
        'color:var(--kasa-n300)',
        'background:transparent',
        'border:none',
        'border-radius:12px',
        'width:48px', 'height:48px',
        'display:flex', 'align-items:center', 'justify-content:center',
        'cursor:pointer', 'flex-shrink:0',
    ].join(';');

    var SVG_BACK   = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>';
    var SVG_FWD    = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>';
    var SVG_RELOAD = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.5 15a9 9 0 1 1-2.8-6.4L23 10"/></svg>';

    // Güvenlik halkası SVG'leri (24x24, outline)
    var SVG_SECURE  = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9,12 11,14 15,10"/></svg>';
    var SVG_DANGER  = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>';
    var SVG_WARNING = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="16" r="0.75" fill="currentColor"/></svg>';

    // Toolbar: 48px yukseklik (6x8), N-950 arkaplan
    var bar = document.createElement('div');
    bar.id = '_kasa_toolbar';
    bar.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0', 'height:48px',
        'background:var(--kasa-n950)', 'display:flex', 'align-items:center',
        'gap:8px', 'padding:0 12px', 'z-index:2147483647',
        'font-family:KasaUI,system-ui,sans-serif', 'font-size:13px',
        'box-shadow:var(--kasa-e2)',
    ].join(';');

    // Adres cubugu: pill (r=9999), yukseklik 36px (4.5x8), KasaMono font
    // NOT: inline onclick/onkeydown KULLANMA — siki CSP'li siteler bunlari bloklar.
    // Tum olaylar asagida addEventListener ile baglanir (izole context, CSP'den etkilenmez).
    bar.innerHTML =
        '<button id="_kb_back" style="' + btnStyle + '" title="Geri">' + SVG_BACK + '</button>' +
        '<button id="_kb_fwd"  style="' + btnStyle + '" title="Ileri">' + SVG_FWD + '</button>' +
        '<button id="_kb_rel"  style="' + btnStyle + '" title="Yenile">' + SVG_RELOAD + '</button>' +
        '<div id="_kasa_addr_box" style="display:flex;flex:1;height:36px;background:var(--kasa-n800);border:1px solid var(--kasa-n700);border-radius:9999px;align-items:center;gap:8px;padding:0 12px;min-width:0;">' +
            '<div id="_kasa_ring" style="flex-shrink:0;display:flex;color:var(--kasa-n300);">' + SVG_WARNING + '</div>' +
            '<input id="_kasa_url" type="text" autocomplete="off" spellcheck="false"' +
                ' style="flex:1;background:transparent;color:var(--kasa-n100);border:none;outline:none;font-family:KasaMono,monospace;font-size:14px;min-width:0;"' +
            '/>' +
            '<span id="_kasa_status" style="color:var(--kasa-n500);font-size:11px;flex-shrink:0;">KASA</span>' +
        '</div>';

    document.body.style.marginTop = '48px';
    document.body.insertBefore(bar, document.body.firstChild);

    // Olay baglama (CSP-uyumlu: inline attribute yerine addEventListener)
    var _btnBack = document.getElementById('_kb_back');
    var _btnFwd  = document.getElementById('_kb_fwd');
    var _btnRel  = document.getElementById('_kb_rel');
    var _urlInp  = document.getElementById('_kasa_url');

    if (_btnBack) _btnBack.addEventListener('click', function() {
        try { window.history.back(); } catch (e) {}
    });
    if (_btnFwd) _btnFwd.addEventListener('click', function() {
        try { window.history.forward(); } catch (e) {}
    });
    if (_btnRel) _btnRel.addEventListener('click', function() {
        try { window.location.reload(); } catch (e) {}
    });
    if (_urlInp) {
        // URL'yi HTML olarak DEGIL, DOM ozelligi olarak yaz. Eskiden adres cubugunun
        // deger niteligi elle kacirilarak HTML dizgesine gomuluyordu; yalniz cift-tirnak
        // kaciriliyor, & isareti kacirilmiyordu. Sonuc klasik cift-cozumleme acigi: URL
        // icinde duz metin olarak bir tirnak-varligi gecerse kacirma hic tetiklenmez,
        // ardindan HTML ayristiricisi onu gercek tirnaga cozer ve nitelikten cikilir.
        // .value atamasi metni HTML olarak hic ayristirmadigi icin kacirma sorusu
        // tamamen ortadan kalkar. Ayni deyim asagidaki URL-degisim yoklamasinda da var.
        _urlInp.value = window.location.href;
        // Enter -> arama/URL tetikle
        _urlInp.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();
                e.stopPropagation();
                window._kasa_navigate(_urlInp.value);
            }
        });
        // Adres cubuguna tiklayinca tum metni sec (tarayici standardi)
        _urlInp.addEventListener('focus', function() {
            setTimeout(function() { try { _urlInp.select(); } catch (e) {} }, 0);
        });
    }

    // Guevenlik halkasini protokole gore guncelle
    function updateSecurityRing() {
        var ring = document.getElementById('_kasa_ring');
        if (!ring) return;
        var proto = window.location.protocol;
        if (proto === 'https:') {
            ring.innerHTML = SVG_SECURE;
            ring.style.color = 'var(--kasa-secure)';
            ring.title = 'Guvenli baglantr (HTTPS)';
        } else if (proto === 'http:') {
            ring.innerHTML = SVG_DANGER;
            ring.style.color = 'var(--kasa-danger)';
            ring.title = 'Guvensiz baglanti (HTTP)';
        } else {
            ring.innerHTML = SVG_WARNING;
            ring.style.color = 'var(--kasa-warning)';
            ring.title = 'Baglanti durumu bilinmiyor';
        }
    }

    // Adres cubugunu URL degisiminde guncelle (500ms polling)
    var _lastUrl = window.location.href;
    updateSecurityRing();
    setInterval(function() {
        if (_lastUrl !== window.location.href) {
            _lastUrl = window.location.href;
            var inp = document.getElementById('_kasa_url');
            // Kullanici yazarken guncelleme
            if (inp && document.activeElement !== inp) {
                inp.value = _lastUrl;
            }
            updateSecurityRing();
        }
    }, 500);
})();
"""


_PRIVACY_JS = r"""
(function() {'use strict';
  if (window._kasa_privacy_applied) return;
  window._kasa_privacy_applied = true;

  // Gizlilik seviyesi (sidebar secici -> localStorage._kasa_privacy_level)
  //   off      : hicbir spoof yok
  //   standard : konum/dil/saat/ekran sahte; canvas/webgl/cerez dokunulmaz
  //   strict   : standart + canvas/webgl zehirleme + tracker cerez zehirleme
  //   paranoid : strict (tracker engelleme ileride)
  var LEVEL = 'strict';
  // Once Python'dan gelen window.__KASA_LEVEL__ (domain-arasi kalici), sonra localStorage
  try {
    LEVEL = window.__KASA_LEVEL__ || localStorage.getItem('_kasa_privacy_level') || 'strict';
  } catch (e) {}
  if (LEVEL === 'off') return;
  var POISON = (LEVEL === 'strict' || LEVEL === 'paranoid');

  // Initialize session seeds
  if (!sessionStorage.getItem('_kp_canvas_seed')) {
    sessionStorage.setItem('_kp_canvas_seed', Math.floor(Math.random() * 256));
  }
  if (!sessionStorage.getItem('_kp_webgl_idx')) {
    sessionStorage.setItem('_kp_webgl_idx', Math.floor(Math.random() * 3));
  }
  if (!sessionStorage.getItem('_kp_geo_idx')) {
    const geoList = [
      {lat:48.8566, lon:2.3522, city:"Paris"},
      {lat:52.5200, lon:13.4050, city:"Berlin"},
      {lat:51.5074, lon:-0.1278, city:"London"},
      {lat:41.9028, lon:12.4964, city:"Rome"},
      {lat:40.4168, lon:-3.7038, city:"Madrid"},
      {lat:53.3498, lon:-6.2603, city:"Dublin"},
      {lat:59.9139, lon:10.7522, city:"Oslo"},
      {lat:50.0755, lon:14.4378, city:"Prague"}
    ];
    sessionStorage.setItem('_kp_geo_idx', Math.floor(Math.random() * geoList.length));
  }
  if (!sessionStorage.getItem('_kp_hw_cores')) {
    const cores = [4, 6, 8];
    sessionStorage.setItem('_kp_hw_cores', cores[Math.floor(Math.random() * cores.length)]);
  }
  if (!sessionStorage.getItem('_kp_mem')) {
    const memory = [4, 8];
    sessionStorage.setItem('_kp_mem', memory[Math.floor(Math.random() * memory.length)]);
  }

  // Fake Geolocation
  try {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
    const originalWatchPosition = navigator.geolocation.watchPosition;
    navigator.geolocation.getCurrentPosition = function(success) {
      const geoList = [
        {lat:48.8566, lon:2.3522, city:"Paris"},
        {lat:52.5200, lon:13.4050, city:"Berlin"},
        {lat:51.5074, lon:-0.1278, city:"London"},
        {lat:41.9028, lon:12.4964, city:"Rome"},
        {lat:40.4168, lon:-3.7038, city:"Madrid"},
        {lat:53.3498, lon:-6.2603, city:"Dublin"},
        {lat:59.9139, lon:10.7522, city:"Oslo"},
        {lat:50.0755, lon:14.4378, city:"Prague"}
      ];
      const idx = sessionStorage.getItem('_kp_geo_idx');
      const selectedCity = geoList[parseInt(idx)];
      const lat = selectedCity.lat + (Math.random() - 0.5) * 0.02;
      const lon = selectedCity.lon + (Math.random() - 0.5) * 0.02;
      success({coords: {latitude: lat, longitude: lon}, accuracy: Math.floor(Math.random() * 100), timestamp: Date.now()});
    };
    navigator.geolocation.watchPosition = function(success) {
      const id = setInterval(() => {
        const geoList = [
          {lat:48.8566, lon:2.3522, city:"Paris"},
          {lat:52.5200, lon:13.4050, city:"Berlin"},
          {lat:51.5074, lon:-0.1278, city:"London"},
          {lat:41.9028, lon:12.4964, city:"Rome"},
          {lat:40.4168, lon:-3.7038, city:"Madrid"},
          {lat:53.3498, lon:-6.2603, city:"Dublin"},
          {lat:59.9139, lon:10.7522, city:"Oslo"},
          {lat:50.0755, lon:14.4378, city:"Prague"}
        ];
        const idx = sessionStorage.getItem('_kp_geo_idx');
        const selectedCity = geoList[parseInt(idx)];
        const lat = selectedCity.lat + (Math.random() - 0.5) * 0.02;
        const lon = selectedCity.lon + (Math.random() - 0.5) * 0.02;
        success({coords: {latitude: lat, longitude: lon}, accuracy: Math.floor(Math.random() * 100), timestamp: Date.now()});
      }, 1000);
      return id;
    };
  } catch (e) {}

  // Canvas Fingerprint Poisoning (yalnizca strict/paranoid)
  if (POISON) try {
    const canvasProto = HTMLCanvasElement.prototype;
    const ctxProto = CanvasRenderingContext2D.prototype;
    const originalToDataURL = canvasProto.toDataURL;
    const originalGetImageData = ctxProto.getImageData;
    canvasProto.toDataURL = function() {
      const seed = parseInt(sessionStorage.getItem('_kp_canvas_seed')) || 1;
      const ctx = this.getContext('2d');
      if (ctx) {
        const imgData = originalGetImageData.call(ctx, 0, 0, this.width, this.height);
        for (let i = 3; i < imgData.data.length; i += 4) {
          imgData.data[i] ^= seed;
        }
        ctx.putImageData(imgData, 0, 0);
      }
      return originalToDataURL.apply(this, arguments);
    };
    ctxProto.getImageData = function(sx, sy, sw, sh) {
      const imgData = originalGetImageData.apply(this, arguments);
      const seed = parseInt(sessionStorage.getItem('_kp_canvas_seed')) || 1;
      for (let i = 3; i < imgData.data.length; i += 4) {
        imgData.data[i] ^= seed;
      }
      return imgData;
    };
  } catch (e) {}

  // WebGL Fingerprint Poisoning (yalnizca strict/paranoid)
  if (POISON) try {
    const webglProto = WebGLRenderingContext.prototype;
    let originalGetParameter;
    originalGetParameter = webglProto.getParameter;
    webglProto.getParameter = function(pname) {
      const GL_VENDOR   = 0x1F00;
      const GL_RENDERER = 0x1F01;
      const UNMASKED_VENDOR_WEBGL   = 0x9245;
      const UNMASKED_RENDERER_WEBGL = 0x9246;
      if (pname === GL_RENDERER || pname === GL_VENDOR || pname === UNMASKED_RENDERER_WEBGL || pname === UNMASKED_VENDOR_WEBGL) {
        const renderers = [
          "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
          "ANGLE (AMD, Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)",
          "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        ];
        const vendors = ["Google Inc. (Intel)", "Google Inc. (AMD)", "Google Inc. (NVIDIA)"];
        const idx = parseInt(sessionStorage.getItem('_kp_webgl_idx')) || 0;
        if (pname === GL_RENDERER || pname === UNMASKED_RENDERER_WEBGL) return renderers[idx];
        if (pname === GL_VENDOR || pname === UNMASKED_VENDOR_WEBGL)   return vendors[idx];
      }
      return originalGetParameter.apply(this, arguments);
    };
    // WebGL2 baglami — AYNI seed (_kp_webgl_idx) ile TUTARLI spoof. WebGL1 sahte ama
    // WebGL2 gercek GPU dondururse, bu tutarsizligin kendisi yeni bir teshis sinyali olur.
    if (typeof WebGL2RenderingContext !== 'undefined') {
      const webgl2Proto = WebGL2RenderingContext.prototype;
      const originalGetParameter2 = webgl2Proto.getParameter;
      webgl2Proto.getParameter = function(pname) {
        const GL_VENDOR   = 0x1F00;
        const GL_RENDERER = 0x1F01;
        const UNMASKED_VENDOR_WEBGL   = 0x9245;
        const UNMASKED_RENDERER_WEBGL = 0x9246;
        if (pname === GL_RENDERER || pname === GL_VENDOR || pname === UNMASKED_RENDERER_WEBGL || pname === UNMASKED_VENDOR_WEBGL) {
          const renderers = [
            "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (AMD, Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"
          ];
          const vendors = ["Google Inc. (Intel)", "Google Inc. (AMD)", "Google Inc. (NVIDIA)"];
          const idx = parseInt(sessionStorage.getItem('_kp_webgl_idx')) || 0;
          if (pname === GL_RENDERER || pname === UNMASKED_RENDERER_WEBGL) return renderers[idx];
          if (pname === GL_VENDOR || pname === UNMASKED_VENDOR_WEBGL)   return vendors[idx];
        }
        return originalGetParameter2.apply(this, arguments);
      };
    }
  } catch (e) {}

  // Navigator Property Spoofing
  try {
    Object.defineProperty(navigator, 'hardwareConcurrency', {value: parseInt(sessionStorage.getItem('_kp_hw_cores')), writable: false, configurable: false});
    Object.defineProperty(navigator, 'deviceMemory', {value: parseInt(sessionStorage.getItem('_kp_mem')), writable: false, configurable: false});
    Object.defineProperty(navigator, 'platform', {value: "Win32", writable: false, configurable: false});
    Object.defineProperty(navigator, 'languages', {value: ["de-DE", "de", "en-US", "en"], writable: false, configurable: false});
    Object.defineProperty(navigator, 'language', {value: "de-DE", writable: false, configurable: false});
  } catch (e) {}

  // Screen Spoofing
  try {
    Object.defineProperty(screen, 'width', {value: 1920, writable: false, configurable: false});
    Object.defineProperty(screen, 'height', {value: 1080, writable: false, configurable: false});
    Object.defineProperty(screen, 'availWidth', {value: 1920, writable: false, configurable: false});
    Object.defineProperty(screen, 'availHeight', {value: 1040, writable: false, configurable: false});
    Object.defineProperty(screen, 'colorDepth', {value: 24, writable: false, configurable: false});
    Object.defineProperty(screen, 'pixelDepth', {value: 24, writable: false, configurable: false});
  } catch (e) {}

  // Timezone Noise
  try {
    const _origDTF = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function() {
      const dtf = new _origDTF(...arguments);
      const origResolved = dtf.resolvedOptions.bind(dtf);
      dtf.resolvedOptions = function() {
        const opts = origResolved();
        opts.timeZone = 'Europe/Berlin';
        return opts;
      };
      return dtf;
    };
    Intl.DateTimeFormat.prototype = _origDTF.prototype;
    // B4 TUTARLILIK: getTimezoneOffset'i SABIT -60 yerine iddia edilen Europe/Berlin'e gore
    // TARIHE BAGLI (DST-farkinda) hesapla -> Intl.timeZone ile TUTARLI (yazin CEST=-120, kisin CET=-60).
    // Sabit -60, yaz tarihlerinde Intl='Europe/Berlin' ile celisiyordu = parmak izi.
    Object.defineProperty(Date.prototype, 'getTimezoneOffset', {value: function() {
      try {
        const s = new _origDTF('en-US', {timeZone:'Europe/Berlin', timeZoneName:'shortOffset'}).format(this);
        const m = s.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
        if (m) { const sign = m[1]==='-'?1:-1; const h=parseInt(m[2],10); const mm=m[3]?parseInt(m[3],10):0; return sign*(h*60+mm); }
      } catch (e) {}
      return -60;
    }, writable: false, configurable: false});
  } catch (e) {}

  // Known Tracker Cookie Poisoning (yalnizca strict/paranoid)
  if (POISON) try {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      cookie = cookie.trim();
      if (!cookie.startsWith('_px') && !cookie.startsWith('_abck') && !cookie.startsWith('bm_') && !cookie.startsWith('dtCookie') && !cookie.startsWith('_pxvid') && !cookie.startsWith('__pxvid') && !cookie.startsWith('_pk_id') && !cookie.startsWith('_pk_ses') && !cookie.startsWith('_twpid') && !cookie.startsWith('RT') && !cookie.startsWith('bm_sv') && !cookie.startsWith('bm_sz') && !cookie.startsWith('bm_mi')) continue;
      const name = cookie.split('=')[0];
      if (name === 'HttpOnly') continue;
      let value = cookie.split('=')[1];
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*\'()';
      let fakeValue = '';
      for (let i = 0; i < value.length; i++) {
        const randomIndex = Math.floor(Math.random() * chars.length);
        fakeValue += chars[randomIndex];
      }
      document.cookie = `${name}=${fakeValue}; path=/`;
    }
  } catch (e) {}

  // Known Tracker Request Blocking (YALNIZCA paranoid — site kirabilir, sifre-korumali kademe).
  // NOT: 'paranoid' seviyesi yalnizca Python set_level ile (owner sifresiyle acilinca) secilebilir;
  // burada calisiyorsa owner bunu bilincli olarak actigi anlamina gelir. strict/standard degismez.
  if (LEVEL === 'paranoid') try {
    const KASA_TRACKER_DOMAINS = [
      'doubleclick.net', 'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com',
      'connect.facebook.net', 'facebook.net', 'analytics.tiktok.com', 'bat.bing.com',
      'scorecardresearch.com', 'adnxs.com', 'criteo.com', 'hotjar.com', 'segment.io',
      'mixpanel.com', 'amplitude.com', 'fullstory.com', 'clarity.ms', 'quantserve.com',
      'moatads.com', 'adsrvr.org'
    ];
    const _kasaIsTracker = function(url) {
      try {
        const h = new URL(url, location.href).hostname;
        return KASA_TRACKER_DOMAINS.some(function(d) { return h === d || h.endsWith('.' + d); });
      } catch (e) { return false; }
    };
    const _origFetch = window.fetch;
    if (typeof _origFetch === 'function') {
      window.fetch = function(input) {
        const url = (typeof input === 'string') ? input : (input && input.url);
        if (url && _kasaIsTracker(url)) {
          return Promise.reject(new TypeError('KASA: tracker request blocked'));
        }
        return _origFetch.apply(this, arguments);
      };
    }
    const _origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      this._kasaBlocked = !!(url && _kasaIsTracker(url));
      return _origOpen.apply(this, arguments);
    };
    const _origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
      if (this._kasaBlocked) { try { this.abort(); } catch (e) {} return; }
      return _origSend.apply(this, arguments);
    };
  } catch (e) {}

  // Layer #4 — WebRTC IP sizinti onleme (yalnizca strict/paranoid).
  // Proxy/VPN acik olsa bile WebRTC STUN gercek yerel+genel IP'yi sizdirir; host/srflx
  // adaylarini dusurerek bunu engelle.
  if (POISON) {
    try {
      var _OrigRTC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
      if (_OrigRTC) {
        var _isLeaky = function(ev) {
          if (!ev || !ev.candidate || !ev.candidate.candidate) return false;
          var c = ev.candidate.candidate;
          return (c.indexOf(' typ host') !== -1) || (c.indexOf(' typ srflx') !== -1);
        };
        var _Wrapped = function(config, constraints) {
          var pc = new _OrigRTC(config, constraints);
          var _origAdd = pc.addEventListener.bind(pc);
          pc.addEventListener = function(type, listener, opts) {
            if (type === 'icecandidate' && typeof listener === 'function') {
              return _origAdd(type, function(ev) { if (_isLeaky(ev)) return; listener(ev); }, opts);
            }
            return _origAdd(type, listener, opts);
          };
          var _userCb = null;
          try {
            Object.defineProperty(pc, 'onicecandidate', {
              configurable: true,
              get: function() { return _userCb; },
              set: function(fn) {
                _userCb = fn;
                _origAdd('icecandidate', function(ev) {
                  if (_isLeaky(ev)) return;
                  if (typeof _userCb === 'function') _userCb(ev);
                });
              }
            });
          } catch (e) {}
          return pc;
        };
        _Wrapped.prototype = _OrigRTC.prototype;
        window.RTCPeerConnection = _Wrapped;
        if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = _Wrapped;
        if (window.mozRTCPeerConnection) window.mozRTCPeerConnection = _Wrapped;
      }
    } catch (e) {}
  }

  // Layer #4 ek — WebRTC SDP-filtre kalkani (vanilla ICE icin 2. katman).
  // Adaylar SDP'ye gomuluyse (trickle degil) host/srflx satirlarini SDP'den de dusur.
  if (POISON) {
    try {
      var _RTCsld = window.RTCPeerConnection;
      if (_RTCsld && _RTCsld.prototype && _RTCsld.prototype.setLocalDescription) {
        var _origSLD = _RTCsld.prototype.setLocalDescription;
        _RTCsld.prototype.setLocalDescription = function(description) {
          try {
            if (description && description.sdp) {
              description.sdp = description.sdp.split('\n').filter(function(line) {
                if (line.indexOf('a=candidate') === 0 &&
                    (line.indexOf(' typ host') !== -1 || line.indexOf(' typ srflx') !== -1)) {
                  return false;
                }
                return true;
              }).join('\n');
            }
          } catch (e) {}
          return _origSLD.apply(this, arguments);
        };
      }
    } catch (e) {}
  }
})();
"""


_SIDEBAR_JS = r"""
(function() {
  if (document.getElementById('_kasa_rail')) return;
  try {
    // CSS token'lari garanti et (toolbar da enjekte eder; guvenli olsun)
    if (!document.getElementById('_kasa_ds_style') && window.__KASA_DESIGN_CSS__) {
      var st = document.createElement('style');
      st.id = '_kasa_ds_style';
      st.textContent = window.__KASA_DESIGN_CSS__;
      (document.head || document.documentElement).appendChild(st);
    }

    // Rail hover + kart stilleri
    var extra = document.createElement('style');
    extra.textContent =
      '#_kasa_rail button:hover{background:var(--kasa-n800)!important}' +
      '#_kasa_rail button._active{background:var(--kasa-n800)!important;color:var(--kasa-n100)!important}' +
      '#_kasa_panel h2{font-size:16px;font-weight:600;margin:0 0 12px;color:var(--kasa-n100)}' +
      '#_kasa_panel label{display:block;margin:10px 0;color:var(--kasa-n300);font-size:13px}' +
      '#_kasa_panel input[type=text],#_kasa_panel select{width:100%;margin-top:4px;background:var(--kasa-n800);' +
        'color:var(--kasa-n100);border:1px solid var(--kasa-n700);border-radius:8px;padding:6px 8px;' +
        'font-family:KasaUI,sans-serif;font-size:13px;outline:none}' +
      '.kasa-row{display:flex;align-items:center;justify-content:space-between;margin:10px 0;' +
        'color:var(--kasa-n100);font-size:13px}' +
      '.kasa-card{border:1px solid var(--kasa-n700);border-radius:12px;padding:10px 12px;margin:8px 0;' +
        'cursor:pointer;background:var(--kasa-n900);transition:border-color var(--kasa-t-micro) var(--kasa-ease)}' +
      '.kasa-card strong{display:block;color:var(--kasa-n100);font-size:13px;margin-bottom:2px}' +
      '.kasa-card span{color:var(--kasa-n500);font-size:11px;line-height:1.4}';
    document.head.appendChild(extra);

    var ICON = {
      menu:  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/></svg>',
      tools: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0 5 5l-1.6 1.6-8.8 8.8a2 2 0 0 1-2.8-2.8l8.8-8.8Z"/><path d="M9 8 3.5 2.5"/></svg>',
      user:  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>',
      shield:'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
      net:   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/></svg>',
      cpu:   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>',
      lock:  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>'
    };

    // ── Rail ──
    var rail = document.createElement('div');
    rail.id = '_kasa_rail';
    rail.style.cssText = [
      'position:fixed','top:48px','left:0','bottom:0','width:56px',
      'background:var(--kasa-n900)','z-index:2147483646','display:flex',
      'flex-direction:column','align-items:center','gap:8px','padding-top:12px',
      'box-shadow:var(--kasa-e2)'
    ].join(';');

    function railBtn(iconKey, title, onClick) {
      var b = document.createElement('button');
      b.type = 'button';
      b.title = title;
      b.innerHTML = ICON[iconKey];
      b.style.cssText = [
        'width:48px','height:48px','display:flex','align-items:center','justify-content:center',
        'background:transparent','border:none','border-radius:12px','color:var(--kasa-n300)',
        'cursor:pointer','flex-shrink:0'
      ].join(';');
      b.addEventListener('click', onClick);
      return b;
    }

    // ── Panel ──
    var panel = document.createElement('div');
    panel.id = '_kasa_panel';
    panel.style.cssText = [
      'position:fixed','top:48px','left:56px','bottom:0','width:256px',
      'background:var(--kasa-n950)','z-index:2147483646','box-shadow:var(--kasa-e2)',
      'overflow-y:auto','padding:16px','color:var(--kasa-n100)',
      'font-family:KasaUI,sans-serif','font-size:14px',
      'transform:translateX(-320px)','transition:transform var(--kasa-t-std) var(--kasa-ease)'
    ].join(';');

    var isOpen = false;
    var activeSection = null;

    function setOpen(v) {
      isOpen = v;
      panel.style.transform = v ? 'translateX(0)' : 'translateX(-320px)';
    }

    // Aktif rail ikonunu vurgula
    function markActive(key) {
      [btnTools, btnUser, btnShield, btnNet, btnModel, btnAdv].forEach(function(b) { b.classList.remove('_active'); });
      if (key === 'araclar')  btnTools.classList.add('_active');
      if (key === 'kullanici') btnUser.classList.add('_active');
      if (key === 'gizlilik')  btnShield.classList.add('_active');
      if (key === 'ag')        btnNet.classList.add('_active');
      if (key === 'model')     btnModel.classList.add('_active');
      if (key === 'advanced')  btnAdv.classList.add('_active');
    }

    // ── Bolum: Araclar ──
    var TOOLS = [
      { key: '_kasa_tool_screenshot', label: 'Ekran goruntusu',      def: false },
      { key: '_kasa_tool_savetext',   label: 'Sayfa metnini kaydet', def: true  },
      { key: '_kasa_tool_cookies',    label: 'Cerez goruntule',      def: true  },
      { key: '_kasa_tool_vault',      label: "Vault'a gonder",       def: true  }
    ];

    function renderAraclar() {
      panel.innerHTML = '<h2>Araclar</h2>';
      TOOLS.forEach(function(t) {
        var saved = localStorage.getItem(t.key);
        var on = saved === null ? t.def : saved === 'true';
        var row = document.createElement('div');
        row.className = 'kasa-row';
        var span = document.createElement('span'); span.textContent = t.label;
        var cb = document.createElement('input');
        cb.type = 'checkbox'; cb.checked = on;
        cb.addEventListener('change', function() {
          localStorage.setItem(t.key, cb.checked ? 'true' : 'false');
        });
        row.appendChild(span); row.appendChild(cb);
        panel.appendChild(row);
      });
    }

    // ── Bolum: Kullanici ──
    function renderKullanici() {
      panel.innerHTML = '<h2>Kullanici Ayarlari</h2>';
      // Takma ad
      var l1 = document.createElement('label'); l1.textContent = 'Takma ad';
      var alias = document.createElement('input'); alias.type = 'text';
      alias.value = localStorage.getItem('_kasa_user_alias') || '';
      alias.addEventListener('input', function() {
        localStorage.setItem('_kasa_user_alias', alias.value);
      });
      l1.appendChild(alias); panel.appendChild(l1);
      // Arama motoru
      var l2 = document.createElement('label'); l2.textContent = 'Arama motoru';
      var sel = document.createElement('select');
      [['duckduckgo','DuckDuckGo'],['startpage','Startpage'],['brave','Brave']].forEach(function(o) {
        var op = document.createElement('option'); op.value = o[0]; op.textContent = o[1]; sel.appendChild(op);
      });
      sel.value = localStorage.getItem('_kasa_user_search') || 'duckduckgo';
      sel.addEventListener('change', function() {
        localStorage.setItem('_kasa_user_search', sel.value);
      });
      l2.appendChild(sel); panel.appendChild(l2);
      // Tema
      var l3 = document.createElement('label'); l3.textContent = 'Tema';
      var th = document.createElement('select');
      [['dark','Koyu'],['system','Sistem']].forEach(function(o) {
        var op = document.createElement('option'); op.value = o[0]; op.textContent = o[1]; th.appendChild(op);
      });
      th.value = localStorage.getItem('_kasa_user_theme') || 'dark';
      th.addEventListener('change', function() {
        localStorage.setItem('_kasa_user_theme', th.value);
      });
      l3.appendChild(th); panel.appendChild(l3);
    }

    // ── Bolum: Gizlilik Seviyesi ──
    var LEVELS = [
      { v: 'off',      t: 'Kapali',    d: 'Hicbir sahte veri yok. Gercek parmak izin gonderilir.' },
      { v: 'standard', t: 'Standart',  d: 'Konum, dil, saat dilimi, ekran sahte. Canvas/WebGL dokunulmaz.' },
      { v: 'strict',   t: 'Siki',      d: 'Standart + Canvas/WebGL(1+2) zehirleme + tracker cerez zehirleme.' }
      // 'paranoid' (tracker istek engelleme) burada YOK — yalniz sifre-korumali 'Gelismis' panelinden.
    ];

    function renderGizlilik() {
      panel.innerHTML = '<h2>Gizlilik Seviyesi</h2>';
      // Python'daki kalici seviye onceliklidir (domain-arasi tutarli)
      var cur = window.__KASA_LEVEL__ || localStorage.getItem('_kasa_privacy_level') || 'strict';
      LEVELS.forEach(function(lv) {
        var card = document.createElement('div');
        card.className = 'kasa-card';
        card.style.borderColor = (lv.v === cur) ? 'var(--kasa-primary)' : 'var(--kasa-n700)';
        card.style.borderWidth = (lv.v === cur) ? '2px' : '1px';
        var s = document.createElement('strong'); s.textContent = lv.t;
        var p = document.createElement('span'); p.textContent = lv.d;
        card.appendChild(s); card.appendChild(p);
        card.addEventListener('click', function() {
          // Python config'e yaz (kalici, domain-arasi) + yerelde de tut (yedek)
          localStorage.setItem('_kasa_privacy_level', lv.v);
          window.__KASA_LEVEL__ = lv.v;
          try {
            if (window.pywebview && window.pywebview.api && window.pywebview.api.set_level) {
              window.pywebview.api.set_level(lv.v);
            }
          } catch (e) {}
          renderGizlilik();
        });
        panel.appendChild(card);
      });
      // Yenile notu + buton
      var note = document.createElement('div');
      note.style.cssText = 'margin-top:12px;color:var(--kasa-n500);font-size:11px;line-height:1.4';
      note.textContent = 'Yeni sayfada gecerli olur. Pre-load spoof da tam uyum icin ' +
        'tarayiciyi yeniden baslat.';
      panel.appendChild(note);
      var rb = document.createElement('button');
      rb.type = 'button'; rb.textContent = 'Sayfayi yenile';
      rb.style.cssText = 'margin-top:8px;width:100%;background:var(--kasa-primary);color:#fff;' +
        'border:none;border-radius:8px;padding:8px;cursor:pointer;font-family:KasaUI,sans-serif;font-size:13px';
      rb.addEventListener('click', function() { location.reload(); });
      panel.appendChild(rb);
    }

    // ── Bolum: Ag / Proxy (Layer #2) ──
    function renderAg() {
      panel.innerHTML = '<h2>Ag / Proxy</h2>';
      // Proxy ac/kapa
      var row = document.createElement('div');
      row.className = 'kasa-row';
      var span = document.createElement('span'); span.textContent = 'Proxy kullan';
      var cb = document.createElement('input');
      cb.type = 'checkbox'; cb.id = '_kasa_proxy_on';
      row.appendChild(span); row.appendChild(cb);
      panel.appendChild(row);
      // Adres
      var lab = document.createElement('label'); lab.textContent = 'Proxy adresi';
      var inp = document.createElement('input');
      inp.type = 'text'; inp.id = '_kasa_proxy_addr';
      inp.placeholder = 'socks5://127.0.0.1:9150';
      lab.appendChild(inp); panel.appendChild(lab);
      // Tor onayari
      var tor = document.createElement('button');
      tor.type = 'button'; tor.textContent = 'Tor (127.0.0.1:9150)';
      tor.style.cssText = 'margin-top:6px;width:100%;background:var(--kasa-n800);color:var(--kasa-n100);' +
        'border:1px solid var(--kasa-n700);border-radius:8px;padding:7px;cursor:pointer;' +
        'font-family:KasaUI,sans-serif;font-size:12px';
      tor.addEventListener('click', function() { inp.value = 'socks5://127.0.0.1:9150'; });
      panel.appendChild(tor);
      // Not
      var note = document.createElement('div');
      note.style.cssText = 'margin-top:12px;color:var(--kasa-n500);font-size:11px;line-height:1.4';
      note.textContent = 'Degisiklik tarayici yeniden baslatilinca gecerli olur. ' +
        'Bos + kapali = dogrudan baglanti (gercek IP gorunur).';
      panel.appendChild(note);
      // Kaydet
      var save = document.createElement('button');
      save.type = 'button'; save.textContent = 'Kaydet';
      save.style.cssText = 'margin-top:8px;width:100%;background:var(--kasa-primary);color:#fff;' +
        'border:none;border-radius:8px;padding:8px;cursor:pointer;font-family:KasaUI,sans-serif;font-size:13px';
      save.addEventListener('click', function() {
        try {
          if (window.pywebview && window.pywebview.api && window.pywebview.api.set_proxy) {
            window.pywebview.api.set_proxy(cb.checked, inp.value);
            save.textContent = 'Kaydedildi (yeniden baslat)';
          }
        } catch (e) {}
      });
      panel.appendChild(save);
      // Mevcut degerleri Python'dan oku
      try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.get_proxy) {
          window.pywebview.api.get_proxy().then(function(cfg) {
            if (cfg && typeof cfg === 'object') {
              cb.checked = !!cfg.proxy_enabled;
              inp.value = cfg.proxy_address || '';
            }
          });
        }
      } catch (e) {}
    }

    // ── Bolum: AI Modeli ──
    function renderModel() {
      panel.innerHTML = '<h2>AI Modeli</h2>';
      var info = document.createElement('div');
      info.style.cssText = 'color:var(--kasa-n500);font-size:11px;line-height:1.4;margin-bottom:8px';
      info.textContent = 'Sistemde kurulu yerel modeller. Secim damitma / bekci beynini belirler.';
      panel.appendChild(info);
      var listWrap = document.createElement('div');
      panel.appendChild(listWrap);

      function fmtSize(b) {
        if (!b) return '';
        var gb = b / 1e9;
        return gb >= 1 ? gb.toFixed(1) + ' GB' : Math.round(b / 1e6) + ' MB';
      }

      function paint(models, cur) {
        listWrap.innerHTML = '';
        if (!models || !models.length) {
          var empty = document.createElement('div');
          empty.style.cssText = 'color:var(--kasa-n500);font-size:12px;line-height:1.5;padding:8px 0';
          empty.textContent = 'Model bulunamadi — yerel model servisi (Ollama) calismiyor.';
          listWrap.appendChild(empty);
          return;
        }
        models.forEach(function(m) {
          var card = document.createElement('div');
          card.className = 'kasa-card';
          var sel = (m.name === cur);
          card.style.borderColor = sel ? 'var(--kasa-primary)' : 'var(--kasa-n700)';
          card.style.borderWidth = sel ? '2px' : '1px';
          var s = document.createElement('strong'); s.textContent = m.name;
          var p = document.createElement('span'); p.textContent = fmtSize(m.size);
          card.appendChild(s); card.appendChild(p);
          card.addEventListener('click', function() {
            // Optimistik: kart zaten kurulu modeller listesinden geliyor (allow-list gecer)
            try {
              if (window.pywebview && window.pywebview.api && window.pywebview.api.set_model) {
                window.pywebview.api.set_model(m.name);
              }
            } catch (e) {}
            paint(models, m.name);
          });
          listWrap.appendChild(card);
        });
      }

      var curModel = 'qwen2.5:7b';
      try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.get_model) {
          window.pywebview.api.get_model().then(function(cm) {
            curModel = cm || curModel;
            if (window.pywebview.api.list_models) {
              window.pywebview.api.list_models().then(function(ms) { paint(ms, curModel); });
            } else { paint([], curModel); }
          });
        } else { paint([], curModel); }
      } catch (e) { paint([], curModel); }

      var note = document.createElement('div');
      note.style.cssText = 'margin-top:12px;color:var(--kasa-n500);font-size:11px;line-height:1.4';
      note.textContent = 'Sonraki damitma turunda / bekci baslatmada gecerli olur.';
      panel.appendChild(note);
    }

    // ── Bolum: Gelismis (Kilitli) ──
    function renderAdvanced() {
      panel.innerHTML = '<h2>Gelismis (Kilitli)</h2>';
      var desc = document.createElement('div');
      desc.style.cssText = 'color:var(--kasa-n500);font-size:11px;line-height:1.4;margin-bottom:10px';
      desc.textContent = 'Site kirabilen agresif ozellik: Paranoyak mod (bilinen tracker isteklerini ' +
        'engeller). Yalniz sifreyle acilir; sifre sadece sende. Yeniden baslatinca kilitlenir.';
      panel.appendChild(desc);

      var api = (window.pywebview && window.pywebview.api) ? window.pywebview.api : null;
      if (!api || !api.adv_status) {
        var na = document.createElement('div');
        na.style.cssText = 'color:var(--kasa-n500);font-size:12px'; na.textContent = 'Kullanilamaz.';
        panel.appendChild(na); return;
      }

      function pwInput(ph) {
        var i = document.createElement('input');
        i.type = 'password'; i.placeholder = ph;
        i.style.cssText = 'width:100%;margin-top:4px;background:var(--kasa-n800);color:var(--kasa-n100);' +
          'border:1px solid var(--kasa-n700);border-radius:8px;padding:6px 8px;' +
          'font-family:KasaUI,sans-serif;font-size:13px;outline:none';
        return i;
      }
      function bigBtn(label, primary) {
        var b = document.createElement('button');
        b.type = 'button'; b.textContent = label;
        b.style.cssText = 'margin-top:8px;width:100%;border:none;border-radius:8px;padding:8px;' +
          'cursor:pointer;font-family:KasaUI,sans-serif;font-size:13px;color:#fff;background:' +
          (primary ? 'var(--kasa-primary)' : 'var(--kasa-n800)');
        return b;
      }
      function msg(t, danger) {
        var m = document.createElement('div');
        m.style.cssText = 'margin-top:8px;font-size:12px;line-height:1.4;color:' +
          (danger ? '#E5484D' : 'var(--kasa-n500)');
        m.textContent = t; panel.appendChild(m);
      }

      function renderSetPw() {
        var l = document.createElement('label'); l.textContent = 'Yeni sifre belirle (en az 4 karakter)';
        var i = pwInput('yeni sifre'); l.appendChild(i); panel.appendChild(l);
        var b = bigBtn('Sifre belirle', true);
        b.addEventListener('click', function() {
          api.adv_set_password(i.value).then(function(ok) {
            if (ok) renderAdvanced(); else msg('Belirlenemedi (en az 4 karakter).', true);
          });
        });
        panel.appendChild(b);
      }
      function renderUnlock() {
        var l = document.createElement('label'); l.textContent = 'Sifre ile ac';
        var i = pwInput('sifre'); l.appendChild(i); panel.appendChild(l);
        var b = bigBtn('Ac', true);
        b.addEventListener('click', function() {
          api.adv_unlock(i.value).then(function(ok) {
            if (ok) renderAdvanced(); else msg('Yanlis sifre.', true);
          });
        });
        panel.appendChild(b);
      }
      function renderUnlocked() {
        var row = document.createElement('div'); row.className = 'kasa-row';
        var span = document.createElement('span'); span.textContent = 'Paranoyak mod (tracker istek engelleme)';
        var cb = document.createElement('input'); cb.type = 'checkbox';
        cb.checked = (window.__KASA_LEVEL__ === 'paranoid');
        cb.addEventListener('change', function() {
          var lv = cb.checked ? 'paranoid' : 'strict';
          api.set_level(lv).then(function(applied) {
            window.__KASA_LEVEL__ = applied;
            try { localStorage.setItem('_kasa_privacy_level', applied); } catch (e) {}
            cb.checked = (applied === 'paranoid');
          });
        });
        row.appendChild(span); row.appendChild(cb); panel.appendChild(row);
        msg('Site kirabilir; kapatinca strict\'e doner. Degisiklik yeni sayfada gecerli olur.');
        var lock = bigBtn('Kilitle', false);
        lock.addEventListener('click', function() { api.adv_lock().then(function() { renderAdvanced(); }); });
        panel.appendChild(lock);
      }

      api.adv_status().then(function(st) {
        if (!st.has_password) renderSetPw();
        else if (!st.unlocked) renderUnlock();
        else renderUnlocked();
      });
    }

    var RENDER = { araclar: renderAraclar, kullanici: renderKullanici, gizlilik: renderGizlilik, ag: renderAg, model: renderModel, advanced: renderAdvanced };

    function showSection(key) {
      if (!RENDER[key]) return;
      RENDER[key]();
      activeSection = key;
      markActive(key);
      setOpen(true);
    }

    // Rail butonlari
    var btnMenu = railBtn('menu', 'Menu', function() {
      if (isOpen) { setOpen(false); markActive(null); }
      else { showSection(activeSection || 'araclar'); }
    });
    var btnTools  = railBtn('tools',  'Araclar',            function() { showSection('araclar'); });
    var btnUser   = railBtn('user',   'Kullanici Ayarlari', function() { showSection('kullanici'); });
    var btnShield = railBtn('shield', 'Gizlilik Seviyesi',  function() { showSection('gizlilik'); });
    var btnNet    = railBtn('net',    'Ag / Proxy',         function() { showSection('ag'); });
    var btnModel  = railBtn('cpu',    'AI Modeli',          function() { showSection('model'); });
    var btnAdv    = railBtn('lock',   'Gelismis (Kilitli)', function() { showSection('advanced'); });

    rail.appendChild(btnMenu);
    rail.appendChild(btnTools);
    rail.appendChild(btnUser);
    rail.appendChild(btnShield);
    rail.appendChild(btnNet);
    rail.appendChild(btnModel);
    rail.appendChild(btnAdv);

    document.body.appendChild(rail);
    document.body.appendChild(panel);

    // Rail icerigi kapatmasin (toolbar zaten marginTop:48 koydu)
    document.body.style.marginLeft = '56px';
  } catch (e) {}
})();
"""

_INGEST_JS = """
(function() {
    var url = window.location.href;
    var title = document.title;
    var body = (document.body ? document.body.innerText : '').substring(0, 3000);
    var cookies = document.cookie.split(';').map(function(c) {
        var parts = c.trim().split('=');
        return { name: parts[0], value: parts.slice(1).join('=') };
    }).slice(0, 20);
    if (window.pywebview && window.pywebview.api) {
        window.pywebview.api.ingest(url, title, body, JSON.stringify(cookies));
    }
})();
"""


class KasaApi:
    def __init__(self):
        self.token = os.environ.get("KASA_BEARER_TOKEN", "")
        self._win = None
        # Gelismis (paranoid) kademe oturumluk kilitlidir; her acilista kilitli baslar.
        self._adv_unlocked = False
        # Boot: kalici 'paranoid' varsa strict'e dusur — agresif kademe yalniz
        # oturum icinde sifreyle acikken aktif olmali (yeniden baslatinca kapanir).
        try:
            cfg = _read_browser_config()
            if cfg.get("privacy_level") == "paranoid":
                cfg["privacy_level"] = "strict"
                with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                    json.dump(cfg, file)
        except Exception:
            pass

    def set_window(self, win):
        self._win = win

    def _verify_origin(self) -> bool:
        if not self._win:
            return False
        try:
            url = self._win.get_current_url()
        except Exception:
            return False
        if not url:
            return True
        if url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or url.startswith("file://") or url.startswith("about:"):
            return True
        print(f"[SECURITY] API block: Origin {url} is not allowed to call privileged JS API.")
        return False

    def ingest(self, url, title, body_text, cookies_json="[]"):
        if not self._verify_origin():
            return
        threading.Thread(
            target=self._post,
            args=(url, title, body_text, cookies_json),
            daemon=True,
        ).start()

    def _post(self, url, title, body_text, cookies_json):
        try:
            payload = json.dumps({
                "tool": "event_ingest",
                "agent_id": "browser",
                "params": {
                    "source": "browser",
                    "type": "page_visit",
                    "content": {
                        "url": url,
                        "title": title,
                        "text": body_text,
                        "cookies": json.loads(cookies_json),
                    },
                    "ttl_days": 30,
                },
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://localhost:8000/v1/ingest",
                data=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=5):
                self._set_status("●", "#2FBF71")
                print(f"[KASA] ingested: {title}")
        except Exception as e:
            self._set_status("!", "#E5484D")
            print(f"[KASA] ingest error: {e}")

    def _set_status(self, message: str, color: str):
        if not self._win:
            return
        try:
            safe = message.replace("'", "\\'")
            self._win.evaluate_js(
                f"var s=document.getElementById('_kasa_status');"
                f"if(s){{s.innerText='{safe}';s.style.color='{color}';}}"
            )
        except Exception:
            pass

    def open_vault(self):
        print("[KASA] open_vault() cagridi — henuz uygulanmadi.")

    # Layer #2 — proxy ayarlari (sidebar 'Ag' bolumunden cagrilir)
    def get_proxy(self):
        return _read_browser_config()

    def set_proxy(self, enabled, address):
        if not self._verify_origin():
            return {"proxy_enabled": False, "proxy_address": ""}
        # MERGE: mevcut config'i oku, sadece proxy anahtarlarini guncelle (privacy_level'i ezme)
        cfg = _read_browser_config()
        cfg["proxy_enabled"] = bool(enabled)
        cfg["proxy_address"] = str(address or "")
        try:
            with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                json.dump(cfg, file)
            print("[KASA] proxy ayarlari kaydedildi (yeniden baslatinca gecerli).")
            return cfg
        except Exception as e:
            print("[KASA] set_proxy hata:", str(e))
            return {"proxy_enabled": False, "proxy_address": ""}

    # Sira 0 — gizlilik seviyesi kaliciligi (Python tarafinda; domain-arasi kalir)
    def get_level(self):
        return _read_browser_config().get("privacy_level") or "strict"

    def set_level(self, level):
        if not self._verify_origin():
            return "strict"
        allowed = ("off", "standard", "strict", "paranoid")
        lvl = level if level in allowed else "strict"
        # GUVENLIK SINIRI (deterministik, JS degil): paranoid = agresif/site-kirabilen kademe;
        # yalniz owner sifresiyle acilmis oturumda secilebilir. Aksi halde reddedilir.
        if lvl == "paranoid" and not self._adv_unlocked:
            print("[KASA] paranoid reddedildi — gelismis mod kilitli (sifre gerekli).")
            return self.get_level()
        cfg = _read_browser_config()  # MERGE
        cfg["privacy_level"] = lvl
        try:
            with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                json.dump(cfg, file)
            print("[KASA] gizlilik seviyesi kaydedildi:", lvl)
            return lvl
        except Exception as e:
            print("[KASA] set_level hata:", str(e))
            return "strict"

    # AI Modeli — sidebar 'Model' panelinden cagrilir. Secim browser_config.json'daki
    # 'agent_model' anahtarina yazilir; distill/engine.py (ve ileride bekci) ayni anahtari okur.
    def list_models(self):
        """Sistemde kurulu (ollama) modelleri listele: [{name, size}]. Servis kapali/hatali -> []."""
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            out = []
            for m in data.get("models", []):
                name = m.get("name")
                if name:
                    out.append({"name": name, "size": m.get("size", 0)})
            return out
        except Exception as e:
            print("[KASA] list_models hata:", str(e))
            return []

    def get_model(self):
        return _read_browser_config().get("agent_model") or "qwen2.5:7b"

    def set_model(self, name):
        # allow-list: yalniz kurulu modeller kabul edilir (uydurma ad config'i bozmasin)
        allowed = {m["name"] for m in self.list_models()}
        if name not in allowed:
            print("[KASA] set_model reddedildi (kurulu degil):", name)
            raise ValueError("model kurulu degil: %s" % name)
        cfg = _read_browser_config()  # MERGE (privacy_level/proxy'yi ezme)
        cfg["agent_model"] = str(name)
        try:
            with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                json.dump(cfg, file)
            print("[KASA] agent modeli kaydedildi:", name)
        except Exception as e:
            print("[KASA] set_model hata:", str(e))
            return self.get_model()
        # SEBEP: bu panel eskiden YALNIZ browser_config.json'a yaziyordu; sohbet ajani ise
        # agent_config.json okuyordu -> kullanicinin UI'dan yaptigi secim ajanda sessizce
        # ETKISIZ kaliyordu. SONUC: secim yetkili depoya da yansitilir, ikisi ayrisamaz.
        # Best-effort: yetkili depo yazilamazsa panel yine calisir (cozucu browser_config'e duser).
        try:
            from ..agent.store import set_selected_model  # gec import: tarayici exe'de yok
            set_selected_model(str(name))
        except Exception as e:
            print("[KASA] set_model: yetkili depoya yansitilamadi:", str(e))
        return name

    # Gelismis (Kilitli) kademe — owner sifresiyle korunur. Sifre PBKDF2-SHA256 hash olarak
    # browser_config.json'da tutulur (asla duz metin); acilis oturumluk (self._adv_unlocked).
    def adv_status(self):
        cfg = _read_browser_config()
        return {"has_password": bool(cfg.get("adv_pw")), "unlocked": bool(self._adv_unlocked)}

    def adv_set_password(self, pw):
        # Yalniz ilk kez (sifre yoksa) ya da acikken degistirilebilir; kilitliyken var olani ezemez.
        cfg = _read_browser_config()
        if cfg.get("adv_pw") and not self._adv_unlocked:
            print("[KASA] adv_set_password reddedildi — once mevcut sifreyle ac.")
            return False
        if not pw or len(str(pw)) < 4:
            return False
        cfg["adv_pw"] = _hash_pw(str(pw))
        try:
            with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                json.dump(cfg, file)
        except Exception as e:
            print("[KASA] adv_set_password hata:", str(e))
            return False
        self._adv_unlocked = True
        return True

    def adv_unlock(self, pw):
        if not self._verify_origin():
            return False
        cfg = _read_browser_config()
        rec = cfg.get("adv_pw")
        if not rec:
            return False
        cand = _hash_pw(str(pw), rec.get("salt"), rec.get("iter", 200000))["hash"]
        ok = secrets.compare_digest(cand, rec.get("hash", ""))
        self._adv_unlocked = bool(ok)
        return bool(ok)

    def adv_lock(self):
        self._adv_unlocked = False
        # Kilitlenince paranoid aciksa strict'e dusur (agresif kademe kilitliyken kalmasin).
        cfg = _read_browser_config()
        if cfg.get("privacy_level") == "paranoid":
            cfg["privacy_level"] = "strict"
            try:
                with open(_BROWSER_CONFIG_PATH, "w", encoding="utf-8") as file:
                    json.dump(cfg, file)
            except Exception:
                pass
        return True


# Layer #2 — Proxy / IP gizleme (iskelet). WebView2 proxy'yi environment olusmadan
# ONCE alir; degisiklik yeniden baslatmayla gecerli olur.
# Turkce not: sabit "d:/kasa/..." YERINE modulun kendi konumundan turetilir
# (src/browser/browser_window.py -> parents[2] = depo koku). Sabit yol, depoyu
# baska bir dizine klonlayan herkeste bu dosyayi bulunamaz yapardi.
_BROWSER_CONFIG_PATH = str(pathlib.Path(__file__).resolve().parents[2] / "browser_config.json")


def _read_browser_config():
    try:
        with open(_BROWSER_CONFIG_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return {"proxy_enabled": False, "proxy_address": ""}
    except Exception as e:
        print("[KASA] browser config okuma hatasi:", str(e))
        return {"proxy_enabled": False, "proxy_address": ""}


def _hash_pw(pw, salt_hex=None, iterations=200000):
    """PBKDF2-HMAC-SHA256 ile sifre hash'i (salt + hash + iter). Duz metin ASLA saklanmaz.
    salt_hex verilirse dogrulama (ayni salt), verilmezse yeni salt (belirleme)."""
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode("utf-8"), salt, iterations)
    return {"salt": salt.hex(), "hash": dk.hex(), "iter": iterations}


def _apply_proxy_env():
    cfg = _read_browser_config()
    addr = (cfg.get("proxy_address") or "").strip()
    if cfg.get("proxy_enabled") and addr:
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = "--proxy-server=" + addr
        print("[KASA] proxy aktif: " + addr)
    else:
        print("[KASA] proxy kapali (dogrudan baglanti).")


def _level_prelude_js():
    # Sira 0 — seviyeyi Python config'ten alip window.__KASA_LEVEL__ olarak yerlestir.
    # _PRIVACY_JS bunu localStorage'dan ONCE okur -> domain-arasi tutarli.
    cfg = _read_browser_config()
    lvl = cfg.get("privacy_level") or "strict"
    # Muhur kalibrasyonu (b1_seal): KASA_PRIVACY_LEVEL env ile injection-OFF baseline kosulabilir.
    # SADECE dusuk-yetki seviyeleri (off/standard/strict); 'paranoid' ASLA env ile acilmaz
    # (owner-gate bypass olmasin) + oturumluk/efemeral (config'i kirletmez, ilke-5).
    env_lvl = os.environ.get("KASA_PRIVACY_LEVEL")
    if env_lvl in ("off", "standard", "strict"):
        lvl = env_lvl
    if lvl not in ("off", "standard", "strict", "paranoid"):
        lvl = "strict"
    return "window.__KASA_LEVEL__=" + json.dumps(lvl) + ";"


def _register_early_privacy(win):
    """Layer #1 — CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync ile _PRIVACY_JS'i
    sayfa scriptlerinden ONCE calistir. Tum sonraki navigasyonlarda gecerli.
    Boylece PerimeterX/Akamai gercek parmak izini okuyamadan spoof devreye girer."""
    try:
        from webview.platforms.winforms import BrowserView
        from System import Action

        instance = BrowserView.instances.get(win.uid)
        if instance is None:
            return False

        def inner():
            core = instance.browser.webview.CoreWebView2
            if core is None:
                return
            # Cloudflare/Turnstile fix: WebView2'nin yerlesik Tracking Prevention'i
            # challenges.cloudflare.com storage'ini kesip challenge'i sonsuz 403 dongusune
            # sokuyordu. Basic (1) kotu tracker'lari hala engeller ama mesru challenge
            # storage'ina izin verir. (0=None, 1=Basic, 2=Balanced=default, 3=Strict)
            try:
                core.Profile.PreferredTrackingPreventionLevel = 1
            except Exception as e:
                print(f"[KASA] tracking prevention ayari: {e}")
            try:
                # Once seviye prelude'u (window.__KASA_LEVEL__), sonra spoof — sirali calisir
                core.AddScriptToExecuteOnDocumentCreatedAsync(_level_prelude_js())
                core.AddScriptToExecuteOnDocumentCreatedAsync(_PRIVACY_JS)
                print("[KASA] erken enjeksiyon kaydedildi (pre-load spoof + seviye aktif).")
            except Exception as e:
                print(f"[KASA] erken enjeksiyon: {e}")

        instance.BeginInvoke(Action(inner))
        return True
    except Exception as e:
        print(f"[KASA] erken enjeksiyon: {e}")
        return False


# ---- B1 cold-session bootstrap (ilke-7) -------------------------------------------------
# Kok-neden: _register_early_privacy on_loaded'da (ilk sayfa YUKLENDIKTEN sonra) cagriliyordu;
# AddScriptToExecuteOnDocumentCreatedAsync yalniz KENDINDEN SONRAKI dokumanlara isler -> cold
# pass==1 spoof'suz gidiyordu. Cozum: inline-html bootstrap ile ac, erken scriptleri KAYDET,
# kayit TAMAMLANINCA (deterministik) gercek url'e git -> sunucunun gordugu ILK istek spoof'lu.
# NOT (ikinci-acik onleme): "about:blank" pywebview'de is_local_url=True olup d:\kasa'yi
# (kasa.db dahil) servis eden kimlik-dogrulamasiz localhost sunucusu baslatir; bu yuzden
# create_window'a html= verilir (original_url=None -> sunucu HIC baslamaz).
# Cekirdek mantik CLR-bagimsiz + GUI'siz test edilir; canli CoreWebView2 davranisi Kapi-2 bekler.

# Bootstrap dokumani: ag istegi/parmak-izi yuzeyi uretmeyen inert inline html.
_BOOTSTRAP_HTML = "<!doctype html><meta charset='utf-8'><title>KASA</title>"

# Fail-audible olay gunlugu (ilke: guvenlik urununde SESSIZ fail-open yasak).
_B1_EVENT_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "_orch", "b1_security_events.log")


def _audit_b1(reason):
    """FAIL-AUDIBLE: B1 korumasi bir fallback yoluna dustuyse (erken enjeksiyon kaydedilemedi ->
    ilk istek spoof'suz gidebilir) bunu DENETLENEBILIR bir olaya yazar. "Bugunku davranis = taban"
    aslinda sizdiran davranis oldugundan, sessiz fail-open bir guvenlik-dusumudur; bu gunluk onu
    gorunur kilar (guvenlik-bench/kullanici tespit eder). Erisilebilirlik icin bloklamiyoruz."""
    import json as _json
    import time as _time
    rec = {"ts": _time.strftime("%Y-%m-%dT%H:%M:%S"),
           "event": "b1_protection_fallback", "reason": reason}
    try:
        os.makedirs(os.path.dirname(_B1_EVENT_LOG), exist_ok=True)
        with open(_B1_EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(_json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(f"[KASA][GUVENLIK] B1 fallback (denetlenebilir): {reason}")


def _make_navigate_once(load_url, on_error=None):
    """Idempotent navigasyon: bootstrap-continuation VE watchdog ayni anda tetiklense bile
    load_url YALNIZ BIR KEZ cagrilir. Thread-safe. load_url ISTISNA firlatirsa (pywebview
    @_shown_call ~20s'te WebViewException) done GERI ALINIR -> on_loaded/watchdog yeniden dener
    (asili-blank regresyonu kapatilir). navigate.done() gerceklesip gerceklesmedigini doner."""
    state = {"done": False}
    lock = threading.Lock()

    def navigate(url):
        with lock:
            if state["done"]:
                return False
            state["done"] = True
        try:
            load_url(url)
        except Exception as e:
            with lock:
                state["done"] = False  # GERI AL -> yeniden deneme mumkun; asili-blank olmaz
            if on_error:
                on_error(f"navigate_load_url_failed:{e}")
            return False
        return True

    navigate.done = lambda: state["done"]
    return navigate


def _bootstrap_privacy_navigation(core, navigate, real_url, early_js):
    """B1 cekirdek DEGISMEZI (ilke-7): erken privacy scripti GERCEK navigasyondan ONCE kaydedilsin.
    Sira: (1) tracking prevention, (2) AddScript(early_js) -> task, (3) task TAMAMLANINCA (kayit
    dokuman-oncesi etkin) -> navigate(real_url). 'core': set_tracking/add_script/when_ready arayuzu.
    Navigate YALNIZ when_ready callback'inde; asla eager degil -> yaris TANIM GEREGI yok
    (zamanlamaya degil, WebView2'nin kayit-tamamlama garantisine dayanir).
    FAIL-OPEN YOK: bir adim patlarsa EXCEPTION YUKARI verilir (navigate ETMEZ). Cold ilk-nav
    fail-closed politikasi (bkz _inject_with_retry) enjeksiyonsuz gercek navigasyonu engeller."""
    core.set_tracking(1)
    task = core.add_script(early_js)
    core.when_ready(task, lambda: navigate(real_url))


def _watchdog_action(navigated, registered):
    """Watchdog karari (saf/test edilebilir), FAIL-CLOSED uyumlu:
      navigated True                   -> 'noop'       (zaten gidildi)
      not navigated + registered True  -> 'navigate'   (kayit VAR, sadece nav gecikti -> guvenli)
      not navigated + registered False -> 'failclosed' (kayit YOK -> enjeksiyonsuz real'e GITME).
    Boylece watchdog fail-closed dalini fail-OPEN'a cevirmez (acik bir kat asagida geri uretilmez)."""
    if navigated:
        return "noop"
    return "navigate" if registered else "failclosed"


def _inject_with_retry(get_core, register, show_error, max_attempts=3):
    """Cold ilk-nav FAIL-CLOSED (owner karari, 2 sartla): (b) NAVIGASYONU degil ENJEKSIYONU tekrar
    dener -> her deneme ayri korunmasiz cold-first istek uretmez; gercek origin'e ancak kayit
    dispatch edilince gidilir. Tum denemeler basarisizsa show_error() -> (a) INERT hata (localhost/
    navigasyon YOK). Doner: True=kayit dispatch edildi, False=fail-closed (enjeksiyonsuz gidilmedi)."""
    for _ in range(max_attempts):
        try:
            core = get_core()
        except Exception:
            core = None
        if core is not None:
            try:
                register(core)
                return True
            except Exception:
                pass  # kayit patladi -> NAVIGATE ETME, enjeksiyonu tekrar dene
    show_error()
    return False


# FAIL-CLOSED hata gorunumu: MEVCUT inert html= dokumaninin uzerine JS ile mesaj basar.
# Navigasyon/localhost/data: YOK -> hata yolu kapatilan localhost sunucusunu geri uyandirmaz (kosul-a).
_INERT_ERROR_JS = (
    "document.title='KASA koruma dogrulanamadi';"
    "document.body.innerHTML='<div style=\"font:16px system-ui;padding:40px;color:#b00\">"
    "KASA gizlilik korumasi bu oturumda dogrulanamadi; guvenlik icin sayfa ACILMADI "
    "(enjeksiyonsuz ilk istek engellendi). Pencereyi kapatip yeniden deneyin.</div>';"
)


def _show_inert_error(win):
    """Cold fail-closed: mevcut inert dokuman uzerine hata mesaji (evaluate_js). Gercek origin'e
    enjeksiyonsuz GIDILMEDIGI icin sizinti olmaz; localhost sunucusu da uyandirilmaz."""
    try:
        win.evaluate_js(_INERT_ERROR_JS)
    except Exception as e:
        print(f"[KASA] inert hata gosterimi: {e}")


class _WinformsCore:
    """Canli CoreWebView2'yi _bootstrap_privacy_navigation arayuzune sarar (CLR-ozel).
    when_ready: AddScript'in dondurdugu Task TAMAMLANINCA (= kayit dokuman-oncesi etkin oldugunda)
    navigate'i zincirler -> DETERMINISTIK (zamanlama-varsayimi degil, runtime garantisi). Tek Task
    + tek ContinueWith kullanilir (WhenAll().Unwrap() kirilganligindan kacinilir; iki script tek
    early_js'de birlestirilmistir). KAPI-2: bu ContinueWith'in canli fire ettigi cold-olcumle
    dogrulanir; fire etmezse watchdog (kayit zaten ~ms'de bitmis olacagindan yine spoof'lu) devreye
    girer ve _audit_b1 olayi yazilir."""

    def __init__(self, core):
        self._core = core

    def set_tracking(self, level):
        # Cloudflare/Turnstile fix (challenges.cloudflare.com storage'i kesilmesin): Basic=1.
        try:
            self._core.Profile.PreferredTrackingPreventionLevel = level
        except Exception as e:
            print(f"[KASA] tracking prevention ayari: {e}")

    def add_script(self, js):
        return self._core.AddScriptToExecuteOnDocumentCreatedAsync(js)

    def when_ready(self, task, cb):
        from System import Action
        from System.Threading.Tasks import Task
        # Kayit TAMAMLANINCA navigate -> dokuman-oncesi kayit garantili (deterministik).
        task.ContinueWith(Action[Task](lambda t: cb()))


def _bootstrap_on_blank(win, real_url, navigate, registered):
    """Bootstrap (inert html=) turunda erken privacy'yi KAYDEDIP kayit tamamlaninca gercek url'e
    gider. Cold ilk-nav FAIL-CLOSED: CoreWebView2 hazir olana kadar (retry) beklenir; kayit
    dispatch edilene kadar gercek origin'e GIDILMEZ; hicbir deneme tutmazsa INERT hata gosterilir
    (localhost/navigasyon YOK). Async kayit-hatasi durumunda registered False kalir -> watchdog
    fail-closed'i uygular. Iki script tek early_js'de (prelude ONCE, privacy SONRA -> tek Task)."""
    early_js = _level_prelude_js() + "\n;\n" + _PRIVACY_JS

    def _get_core():
        from webview.platforms.winforms import BrowserView  # CLR; hazir degilse retry
        instance = BrowserView.instances.get(win.uid)
        if instance is None:
            raise RuntimeError("BrowserView instance hazir degil")
        core = getattr(instance.browser.webview, "CoreWebView2", None)
        if core is None:
            raise RuntimeError("CoreWebView2 hazir degil")
        return instance, core

    def _register(ic):
        instance, core = ic
        from System import Action

        def _do():
            # Kayit patlarsa registered False kalir + navigate cagrilmaz -> watchdog fail-closed.
            _bootstrap_privacy_navigation(_WinformsCore(core), navigate, real_url, early_js)
            registered["done"] = True

        instance.BeginInvoke(Action(_do))

    ok = _inject_with_retry(
        _get_core, _register,
        lambda: (_audit_b1("cold_failclosed_no_injection"), _show_inert_error(win)))
    if ok:
        print("[KASA] B1 bootstrap: kayit dispatch edildi (deterministik), navigasyon zincirlenecek.")


#: Opt-in switch for the experimental browser. Unset -> the browser refuses to start.
BROWSER_ENABLE_ENV = "KASA_ENABLE_BROWSER"

_BROWSER_DISABLED_MSG = (
    "KASA browser is DISABLED by default in this release.\n"
    "\n"
    "Reason (measured, see SECURITY.md 'Known-unsafe surfaces'): the pywebview JS API\n"
    "bridge (js_api=) lives in the *visited page's* JavaScript context, and page scripts\n"
    "are injected on every load with no origin check. Any site you visit can therefore\n"
    "call window.pywebview.api.* directly -- including set_proxy() (traffic redirection)\n"
    "and ingest() (writing arbitrary content into the vault).\n"
    "\n"
    "This is a design-level issue, not a typo: pywebview's js_api is per-window, not\n"
    "per-origin, so nothing placed in page context can be hidden from the page. The fix\n"
    "requires moving privileged UI out of page context and is tracked on the roadmap.\n"
    "\n"
    "To run it anyway (isolated VM / throwaway profile / no real data ONLY):\n"
    "    set KASA_ENABLE_BROWSER=1\n"
)


def browser_enabled() -> bool:
    """True only when the operator explicitly opted in via the environment."""
    return os.environ.get(BROWSER_ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def open_browser(url: str = "https://lite.duckduckgo.com/lite"):
    # Fail closed BEFORE any side effect: no proxy env applied, no window, no bridge.
    #
    # Turkce not: bu kapi bilerek fonksiyonun ILK satirinda. Asagidaki _apply_proxy_env()
    # surec ortamini degistirir ve create_window(js_api=...) kopruyu kurar; kapi daha
    # sonra olsaydi "kapali" durumda bile bu yan etkiler olusurdu. Fail-closed demek,
    # supheye dusuldugunde ACILMAMAK demektir -- uyari basip devam etmek degil.
    if not browser_enabled():
        raise RuntimeError(_BROWSER_DISABLED_MSG)

    _hc_url = os.environ.get("KASA_HEALTHCHECK_URL")
    if _hc_url:
        url = _hc_url
    real_url = url
    _apply_proxy_env()  # Layer #2: proxy'yi WebView2 olusmadan ONCE uygula
    # Fix: reklam/_blank linkleri harici Chrome yerine AYNI pencerede ac
    # (pywebview on_new_window_request bu ayar False iken self.load_url kullanir)
    webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False
    api = KasaApi()
    # B1 (ilke-7): inline-html ile ac -> erken privacy KAYDEDILDIKTEN sonra gercek url'e git.
    # html= (about:blank DEGIL): about:blank pywebview'de is_local_url=True olup d:\kasa'yi
    # (kasa.db dahil) servis eden kimlik-dogrulamasiz localhost sunucusu baslatir (ikinci-acik).
    # html= -> original_url=None -> sunucu HIC baslamaz; inert dokuman ag/parmak-izi yuzeyi uretmez.
    win = webview.create_window(
        "KASA Browser",
        html=_BOOTSTRAP_HTML,
        js_api=api,
        width=1280,
        height=860,
    )
    api.set_window(win)

    navigate = _make_navigate_once(win.load_url, on_error=_audit_b1)
    _registered = {"done": False}

    # Availability watchdog (#2b) + FAIL-CLOSED uyumu: ~3s icinde navigasyon olmadiysa KARAR
    # _watchdog_action'a birakilir. Kayit VARSA guvenli taban navigasyon; kayit YOKSA gercek
    # origin'e enjeksiyonsuz GITMEZ (fail-closed): inert hata + denetlenebilir olay. Boylece
    # watchdog, cold fail-closed'i bir kat asagida fail-OPEN'a cevirmez.
    def _watchdog():
        try:
            time.sleep(3.0)
            action = _watchdog_action(navigate.done(), _registered["done"])
            if action == "navigate":
                print("[KASA] B1 watchdog: kayit var, nav gecikti -> navigasyon.")
                navigate(real_url)
            elif action == "failclosed":
                _audit_b1("watchdog_failclosed_no_registration")
                _show_inert_error(win)  # enjeksiyonsuz real'e GITME
        except Exception:
            pass
    threading.Thread(target=_watchdog, daemon=True).start()

    if _hc_url:
        # Otonom dongu saglik kapisi (browser_gate.py) icin: sure dolunca kendini kapat.
        # KASA_CAPTURE_OUT verilirse kapanmadan once sayfadan JS ile veri toplayip dosyaya yazar
        # (disaridan rapor/fingerprint denetimi icin, orn. coveryourtracks.eff.org).
        def _autoclose():
            try:
                # #6: geri-sayimi GERCEK navigasyon baslayana kadar beklet (max 3s) ki capture
                # about:blank'i degil gercek sayfayi yakalasin.
                _w = 0.0
                while not navigate.done() and _w < 3.0:
                    time.sleep(0.05)
                    _w += 0.05
                time.sleep(int(os.environ.get("KASA_HEALTHCHECK_MS", "9000")) / 1000.0)
                _capture_out = os.environ.get("KASA_CAPTURE_OUT")
                if _capture_out:
                    js = os.environ.get("KASA_CAPTURE_JS", "document.body.textContent")
                    try:
                        result = win.evaluate_js(js)
                    except Exception as e:
                        result = "CAPTURE_ERROR: " + str(e)
                    with open(_capture_out, "w", encoding="utf-8") as f:
                        f.write(result or "")
                win.destroy()
            except Exception:
                pass
        threading.Thread(target=_autoclose, daemon=True).start()

    def on_loaded():
        # Ilk (inline-html bootstrap) loaded: erken privacy'yi KAYDET, kayit tamamlaninca gercek
        # url'e git. Bootstrap turunda UI enjekte etme (toolbar/sidebar inert dokumana girmez).
        if not navigate.done():
            _bootstrap_on_blank(win, real_url, navigate, _registered)
            return

        # Gercek sayfa (ve sonraki kullanici navigasyonlari): bugunku davranis bit-bit ayni.
        # Taban: bootstrap erken kayit yapamadiysa (instance/core alinamadi) burada kaydet.
        if not _registered["done"]:
            _registered["done"] = _register_early_privacy(win)

        # CSS token'larini global degisken olarak yerlestir; toolbar JS okusun
        escaped = _DESIGN_CSS.replace("\\", "\\\\").replace("`", "\\`")
        win.evaluate_js(f"window.__KASA_DESIGN_CSS__ = `{escaped}`;")
        # Sira 0: seviyeyi _PRIVACY_JS'ten ONCE yerlestir (post-load fallback yolu icin)
        win.evaluate_js(_level_prelude_js())
        # _PRIVACY_JS post-load fallback (idempotent guard var)
        win.evaluate_js(_PRIVACY_JS)
        win.evaluate_js(_TOOLBAR_JS)
        win.evaluate_js(_SIDEBAR_JS)
        win.evaluate_js(_INGEST_JS)

    win.events.loaded += on_loaded

    # Yeni pencere / sekme isteklerini ayni pencerede ac
    def on_new_window(event):
        try:
            target_url = event.url if hasattr(event, "url") else str(event)
            win.load_url(target_url)
        except Exception as e:
            print(f"[KASA] new_window_requested error: {e}")

    try:
        win.events.new_window_requested += on_new_window
    except AttributeError:
        pass  # Eski pywebview versiyonlarinda bu olay yoktur

    # debug=True -> DevTools + sag-tik "Inspect" + F12 acilir (pywebview _state['debug'])
    webview.start(debug=True)


if __name__ == "__main__":
    open_browser()
