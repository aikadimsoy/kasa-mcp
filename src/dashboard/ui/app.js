// kasa/dashboard_ui/app.js
// Uretim: yerel model (qwen2.5-coder:14b, zero-token). Opus: spec + guvenlik-denetimi + splice.
// Guvenlik: yalniz same-origin relative fetch (/v1/dashboard/*), bearer header,
// createElement+textContent (innerHTML/eval yok). 4 gorunum + rail router.

const TITLES = {
  dashboard: "Güvenlik Panosu",
  events: "Olaylar",
  profile: "Profil",
  security: "Güvenlik Merkezi",
  ajan: "Ajan",
  audit: "Sistem Denetimi"
};

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString('tr-TR');
}

function statusPill(masked) {
  const pill = document.createElement('span');
  pill.className = masked ? 'pill masked' : 'pill raw';
  pill.textContent = masked ? 'maskeli' : 'ham';
  return pill;
}

function renderBars(container, byType) {
  container.replaceChildren();
  if (Object.keys(byType).length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty';
    emptyDiv.textContent = 'Maskesiz sır yok — temiz.';
    container.appendChild(emptyDiv);
  } else {
    const max = Math.max(...Object.values(byType));
    const denom = max || 1;
    for (const [type, count] of Object.entries(byType)) {
      const barDiv = document.createElement('div');
      barDiv.className = 'bar';

      const rowDiv = document.createElement('div');
      rowDiv.className = 'row';
      const labelSpan = document.createElement('span');
      labelSpan.textContent = { entropy: "Entropi ağı", base64: "Base64", cred: "Kredensiyel", hex: "Hex", phrase: "İfade" }[type] || type;
      rowDiv.appendChild(labelSpan);
      const countSpan = document.createElement('span');
      countSpan.className = 'n';
      countSpan.textContent = count;
      rowDiv.appendChild(countSpan);
      barDiv.appendChild(rowDiv);

      const trackDiv = document.createElement('div');
      trackDiv.className = 'track';
      const fillDiv = document.createElement('div');
      fillDiv.className = `fill ${type}`;
      fillDiv.style.width = `${Math.round((count / denom) * 100)}%`;
      trackDiv.appendChild(fillDiv);
      barDiv.appendChild(trackDiv);

      container.appendChild(barDiv);
    }
  }
}

function createPostureRow(label, sub, state, color) {
  const prowDiv = document.createElement('div');
  prowDiv.className = 'prow';

  const kSpan = document.createElement('span');
  kSpan.className = 'k';
  kSpan.textContent = label;
  const small = document.createElement('small');
  small.textContent = sub;
  kSpan.appendChild(small);
  prowDiv.appendChild(kSpan);

  const vSpan = document.createElement('span');
  vSpan.className = 'v';

  const dotSpan = document.createElement('span');
  dotSpan.className = `dot ${color}`;
  vSpan.appendChild(dotSpan);

  vSpan.appendChild(document.createTextNode(state));
  prowDiv.appendChild(vSpan);

  return prowDiv;
}

function renderDashboard(stats, events) {
  document.getElementById('kpi-events-total').textContent = stats.events.total;
  document.getElementById('kpi-events-meta').textContent = `${stats.events.distilled} damıtılmış · ${stats.events.pending} bekleyen`;
  document.getElementById('kpi-masked').textContent = stats.redaction.masked_markers;
  document.getElementById('kpi-live').textContent = stats.redaction.live_secrets_found;
  const auditDot = document.getElementById('kpi-audit-dot');
  auditDot.className = stats.audit.chain_valid ? 'dot secure' : 'dot danger';
  document.getElementById('kpi-audit').textContent = stats.audit.chain_valid ? "Bütün" : "BOZUK";
  document.getElementById('kpi-audit-records').textContent = stats.audit.records;
  const atRestStatus = { full: "Tam (hücre)", partial: "Kısmi" }[stats.at_rest.cell_encryption.status] || "Yok";
  document.getElementById('kpi-atrest').textContent = atRestStatus;
  document.getElementById('kpi-atrest-meta').textContent = `hücre ${stats.at_rest.cell_encryption.status} · tam-DB ${stats.at_rest.full_db.status}`;

  const recentTbody = document.getElementById('dash-recent-tbody');
  recentTbody.replaceChildren();
  if (events.length === 0) {
    const emptyTr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'empty';
    td.textContent = 'Kayıt yok.';
    emptyTr.appendChild(td);
    recentTbody.appendChild(emptyTr);
  } else {
    for (const ev of events.slice(0, 6)) {
      const tr = document.createElement('tr');
      const idTd = document.createElement('td');
      idTd.className = 'mono';
      idTd.textContent = ev.id;
      tr.appendChild(idTd);

      const typeTd = document.createElement('td');
      typeTd.textContent = ev.type;
      tr.appendChild(typeTd);

      const sourceTd = document.createElement('td');
      sourceTd.className = 'src';
      sourceTd.textContent = ev.source;
      tr.appendChild(sourceTd);

      const statusTd = document.createElement('td');
      statusTd.appendChild(statusPill(ev.masked));
      tr.appendChild(statusTd);

      recentTbody.appendChild(tr);
    }
  }

  renderBars(document.getElementById('redaction-bars'), stats.redaction.live_by_type);
}

function renderEvents(events) {
  document.getElementById('events-count').textContent = `${events.length} kayıt · maskeli`;

  const eventsTbody = document.getElementById('events-tbody');
  eventsTbody.replaceChildren();
  if (events.length === 0) {
    const emptyTr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'empty';
    td.textContent = 'Kayıt yok.';
    emptyTr.appendChild(td);
    eventsTbody.appendChild(emptyTr);
  } else {
    for (const ev of events) {
      const tr = document.createElement('tr');

      const idTd = document.createElement('td');
      idTd.className = 'mono';
      idTd.textContent = ev.id;
      tr.appendChild(idTd);

      const timestampTd = document.createElement('td');
      timestampTd.className = 'mono';
      timestampTd.textContent = fmtTime(ev.timestamp);
      tr.appendChild(timestampTd);

      const typeTd = document.createElement('td');
      typeTd.textContent = ev.type;
      tr.appendChild(typeTd);

      const sourceTd = document.createElement('td');
      sourceTd.className = 'src';
      sourceTd.textContent = ev.source;
      tr.appendChild(sourceTd);

      const statusTd = document.createElement('td');
      statusTd.appendChild(statusPill(ev.masked));
      tr.appendChild(statusTd);

      eventsTbody.appendChild(tr);
    }
  }
}

function renderProfile(profile) {
  document.getElementById('profile-count').textContent = `${profile.length} anahtar`;

  const profileTbody = document.getElementById('profile-tbody');
  profileTbody.replaceChildren();
  if (profile.length === 0) {
    const emptyTr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'empty';
    td.textContent = 'Kayıt yok.';
    emptyTr.appendChild(td);
    profileTbody.appendChild(emptyTr);
  } else {
    for (const p of profile) {
      const tr = document.createElement('tr');

      const keyTd = document.createElement('td');
      keyTd.className = 'mono';
      keyTd.textContent = p.key;
      tr.appendChild(keyTd);

      const valueTd = document.createElement('td');
      valueTd.className = 'val';
      valueTd.textContent = (p.value == null ? "—" : (typeof p.value === "string" ? p.value : JSON.stringify(p.value)));
      tr.appendChild(valueTd);

      const provenanceTd = document.createElement('td');
      provenanceTd.textContent = `${p.provenance_count} olay`;
      tr.appendChild(provenanceTd);

      const updatedAtTd = document.createElement('td');
      updatedAtTd.className = 'mono';
      updatedAtTd.textContent = fmtTime(p.updated_at);
      tr.appendChild(updatedAtTd);

      profileTbody.appendChild(tr);
    }
  }
}

function renderSecurity(stats) {
  const postureDiv = document.getElementById('posture');
  postureDiv.replaceChildren(
    createPostureRow("Anahtar yönetimi", stats.at_rest.key_management.scheme, "korumalı", "secure"),
    createPostureRow("Hücre şifreleme", `${stats.at_rest.cell_encryption.algo} · ${stats.at_rest.cell_encryption.encrypted_cells}/${stats.at_rest.cell_encryption.total_cells} hücre`, stats.at_rest.cell_encryption.status, ({ full: "secure", partial: "warn" }[stats.at_rest.cell_encryption.status]) || "danger"),
    createPostureRow("Tam-DB at-rest", stats.at_rest.full_db.scheme, stats.at_rest.full_db.status, stats.at_rest.full_db.status === "pending" ? "warn" : "secure"),
    createPostureRow("Audit bütünlüğü", "SHA-256 hash-chain", stats.audit.chain_valid ? "doğrulandı" : "BOZUK", stats.audit.chain_valid ? "secure" : "danger")
  );

  renderBars(document.getElementById('sec-redaction-bars'), stats.redaction.live_by_type);
}

async function fetchJSON(url) {
  const res = await fetch(url, {
    headers: { Authorization: "Bearer " + window.KASA_TOKEN }
  });
  if (!res.ok) throw new Error(url + " " + res.status);
  return res.json();
}

async function init() {
  try {
    const [stats, ev, pr] = await Promise.all([
      fetchJSON('/v1/dashboard/stats'),
      fetchJSON('/v1/dashboard/events?limit=50'),
      fetchJSON('/v1/dashboard/profile')
    ]);
    document.getElementById('generated-at').textContent = fmtTime(stats.generated_at);
    renderDashboard(stats, ev.events || []);
    renderEvents(ev.events || []);
    renderProfile(pr.profile || []);
    renderSecurity(stats);
    setupRouter();
    document.getElementById('status').style.display = 'none';
  } catch (err) {
    const st = document.getElementById('status');
    st.className = 'err';
    st.style.display = 'block';
    st.textContent = 'Panoya bağlanılamadı: ' + err.message;
  }
}

function setupRouter() {
  const railButtons = document.querySelectorAll('button[data-view]');
  for (const button of railButtons) {
    if (!button.classList.contains('locked') && !button.disabled) {
      button.addEventListener('click', () => {
        const view = button.getAttribute('data-view');
        for (const section of document.querySelectorAll('.view')) {
          section.hidden = true;
        }
        document.getElementById(`view-${view}`).hidden = false;

        for (const btn of railButtons) {
          btn.classList.remove('active');
        }
        button.classList.add('active');

        document.getElementById('page-title').textContent = TITLES[view];
      });
    }
  }
}

if (document.readyState === 'loading') {
  addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// ============================================================================
// AJAN gorunumu — yerel model + arac koprusu. Uretim: yerel model (deepseek->qwen,
// zero-token). Opus: spec + guvenlik denetimi (innerHTML/eval yok; yalniz same-origin
// /v1/agent/*; textContent-only) + splice (cift-init kaldirildi, lazy-once guard eklendi).
// ============================================================================

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${window.KASA_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { const e = await res.json(); detail = e.detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

const _ajanHistory = [];
function ajanChatHistory() {
  while (_ajanHistory.length > 20) { _ajanHistory.shift(); }
  return _ajanHistory;
}

async function loadAjanModels() {
  try {
    const models = await fetchJSON('/v1/agent/models');
    const statusEl = document.querySelector('#ajan-model-status');
    const list = document.querySelector('#ajan-model-list');
    list.replaceChildren();
    if (!models.service_up) {
      statusEl.textContent = "Yerel model servisi kapalı — modeller listelenemiyor.";
      return;
    }
    statusEl.textContent = '';
    (models.models || []).forEach(model => {
      const chip = document.createElement('div');
      chip.className = 'model-chip' + (model.name === models.selected ? ' sel' : '');
      const nameSpan = document.createElement('span');
      nameSpan.textContent = model.name;
      const st = document.createElement('span');
      st.className = 'st';
      st.textContent = model.name === models.selected ? "seçili" : "seç";
      chip.appendChild(nameSpan);
      chip.appendChild(st);
      list.appendChild(chip);
      chip.addEventListener('click', async () => {
        try {
          await postJSON('/v1/agent/model', { name: model.name });
          loadAjanModels();
        } catch (e) {
          statusEl.textContent = `Hata: ${e.message}`;
        }
      });
    });
  } catch (e) {
    document.querySelector('#ajan-model-status').textContent = `Hata: ${e.message}`;
  }
}

// Guvenli hafif markdown temizligi (innerHTML YOK): baslik #, kod citi, madde isaretleri
// normalize; satir sonlari korunur (CSS pre-wrap). ** ** renderRichText'te <b>'ye donusur.
function cleanReply(text) {
  return String(text)
    .replace(/\r/g, '')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/`{1,3}/g, '')
    .replace(/^\s*[-*]\s+/gm, '• ')
    .trim();
}

// **bold** segmentlerini <b> yapar; gerisi textNode. innerHTML/eval kullanMAZ.
function renderRichText(el, text) {
  const parts = String(text).split(/\*\*(.+?)\*\*/g); // tek indeksler = kalin
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      const b = document.createElement('b');
      b.textContent = part;
      el.appendChild(b);
    } else if (part) {
      el.appendChild(document.createTextNode(part));
    }
  });
}

function appendAjanMsg(role, text) {
  const isMe = role === 'user';
  const isErr = role === 'err';
  const msg = document.createElement('div');
  msg.className = 'msg ' + (isMe ? 'me' : (isErr ? 'ai err' : 'ai'));
  const who = document.createElement('div');
  who.className = 'who';
  who.textContent = isMe ? 'Sen' : 'Ajan';
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  if (isMe || isErr) { bubble.textContent = text; }
  else { renderRichText(bubble, cleanReply(text)); }
  msg.appendChild(who);
  msg.appendChild(bubble);
  const log = document.getElementById('ajan-log');
  log.appendChild(msg);
  log.scrollTop = log.scrollHeight;
}

function renderAjanTrace(trace) {
  const box = document.querySelector('#ajan-trace');
  box.replaceChildren();
  if (!trace || trace.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty';
    emptyDiv.textContent = "Araç çağrısı olmadı.";
    box.appendChild(emptyDiv);
    return;
  }
  trace.forEach(entry => {
    const row = document.createElement('div');
    row.className = 'trow';
    const step = document.createElement('span');
    step.className = 'step';
    step.textContent = `#${entry.step}`;
    const type = document.createElement('span');
    type.className = 'ttype ' + entry.type;
    type.textContent = entry.type;
    row.appendChild(step);
    row.appendChild(type);
    if (entry.tool) {
      const tool = document.createElement('span');
      tool.className = 'tool';
      tool.textContent = entry.tool;
      row.appendChild(tool);
    }
    const detail = document.createElement('span');
    detail.className = 'td';
    detail.textContent = entry.detail;
    row.appendChild(detail);
    box.appendChild(row);
  });
}

async function sendAjanChat() {
  const input = document.querySelector('#ajan-input');
  const inputText = input.value.trim();
  if (!inputText) return;
  const btn = document.querySelector('#ajan-send');
  const busyDiv = document.querySelector('#ajan-busy');
  btn.disabled = true;
  busyDiv.hidden = false;
  appendAjanMsg('user', inputText);
  input.value = '';
  _ajanHistory.push({ role: 'user', content: inputText });
  try {
    const response = await postJSON('/v1/agent/chat',
      { message: inputText, history: ajanChatHistory().slice(0, -1) });
    appendAjanMsg('ai', response.reply || "(boş yanıt)");
    _ajanHistory.push({ role: 'assistant', content: response.reply || "" });
    renderAjanTrace(response.trace || []);
  } catch (e) {
    appendAjanMsg('err', `Hata: ${e.message}`);
  } finally {
    btn.disabled = false;
    busyDiv.hidden = true;
  }
}

let _ajanModelsLoaded = false;
function setupAjan() {
  const railBtn = document.querySelector('[data-view="ajan"]');
  if (railBtn) {
    railBtn.addEventListener('click', () => {
      if (!_ajanModelsLoaded) { _ajanModelsLoaded = true; loadAjanModels(); }
    });
  }
  const sendBtn = document.querySelector('#ajan-send');
  if (sendBtn) { sendBtn.addEventListener('click', sendAjanChat); }
  const inputField = document.querySelector('#ajan-input');
  if (inputField) {
    inputField.addEventListener('keydown', event => {
      if (event.ctrlKey && event.key === 'Enter') { sendAjanChat(); }
    });
  }
}

if (document.readyState === 'loading') {
  addEventListener('DOMContentLoaded', setupAjan);
} else {
  setupAjan();
}

// ============================================================================
// YARIŞ MODU (Race Mode) — ayni soruyu 2-4 YEREL modele sor, yan yana karsilastir, sec.
// Atoms.dev "Race Mode" deseninden ilham (yalniz yerel; air-gap korunur). Uretim: yerel
// model (deepseek->qwen). Opus: guvenlik denetimi (innerHTML/eval yok; same-origin) + splice
// (busy 'hidden' yonetimi duzeltildi; olu _raceLoaded kaldirildi).
// ============================================================================

async function loadRaceModels() {
  try {
    const data = await fetchJSON('/v1/agent/models');
    const box = document.getElementById('race-models');
    if (!data.service_up) {
      box.textContent = "Yerel model servisi kapalı.";
      return;
    }
    box.replaceChildren();
    box.className = 'race-picks';
    (data.models || []).forEach(model => {
      const label = document.createElement('label');
      label.className = 'race-pick';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.value = model.name;
      label.appendChild(input);
      label.appendChild(document.createTextNode(model.name));
      box.appendChild(label);
    });
  } catch (e) {
    document.getElementById('race-models').textContent = `Hata: ${e.message}`;
  }
}

function selectedRaceModels() {
  const cbs = document.querySelectorAll('#race-models input[type="checkbox"]');
  return Array.from(cbs).filter(cb => cb.checked).map(cb => cb.value);
}

function renderRaceResults(results) {
  const box = document.getElementById('race-results');
  box.replaceChildren();
  if (!results || results.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty';
    emptyDiv.textContent = "Sonuç yok.";
    box.appendChild(emptyDiv);
    return;
  }
  results.forEach(result => {
    const col = document.createElement('div');
    col.className = 'race-col' + (result.error ? ' err' : '');

    const header = document.createElement('div');
    header.className = 'rc-model';
    header.textContent = result.model;
    col.appendChild(header);

    if (result.error) {
      const errorDiv = document.createElement('div');
      errorDiv.className = 'empty';
      errorDiv.textContent = `Hata: ${result.error}`;
      col.appendChild(errorDiv);
    } else {
      const replyDiv = document.createElement('div');
      replyDiv.className = 'rc-reply';
      renderRichText(replyDiv, cleanReply(result.reply || "(boş)"));
      col.appendChild(replyDiv);

      const metaDiv = document.createElement('div');
      metaDiv.className = 'rc-meta';
      metaDiv.textContent = `${result.iterations} tur · ${result.elapsed_ms} ms`;
      col.appendChild(metaDiv);

      (result.trace || []).forEach(t => {
        const tr = document.createElement('div');
        tr.className = 'rc-trace' + (t.type === 'gate_reject' ? ' rj' : '');
        tr.textContent = `#${t.step} ${t.type} ${t.tool || ''}`.trim();
        col.appendChild(tr);
      });

      const pickBtn = document.createElement('button');
      pickBtn.type = 'button';
      pickBtn.className = 'btn sm primary';
      pickBtn.textContent = "Bunu seç";
      pickBtn.addEventListener('click', async () => {
        try {
          await postJSON('/v1/agent/model', { name: result.model });
          pickBtn.textContent = "seçildi ✓";
          pickBtn.disabled = true;
          loadAjanModels();
        } catch (e) {
          pickBtn.textContent = "hata";
        }
      });
      col.appendChild(pickBtn);
    }
    box.appendChild(col);
  });
}

async function runRace() {
  const models = selectedRaceModels();
  const msg = document.getElementById('race-input').value.trim();
  const busyDiv = document.getElementById('race-busy');
  if (models.length < 2 || models.length > 4) {
    busyDiv.hidden = false;
    busyDiv.textContent = "2-4 model seç.";
    return;
  }
  if (!msg) return;
  const runButton = document.getElementById('race-run');
  runButton.disabled = true;
  busyDiv.hidden = false;
  busyDiv.textContent = "Modeller yarışıyor… (yerel GPU'da sırayla, sabırlı ol)";
  try {
    const response = await postJSON('/v1/agent/race', { message: msg, models });
    renderRaceResults(response.results || []);
  } catch (e) {
    const box = document.getElementById('race-results');
    box.replaceChildren();
    const errorDiv = document.createElement('div');
    errorDiv.className = 'empty';
    errorDiv.textContent = `Hata: ${e.message}`;
    box.appendChild(errorDiv);
  } finally {
    runButton.disabled = false;
    busyDiv.hidden = true;
    busyDiv.textContent = '';
  }
}

function setupRace() {
  const railButton = document.querySelector('button[data-view="ajan"]');
  if (railButton) {
    railButton.addEventListener('click', loadRaceModels, { once: true });
  }
  const runBtn = document.getElementById('race-run');
  if (runBtn) { runBtn.addEventListener('click', runRace); }
}

if (document.readyState === 'loading') {
  addEventListener('DOMContentLoaded', setupRace);
} else {
  setupRace();
}

// ============================================================================
// GÜVENLİK DENETİMİ (Security Audit)
// ============================================================================

function renderAuditResults(tests) {
  const box = document.getElementById('audit-results');
  box.replaceChildren();
  
  if (!tests || tests.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = "Test sonucu bulunamadı.";
    box.appendChild(empty);
    return;
  }
  
  tests.forEach(test => {
    const pdiv = document.createElement('div');
    pdiv.className = 'panel';
    pdiv.style.marginBottom = '12px';
    
    const h2 = document.createElement('h2');
    h2.textContent = test.name;
    
    const pill = document.createElement('span');
    pill.style.marginLeft = 'auto';
    if (test.status === 'PASS') {
      pill.className = 'pill masked'; // secure green
      pill.textContent = 'BAŞARILI';
    } else if (test.status === 'FAIL') {
      pill.className = 'pill raw'; // danger
      pill.style.background = 'rgba(229,72,77,.14)';
      pill.style.color = 'var(--kasa-danger)';
      pill.textContent = 'BAŞARISIZ';
    } else {
      pill.className = 'pill raw';
      pill.textContent = test.status;
    }
    h2.appendChild(pill);
    pdiv.appendChild(h2);
    
    const body = document.createElement('div');
    body.className = 'body flush';
    
    const desc = document.createElement('div');
    desc.style.fontSize = '12.5px';
    desc.style.color = 'var(--kasa-n300)';
    desc.style.marginBottom = '8px';
    desc.textContent = test.description;
    body.appendChild(desc);
    
    const msg = document.createElement('div');
    msg.style.fontSize = '13px';
    msg.style.fontWeight = '500';
    msg.style.color = test.status === 'PASS' ? 'var(--kasa-secure)' : (test.status === 'FAIL' ? 'var(--kasa-danger)' : 'var(--kasa-warning)');
    msg.textContent = test.message;
    body.appendChild(msg);
    
    const meta = document.createElement('div');
    meta.className = 'hint';
    meta.style.marginTop = '8px';
    meta.textContent = `Süre: ${test.duration_ms} ms`;
    body.appendChild(meta);
    
    pdiv.appendChild(body);
    box.appendChild(pdiv);
  });
}

async function runAudit() {
  const btn = document.getElementById('run-audit-btn');
  const busy = document.getElementById('audit-busy');
  const results = document.getElementById('audit-results');
  const layerSelect = document.getElementById('audit-layer-select');
  const downloadBtn = document.getElementById('download-report-btn');
  
  const layer = layerSelect ? layerSelect.value : 'all';
  
  btn.disabled = true;
  busy.hidden = false;
  if(downloadBtn) downloadBtn.hidden = true;
  results.replaceChildren();
  
  try {
    const res = await fetchJSON(`/v1/dashboard/audit/run?target_layer=${layer}`);
    renderAuditResults(res.tests || []);
    if(downloadBtn && res.tests && res.tests.length > 0) downloadBtn.hidden = false;
  } catch(e) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'empty';
    errorDiv.style.color = 'var(--kasa-danger)';
    errorDiv.textContent = `Testler çalıştırılamadı: ${e.message}`;
    results.appendChild(errorDiv);
  } finally {
    btn.disabled = false;
    busy.hidden = true;
  }
}

function setupAudit() {
  const btn = document.getElementById('run-audit-btn');
  if (btn) {
    btn.addEventListener('click', runAudit);
  }
  
  const dlBtn = document.getElementById('download-report-btn');
  if (dlBtn) {
    dlBtn.addEventListener('click', async () => {
      const layerSelect = document.getElementById('audit-layer-select');
      const layer = layerSelect ? layerSelect.value : 'all';
      
      try {
        const res = await fetch(`/v1/dashboard/audit/report?target_layer=${layer}`, {
            headers: { Authorization: "Bearer " + window.KASA_TOKEN }
        });
        if (!res.ok) throw new Error("Rapor indirilemedi");
        
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `kasa_audit_report_${layer}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      } catch (e) {
        alert("Hata: " + e.message);
      }
    });
  }
}

if (document.readyState === 'loading') {
  addEventListener('DOMContentLoaded', setupAudit);
} else {
  setupAudit();
}

// --- Ayarlar: native dosya/klasor secici (pywebview js_api koprusu) ---
function setupSettings() {
  const pathEl = document.getElementById('settings-selected-path');
  const show = (p, empty) => { if (pathEl) pathEl.textContent = p ? ('Seçilen: ' + p) : empty; };

  const folderBtn = document.getElementById('pick-folder-btn');
  if (folderBtn) folderBtn.addEventListener('click', async () => {
    if (!window.pywebview || !window.pywebview.api) return;   // tarayicida acilirsa sessiz gec
    show(await window.pywebview.api.pick_folder(), 'Seçim yapılmadı.');
  });

  const fileBtn = document.getElementById('pick-file-btn');
  if (fileBtn) fileBtn.addEventListener('click', async () => {
    if (!window.pywebview || !window.pywebview.api) return;
    show(await window.pywebview.api.pick_file(), 'Seçim yapılmadı.');
  });

  // Kayitli yolu yukle: api hazir degilse pywebviewready'yi bekle (pywebview api'yi async enjekte eder).
  const loadSaved = () => {
    if (!window.pywebview || !window.pywebview.api) return;
    window.pywebview.api.get_saved_vault_path().then(p => { if (p) show(p, ''); }).catch(() => {});
  };
  if (window.pywebview && window.pywebview.api) loadSaved();
  else addEventListener('pywebviewready', loadSaved);
}

if (document.readyState === 'loading') {
  addEventListener('DOMContentLoaded', setupSettings);
} else {
  setupSettings();
}
