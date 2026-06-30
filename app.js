/* AI Model Radar — account auth + per-section decryption + admin */
(function () {
  'use strict';

  // ============ constants ============
  const SECTIONS = ['releases', 'news', 'analysis'];
  const SECTION_LABEL = { releases: 'モデルリリース', news: 'ニュース・噂', analysis: '状況分析' };
  const REPO = 'w1124c/ai-model-radar';
  const subtle = crypto.subtle;
  const td = new TextDecoder();
  const te = new TextEncoder();
  const b64 = (u8) => btoa(String.fromCharCode.apply(null, u8));
  const ub64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  const CAT_LABEL = {
    image: '画像', video: '動画', '3d': '3D', audio: '音声', llm: 'LLM',
    multimodal: 'マルチモーダル', coding: 'コーディング', mcp: 'MCP', tool: 'ツール',
  };
  const TYPE_LABEL = { 'major-lab': '主要ラボ', 'open-source': 'オープンソース' };
  const CRED_LABEL = { official: '公式', report: '報道', rumor: '噂' };
  const CRED_COLOR = { official: 'var(--color-primary)', report: 'var(--cat-llm)', rumor: 'var(--cat-3d)' };
  const WEEKDAYS = ['日', '月', '火', '水', '木', '金', '土'];

  // ============ theme ============
  const SUN = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>';
  const MOON = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  const toggle = document.querySelector('[data-theme-toggle]');
  const root = document.documentElement;
  let theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  root.setAttribute('data-theme', theme);
  if (toggle) {
    toggle.innerHTML = theme === 'dark' ? SUN : MOON;
    toggle.addEventListener('click', () => {
      theme = theme === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', theme);
      toggle.innerHTML = theme === 'dark' ? SUN : MOON;
    });
  }

  // ============ crypto helpers ============
  async function deriveKey(password, salt, iter) {
    const km = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }
  async function importRawKey(rawU8) {
    return subtle.importKey('raw', rawU8, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function aesEncrypt(key, bytes) {
    const n = crypto.getRandomValues(new Uint8Array(12));
    const c = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: n }, key, bytes));
    return { n: b64(n), c: b64(c) };
  }
  async function aesDecrypt(key, obj) {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: ub64(obj.n) }, key, ub64(obj.c)));
  }

  // ============ state ============
  const state = { view: null, type: 'all', category: 'all', query: '' };
  let releases = [], news = [], analysis = null, updatedAt = null;
  let usersDoc = null, encData = null;
  let session = null; // { email, role, perms:[], rawKeys:{section:Uint8Array} }

  const $ = (id) => document.getElementById(id);
  const esc = (s) => { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; };
  function fmtDate(iso) {
    const p = (iso || '').split('-').map(Number);
    if (p.length !== 3 || p.some(isNaN)) return iso;
    const wd = new Date(Date.UTC(p[0], p[1] - 1, p[2])).getUTCDay();
    return p[1] + '/' + p[2] + ' (' + WEEKDAYS[wd] + ')';
  }
  function daysAgo(n) {
    const d = new Date(Date.now() + 9 * 3600 * 1000);
    d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() - n);
    return d.toISOString().slice(0, 10);
  }

  // ============ data load ============
  const safeJSON = (path) => fetch(path + (path.includes('?') ? '' : '?t=' + Date.now())).then((r) => (r.ok ? r.json() : null)).catch(() => null);

  async function loadInfra() {
    [usersDoc, encData] = await Promise.all([safeJSON('./users.json'), safeJSON('./data/data.enc')]);
  }

  // try login: returns true on success
  async function attemptLogin(email, password) {
    if (!usersDoc || !encData) return false;
    const u = (usersDoc.users || []).find((x) => x.email.toLowerCase() === email.toLowerCase());
    if (!u) return false;
    const iter = (usersDoc.kdf && usersDoc.kdf.iter) || 200000;
    const pk = await deriveKey(password, ub64(u.salt), iter);
    const rawKeys = {};
    const perms = [];
    let any = false;
    for (const s of SECTIONS) {
      if (!u.wrapped || !u.wrapped[s]) continue;
      try {
        rawKeys[s] = await aesDecrypt(pk, u.wrapped[s]);
        perms.push(s); any = true;
      } catch (e) { return false; } // any wrapped section that fails => wrong password
    }
    if (!any) return false;
    session = { email: u.email, role: u.role || 'viewer', perms, rawKeys, pk };
    await decryptSections();
    return true;
  }

  async function decryptSections() {
    for (const s of session.perms) {
      const key = await importRawKey(session.rawKeys[s]);
      const json = JSON.parse(td.decode(await aesDecrypt(key, encData.sections[s])));
      if (s === 'releases') { releases = (json.releases || []).slice().sort(byDateDesc); updatedAt = json.updated; }
      else if (s === 'news') { news = (json.items || []).slice().sort(byDateDesc); }
      else if (s === 'analysis') { analysis = json; }
    }
  }
  const byDateDesc = (a, b) => (a.date < b.date ? 1 : -1);

  // ============ render ============
  function renderUpdatedAt() {
    if (!updatedAt) return;
    const d = new Date(new Date(updatedAt).getTime() + 9 * 3600 * 1000);
    $('updated-at').textContent = '最終更新 ' + d.getUTCFullYear() + '/' + (d.getUTCMonth() + 1) + '/' +
      d.getUTCDate() + ' ' + String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0') + ' JST';
  }

  function renderKPIs() {
    if (!session.perms.includes('releases')) { $('kpi-row').hidden = true; return; }
    const weekAgo = daysAgo(6);
    animateNumber('kpi-today', releases.filter((r) => r.date >= daysAgo(1)).length);
    animateNumber('kpi-week', releases.filter((r) => r.date >= weekAgo).length);
    animateNumber('kpi-lab', releases.filter((r) => r.type === 'major-lab').length);
    animateNumber('kpi-oss', releases.filter((r) => r.type === 'open-source').length);
    const counts = [];
    for (let i = 13; i >= 0; i--) { const day = daysAgo(i); counts.push({ day, n: releases.filter((r) => r.date === day).length }); }
    const max = Math.max(1, ...counts.map((c) => c.n));
    $('bar-chart').innerHTML = counts.map((c, i) =>
      '<div class="bar' + (i === 13 ? ' is-today' : '') + '" style="height:' + Math.max(4, Math.round((c.n / max) * 100)) + '%" title="' + esc(fmtDate(c.day) + ': ' + c.n + '件') + '"></div>').join('');
  }
  function animateNumber(id, target) {
    const el = $(id), dur = 600, start = performance.now();
    (function tick(t) { const p = Math.min(1, (t - start) / dur); el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(tick); })(start);
  }

  function renderAnalysis() {
    if (!session.perms.includes('analysis') || !analysis || !analysis.current) { $('analysis-panel').hidden = true; return; }
    const a = analysis.current;
    $('analysis-panel').hidden = false;
    $('analysis-date').textContent = fmtDate(a.date) + ' 時点';
    $('analysis-headline').textContent = a.headline || '';
    $('analysis-points').innerHTML = (a.points || []).map((p) => '<li>' + esc(p) + '</li>').join('');
    if (a.body) $('analysis-body').textContent = a.body; else $('analysis-body').textContent = '';
  }

  function renderTabs() {
    const tabs = [];
    if (session.perms.includes('releases')) tabs.push({ v: 'releases', label: 'モデルリリース', count: releases.length });
    if (session.perms.includes('news')) tabs.push({ v: 'news', label: 'ニュース・噂', count: news.length });
    if (!tabs.length) return;
    if (!state.view) state.view = tabs[0].v;
    document.body.setAttribute('data-view', state.view);
    $('view-tabs').innerHTML = tabs.map((t) =>
      '<button class="view-tab' + (t.v === state.view ? ' is-active' : '') + '" data-view="' + t.v + '">' + esc(t.label) + ' <span class="tab-count">' + t.count + '</span></button>').join('');
    $('view-tabs').querySelectorAll('.view-tab').forEach((tab) => tab.addEventListener('click', () => {
      $('view-tabs').querySelectorAll('.view-tab').forEach((t) => t.classList.remove('is-active'));
      tab.classList.add('is-active'); state.view = tab.dataset.view; document.body.setAttribute('data-view', state.view); renderTimeline();
    }));
  }

  function filteredReleases() {
    const q = state.query.trim().toLowerCase();
    return releases.filter((r) => {
      if (state.type !== 'all' && r.type !== state.type) return false;
      if (state.category !== 'all' && r.category !== state.category) return false;
      if (q && !((r.name + ' ' + r.org + ' ' + (r.tags || []).join(' ') + ' ' + r.summary).toLowerCase().includes(q))) return false;
      return true;
    });
  }
  function filteredNews() {
    const q = state.query.trim().toLowerCase();
    return news.filter((n) => !q || (n.title + ' ' + n.source + ' ' + (n.tags || []).join(' ') + ' ' + n.summary).toLowerCase().includes(q));
  }

  function releaseCardHTML(r) {
    const tags = (r.tags || []).slice(0, 5).map((t) => '<span class="tag">' + esc(t) + '</span>').join('');
    return '<article class="release-card" style="--cat-color: var(--cat-' + esc(r.category) + ', var(--color-border))">' +
      '<div class="release-head"><h3 class="release-name"><a href="' + esc(r.url) + '" target="_blank" rel="noopener noreferrer">' + esc(r.name) + '</a></h3>' +
      '<span class="release-org">' + esc(r.org) + '</span><div class="badges">' +
      '<span class="badge badge-cat">' + esc(CAT_LABEL[r.category] || r.category) + '</span>' +
      '<span class="badge">' + esc(TYPE_LABEL[r.type] || r.type) + '</span></div></div>' +
      '<p class="release-summary">' + esc(r.summary) + '</p>' +
      '<div class="release-foot"><div class="tag-list">' + tags + '</div>' +
      '<a class="source-link" href="' + esc(r.url) + '" target="_blank" rel="noopener noreferrer">ソースを見る ↗</a></div></article>';
  }
  function newsCardHTML(n) {
    const cred = n.credibility || 'report';
    const tags = (n.tags || []).slice(0, 5).map((t) => '<span class="tag">' + esc(t) + '</span>').join('');
    return '<article class="release-card" style="--cat-color: ' + (CRED_COLOR[cred] || 'var(--color-border)') + '">' +
      '<div class="release-head"><h3 class="release-name"><a href="' + esc(n.url) + '" target="_blank" rel="noopener noreferrer">' + esc(n.title) + '</a></h3>' +
      '<span class="news-source">' + esc(n.source) + '</span><div class="badges">' +
      '<span class="badge badge-' + esc(cred) + '">' + esc(CRED_LABEL[cred] || cred) + '</span></div></div>' +
      '<p class="release-summary">' + esc(n.summary) + '</p>' +
      '<div class="release-foot"><div class="tag-list">' + tags + '</div>' +
      '<a class="source-link" href="' + esc(n.url) + '" target="_blank" rel="noopener noreferrer">ソースを見る ↗</a></div></article>';
  }

  function renderTimeline() {
    const isNews = state.view === 'news';
    const list = isNews ? filteredNews() : filteredReleases();
    const timeline = $('timeline'), empty = $('empty-state');
    if (!list.length) { timeline.innerHTML = ''; empty.hidden = false; return; }
    empty.hidden = true;
    const byDate = {};
    list.forEach((r) => { (byDate[r.date] = byDate[r.date] || []).push(r); });
    timeline.innerHTML = Object.keys(byDate).sort().reverse().map((d) => {
      const items = byDate[d];
      return '<div class="day-group"><div class="day-label"><span>' + esc(fmtDate(d)) + '</span><span class="day-count">' + items.length + '件</span></div>' +
        '<div class="day-cards">' + items.map(isNews ? newsCardHTML : releaseCardHTML).join('') + '</div></div>';
    }).join('');
  }

  function renderAll() {
    $('main').hidden = false;
    $('logout-btn').hidden = false;
    $('admin-btn').hidden = session.role !== 'admin';
    renderUpdatedAt(); renderKPIs(); renderAnalysis(); renderTabs(); renderTimeline();
  }

  // ============ filters ============
  function bindChips(containerId, attr, key) {
    $(containerId).addEventListener('click', (e) => {
      const btn = e.target.closest('.chip'); if (!btn) return;
      $(containerId).querySelectorAll('.chip').forEach((c) => c.classList.remove('is-active'));
      btn.classList.add('is-active'); state[key] = btn.dataset[attr]; renderTimeline();
    });
  }
  bindChips('type-filters', 'type', 'type');
  bindChips('category-filters', 'category', 'category');
  $('search').addEventListener('input', (e) => { state.query = e.target.value; renderTimeline(); });
  $('reset-filters').addEventListener('click', () => {
    state.type = 'all'; state.category = 'all'; state.query = ''; $('search').value = '';
    document.querySelectorAll('.filter-group .chip').forEach((c) => c.classList.toggle('is-active', c.dataset.type === 'all' || c.dataset.category === 'all'));
    renderTimeline();
  });

  // ============ login UI ============
  const overlay = $('lock-overlay');
  function showLogin() { overlay.hidden = false; $('lock-email').focus(); }
  $('lock-form').addEventListener('submit', async (e) => {
    e.preventDefault(); $('lock-error').hidden = true;
    const email = $('lock-email').value.trim(), pass = $('lock-pass').value;
    const submitBtn = e.target.querySelector('.lock-submit');
    submitBtn.disabled = true; submitBtn.textContent = '確認中…';
    const ok = await attemptLogin(email, pass);
    submitBtn.disabled = false; submitBtn.textContent = 'ログイン';
    if (ok) {
      if ($('lock-remember').checked) { localStorage.setItem('amr_email', email); localStorage.setItem('amr_pass', pass); }
      else { localStorage.removeItem('amr_email'); localStorage.removeItem('amr_pass'); }
      overlay.hidden = true; renderAll();
    } else {
      $('lock-error').hidden = false; $('lock-pass').value = ''; $('lock-pass').focus();
    }
  });
  $('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('amr_pass'); session = null; releases = []; news = []; analysis = null;
    location.reload();
  });

  // ============ admin panel ============
  const adminModal = $('admin-modal');
  let editingEmail = null;
  $('admin-btn').addEventListener('click', () => { editingEmail = null; resetForm(); renderUserTable(); adminModal.hidden = false; });
  $('admin-close').addEventListener('click', () => { adminModal.hidden = true; });
  adminModal.addEventListener('click', (e) => { if (e.target === adminModal) adminModal.hidden = true; });

  function renderUserTable() {
    const tb = $('user-tbody');
    tb.innerHTML = (usersDoc.users || []).map((u) => {
      const perms = Object.keys(u.wrapped || {}).map((s) => SECTION_LABEL[s] || s).join('・');
      const isSelf = session && u.email.toLowerCase() === session.email.toLowerCase();
      return '<tr><td>' + esc(u.email) + (isSelf ? ' <span class="self-tag">あなた</span>' : '') + '</td>' +
        '<td>' + (u.role === 'admin' ? '<span class="role-admin">管理者</span>' : '閲覧') + '</td>' +
        '<td class="perm-cell">' + esc(perms || '—') + '</td>' +
        '<td class="row-actions">' +
        '<button class="mini-btn" data-edit="' + esc(u.email) + '">編集</button>' +
        (isSelf ? '' : '<button class="mini-btn danger" data-del="' + esc(u.email) + '">削除</button>') +
        '</td></tr>';
    }).join('');
    tb.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => startEdit(b.dataset.edit)));
    tb.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => deleteUser(b.dataset.del)));
  }

  function resetForm() {
    editingEmail = null;
    $('form-title').textContent = 'アカウントを追加';
    $('f-email').value = ''; $('f-email').disabled = false; $('f-pass').value = '';
    $('p-releases').checked = true; $('p-news').checked = true; $('p-analysis').checked = true;
    $('f-admin').checked = false; $('f-cancel').hidden = true; $('form-msg').hidden = true;
  }
  function startEdit(email) {
    const u = usersDoc.users.find((x) => x.email.toLowerCase() === email.toLowerCase());
    if (!u) return;
    editingEmail = u.email;
    $('form-title').textContent = 'アカウントを編集: ' + u.email;
    $('f-email').value = u.email; $('f-email').disabled = true; $('f-pass').value = '';
    $('p-releases').checked = !!(u.wrapped && u.wrapped.releases);
    $('p-news').checked = !!(u.wrapped && u.wrapped.news);
    $('p-analysis').checked = !!(u.wrapped && u.wrapped.analysis);
    $('f-admin').checked = u.role === 'admin';
    $('f-cancel').hidden = false; $('form-msg').hidden = true;
    adminModal.scrollTop = adminModal.scrollHeight;
  }
  $('f-cancel').addEventListener('click', resetForm);
  $('f-genpass').addEventListener('click', () => { $('f-pass').value = genPassword(); });
  function genPassword() {
    const adj = ['swift', 'lunar', 'cobalt', 'vivid', 'nova', 'prism', 'onyx', 'azure'];
    const noun = ['radar', 'vector', 'pixel', 'cipher', 'matrix', 'quartz', 'falcon', 'delta'];
    const pick = (a) => a[Math.floor(Math.random() * a.length)];
    const cap = (s) => s[0].toUpperCase() + s.slice(1);
    return cap(pick(adj)) + '-' + cap(pick(noun)) + '-' + (1000 + Math.floor(Math.random() * 9000));
  }

  function formMsg(msg, ok) { const el = $('form-msg'); el.hidden = false; el.textContent = msg; el.className = 'form-msg ' + (ok ? 'msg-ok' : 'msg-err'); }

  $('f-save').addEventListener('click', async () => {
    const email = $('f-email').value.trim();
    const pass = $('f-pass').value;
    const isAdmin = $('f-admin').checked;
    let perms = [];
    if (isAdmin) perms = SECTIONS.slice();
    else { if ($('p-releases').checked) perms.push('releases'); if ($('p-news').checked) perms.push('news'); if ($('p-analysis').checked) perms.push('analysis'); }
    if (!email || !/.+@.+\..+/.test(email)) return formMsg('有効なメールアドレスを入力してください', false);
    if (!perms.length) return formMsg('閲覧範囲を1つ以上選択してください', false);
    const existing = usersDoc.users.find((x) => x.email.toLowerCase() === email.toLowerCase());
    if (!editingEmail && existing) return formMsg('このメールアドレスは既に登録されています', false);
    if (!pass) return formMsg('パスワードを入力してください（編集時も再設定が必要です）', false);

    // build wrapped keys with the provided password
    const iter = (usersDoc.kdf && usersDoc.kdf.iter) || 200000;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const pk = await deriveKey(pass, salt, iter);
    const wrapped = {};
    for (const s of perms) wrapped[s] = await aesEncrypt(pk, session.rawKeys[s]); // admin holds raw section keys
    const rec = { email, salt: b64(salt), role: isAdmin ? 'admin' : 'viewer', wrapped };
    if (editingEmail) {
      const idx = usersDoc.users.findIndex((x) => x.email.toLowerCase() === editingEmail.toLowerCase());
      rec.created = usersDoc.users[idx].created || new Date().toISOString();
      usersDoc.users[idx] = rec;
    } else {
      rec.created = new Date().toISOString();
      usersDoc.users.push(rec);
    }
    renderUserTable(); resetForm();
    formMsg('保存しました（画面上で反映）。公開反映は下の「GitHubに保存」を押してください。', true);
  });

  async function deleteUser(email) {
    if (!confirm(email + ' を削除しますか？')) return;
    usersDoc.users = usersDoc.users.filter((x) => x.email.toLowerCase() !== email.toLowerCase());
    renderUserTable();
  }

  // ---- persistence ----
  function persistMsg(msg, ok) { const el = $('persist-msg'); el.hidden = false; el.textContent = msg; el.className = 'form-msg ' + (ok ? 'msg-ok' : 'msg-err'); }
  $('gh-settings').addEventListener('click', () => {
    const row = $('gh-token-row'); row.hidden = !row.hidden;
    if (!row.hidden) $('gh-token').value = localStorage.getItem('amr_gh_pat') || '';
  });
  $('gh-token-save').addEventListener('click', () => {
    const t = $('gh-token').value.trim();
    if (t) localStorage.setItem('amr_gh_pat', t); else localStorage.removeItem('amr_gh_pat');
    $('gh-token-row').hidden = true; persistMsg('GitHubトークンを保存しました（この端末のみ）。', true);
  });
  $('json-export').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(usersDoc, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'users.json'; a.click();
    persistMsg('users.json をダウンロードしました。', true);
  });
  $('gh-save').addEventListener('click', async () => {
    const pat = localStorage.getItem('amr_gh_pat');
    if (!pat) { $('gh-token-row').hidden = false; return persistMsg('先にGitHubトークンを設定してください。', false); }
    persistMsg('保存中…', true);
    try {
      const api = 'https://api.github.com/repos/' + REPO + '/contents/users.json';
      const headers = { Authorization: 'Bearer ' + pat, Accept: 'application/vnd.github+json' };
      const cur = await fetch(api + '?t=' + Date.now(), { headers });
      const sha = cur.ok ? (await cur.json()).sha : undefined;
      const content = btoa(unescape(encodeURIComponent(JSON.stringify(usersDoc, null, 2))));
      const res = await fetch(api, { method: 'PUT', headers, body: JSON.stringify({ message: 'admin: update users.json', content, sha }) });
      if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + (await res.text()).slice(0, 200));
      persistMsg('公開サイトに保存しました。反映まで最大1分ほどかかります。', true);
    } catch (e) { persistMsg('保存に失敗しました: ' + e.message, false); }
  });

  // ============ boot ============
  (async function boot() {
    await loadInfra();
    if (!usersDoc || !encData) { showLogin(); $('lock-error').hidden = false; $('lock-error').textContent = 'データを読み込めませんでした。'; return; }
    const savedEmail = localStorage.getItem('amr_email'), savedPass = localStorage.getItem('amr_pass');
    if (savedEmail) $('lock-email').value = savedEmail;
    if (savedEmail && savedPass && await attemptLogin(savedEmail, savedPass)) { renderAll(); return; }
    showLogin();
  })();
})();
