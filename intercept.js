/*
 ============================================================================
  Browser Intercept — lightweight Burp-style tool for YOUR OWN authorized tests
 ============================================================================
  ملف واحد (intercept.js) يعمل في سياقين:
    1) Service Worker (background): يتحكم في chrome.debugger (CDP) + Repeater.
    2) Content Script: الزر العائم والواجهة (Shadow DOM) داخل الصفحة.
  (Chrome يفرض وجود manifest.json بجانبه — 12 سطر فقط.)

  التثبيت:
    chrome://extensions  ->  فعّل Developer mode  ->  Load unpacked  ->  اختر هذا المجلد.
    ثم افتح موقعك المصرّح به، اضغط الزر ⚡، من Dashboard أكّد التصريح ثم "Attach".

  كيف يعمل الاعتراض (حقيقي وليس محاكاة):
    chrome.debugger.attach -> Network.enable (تسجيل) + Fetch.enable (إيقاف الطلب)
    -> Fetch.requestPaused -> Forward (continueRequest مع التعديلات) / Drop (failRequest).

  حدود صادقة (لا يمكن تجاوزها بواجهات المتصفح):
    * يظهر شريط "… يقوم بتصحيح هذا المتصفح" ولا يمكن إخفاؤه.
    * لا يلتقط إلا بعد الضغط على Attach؛ الطلبات التي بدأت قبل ذلك لا تُلتقط.
    * لا يعمل على chrome://, متجر Chrome, صفحات الإضافات، ولا إذا كان debugger آخر مربوطاً.
    * Service Workers / WebSocket / الطلبات خارج التاب: تغطية جزئية أو معدومة.
    * HTTPS: نرى الطلب داخل المتصفح بعد فك التشفير. لا MITM ولا تجاوز لـ TLS.
    * تعديل Cookie أثناء الإيقاف "best-effort": المتصفح قد يعيد إضافة كوكيز الجلسة.
    * Repeater يستخدم fetch من الإضافة: Host / Content-Length / Sec-* / Connection ...
      يحددها المتصفح ولا يمكن تغييرها. Cookie/Origin/Referer/User-Agent تُضبط عبر
      declarativeNetRequest (قد تفشل لروابط طويلة جداً). لا يمكن إعادة ترتيب
      الهيدرز ولا نسخة HTTP ولا بصمة TLS كما في الطلب الأصلي، ولا قراءة Set-Cookie.
    * الـ Service Worker في MV3 قد ينام: نبقيه حياً أثناء الربط، لكن لو أُعيد
      تشغيله فالطلبات الموقوفة حالياً لا يمكن استعادتها.

  الخصوصية والأمان:
    * لا شيء يُرسل لأي خادم خارجي؛ كل التخزين محلي (chrome.storage.local).
    * لا يعمل قبل تأكيد صريح أنك مخوّل باختبار الأهداف، مع Scope (Regex) اختياري.
    * التوكنات والكوكيز مُقنّعة افتراضياً، والتصدير يسأل صراحةً قبل تضمينها.
    * لا تجاوز لحماية TLS أو سياسات المتصفح.
 ============================================================================
*/
(() => {
'use strict';

/* ============================== SHARED PURE HELPERS ============================== */
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
const TYPES = ['Document', 'XHR', 'Fetch', 'Script', 'Stylesheet', 'Image', 'Font', 'Media', 'Other'];
const MASK = '••••••••';
const SECRET_HDR = /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$|token|secret|api[-_]?key|password|passwd/i;
const BROWSER_HDR = /^(host|content-length|connection|keep-alive|transfer-encoding|upgrade|te|trailer|accept-encoding|proxy-.*|sec-.*|priority|:.*)$/i;
const isSecretHeader = n => SECRET_HDR.test(n);
const getH = (hs, lname) => { const x = hs.find(([n]) => n.toLowerCase() === lname); return x ? x[1] : undefined; };
const parseCookies = s => String(s || '').split(/;\s*/).filter(Boolean).map(p => { const i = p.indexOf('='); return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)]; });
const joinCookies = a => a.filter(([n]) => n).map(([n, v]) => n + '=' + v).join('; ');
const fmtBytes = b => b == null ? '–' : b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const escH = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/* ---- syntax highlighting (tiny, dependency-free) ---- */
function hlJson(s) {
  return escH(s).replace(/("(?:\\.|[^"\\\n])*")(\s*:)?|\b(true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g,
    (m, str, colon, kw) => str ? (colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`)
      : kw ? `<span class="b">${m}</span>` : `<span class="n">${m}</span>`);
}
function hlHtml(s) {
  return escH(s).replace(/(&lt;!--[\s\S]*?--&gt;)|(&lt;\/?)([\w:-]+)([\s\S]*?)(\/?&gt;)/g, (m, c, o, t, a, e) => {
    if (c) return `<span class="c">${c}</span>`;
    a = a.replace(/([\w:@.-]+)(=)("[^"]*"|'[^']*')/g, '<span class="a">$1</span>$2<span class="s">$3</span>');
    return `<span class="t">${o}${t}</span>${a}<span class="t">${e}</span>`;
  });
}
function hlHttp(raw) {
  const n = raw.replace(/\r\n/g, '\n'), i = n.indexOf('\n\n');
  const head = i < 0 ? n : n.slice(0, i), body = i < 0 ? null : n.slice(i + 2);
  const L = head.split('\n'), first = L.shift() || '', m = /^(\S+)\s+(\S+)\s*(\S*)$/.exec(first);
  let out = m ? `<span class="m">${escH(m[1])}</span> <span class="u">${escH(m[2])}</span> <span class="v">${escH(m[3])}</span>` : escH(first);
  for (const l of L) { const k = l.indexOf(':'); out += '\n' + (k > 0 ? `<span class="k">${escH(l.slice(0, k))}</span>:${escH(l.slice(k + 1))}` : escH(l)); }
  if (body !== null) out += '\n\n' + (/^\s*[\[{]/.test(body) ? hlJson(body) : /^\s*</.test(body) ? hlHtml(body) : escH(body));
  return out;
}
function highlight(lang, t) {
  if (t.length > 2e5) return escH(t); // large bodies: no highlighting (keeps UI responsive)
  return lang === 'json' ? hlJson(t) : lang === 'html' ? hlHtml(t) : lang === 'http' ? hlHttp(t) : escH(t);
}
function prettyHtml(s) {
  let d = 0;
  return s.replace(/>\s*</g, '>\n<').split('\n').map(l => {
    l = l.trim();
    if (/^<\//.test(l)) d = Math.max(0, d - 1);
    const out = '  '.repeat(d) + l;
    if (/^<[a-z][^>]*[^\/]>$/i.test(l) && !/^<(br|hr|img|input|meta|link|!doctype)/i.test(l)) d++;
    return out;
  }).join('\n');
}
function diffLines(a, b) {
  const A = a.split('\n'), B = b.split('\n'), n = A.length, m = B.length, ops = [];
  if (n * m > 4e6) { A.forEach(l => ops.push({ t: '-', s: l })); B.forEach(l => ops.push({ t: '+', s: l })); return ops; }
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { ops.push({ t: ' ', s: A[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push({ t: '-', s: A[i++] }); else ops.push({ t: '+', s: B[j++] });
  }
  while (i < n) ops.push({ t: '-', s: A[i++] });
  while (j < m) ops.push({ t: '+', s: B[j++] });
  return ops;
}

/* ---- request <-> text conversions ---- */
function parseQuery(url) { try { return [...new URL(url).searchParams]; } catch { return []; } }
function parseMultipart(body, ct) {
  const m = /boundary=("?)([^";]+)\1/i.exec(ct || '');
  if (!m) return 'No boundary found in Content-Type';
  return body.split('--' + m[2]).slice(1).filter(p => p.trim() && !/^--\s*$/.test(p)).map((p, i) => {
    const [hd, ...rest] = p.replace(/^\r?\n/, '').split(/\r?\n\r?\n/);
    const bd = rest.join('\n\n').replace(/\r?\n$/, '');
    return `#${i + 1}\n${hd.trim()}\n\n${bd.length > 500 ? bd.slice(0, 500) + '… (' + bd.length + ' chars)' : bd}`;
  }).join('\n\n----------------\n');
}
// req = {method,url,headers:[[n,v]],body}
function toRaw(req, { secrets = true, maskStr = MASK } = {}) {
  let u = null; try { u = new URL(req.url); } catch { /* keep raw url */ }
  const out = [`${req.method} ${u ? u.pathname + u.search : req.url} HTTP/1.1`];
  if (u && getH(req.headers, 'host') === undefined) out.push('Host: ' + u.host);
  for (const [n, v] of req.headers) {
    let val = v;
    if (!secrets) {
      if (n.toLowerCase() === 'cookie') val = joinCookies(parseCookies(v).map(([a]) => [a, maskStr]));
      else if (isSecretHeader(n)) val = maskStr;
    }
    out.push(n + ': ' + val);
  }
  return out.join('\n') + '\n\n' + (req.body || '');
}
function parseRaw(text, baseUrl) {
  const norm = text.replace(/\r\n/g, '\n'), i = norm.indexOf('\n\n');
  const head = i < 0 ? norm : norm.slice(0, i), body = i < 0 ? '' : norm.slice(i + 2);
  const lines = head.split('\n'), [method, target] = (lines.shift() || '').trim().split(/\s+/);
  if (!method || !target) throw new Error('Bad request line (expected: METHOD /path HTTP/1.1)');
  const hs = []; let host = null;
  for (const l of lines) {
    if (!l.trim()) continue;
    const k = l.indexOf(':');
    if (k < 1) throw new Error('Bad header line: ' + l);
    const n = l.slice(0, k).trim(), v = l.slice(k + 1).trim();
    if (n.toLowerCase() === 'host') host = v; else hs.push([n, v]);
  }
  let url;
  if (/^https?:\/\//i.test(target)) url = target;
  else { const b = new URL(baseUrl); url = b.protocol + '//' + (host || b.host) + target; }
  return { method: method.toUpperCase(), url, headers: hs, body };
}

/* ---- exporters ---- */
function pyLit(v, ind = 0) {
  const pad = '    '.repeat(ind + 1), end = '    '.repeat(ind);
  if (v === null) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return v.length ? '[\n' + v.map(x => pad + pyLit(x, ind + 1)).join(',\n') + '\n' + end + ']' : '[]';
  const k = Object.keys(v);
  return k.length ? '{\n' + k.map(x => pad + JSON.stringify(x) + ': ' + pyLit(v[x], ind + 1)).join(',\n') + '\n' + end + '}' : '{}';
}
function toPython(req, { secrets = false } = {}) {
  const method = String(req.method).toUpperCase(), m = method.toLowerCase();
  const omitted = [], hdr = {};
  for (const [n, v] of req.headers) {
    if (BROWSER_HDR.test(n)) continue;                       // browser-generated / restricted
    if (isSecretHeader(n) && !secrets) { omitted.push(n); continue; } // explicit opt-in only
    hdr[n] = v;
  }
  const ct = (getH(req.headers, 'content-type') || '').toLowerCase(), body = req.body;
  let pre = '', kw = '';
  if (body != null && body !== '') {
    if (/json/.test(ct)) {
      try { pre = 'payload = ' + pyLit(JSON.parse(body)) + '\n\n'; kw = '    json=payload,\n'; }
      catch { pre = 'payload = ' + JSON.stringify(body) + '\n\n'; kw = '    data=payload.encode("utf-8"),\n'; }
    } else if (/x-www-form-urlencoded/.test(ct)) {
      const ps = [...new URLSearchParams(body)], dup = new Set(ps.map(p => p[0])).size !== ps.length;
      pre = 'payload = ' + (dup ? pyLit(ps) : pyLit(Object.fromEntries(ps))) + '\n\n'; kw = '    data=payload,\n';
    } else {
      pre = (/multipart\//.test(ct) ? '# multipart body sent raw (boundary comes from the Content-Type header)\n' : '') +
        'payload = ' + JSON.stringify(body) + '\n\n';
      kw = '    data=payload.encode("utf-8"),\n';
    }
  }
  const hasH = Object.keys(hdr).length;
  const call = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(m) ? `requests.${m}(` : `requests.request(${JSON.stringify(method)},`;
  return 'import requests\n\n' +
    (omitted.length ? `# Omitted (secrets): ${omitted.join(', ')} — export again with "Include secrets" if you need them\n` : '') +
    `url = ${JSON.stringify(req.url)}\n\n` +
    (hasH ? 'headers = ' + pyLit(hdr) + '\n\n' : '') + pre +
    `response = ${call}\n    url,\n` + (hasH ? '    headers=headers,\n' : '') + kw + '    timeout=30,\n)\n\n' +
    'print(response.status_code)\nprint(response.headers)\nprint(response.text)\n';
}
const shq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
function toCurl(req, { secrets = false } = {}) {
  const method = String(req.method).toUpperCase(), p = ['curl ' + shq(req.url)];
  if (method === 'HEAD') p.push('-I'); else if (method !== 'GET') p.push('-X ' + method);
  const omitted = [];
  for (const [n, v] of req.headers) {
    if (BROWSER_HDR.test(n)) continue;
    if (isSecretHeader(n) && !secrets) { omitted.push(n); continue; }
    p.push('-H ' + shq(n + ': ' + v));
  }
  if (req.body) p.push('--data-raw ' + shq(req.body));
  return (omitted.length ? `# Omitted (secrets): ${omitted.join(', ')}\n` : '') + p.join(' \\\n  ');
}

if (typeof module !== 'undefined' && module.exports) { // Node (tests only)
  module.exports = { toPython, toCurl, toRaw, parseRaw, parseMultipart, hlJson, hlHtml, hlHttp, prettyHtml, diffLines, parseCookies, joinCookies, parseQuery };
  return;
}
const isSW = typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope;
if (isSW) backgroundMain(); else if (typeof document !== 'undefined') contentMain();

/* ============================================================================
   BACKGROUND (service worker): interception engine, history manager, repeater
   ============================================================================ */
function backgroundMain() {
  const DEF = { authorized: false, scope: '', pauseTypes: ['Document', 'XHR', 'Fetch'], maxEntries: 300, maxBodyKB: 256, persist: true, mask: true, interceptOn: false };
  let S = { ...DEF };
  let history = [];
  const byId = new Map(), live = new Map(), xReq = new Map(), xRes = new Map();
  const targets = new Map(), pending = new Map(), ports = new Set();
  let seq = 0, saveT = 0, keepT = 0, scopeSrc = null, scopeRx = null;
  const uid = () => Date.now().toString(36) + (seq++).toString(36);
  const tk = t => t.tabId + ':' + (t.sessionId || '');
  const dbg = s => s.sessionId ? { tabId: s.tabId, sessionId: s.sessionId } : { tabId: s.tabId };
  const cmd = (t, m, p) => chrome.debugger.sendCommand(dbg(t), m, p || {});
  const clampInt = (v, lo, hi, d) => { v = parseInt(v, 10); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
  const b64 = s => { const u = new TextEncoder().encode(s); let b = ''; for (let i = 0; i < u.length; i += 0x8000) b += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(b); };
  const bufB64 = u => { let b = ''; for (let i = 0; i < u.length; i += 0x8000) b += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(b); };

  // Scope is fail-closed: an invalid regex means nothing is in scope.
  function inScope(url) {
    if (!S.scope.trim()) return true;
    if (scopeSrc !== S.scope) {
      scopeSrc = S.scope;
      try { scopeRx = new RegExp(S.scope.trim().split(/\n+/).filter(Boolean).map(x => '(?:' + x + ')').join('|'), 'i'); } catch { scopeRx = null; }
    }
    return scopeRx ? scopeRx.test(url) : false;
  }
  const broadcast = m => { for (const p of ports) { try { p.postMessage(m); } catch { ports.delete(p); } } };
  const attachedTabs = () => [...new Set([...targets.values()].map(t => t.tabId))];
  const pubState = () => ({ settings: S, interceptOn: S.interceptOn, attached: attachedTabs(), count: history.length });
  const bState = () => broadcast({ ev: 'state', st: pubState() });
  const saveSettings = () => chrome.storage.local.set({ settings: S });
  const persistAttached = () => chrome.storage.session.set({ attached: attachedTabs() }).catch(() => {});
  function keep() { // keeps the MV3 worker alive while a debugger session exists
    if (targets.size && !keepT) keepT = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 20000);
    else if (!targets.size && keepT) { clearInterval(keepT); keepT = 0; }
  }
  function scheduleSave() {
    if (!S.persist || saveT) return;
    saveT = setTimeout(() => { saveT = 0; chrome.storage.local.set({ history }).catch(() => {}); }, 2000);
  }
  function summary(e) {
    let host = '', path = e.url;
    try { const u = new URL(e.url); host = u.host; path = u.pathname + u.search; } catch { /* ignore */ }
    return { id: e.id, ts: e.ts, method: e.method, url: e.url, host, path, status: e.status, type: e.type, size: e.size, dur: e.dur, tabId: e.tabId };
  }
  function trimHistory() {
    const ev = [];
    while (history.length > S.maxEntries) { const o = history.shift(); byId.delete(o.id); ev.push(o.id); }
    return ev;
  }
  function addHistory(e) {
    history.push(e); byId.set(e.id, e);
    broadcast({ ev: 'entry', s: summary(e), evicted: trimHistory() });
    scheduleSave();
  }
  const emitUpd = e => broadcast({ ev: 'upd', s: summary(e) });

  const ready = (async () => {
    const s = await chrome.storage.local.get(['settings', 'history']);
    S = { ...DEF, ...(s.settings || {}) };
    history = Array.isArray(s.history) ? s.history : [];
    history.forEach(e => byId.set(e.id, e));
    const ss = await chrome.storage.session.get('attached').catch(() => ({}));
    const ids = ss.attached || [];
    if (ids.length) {
      const ts = await chrome.debugger.getTargets();
      for (const id of ids) {
        if (!ts.some(t => t.tabId === id && t.attached)) continue;
        const t = { tabId: id }; targets.set(tk(t), t);
        try { await enableDomains(t); } catch { targets.delete(tk(t)); }
      }
      keep();
    }
  })();

  /* ---------- debugger session management ---------- */
  async function applyFetch(t) {
    if (S.interceptOn && S.pauseTypes.length)
      await cmd(t, 'Fetch.enable', { patterns: S.pauseTypes.map(r => ({ urlPattern: '*', resourceType: r, requestStage: 'Request' })) });
    else await cmd(t, 'Fetch.disable').catch(() => {});
  }
  async function enableDomains(t) {
    await cmd(t, 'Network.enable', { maxPostDataSize: 1048576 });
    await applyFetch(t);
  }
  async function attachTab(tabId) {
    if (!S.authorized) throw new Error('Confirm authorization first (Dashboard).');
    const tab = await chrome.tabs.get(tabId);
    if (!/^https?:/i.test(tab.url || '')) throw new Error('Only http(s) pages can be attached.');
    if (targets.has(tabId + ':')) return;
    await chrome.debugger.attach({ tabId }, '1.3'); // fails if another debugger is attached
    const t = { tabId }; targets.set(tk(t), t);
    try {
      await enableDomains(t);
      // children (OOPIF iframes, workers) get their own flat sessions
      await cmd(t, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }).catch(() => {});
    } catch (e) { await detachTab(tabId); throw e; }
    persistAttached(); keep(); bState();
  }
  async function detachTab(tabId) {
    try { await chrome.debugger.detach({ tabId }); } catch { /* already detached */ }
    cleanupTab(tabId);
  }
  function cleanupTab(tabId) {
    for (const [k, t] of targets) if (t.tabId === tabId) targets.delete(k);
    for (const [k, p] of pending) if (p.source.tabId === tabId) { pending.delete(k); broadcast({ ev: 'resolved', id: k, how: 'detached' }); }
    for (const [k, e] of live) if (e.tabId === tabId) live.delete(k);
    persistAttached(); keep(); bState();
  }
  chrome.debugger.onDetach.addListener(src => { if (src.tabId != null && !src.sessionId) cleanupTab(src.tabId); });
  chrome.debugger.onEvent.addListener((source, method, p) => { handle(source, method, p).catch(e => console.warn('[BI]', method, e)); });

  /* ---------- CDP events -> history + interception ---------- */
  const cleanH = h => { const o = {}; for (const k in h || {}) if (!k.startsWith(':')) o[k] = h[k]; return o; };
  function mergeH(base, extra) { // case-insensitive merge, skips HTTP/2 pseudo headers
    const low = new Map(Object.keys(base).map(k => [k.toLowerCase(), k]));
    for (const [k, v] of Object.entries(extra || {})) {
      if (k.startsWith(':')) continue;
      const lk = k.toLowerCase();
      if (low.has(lk)) base[low.get(lk)] = v; else { base[k] = v; low.set(lk, k); }
    }
    return base;
  }
  function fillResponse(e, r) {
    e.status = r.status; e.statusText = r.statusText; e.resMime = r.mimeType; e.proto = r.protocol;
    e.resHeaders = mergeH(cleanH(r.headers), {});
  }
  function storeBody(e, r) {
    const cap = S.maxBodyKB * 1024, mime = e.resMime || '';
    if (r.base64Encoded) {
      if (/^image\//.test(mime) && r.body.length <= cap * 1.4) e.resB64 = r.body;
      else e.resBody = `[binary ${mime || 'data'}, ${Math.floor(r.body.length * 0.75)} bytes — not stored]`;
    } else { e.resTrunc = r.body.length > cap; e.resBody = e.resTrunc ? r.body.slice(0, cap) : r.body; }
  }
  async function handle(source, method, p) {
    await ready;
    const nk = id => source.tabId + ':' + (source.sessionId || '') + ':' + id;
    switch (method) {
      case 'Target.attachedToTarget': {
        const c = { tabId: source.tabId, sessionId: p.sessionId };
        targets.set(tk(c), c);
        try { await enableDomains(c); await cmd(c, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }).catch(() => {}); }
        catch { targets.delete(tk(c)); }
        return;
      }
      case 'Target.detachedFromTarget': targets.delete(source.tabId + ':' + p.sessionId); return;
      case 'Network.requestWillBeSent': {
        const url = p.request.url;
        if (!/^(https?|wss?):/i.test(url) || !inScope(url)) return;
        const k = nk(p.requestId), prev = live.get(k);
        if (prev && p.redirectResponse) { fillResponse(prev, p.redirectResponse); prev.dur = Math.max(0, Math.round((p.timestamp - prev.mono) * 1000)); live.delete(k); emitUpd(prev); }
        const e = { id: uid(), tabId: source.tabId, ts: p.wallTime ? Math.round(p.wallTime * 1000) : Date.now(), mono: p.timestamp,
          method: p.request.method, url, headers: cleanH(p.request.headers), body: p.request.postData ?? null, type: p.type || 'Other', status: null };
        if (xReq.has(k)) { mergeH(e.headers, xReq.get(k)); xReq.delete(k); }
        if (live.size > 2000) live.delete(live.keys().next().value);
        live.set(k, e); addHistory(e);
        if (p.request.hasPostData && e.body == null)
          cmd(source, 'Network.getRequestPostData', { requestId: p.requestId }).then(r => { e.body = r.postData; scheduleSave(); }).catch(() => {});
        return;
      }
      case 'Network.requestWillBeSentExtraInfo': { // real headers incl. Cookie
        const e = live.get(nk(p.requestId));
        if (e) { mergeH(e.headers, p.headers); scheduleSave(); } else xReq.set(nk(p.requestId), p.headers);
        if (xReq.size > 500) xReq.delete(xReq.keys().next().value);
        return;
      }
      case 'Network.responseReceived': {
        const e = live.get(nk(p.requestId)); if (!e) return;
        fillResponse(e, p.response); e.type = p.type || e.type;
        const x = xRes.get(nk(p.requestId)); if (x) { mergeH(e.resHeaders, x); xRes.delete(nk(p.requestId)); }
        emitUpd(e); return;
      }
      case 'Network.responseReceivedExtraInfo': { // includes Set-Cookie
        const e = live.get(nk(p.requestId));
        if (e) { e.resHeaders = mergeH(e.resHeaders || {}, p.headers); if (e.status == null) e.status = p.statusCode; emitUpd(e); }
        else xRes.set(nk(p.requestId), p.headers);
        if (xRes.size > 500) xRes.delete(xRes.keys().next().value);
        return;
      }
      case 'Network.loadingFinished': {
        const k = nk(p.requestId), e = live.get(k); if (!e) return;
        live.delete(k);
        e.size = Math.round(p.encodedDataLength); e.dur = Math.max(0, Math.round((p.timestamp - e.mono) * 1000));
        if (e.status != null && e.status !== 204 && e.status !== 304 && p.encodedDataLength <= 8 * 1048576) {
          try { storeBody(e, await cmd(source, 'Network.getResponseBody', { requestId: p.requestId })); } catch { /* body unavailable */ }
        }
        emitUpd(e); scheduleSave(); return;
      }
      case 'Network.loadingFailed': {
        const k = nk(p.requestId), e = live.get(k); if (!e) return;
        live.delete(k); e.error = p.errorText; if (e.status == null) e.status = 'ERR';
        emitUpd(e); scheduleSave(); return;
      }
      case 'Fetch.requestPaused': return onPaused(source, p);
    }
  }
  const resume = (src, id) => cmd(src, 'Fetch.continueRequest', { requestId: id }).catch(() => {});
  async function onPaused(source, p) {
    const url = p.request.url;
    if (!S.interceptOn || !inScope(url)) return resume(source, p.requestId);
    const req = { method: p.request.method, url, headers: cleanH(p.request.headers), body: p.request.postData ?? null, type: p.resourceType };
    if (p.request.hasPostData && req.body == null) {
      try { req.body = (await cmd(source, 'Network.getRequestPostData', { requestId: p.networkId || p.requestId })).postData; } catch { /* large/binary body */ }
    }
    let cookieNote = false;
    if (!Object.keys(req.headers).some(k => k.toLowerCase() === 'cookie')) {
      try { // Cookie header is added later by the network stack: prefill from the jar so it can be reviewed/edited
        const r = await cmd(source, 'Network.getCookies', { urls: [url] });
        if (r.cookies.length) { req.headers.Cookie = r.cookies.map(c => c.name + '=' + c.value).join('; '); cookieNote = true; }
      } catch { /* ignore */ }
    }
    const id = source.tabId + ':' + (source.sessionId || '') + ':f' + p.requestId;
    pending.set(id, { id, source: dbg(source), fetchId: p.requestId, orig: JSON.parse(JSON.stringify(req)), cookieNote, ts: Date.now() });
    broadcast({ ev: 'paused', item: { id, ts: Date.now(), req, cookieNote, tabId: source.tabId } });
  }
  const normH = o => Object.entries(o).map(([n, v]) => [n.toLowerCase(), String(v)]).sort((a, b) => a[0] < b[0] ? -1 : 1);
  async function forward(id, ed) {
    const it = pending.get(id); if (!it) throw new Error('Request is no longer pending.');
    const o = it.orig, prm = { requestId: it.fetchId };
    if (ed.method && ed.method !== o.method) prm.method = ed.method;
    if (ed.url && ed.url !== o.url) prm.url = ed.url;
    let hs = ed.headers.filter(([n]) => n.trim() && !/^(content-length|host|transfer-encoding|connection)$/i.test(n));
    if ((hs.length !== Object.keys(o.headers).length) || JSON.stringify(normH(Object.fromEntries(hs))) !== JSON.stringify(normH(o.headers))) {
      if (it.cookieNote && getH(hs, 'cookie') === o.headers.Cookie) hs = hs.filter(([n]) => n.toLowerCase() !== 'cookie'); // untouched prefill
      prm.headers = hs.map(([name, value]) => ({ name, value }));
    }
    if ((ed.body || '') !== (o.body || '')) prm.postData = b64(ed.body || '');
    try { await cmd(it.source, 'Fetch.continueRequest', prm); }
    finally { pending.delete(id); broadcast({ ev: 'resolved', id, how: 'forwarded' }); }
  }
  async function dropReq(id) {
    const it = pending.get(id); if (!it) throw new Error('Request is no longer pending.');
    try { await cmd(it.source, 'Fetch.failRequest', { requestId: it.fetchId, errorReason: 'BlockedByClient' }); }
    finally { pending.delete(id); broadcast({ ev: 'resolved', id, how: 'dropped' }); }
  }
  async function continueReq(id) {
    const it = pending.get(id); if (!it) throw new Error('Request is no longer pending.');
    try { await cmd(it.source, 'Fetch.continueRequest', { requestId: it.fetchId }); }
    finally { pending.delete(id); broadcast({ ev: 'resolved', id, how: 'continued' }); }
  }
  async function setIntercept(on) {
    S.interceptOn = !!on; saveSettings();
    for (const t of targets.values()) await applyFetch(t).catch(() => {});
    if (!on) for (const [id, it] of [...pending]) { await resume(it.source, it.fetchId); pending.delete(id); broadcast({ ev: 'resolved', id, how: 'continued' }); }
    bState();
  }

  /* ---------- Repeater ---------- */
  const FORBIDDEN = /^(host|content-length|connection|keep-alive|transfer-encoding|upgrade|te|trailer|expect|date|dnt|via|accept-charset|accept-encoding|access-control-request-.*|proxy-.*|sec-.*|:.*)$/i;
  const DNR_SET = new Set(['cookie', 'origin', 'referer', 'user-agent']);
  let dnrSeq = 0, dnrChain = Promise.resolve();
  async function withDnr(url, hdrs, run) {
    const id = 1000 + (dnrSeq++ % 100000);
    const rx = '^' + url.split('#')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
    let ok = false;
    try {
      // tabIds:[-1] => only requests not tied to a tab, i.e. this worker's own fetch()
      await chrome.declarativeNetRequest.updateSessionRules({ addRules: [{ id, priority: 1, action: { type: 'modifyHeaders', requestHeaders: hdrs },
        condition: { regexFilter: rx, tabIds: [-1], resourceTypes: ['xmlhttprequest', 'other'] } }] });
      ok = true;
    } catch { /* URL too long for the regex engine, etc. */ }
    try { return await run(ok); }
    finally { if (ok) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id] }).catch(() => {}); }
  }
  async function repeat(req) {
    if (!S.authorized) throw new Error('Confirm authorization first (Dashboard).');
    if (!/^https?:\/\//i.test(req.url || '')) throw new Error('URL must start with http:// or https://');
    if (!inScope(req.url)) throw new Error('URL is outside the configured Scope (Settings).');
    const warnings = [], hdr = new Headers(), dnr = [];
    for (const [n, v] of req.headers || []) {
      const l = n.trim().toLowerCase(); if (!l) continue;
      if (DNR_SET.has(l)) dnr.push({ header: l, operation: 'set', value: v });
      else if (FORBIDDEN.test(l)) warnings.push(n);
      else { try { hdr.append(n, v); } catch { warnings.push(n); } }
    }
    const method = String(req.method || 'GET').toUpperCase();
    const init = { method, headers: hdr, credentials: req.useCookies ? 'include' : 'omit', redirect: 'follow', cache: 'no-store', signal: AbortSignal.timeout(60000) };
    if (!/^(GET|HEAD)$/.test(method) && req.body) init.body = req.body;
    const run = async dnrOk => {
      const w = warnings.slice();
      if (dnr.length && !dnrOk) w.push('Cookie/Origin/Referer/User-Agent overrides unavailable');
      const t0 = performance.now();
      try {
        const res = await fetch(req.url, init), buf = new Uint8Array(await res.arrayBuffer());
        const mime = (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
        const out = { ok: true, status: res.status, statusText: res.statusText, url: res.url, redirected: res.redirected, headers: [...res.headers.entries()],
          size: buf.length, dur: Math.round(performance.now() - t0), mime, warnings: w };
        if (/^image\//.test(mime) && buf.length <= 5e6) out.b64 = bufB64(buf);
        else {
          const cap = 2 * 1048576, txt = new TextDecoder().decode(buf.length > cap ? buf.subarray(0, cap) : buf), head = txt.slice(0, 2000);
          if (/\u0000/.test(head) || (head.match(/\uFFFD/g) || []).length > 20) out.body = `[binary content, ${buf.length} bytes]`;
          else { out.body = txt; out.truncated = buf.length > cap; }
        }
        return out;
      } catch (e) { return { ok: false, error: String(e && e.message || e), dur: Math.round(performance.now() - t0), warnings: w }; }
    };
    if (!dnr.length) return run(true);
    const pr = dnrChain.then(() => withDnr(req.url, dnr, run)); // serialized: DNR rules for same URL would conflict
    dnrChain = pr.catch(() => {});
    return pr;
  }

  /* ---------- messaging ---------- */
  chrome.runtime.onConnect.addListener(p => {
    if (p.name !== 'ui') return;
    ports.add(p);
    p.onDisconnect.addListener(() => ports.delete(p));
    p.onMessage.addListener(() => { /* ping: any message resets the worker idle timer */ });
  });
  chrome.action.onClicked.addListener(tab => { if (tab.id != null) chrome.tabs.sendMessage(tab.id, { ev: 'toggle-ui' }).catch(() => {}); });

  async function onMsg(m, sender) {
    await ready;
    switch (m.t) {
      case 'state': return { ...pubState(), tab: sender.tab ? sender.tab.id : null, pending: [...pending.values()].map(it => ({ id: it.id, ts: it.ts, req: it.orig, cookieNote: it.cookieNote })) };
      case 'history': return history.map(summary);
      case 'entry': { const e = byId.get(m.id); if (!e) throw new Error('Entry not found'); return e; }
      case 'entries': return (m.ids || []).map(i => byId.get(i)).filter(Boolean);
      case 'find': {
        const q = String(m.q || '').toLowerCase(); if (!q) return null;
        const hit = e => [e.method, e.url, e.body, e.resBody, e.status].some(x => x != null && String(x).toLowerCase().includes(q)) ||
          Object.entries({ ...e.headers, ...e.resHeaders }).some(([k, v]) => (k + ': ' + v).toLowerCase().includes(q));
        return history.filter(hit).map(e => e.id);
      }
      case 'attach': if (!sender.tab) throw new Error('No tab'); return attachTab(sender.tab.id);
      case 'detach': if (!sender.tab) throw new Error('No tab'); return detachTab(sender.tab.id);
      case 'intercept': return setIntercept(m.on);
      case 'forward': return forward(m.id, m.edits);
      case 'drop': return dropReq(m.id);
      case 'continue': return continueReq(m.id);
      case 'repeat': return repeat(m.req);
      case 'del': { const ids = new Set(m.ids || []); history = history.filter(e => !ids.has(e.id)); ids.forEach(i => byId.delete(i)); broadcast({ ev: 'deleted', ids: [...ids] }); scheduleSave(); return true; }
      case 'clear': history = []; byId.clear(); broadcast({ ev: 'cleared' }); chrome.storage.local.set({ history: [] }); return true;
      case 'settings': {
        const n = m.s || {}, old = S, g = (k, f) => k in n ? f(n[k]) : S[k];
        S = { ...S,
          authorized: g('authorized', Boolean), scope: g('scope', v => String(v)),
          pauseTypes: g('pauseTypes', v => Array.isArray(v) ? v.filter(x => TYPES.includes(x)) : S.pauseTypes),
          maxEntries: g('maxEntries', v => clampInt(v, 10, 5000, S.maxEntries)), maxBodyKB: g('maxBodyKB', v => clampInt(v, 1, 8192, S.maxBodyKB)),
          persist: g('persist', Boolean), mask: g('mask', Boolean) };
        if (!S.authorized) { for (const t of attachedTabs()) await detachTab(t); S.interceptOn = false; }
        const ev = trimHistory(); if (ev.length) broadcast({ ev: 'deleted', ids: ev });
        if (old.pauseTypes.join() !== S.pauseTypes.join()) for (const t of targets.values()) await applyFetch(t).catch(() => {});
        if (!S.persist) chrome.storage.local.set({ history: [] }); else scheduleSave();
        await saveSettings(); bState(); return true;
      }
      case 'wipe': history = []; byId.clear(); await chrome.storage.local.clear(); await saveSettings(); broadcast({ ev: 'cleared' }); return true;
      default: throw new Error('Unknown message: ' + m.t);
    }
  }
  chrome.runtime.onMessage.addListener((m, sender, reply) => {
    onMsg(m, sender).then(r => reply({ ok: true, r }), e => reply({ ok: false, error: String(e && e.message || e) }));
    return true; // async reply
  });
}

/* ============================================================================
   CONTENT SCRIPT: floating button + main interface (Shadow DOM)
   ============================================================================ */
function contentMain() {
  if (window.top !== window || window.__biLoaded) return;
  window.__biLoaded = true;

  const h = (t, a = {}, ...c) => {
    const e = document.createElement(t);
    for (const k in a) {
      const v = a[k];
      if (k === 'class') e.className = v; else if (k === 'style') e.style.cssText = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, ''); else if (v !== false && v != null) e.setAttribute(k, v);
    }
    c.flat(Infinity).forEach(x => x != null && e.append(x.nodeType ? x : document.createTextNode(String(x))));
    return e;
  };
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const debounce = (f, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; };
  const raf = f => { let p = 0; return () => { if (p) return; p = 1; requestAnimationFrame(() => { p = 0; f(); }); }; };

  const ctx = { settings: { mask: true, pauseTypes: [], maxEntries: 300, maxBodyKB: 256, persist: true, scope: '', authorized: false },
    st: { interceptOn: false, attached: [], tab: null }, hist: [], map: new Map(), pending: [], reveal: false };
  const subs = {};
  const on = (n, f) => (subs[n] = subs[n] || []).push(f);
  const fire = n => (subs[n] || []).forEach(f => { try { f(); } catch (e) { console.error('[BI]', e); } });
  const maskOn = () => ctx.settings.mask && !ctx.reveal;
  const ui = { fab: { x: null, y: null }, panel: { x: null, y: null, w: 1000, h: 620 }, open: false, max: false, compact: false, visible: true, tab: 'dashboard' };
  const saveUi = debounce(() => { try { chrome.storage.local.set({ ui }); } catch { /* context invalidated */ } }, 300);

  const rpc = (t, p = {}) => new Promise((res, rej) => {
    try {
      chrome.runtime.sendMessage({ t, ...p }, r => {
        const le = chrome.runtime.lastError;
        if (le) return rej(new Error(le.message));
        if (!r) return rej(new Error('No response from background'));
        r.ok ? res(r.r) : rej(new Error(r.error));
      });
    } catch (e) { rej(new Error('Extension was reloaded — refresh this page.')); }
  });

  /* ---------------- shell DOM ---------------- */
  const host = h('div', { id: '__browser_intercept__' });
  host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
  const root = host.attachShadow({ mode: 'open' });
  const box = h('div', { class: 'bi' });
  root.append(h('style', {}, CSS()), box);
  ['keydown', 'keyup', 'keypress'].forEach(ev => host.addEventListener(ev, e => e.stopPropagation())); // keep typing away from site hotkeys

  function toast(msg, bad) {
    const t = h('div', { class: 'toast' + (bad ? ' bad' : '') }, msg);
    box.append(t); setTimeout(() => t.remove(), 3800);
  }
  function modal(title, body, btns = ['OK']) {
    return new Promise(res => {
      const done = i => { m.remove(); res(i); };
      const m = h('div', { class: 'modal', tabindex: '-1' }, h('div', { class: 'mbox' }, h('div', { class: 'mt' }, title), h('div', { class: 'mb' }, body),
        h('div', { class: 'mf' }, btns.map((b, i) => h('button', { class: 'btn' + (i === btns.length - 1 && btns.length > 1 ? ' pri' : ''), onclick: () => done(i) }, b)))));
      m.addEventListener('keydown', e => { if (e.key === 'Escape') done(-1); });
      box.append(m); m.focus();
    });
  }
  async function copyText(t) {
    try { await navigator.clipboard.writeText(t); return true; } catch { /* insecure context or no focus */ }
    try { const ta = h('textarea', { style: 'position:fixed;opacity:0' }); ta.value = t; box.append(ta); ta.select(); const ok = document.execCommand('copy'); ta.remove(); if (ok) return true; } catch { /* fall through */ }
    await modal('Copy manually', h('textarea', { class: 'in', style: 'width:min(70vw,640px);height:40vh' }, t)); return false;
  }
  async function doExport(kind, req) {
    const opts = { secrets: false };
    if (req.headers.some(([n]) => isSecretHeader(n))) {
      const c = await modal('Secrets detected', 'This request contains cookies / authorization / token values. Include them in the export? (They only go to your clipboard.)',
        ['Cancel', 'Export without secrets', 'Include secrets']);
      if (c <= 0) return;
      opts.secrets = c === 2;
    }
    const txt = kind === 'python' ? toPython(req, opts) : kind === 'curl' ? toCurl(req, opts) : toRaw(req, { secrets: opts.secrets, maskStr: '[REDACTED]' });
    toast((await copyText(txt)) ? 'Copied ' + kind : 'Copy failed', false);
  }
  const exportBtns = getReq => h('span', { class: 'grp' },
    h('button', { class: 'btn sm', onclick: () => doExport('python', getReq()) }, 'Copy as Python'),
    h('button', { class: 'btn sm', onclick: () => doExport('curl', getReq()) }, 'Copy as cURL'),
    h('button', { class: 'btn sm', onclick: () => doExport('raw', getReq()) }, 'Copy raw request'));

  /* ---------------- reusable components ---------------- */
  function codeBox({ lang = 'text', readOnly = false, onInput } = {}) {
    let lng = lang;
    const pre = h('pre', { class: 'cb-pre' }), ta = h('textarea', { class: 'cb-ta', spellcheck: 'false', wrap: 'off' });
    if (readOnly) ta.readOnly = true;
    const paint = () => { pre.innerHTML = highlight(lng, ta.value) + '\n'; };
    ta.addEventListener('input', () => { paint(); onInput && onInput(ta.value); });
    ta.addEventListener('scroll', () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; });
    return { el: h('div', { class: 'cb' }, pre, ta), get: () => ta.value, set(v, l) { ta.value = v == null ? '' : v; if (l) lng = l; paint(); } };
  }
  function kvEditor({ onChange, masked, ph = ['name', 'value'] }) {
    let rows = [];
    const list = h('div', { class: 'kv' });
    const ch = () => onChange && onChange();
    const render = () => {
      list.textContent = '';
      rows.forEach((r, i) => {
        const ni = h('input', { class: 'in', placeholder: ph[0], spellcheck: 'false' }), vi = h('input', { class: 'in', placeholder: ph[1], spellcheck: 'false' });
        const mk = () => masked && masked(r.n);
        ni.value = r.n; vi.value = mk() ? MASK : r.v;
        ni.oninput = () => { r.n = ni.value; ch(); };
        vi.onfocus = () => { if (mk()) vi.value = r.v; }; // reveal only while editing a masked value
        vi.onblur = () => { if (mk()) vi.value = MASK; };
        vi.oninput = () => { r.v = vi.value; ch(); };
        list.append(h('div', { class: 'kvr' }, ni, vi, h('button', { class: 'btn sm danger', title: 'Delete', onclick: () => { rows.splice(i, 1); render(); ch(); } }, '×')));
      });
    };
    const el = h('div', { class: 'kvw' }, list, h('button', { class: 'btn sm', onclick: () => { rows.push({ n: '', v: '' }); render(); ch(); } }, '+ Add'));
    return { el, set(a) { rows = a.map(([n, v]) => ({ n, v })); render(); }, get: () => rows.map(r => [r.n, r.v]), refresh: render };
  }

  /* ---- request editor: method, URL, path, params, headers, cookies, body, raw ---- */
  function makeEditor(opts = {}) {
    const chg = () => opts.onChange && opts.onChange();
    const S = { body: '' }; let tabIdx = 0, rawPrev = null;
    const mSel = h('select', { class: 'in meth', onchange: () => { chg(); if (tabIdx === 4) refreshRaw(); } }, METHODS.map(m => h('option', { value: m }, m)));
    const urlIn = h('input', { class: 'in grow', placeholder: 'https://host/path?x=1', spellcheck: 'false' });
    const pathIn = h('input', { class: 'in grow', placeholder: '/path', spellcheck: 'false' });
    const params = kvEditor({ ph: ['param', 'value'], onChange: () => { syncUrl(); chg(); } });
    const hdrs = kvEditor({ ph: ['Header', 'value'], onChange: chg, masked: n => maskOn() && isSecretHeader(n) });
    const cookies = kvEditor({ ph: ['cookie', 'value'], onChange: chg, masked: () => maskOn() });
    const bodyBox = codeBox({ onInput: v => { S.body = v; chg(); } });
    const form = kvEditor({ ph: ['field', 'value'], onChange: () => { S.body = new URLSearchParams(form.get().filter(r => r[0])).toString(); bodyBox.set(S.body); chg(); } });
    const mp = h('pre', { class: 'mp' });
    const ctOf = () => getH(hdrs.get(), 'content-type') || '';
    const bodyMode = h('select', { class: 'in', onchange: () => showBody() },
      h('option', { value: 'raw' }, 'Raw'), h('option', { value: 'form' }, 'URL-encoded form'), h('option', { value: 'multipart' }, 'Multipart (view)'));
    const jsonFmt = (pretty) => () => {
      try { const j = JSON.parse(S.body); S.body = pretty ? JSON.stringify(j, null, 2) : JSON.stringify(j); bodyBox.set(S.body, 'json'); chg(); }
      catch { toast('Body is not valid JSON', true); }
    };
    function showBody() {
      const m = bodyMode.value;
      bodyBox.el.style.display = m === 'raw' ? '' : 'none'; form.el.style.display = m === 'form' ? '' : 'none'; mp.style.display = m === 'multipart' ? '' : 'none';
      if (m === 'form') form.set([...new URLSearchParams(S.body)]);
      if (m === 'multipart') mp.textContent = parseMultipart(S.body, ctOf());
    }
    const bodyPane = h('div', { class: 'col' }, h('div', { class: 'tb' }, bodyMode,
      h('button', { class: 'btn sm', onclick: jsonFmt(true) }, 'Pretty JSON'), h('button', { class: 'btn sm', onclick: jsonFmt(false) }, 'Minify')), bodyBox.el, form.el, mp);
    const rawBox = codeBox({ lang: 'http' });
    const rawPane = h('div', { class: 'col' }, h('div', { class: 'tb' },
      h('button', { class: 'btn sm', onclick: () => refreshRaw() }, '↻ From editor'), h('button', { class: 'btn sm pri', onclick: () => applyRaw() }, 'Apply raw → editor'),
      h('span', { class: 'mut' }, 'Edit, then Apply. Masked values (••••) keep their real value.')), rawBox.el);
    const names = ['Params', 'Headers', 'Cookies', 'Body', 'Raw'], panes = [params.el, hdrs.el, cookies.el, bodyPane, rawPane];
    const tabBtns = names.map((n, i) => h('button', { onclick: () => showTab(i) }, n));
    const pane = h('div', { class: 'edpane' }, panes);
    function showTab(i) { tabIdx = i; tabBtns.forEach((b, k) => b.classList.toggle('act', k === i)); panes.forEach((p, k) => { p.style.display = k === i ? '' : 'none'; }); if (i === 4) refreshRaw(); if (i === 3) showBody(); }
    function syncUrl() {
      const u = urlIn.value, hashI = u.indexOf('#'), hash = hashI < 0 ? '' : u.slice(hashI), base = (hashI < 0 ? u : u.slice(0, hashI)).split('?')[0];
      const sp = new URLSearchParams(); params.get().forEach(([n, v]) => { if (n) sp.append(n, v); });
      const q = sp.toString(); urlIn.value = base + (q ? '?' + q : '') + hash;
    }
    function readUrl() {
      params.set(parseQuery(urlIn.value));
      try { pathIn.value = new URL(urlIn.value).pathname; } catch { pathIn.value = ''; }
    }
    urlIn.addEventListener('change', () => { readUrl(); chg(); });
    pathIn.addEventListener('change', () => { try { const u = new URL(urlIn.value); u.pathname = pathIn.value || '/'; urlIn.value = u.toString(); readUrl(); chg(); } catch { toast('Invalid URL', true); } });
    function get() {
      const headers = hdrs.get().filter(([n]) => n.trim()), ck = joinCookies(cookies.get());
      if (ck) headers.push(['Cookie', ck]);
      let body = S.body;
      if (/multipart\//i.test(getH(headers, 'content-type') || '')) body = body.replace(/\r?\n/g, '\r\n'); // textarea normalises to LF
      return { method: mSel.value, url: urlIn.value.trim(), headers, body };
    }
    function load(r) {
      let hs = Array.isArray(r.headers) ? r.headers.map(x => [x[0], x[1]]) : Object.entries(r.headers || {});
      const ck = getH(hs, 'cookie'); hs = hs.filter(([n]) => !/^(cookie|host)$/i.test(n));
      if (![...mSel.options].some(o => o.value === r.method)) mSel.append(h('option', { value: r.method }, r.method));
      mSel.value = r.method; urlIn.value = r.url; readUrl(); hdrs.set(hs); cookies.set(parseCookies(ck || ''));
      S.body = r.body || '';
      const c = getH(hs, 'content-type') || '';
      bodyBox.set(S.body, /json/i.test(c) || /^\s*[\[{]/.test(S.body) ? 'json' : /html/i.test(c) ? 'html' : 'text');
      bodyMode.value = /x-www-form-urlencoded/i.test(c) ? 'form' : /multipart\//i.test(c) ? 'multipart' : 'raw';
      showBody(); if (tabIdx === 4) refreshRaw();
    }
    function refreshRaw() { rawPrev = get(); rawBox.set(toRaw(rawPrev, { secrets: !maskOn() }), 'http'); }
    function applyRaw() {
      try {
        const p = parseRaw(rawBox.get(), urlIn.value || 'http://localhost/'), prev = rawPrev || get();
        p.headers = p.headers.map(([n, v]) => {
          if (n.toLowerCase() === 'cookie') {
            const pc = Object.fromEntries(parseCookies(getH(prev.headers, 'cookie') || ''));
            return [n, joinCookies(parseCookies(v).map(([cn, cv]) => [cn, cv === MASK ? (pc[cn] ?? '') : cv]))];
          }
          return [n, v === MASK ? (getH(prev.headers, n.toLowerCase()) ?? '') : v];
        });
        load(p); chg(); toast('Raw applied');
      } catch (e) { toast(e.message, true); }
    }
    const el = h('div', { class: 'ed' },
      h('div', { class: 'edtop' }, mSel, urlIn), h('div', { class: 'edtop' }, h('span', { class: 'mut' }, 'Path'), pathIn),
      h('div', { class: 'tabs sm' }, tabBtns), pane);
    showTab(1);
    return { el, load, get, refresh() { hdrs.refresh(); cookies.refresh(); if (tabIdx === 4) refreshRaw(); } };
  }

  /* ---- response viewer: Headers / Body / Preview ---- */
  async function drawImg(b64, mime, boxEl) {
    boxEl.textContent = '';
    try { // canvas path avoids the host page's CSP img-src restrictions on data: URLs
      const bin = atob(b64), u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      const bm = await createImageBitmap(new Blob([u], { type: mime }));
      const c = h('canvas', { class: 'cv' }); c.width = bm.width; c.height = bm.height; c.getContext('2d').drawImage(bm, 0, 0); boxEl.append(c);
    } catch { boxEl.append(h('img', { class: 'cv', src: `data:${mime};base64,${b64}` })); }
  }
  function makeResp() {
    let cur = null;
    const meta = h('div', { class: 'meta' }, 'No response yet'), warn = h('div', { class: 'warn' });
    const hdrPane = h('div', { class: 'hdrs' }), prev = h('div', { class: 'prev' });
    const fmt = h('select', { class: 'in', onchange: () => render() }, ['auto', 'json', 'html', 'text', 'raw'].map(o => h('option', { value: o }, o === 'auto' ? 'Auto format' : o.toUpperCase())));
    const bodyBox = codeBox({ readOnly: true });
    const bodyPane = h('div', { class: 'col' }, h('div', { class: 'tb' }, fmt, h('span', { class: 'mut', id: 'rinfo' })), bodyBox.el);
    const panes = [hdrPane, bodyPane, prev], names = ['Headers', 'Body', 'Preview'];
    let idx = 1; const btns = names.map((n, i) => h('button', { onclick: () => show(i) }, n));
    function show(i) { idx = i; btns.forEach((b, k) => b.classList.toggle('act', k === i)); panes.forEach((p, k) => { p.style.display = k === i ? '' : 'none'; }); }
    function render() {
      warn.textContent = '';
      if (!cur) { meta.textContent = 'No response yet'; hdrPane.textContent = ''; bodyBox.set(''); prev.textContent = ''; return; }
      if (cur.ok === false || (cur.error && cur.status == null)) {
        meta.innerHTML = `<span class="st e">ERROR</span> ${esc(cur.error || 'failed')}${cur.dur != null ? ' · ' + cur.dur + ' ms' : ''}`;
        hdrPane.textContent = ''; bodyBox.set(cur.error || ''); prev.textContent = '';
        if (cur.warnings && cur.warnings.length) warn.textContent = 'Not sent (browser-controlled): ' + cur.warnings.join(', ');
        return;
      }
      const s = cur.status, cls = s == null ? '' : s >= 400 ? 'e' : s >= 300 ? 'w' : 'o';
      meta.innerHTML = `<span class="st ${cls}">${s ?? '…'} ${esc(cur.statusText || '')}</span> · ${fmtBytes(cur.size)} · ${cur.dur ?? '–'} ms · ${esc(cur.mime || '')}${cur.proto ? ' · ' + esc(cur.proto) : ''}${cur.redirected ? ' · redirected → ' + esc(cur.url) : ''}`;
      if (cur.warnings && cur.warnings.length) warn.textContent = 'Not sent (browser-controlled, cannot be reproduced exactly): ' + cur.warnings.join(', ');
      const arr = Array.isArray(cur.headers) ? cur.headers : Object.entries(cur.headers || {});
      hdrPane.innerHTML = arr.map(([n, v]) => `<div><span class="k">${esc(n)}</span>: ${esc(maskOn() && isSecretHeader(n) ? MASK : v)}</div>`).join('') || '<span class="mut">No headers</span>';
      const text = cur.body == null ? '' : String(cur.body), isImg = !!cur.b64;
      let out = text, lang = 'text';
      const f = fmt.value, m = (cur.mime || '').toLowerCase();
      const kind = f !== 'auto' ? f : /json/.test(m) ? 'json' : /html|xml/.test(m) ? 'html' : /^\s*[\[{]/.test(text) ? 'json' : 'text';
      if (isImg) out = `[image ${cur.mime}, ${fmtBytes(cur.size)} — see Preview]`;
      else if (kind === 'json') { lang = 'json'; try { out = JSON.stringify(JSON.parse(text), null, 2); } catch { /* not JSON */ } }
      else if (kind === 'html') { lang = 'html'; out = prettyHtml(text); }
      else if (kind === 'raw') lang = /json/.test(m) ? 'json' : /html/.test(m) ? 'html' : 'text';
      bodyPane.querySelector('#rinfo').textContent = cur.truncated ? 'truncated (size cap)' : '';
      bodyBox.set(out, lang);
      prev.textContent = '';
      if (isImg) drawImg(cur.b64, cur.mime, prev);
      else if (/html/.test(m) || (kind === 'html' && /<html|<body|<!doctype/i.test(text))) prev.append(h('iframe', { class: 'ifr', sandbox: '', srcdoc: text }));
      else prev.append(h('pre', { class: 'mp' }, out));
    }
    show(1);
    return { el: h('div', { class: 'ed' }, meta, warn, h('div', { class: 'tabs sm' }, btns), h('div', { class: 'edpane' }, panes)),
      load(r) { cur = r; render(); }, clear() { cur = null; render(); }, loading() { meta.textContent = 'Sending…'; }, refresh: render };
  }
  const entryToResp = e => ({ ok: true, status: e.status, statusText: e.statusText, headers: e.resHeaders || {}, body: e.resBody, b64: e.resB64, mime: e.resMime,
    size: e.size, dur: e.dur, truncated: e.resTrunc, proto: e.proto, error: e.error });
  const entryToReq = e => ({ method: e.method, url: e.url, headers: e.headers || {}, body: e.body });

  function workspace(...panes) {
    return h('div', { class: 'ws' + (panes.length === 2 ? ' two' : '') }, panes.map(p => h('div', { class: 'pane' }, p)));
  }
  const stCls = s => s == null ? '' : (s === 'ERR' || s >= 400) ? 'e' : s >= 300 ? 'w' : 'o';

  /* ---------------- views ---------------- */
  function dashboardView() {
    const el = h('div', { class: 'view dash' });
    const render = raf(() => {
      el.textContent = '';
      const att = ctx.st.attached.includes(ctx.st.tab), s = ctx.settings;
      if (!s.authorized) {
        const cb = h('input', { type: 'checkbox', onchange: () => rpc('settings', { s: { authorized: cb.checked } }).catch(e => toast(e.message, true)) });
        el.append(h('div', { class: 'card warnc' }, h('b', {}, 'Authorization required'),
          h('p', {}, 'Use this tool only on systems you own or are explicitly authorized to test. Nothing is captured until you confirm.'),
          h('label', {}, cb, ' I confirm I am authorized to test the sites I attach to.')));
      }
      const m = {}, c = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, 'ERR': 0 }, hosts = {};
      for (const e of ctx.hist) {
        m[e.method] = (m[e.method] || 0) + 1; hosts[e.host] = (hosts[e.host] || 0) + 1;
        const st = e.status; if (st === 'ERR') c.ERR++; else if (st >= 200 && st < 600) c[Math.floor(st / 100) + 'xx']++;
      }
      const bars = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) =>
        h('div', { class: 'bar2' }, h('span', {}, k || '(none)'), h('i', { style: `width:${Math.max(3, 100 * v / Math.max(1, ctx.hist.length))}%` }), h('b', {}, v)));
      el.append(h('div', { class: 'cards' },
        h('div', { class: 'card' }, h('b', {}, 'This tab'), h('p', {}, att ? '● Debugger attached' : '○ Not attached'),
          h('button', { class: 'btn ' + (att ? '' : 'pri'), disabled: !s.authorized, onclick: () => rpc(att ? 'detach' : 'attach').catch(e => toast(e.message, true)) }, att ? 'Detach' : 'Attach to this tab')),
        h('div', { class: 'card' }, h('b', {}, 'Intercept'), h('p', {}, ctx.st.interceptOn ? 'ON — eligible requests are paused' : 'OFF — requests flow normally'),
          h('button', { class: 'btn ' + (ctx.st.interceptOn ? 'on' : ''), onclick: () => rpc('intercept', { on: !ctx.st.interceptOn }).catch(e => toast(e.message, true)) }, ctx.st.interceptOn ? 'Turn OFF' : 'Turn ON')),
        h('div', { class: 'card' }, h('b', {}, 'Totals'), h('p', {}, `${ctx.hist.length} requests · ${ctx.pending.length} pending`)),
        h('div', { class: 'card' }, h('b', {}, 'Methods'), bars(m, 7)), h('div', { class: 'card' }, h('b', {}, 'Status'), bars(c, 5)), h('div', { class: 'card' }, h('b', {}, 'Top hosts'), bars(hosts, 6))),
        h('div', { class: 'note' }, 'Tip: Chrome shows a "debugging this browser" bar while attached (cannot be hidden). Only requests made after Attach are captured; use Settings → Scope to restrict capture to your test hosts.'));
    });
    ['state', 'hist', 'pending'].forEach(n => on(n, render)); render();
    return { el, id: 'dashboard', title: 'Dashboard' };
  }

  function interceptView() {
    const el = h('div', { class: 'view' });
    let cur = null, orig = null;
    const editor = makeEditor(), origBox = codeBox({ lang: 'http', readOnly: true });
    const list = h('div', { class: 'list' });
    const sw = h('button', { class: 'btn', onclick: () => rpc('intercept', { on: !ctx.st.interceptOn }).catch(e => toast(e.message, true)) });
    const act = (t, label) => async () => {
      if (!cur) return toast('No request selected', true);
      try {
        const id = cur;
        await rpc(t, t === 'forward' ? { id, edits: editor.get() } : { id });
      } catch (e) { toast(e.message, true); }
    };
    const bF = h('button', { class: 'btn pri', title: 'Send the edited request', onclick: act('forward') }, 'Forward');
    const bD = h('button', { class: 'btn danger', title: 'Block the request', onclick: act('drop') }, 'Drop');
    const bC = h('button', { class: 'btn', title: 'Send the original, unmodified', onclick: act('continue') }, 'Continue');
    const info = h('span', { class: 'mut' });
    const tb = h('div', { class: 'tb' }, sw, bF, bC, bD, info, exportBtns(() => editor.get()));
    function select(id) {
      cur = id; const it = ctx.pending.find(p => p.id === id);
      if (it) { orig = it.req; editor.load(it.req); origBox.set(toRaw({ ...entryToReq(it.req), headers: Object.entries(it.req.headers) }, { secrets: !maskOn() }), 'http'); }
      else { editor.load({ method: 'GET', url: '', headers: [], body: '' }); origBox.set(''); }
      renderList();
    }
    function renderList() {
      sw.textContent = 'Intercept: ' + (ctx.st.interceptOn ? 'ON' : 'OFF'); sw.classList.toggle('on', ctx.st.interceptOn);
      info.textContent = ctx.pending.length + ' pending' + (ctx.st.attached.includes(ctx.st.tab) ? '' : ' · attach this tab first (Dashboard)');
      [bF, bC, bD].forEach(b => { b.disabled = !cur; });
      list.innerHTML = ctx.pending.map(p => `<div class="row${p.id === cur ? ' sel' : ''}" data-id="${esc(p.id)}"><b class="m m-${esc(p.req.method)}">${esc(p.req.method)}</b><span class="u" title="${esc(p.req.url)}">${esc(p.req.url)}</span></div>`).join('') || '<div class="empty">Nothing paused.<br>Turn Intercept ON, attach a tab and browse.</div>';
    }
    list.addEventListener('click', e => { const r = e.target.closest('.row'); if (r) select(r.dataset.id); });
    on('pending', () => { if (cur && !ctx.pending.some(p => p.id === cur)) { cur = null; if (ctx.pending[0]) select(ctx.pending[0].id); else select(null); } else if (!cur && ctx.pending[0]) select(ctx.pending[0].id); else renderList(); });
    on('state', renderList); on('reveal', () => { editor.refresh(); if (cur) select(cur); });
    el.append(tb, workspace(list, editor.el, h('div', { class: 'col' }, h('div', { class: 'tb' }, h('b', {}, 'Original request')), origBox.el)));
    renderList();
    return { el, id: 'intercept', title: 'Intercept', badge: () => ctx.pending.length };
  }

  function historyView() {
    const el = h('div', { class: 'view' });
    const f = { url: '', host: '', method: '', status: '', type: '', q: '' };
    let found = null, curId = null, curEntry = null, desc = true;
    const sel = new Set();
    const editor = makeEditor(), resp = makeResp(), list = h('div', { class: 'list' });
    const inp = (ph, k, w) => h('input', { class: 'in', placeholder: ph, style: `width:${w}px`, oninput: ev => { f[k] = ev.target.value; if (k === 'q') findDebounced(); else render(); } });
    const sel2 = (k, opts, lab) => h('select', { class: 'in', onchange: ev => { f[k] = ev.target.value; render(); } }, h('option', { value: '' }, lab), opts.map(o => h('option', { value: o }, o)));
    const findDebounced = debounce(async () => {
      if (f.q.length < 2) { found = null; return render(); }
      try { found = new Set(await rpc('find', { q: f.q })); } catch { found = null; }
      render();
    }, 250);
    const match = s => {
      if (f.method && s.method !== f.method) return false;
      if (f.type && s.type !== f.type) return false;
      if (f.host && !s.host.toLowerCase().includes(f.host.toLowerCase())) return false;
      if (f.url && !s.url.toLowerCase().includes(f.url.toLowerCase())) return false;
      if (f.status) {
        const st = s.status;
        if (f.status === 'ERR' ? st !== 'ERR' : f.status === 'pending' ? st != null : !(typeof st === 'number' && Math.floor(st / 100) === +f.status[0])) return false;
      }
      return !(found && !found.has(s.id));
    };
    const visible = () => { const a = ctx.hist.filter(match); return desc ? a.slice().reverse() : a; };
    const render = raf(() => {
      const a = visible();
      list.innerHTML = a.map(s => `<div class="row${s.id === curId ? ' sel' : ''}" data-id="${esc(s.id)}"><input type="checkbox"${sel.has(s.id) ? ' checked' : ''}><span class="t">${new Date(s.ts).toLocaleTimeString()}</span><b class="m m-${esc(s.method)}">${esc(s.method)}</b><span class="st ${stCls(s.status)}">${s.status ?? '…'}</span><span class="u" title="${esc(s.url)}">${esc(s.host)}${esc(s.path)}</span><span class="z">${fmtBytes(s.size)}</span></div>`).join('') || '<div class="empty">No requests match.</div>';
      cnt.textContent = `${a.length}/${ctx.hist.length}` + (sel.size ? ` · ${sel.size} selected` : '');
    });
    const cnt = h('span', { class: 'mut' });
    async function open(id) {
      curId = id;
      try { curEntry = await rpc('entry', { id }); editor.load(entryToReq(curEntry)); resp.load(entryToResp(curEntry)); } catch (e) { toast(e.message, true); }
      render();
    }
    list.addEventListener('click', e => {
      const r = e.target.closest('.row'); if (!r) return;
      if (e.target.matches('input')) { e.target.checked ? sel.add(r.dataset.id) : sel.delete(r.dataset.id); render(); } else open(r.dataset.id);
    });
    const targetIds = () => sel.size ? [...sel] : (curId ? [curId] : []);
    const redact = e => {
      const rd = o => Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [k, isSecretHeader(k) ? '[REDACTED]' : v]));
      return { ...e, headers: rd(e.headers), resHeaders: rd(e.resHeaders) };
    };
    async function exportJson() {
      const ids = sel.size ? [...sel] : visible().map(s => s.id);
      if (!ids.length) return toast('Nothing to export', true);
      const c = await modal('Export history', `Export ${ids.length} request(s) as JSON. Cookies / Authorization / token headers are redacted unless you choose to include them.`, ['Cancel', 'Export redacted', 'Include secrets']);
      if (c <= 0) return;
      try {
        let es = await rpc('entries', { ids }); if (c === 1) es = es.map(redact);
        const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), entries: es }, null, 2)], { type: 'application/json' })), download: `intercept-history-${Date.now()}.json` });
        box.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      } catch (e) { toast(e.message, true); }
    }
    const tb1 = h('div', { class: 'tb' }, inp('URL contains', 'url', 120), inp('Domain', 'host', 90), sel2('method', METHODS, 'Method'),
      sel2('status', ['2xx', '3xx', '4xx', '5xx', 'ERR', 'pending'], 'Status'), sel2('type', TYPES, 'Type'), inp('Search headers/bodies', 'q', 150));
    const tb2 = h('div', { class: 'tb' },
      h('button', { class: 'btn sm', onclick: () => { desc = !desc; sortB.textContent = desc ? 'Newest ↓' : 'Oldest ↑'; render(); } }, ''), cnt,
      h('button', { class: 'btn sm', onclick: () => { if (!curEntry) return toast('Select a request first', true); fire('toRepeater'); window.__biToRepeater && window.__biToRepeater(editor.get()); } }, '→ Repeater'),
      exportBtns(() => editor.get()),
      h('button', { class: 'btn sm danger', onclick: async () => { const ids = targetIds(); if (!ids.length) return; await rpc('del', { ids }).catch(e => toast(e.message, true)); sel.clear(); } }, 'Delete'),
      h('button', { class: 'btn sm danger', onclick: async () => { if (await modal('Clear history', 'Delete all recorded requests?', ['Cancel', 'Clear']) === 1) rpc('clear').catch(e => toast(e.message, true)); } }, 'Clear'),
      h('button', { class: 'btn sm', onclick: exportJson }, 'Export JSON'));
    const sortB = tb2.firstChild; sortB.textContent = 'Newest ↓';
    on('hist', render); on('reveal', () => { editor.refresh(); resp.refresh(); });
    on('histUpd', id => { if (id === curId) open(id); });
    el.append(tb1, tb2, workspace(list, editor.el, resp.el));
    render();
    return { el, id: 'history', title: 'HTTP History', badge: null };
  }

  function repeaterView() {
    const el = h('div', { class: 'view' });
    const strip = h('div', { class: 'rtabs' }), body = h('div', { class: 'rbody' });
    let tabs = [], active = null, n = 0;
    const save = debounce(() => { try { chrome.storage.local.set({ repeater: tabs.map(t => ({ name: t.name, req: t.ed.get(), orig: t.orig, useCookies: t.useCookies })) }); } catch { /* ignore */ } }, 500);
    function label(t) { const r = t.ed.get(); let p = r.url; try { const u = new URL(r.url); p = u.pathname; } catch { /* keep */ } return `${r.method} ${p}`.slice(0, 26); }
    function newTab(req, useCookies = false, orig) {
      const t = { id: ++n, useCookies, ed: makeEditor({ onChange: () => { t.btn.firstChild.textContent = label(t); save(); } }), rs: makeResp() };
      t.ed.load(req); t.orig = orig || t.ed.get(); t.name = label(t);
      const send = h('button', { class: 'btn pri', onclick: async () => {
        const r = t.ed.get(); send.disabled = true; t.rs.loading();
        try { t.rs.load(await rpc('repeat', { req: { ...r, useCookies: t.useCookies } })); } catch (e) { t.rs.load({ ok: false, error: e.message }); }
        send.disabled = false;
      } }, 'Send ▶');
      const ck = h('input', { type: 'checkbox', onchange: () => { t.useCookies = ck.checked; save(); } }); ck.checked = useCookies;
      const tb = h('div', { class: 'tb' }, send, h('label', { title: 'credentials: include — send the browser cookie jar for this URL' }, ck, ' browser cookies'),
        h('button', { class: 'btn sm', onclick: () => showDiff(t) }, 'Compare'), h('button', { class: 'btn sm', onclick: () => { t.orig = t.ed.get(); toast('Baseline updated'); save(); } }, 'Set baseline'),
        h('button', { class: 'btn sm', onclick: () => { const c = newTab(t.ed.get(), t.useCookies); activate(c); } }, 'Duplicate'), exportBtns(() => t.ed.get()));
      t.pane = h('div', { class: 'ws two', style: 'display:none' }, h('div', { class: 'pane' }, tb, t.ed.el), h('div', { class: 'pane' }, t.rs.el));
      t.btn = h('div', { class: 'rtab', onclick: () => activate(t) }, h('span', {}, t.name), h('i', { onclick: ev => { ev.stopPropagation(); close(t); } }, '×'));
      tabs.push(t); strip.insertBefore(t.btn, plus); body.append(t.pane); save();
      return t;
    }
    function activate(t) { active = t; tabs.forEach(x => { x.pane.style.display = x === t ? '' : 'none'; x.btn.classList.toggle('act', x === t); }); }
    function close(t) {
      tabs = tabs.filter(x => x !== t); t.pane.remove(); t.btn.remove();
      if (!tabs.length) activate(newTab({ method: 'GET', url: 'https://', headers: [], body: '' })); else if (active === t) activate(tabs[tabs.length - 1]); save();
    }
    function showDiff(t) {
      const a = toRaw(t.orig, { secrets: false }), b = toRaw(t.ed.get(), { secrets: false }); // secrets masked in the diff view
      const ops = diffLines(a, b), same = ops.every(o => o.t === ' ');
      modal('Original vs modified request', same ? 'No differences.' : h('pre', { class: 'diff' }, ops.map(o => h('div', { class: 'd' + (o.t === '+' ? 'a' : o.t === '-' ? 'r' : 'n') }, (o.t === ' ' ? '  ' : o.t + ' ') + o.s))), ['Close']);
    }
    const plus = h('div', { class: 'rtab plus', onclick: () => activate(newTab({ method: 'GET', url: 'https://', headers: [], body: '' })) }, '+');
    strip.append(plus);
    window.__biToRepeater = req => { activate(newTab(req)); setTab('repeater'); };
    on('reveal', () => tabs.forEach(t => { t.ed.refresh(); t.rs.refresh(); }));
    (async () => {
      let saved = []; try { saved = (await chrome.storage.local.get('repeater')).repeater || []; } catch { /* ignore */ }
      if (saved.length) { saved.forEach(s => newTab(s.req, s.useCookies, s.orig)); activate(tabs[0]); }
      else activate(newTab({ method: 'GET', url: 'https://', headers: [], body: '' }));
    })();
    el.append(strip, body);
    return { el, id: 'repeater', title: 'Repeater' };
  }

  function settingsView() {
    const el = h('div', { class: 'view pad' });
    const f = {};
    const save = debounce(() => {
      const s = { scope: f.scope.value, maxEntries: f.maxEntries.value, maxBodyKB: f.maxBodyKB.value, persist: f.persist.checked, mask: f.mask.checked, authorized: f.auth.checked,
        pauseTypes: TYPES.filter(t => f['t_' + t].checked) };
      try { new RegExp(s.scope || '.'); f.err.textContent = ''; } catch (e) { f.err.textContent = 'Invalid regex — nothing will be in scope until fixed: ' + e.message; }
      rpc('settings', { s }).catch(e => toast(e.message, true));
    }, 400);
    const row = (lab, ctl, hint) => h('div', { class: 'srow' }, h('label', {}, lab), ctl, hint ? h('small', { class: 'mut' }, hint) : null);
    const chk = (k) => { f[k] = h('input', { type: 'checkbox', onchange: save }); return f[k]; };
    const num = k => { f[k] = h('input', { class: 'in', type: 'number', style: 'width:110px', onchange: save }); return f[k]; };
    f.scope = h('textarea', { class: 'in', rows: '3', placeholder: 'e.g.  ^https://(.*\\.)?myapp\\.test/\n(one regex per line; empty = everything you attach to)', oninput: save });
    f.err = h('div', { class: 'warn' });
    el.append(
      row('Authorized testing', chk('auth'), 'I am authorized to test the targets I attach to.'),
      row('Scope (URL regex)', h('div', {}, f.scope, f.err), 'Requests outside the scope are neither recorded, paused nor replayed.'),
      row('Pause these resource types', h('div', { class: 'wrap' }, TYPES.map(t => h('label', {}, (f['t_' + t] = h('input', { type: 'checkbox', onchange: save })), ' ' + t))), 'Only these are paused when Intercept is ON (others still recorded).'),
      row('Max history entries', num('maxEntries')), row('Max stored body (KB)', num('maxBodyKB'), 'Larger bodies are truncated in storage.'),
      row('Persist history', chk('persist'), 'Stored locally in chrome.storage.local only.'),
      row('Mask secrets', chk('mask'), 'Hides Authorization / cookies / tokens in the UI (use 🔒 to reveal temporarily).'),
      h('div', { class: 'srow' }, h('button', { class: 'btn danger', onclick: async () => { if (await modal('Wipe all data', 'Delete history, repeater tabs, UI preferences and settings stored by this extension?', ['Cancel', 'Wipe']) === 1) { await rpc('wipe').catch(e => toast(e.message, true)); toast('Wiped — reload the page'); } } }, 'Wipe all local data'),
        h('button', { class: 'btn', onclick: () => { ui.fab = { x: null, y: null }; ui.panel = { x: null, y: null, w: 1000, h: 620 }; ui.max = false; layout(); saveUi(); } }, 'Reset window position')));
    function load() {
      const s = ctx.settings; f.scope.value = s.scope || ''; f.maxEntries.value = s.maxEntries; f.maxBodyKB.value = s.maxBodyKB;
      f.persist.checked = s.persist; f.mask.checked = s.mask; f.auth.checked = s.authorized; TYPES.forEach(t => { f['t_' + t].checked = s.pauseTypes.includes(t); });
    }
    on('state', () => { if (!root.activeElement || !el.contains(root.activeElement)) load(); }); load();
    return { el, id: 'settings', title: 'Settings' };
  }

  /* ---------------- floating UI shell ---------------- */
  const views = [dashboardView(), interceptView(), historyView(), repeaterView(), settingsView()];
  const tabBar = h('div', { class: 'tabs' });
  const tabBtns = views.map(v => { const b = h('button', { onclick: () => setTab(v.id) }, v.title, h('span', { class: 'bdg' })); tabBar.append(b); return b; });
  function setTab(id) { ui.tab = id; views.forEach((v, i) => { v.el.classList.toggle('act', v.id === id); tabBtns[i].classList.toggle('act', v.id === id); }); saveUi(); }
  function updateBadges() {
    views.forEach((v, i) => {
      const b = tabBtns[i].querySelector('.bdg'), n = v.badge ? v.badge() : 0;
      b.textContent = n ? n : ''; b.style.display = n ? 'inline-block' : 'none';
    });
    fabBadge.textContent = ctx.pending.length; fabBadge.style.display = ctx.pending.length ? 'flex' : 'none';
    const att = ctx.st.attached.includes(ctx.st.tab);
    pAtt.textContent = att ? '● attached' : '○ detached'; pAtt.classList.toggle('on', att);
    pInt.textContent = 'intercept ' + (ctx.st.interceptOn ? 'ON' : 'OFF'); pInt.classList.toggle('on', ctx.st.interceptOn);
    document.title === undefined; // (no-op: never touch the page title)
  }
  const pAtt = h('span', { class: 'pill', title: 'Attach / detach this tab', onclick: () => rpc(ctx.st.attached.includes(ctx.st.tab) ? 'detach' : 'attach').catch(e => toast(e.message, true)) });
  const pInt = h('span', { class: 'pill', title: 'Toggle interception', onclick: () => rpc('intercept', { on: !ctx.st.interceptOn }).catch(e => toast(e.message, true)) });
  const bLock = h('button', { class: 'btn sm', title: 'Reveal / mask secrets', onclick: () => { ctx.reveal = !ctx.reveal; bLock.textContent = ctx.reveal ? '🔓' : '🔒'; fire('reveal'); } }, '🔒');
  const wb = (txt, title, fn) => h('button', { class: 'btn sm wbtn', title, onclick: fn }, txt);
  const bar = h('div', { class: 'bar' }, h('b', {}, '⚡ Browser Intercept'), pAtt, pInt, bLock,
    wb('◧', 'Compact mode', () => { ui.compact = !ui.compact; layout(); saveUi(); }),
    wb('–', 'Minimize to button', () => { ui.open = false; layout(); saveUi(); }),
    wb('▢', 'Maximize / restore', () => { ui.max = !ui.max; layout(); saveUi(); }),
    wb('✕', 'Close (click the toolbar icon to reopen)', () => { ui.visible = false; ui.open = false; layout(); saveUi(); }));
  const panel = h('div', { class: 'panel closed' }, bar, tabBar, h('div', { class: 'views' }, views.map(v => v.el)));
  const fabBadge = h('span', { class: 'badge' });
  const fab = h('button', { class: 'fab hide', title: 'Browser Intercept' }, '⚡', fabBadge);
  box.append(panel, fab);

  function layout() {
    const vw = innerWidth, vh = innerHeight;
    if (ui.fab.x == null) ui.fab = { x: vw - 70, y: vh - 90 };
    if (ui.panel.x == null) ui.panel.x = Math.max(8, (vw - ui.panel.w) / 2), ui.panel.y = Math.max(8, (vh - ui.panel.h) / 2);
    const w = clamp(ui.panel.w, 340, vw - 8), hh = clamp(ui.panel.h, 260, vh - 8);
    Object.assign(panel.style, { left: clamp(ui.panel.x, 0, vw - 120) + 'px', top: clamp(ui.panel.y, 0, vh - 60) + 'px', width: w + 'px', height: hh + 'px' });
    Object.assign(fab.style, { left: clamp(ui.fab.x, 0, vw - 46) + 'px', top: clamp(ui.fab.y, 0, vh - 46) + 'px' });
    panel.classList.toggle('closed', !(ui.open && ui.visible)); panel.classList.toggle('max', ui.max); panel.classList.toggle('compact', ui.compact);
    fab.classList.toggle('hide', !ui.visible || ui.open);
  }
  function drag(handle, target, key, { ignore, onTap } = {}) {
    handle.addEventListener('pointerdown', e => {
      if (e.button !== 0 || (ignore && ignore(e)) || (key === 'panel' && ui.max)) return;
      const r = target.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top, sx = e.clientX, sy = e.clientY;
      let moved = false; handle.setPointerCapture(e.pointerId); target.classList.add('drag');
      const mv = ev => {
        if (!moved && Math.hypot(ev.clientX - sx, ev.clientY - sy) < 4) return;
        moved = true;
        const x = clamp(ev.clientX - dx, 0, innerWidth - 46), y = clamp(ev.clientY - dy, 0, innerHeight - 40);
        target.style.left = x + 'px'; target.style.top = y + 'px'; ui[key].x = x; ui[key].y = y;
      };
      const up = ev => {
        try { handle.releasePointerCapture(ev.pointerId); } catch { /* ignore */ }
        handle.removeEventListener('pointermove', mv); handle.removeEventListener('pointerup', up); target.classList.remove('drag');
        if (moved) saveUi(); else if (onTap) onTap();
      };
      handle.addEventListener('pointermove', mv); handle.addEventListener('pointerup', up);
    });
  }
  drag(bar, panel, 'panel', { ignore: e => e.target.closest('button,.pill') });
  drag(fab, fab, 'fab', { onTap: () => { ui.open = true; ui.visible = true; layout(); saveUi(); } });
  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => {
      if (ui.max || !ui.open) return;
      const r = panel.getBoundingClientRect();
      if (r.width > 100 && (Math.abs(r.width - ui.panel.w) > 2 || Math.abs(r.height - ui.panel.h) > 2)) { ui.panel.w = Math.round(r.width); ui.panel.h = Math.round(r.height); saveUi(); }
    }).observe(panel);
  }
  addEventListener('resize', debounce(layout, 100));

  /* ---------------- background sync ---------------- */
  let port = null;
  function onEvent(m) {
    switch (m.ev) {
      case 'entry': ctx.hist.push(m.s); ctx.map.set(m.s.id, m.s); (m.evicted || []).forEach(id => ctx.map.delete(id));
        if (m.evicted && m.evicted.length) { const g = new Set(m.evicted); ctx.hist = ctx.hist.filter(s => !g.has(s.id)); } fire('hist'); break;
      case 'upd': { const e = ctx.map.get(m.s.id); if (e) Object.assign(e, m.s); fire('hist'); (subs.histUpd || []).forEach(f => f(m.s.id)); break; }
      case 'paused': ctx.pending.push(m.item); updateBadges(); fire('pending'); break;
      case 'resolved': ctx.pending = ctx.pending.filter(p => p.id !== m.id); updateBadges(); fire('pending'); break;
      case 'deleted': { const g = new Set(m.ids); ctx.hist = ctx.hist.filter(s => !g.has(s.id)); g.forEach(id => ctx.map.delete(id)); fire('hist'); break; }
      case 'cleared': ctx.hist = []; ctx.map.clear(); fire('hist'); break;
      case 'state': ctx.st = { ...ctx.st, ...m.st }; ctx.settings = m.st.settings; updateBadges(); fire('state'); break;
    }
    updateBadges();
  }
  async function resync() {
    const st = await rpc('state'); ctx.st = { interceptOn: st.interceptOn, attached: st.attached, tab: st.tab }; ctx.settings = st.settings; ctx.pending = st.pending || [];
    ctx.hist = await rpc('history'); ctx.map = new Map(ctx.hist.map(s => [s.id, s]));
    updateBadges(); fire('state'); fire('hist'); fire('pending');
  }
  function connect() {
    try { port = chrome.runtime.connect({ name: 'ui' }); } catch { return dead(); }
    port.onMessage.addListener(onEvent);
    port.onDisconnect.addListener(() => {
      if (!chrome.runtime || !chrome.runtime.id) return dead();
      setTimeout(() => { connect(); resync().catch(() => {}); }, 800); // worker went idle: reconnect + resync
    });
  }
  function dead() { toast('Extension was reloaded — refresh this page to continue.', true); }
  setInterval(() => { if (ctx.st.attached.length && port) { try { port.postMessage({ ping: 1 }); } catch { /* reconnect handled by onDisconnect */ } } }, 20000);
  chrome.runtime.onMessage.addListener(m => {
    if (m && m.ev === 'toggle-ui') { if (!ui.visible) { ui.visible = true; ui.open = true; } else ui.open = !ui.open; layout(); saveUi(); }
  });

  /* ---------------- boot ---------------- */
  (async () => {
    try { const s = await chrome.storage.local.get('ui'); if (s.ui) { Object.assign(ui, s.ui); ui.fab = { ...{ x: null, y: null }, ...(s.ui.fab || {}) }; ui.panel = { ...ui.panel, ...(s.ui.panel || {}) }; } } catch { /* ignore */ }
    (document.documentElement || document).append(host);
    setTab(ui.tab && views.some(v => v.id === ui.tab) ? ui.tab : 'dashboard');
    layout(); updateBadges();
    connect();
    try { await resync(); } catch (e) { toast(e.message, true); }
  })();

  /* ---------------- styles ---------------- */
  function CSS() {
    return `
.bi{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#e2e8f0;pointer-events:none;--bg:#0b1120;--b2:#0f172a;--b3:#1e293b;--bd:#27364f;--mut:#94a3b8;--ac:#38bdf8;--ok:#22c55e;--wn:#eab308;--er:#ef4444}
.bi *{box-sizing:border-box}
button,input,select,textarea{font:inherit;color:inherit}
.in{background:var(--b2);border:1px solid var(--bd);border-radius:5px;padding:4px 6px;min-width:0;outline:0}
.in:focus{border-color:var(--ac)} select.in{padding:3px} textarea.in{width:100%;resize:vertical}
.grow{flex:1}.mut{color:var(--mut)}
.btn{background:var(--b3);border:1px solid var(--bd);border-radius:5px;padding:4px 10px;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--ac)}.btn:disabled{opacity:.4;cursor:default}
.btn.sm{padding:2px 7px}.btn.pri{background:var(--ac);color:#04121c;border-color:var(--ac);font-weight:700}
.btn.danger{color:#fecaca}.btn.danger:hover{border-color:var(--er);background:#3b1219}
.btn.on{background:var(--ok);color:#03150a;border-color:var(--ok);font-weight:700}
.fab{position:fixed;width:46px;height:46px;border-radius:50%;border:1px solid var(--ac);background:var(--b3);color:var(--ac);font-size:20px;cursor:grab;pointer-events:auto;box-shadow:0 4px 18px #0009;display:flex;align-items:center;justify-content:center;transition:transform .15s,opacity .2s;user-select:none;touch-action:none}
.fab:hover{transform:scale(1.08)}.fab.drag{cursor:grabbing;transition:none}.fab.hide{opacity:0;pointer-events:none;transform:scale(.5)}
.badge{position:absolute;top:-4px;right:-4px;min-width:18px;height:18px;border-radius:9px;background:var(--er);color:#fff;font-size:10px;display:none;align-items:center;justify-content:center;padding:0 4px}
.panel{position:fixed;min-width:340px;min-height:260px;background:var(--bg);border:1px solid var(--bd);border-radius:10px;display:flex;flex-direction:column;overflow:hidden;resize:both;pointer-events:auto;box-shadow:0 10px 50px #000c;container-type:inline-size;transition:opacity .18s,transform .18s,visibility .18s;transform-origin:bottom right}
.panel.closed{opacity:0;transform:scale(.94);visibility:hidden;pointer-events:none}
.panel.max{inset:8px!important;width:auto!important;height:auto!important;resize:none}
.panel.drag{transition:none}
.bar{display:flex;align-items:center;gap:6px;padding:7px 10px;background:var(--b3);cursor:move;user-select:none;flex:none;flex-wrap:wrap}
.bar b{color:var(--ac);font-size:13px;margin-right:auto}
.pill{padding:2px 8px;border-radius:10px;border:1px solid var(--bd);cursor:pointer;color:var(--mut)}.pill.on{border-color:var(--ok);color:var(--ok)}
.tabs{display:flex;gap:2px;background:var(--b2);border-bottom:1px solid var(--bd);overflow:auto;flex:none}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:6px 12px;cursor:pointer;color:var(--mut);white-space:nowrap}
.tabs button.act{color:var(--ac);border-bottom-color:var(--ac)}.tabs.sm button{padding:3px 9px}
.bdg{display:none;margin-left:5px;background:var(--er);color:#fff;border-radius:8px;padding:0 5px;font-size:10px}
.views{flex:1;min-height:0;position:relative}
.view{position:absolute;inset:0;display:none;flex-direction:column;overflow:auto}.view.act{display:flex}.view.pad{padding:12px;gap:10px}
.tb{display:flex;gap:6px;padding:6px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--bd);flex:none}
.grp{display:inline-flex;gap:4px;flex-wrap:wrap}
.ws{display:grid;grid-template-columns:minmax(170px,.9fr) minmax(260px,1.5fr) minmax(220px,1.2fr);flex:1;min-height:0}
.ws.two{grid-template-columns:1fr 1fr}
.pane{display:flex;flex-direction:column;min-width:0;min-height:0;border-right:1px solid var(--bd);overflow:hidden}
.pane:last-child{border-right:0}
@container (max-width:780px){.ws,.ws.two{grid-template-columns:1fr;grid-auto-rows:minmax(320px,auto);overflow:auto}.pane{border-right:0;border-bottom:1px solid var(--bd);min-height:320px}}
.panel.compact{font-size:11px}.panel.compact .bar{padding:3px 8px}.panel.compact .tabs button{padding:3px 8px}
.panel.compact .ws,.panel.compact .ws.two{grid-template-columns:1fr;grid-auto-rows:minmax(300px,auto);overflow:auto}
.list{flex:1;overflow:auto;background:var(--b2)}
.row{display:flex;gap:6px;align-items:center;padding:4px 8px;border-bottom:1px solid var(--bd);cursor:pointer;white-space:nowrap}
.row:hover{background:#16233a}.row.sel{background:#12304a}.row .u{flex:1;overflow:hidden;text-overflow:ellipsis;min-width:0}.row .t,.row .z{color:var(--mut)}
.m{min-width:50px}.m-GET{color:#4ade80}.m-POST{color:#fbbf24}.m-PUT,.m-PATCH{color:#60a5fa}.m-DELETE{color:#f87171}
.st.o{color:var(--ok)}.st.w{color:var(--wn)}.st.e{color:var(--er)}
.empty{padding:20px;color:var(--mut);text-align:center}
.ed{display:flex;flex-direction:column;flex:1;min-height:0}
.edtop{display:flex;gap:6px;padding:6px 6px 0;align-items:center}.meth{width:90px}
.edpane{flex:1;overflow:auto;padding:6px;display:flex;flex-direction:column;min-height:0}
.col{display:flex;flex-direction:column;flex:1;min-height:0}
.kv{display:flex;flex-direction:column;gap:4px;margin-bottom:6px}.kvr{display:flex;gap:4px}.kvr .in:first-child{width:36%}.kvr .in:nth-child(2){flex:1}
.cb{position:relative;flex:1;min-height:140px;background:var(--b2);border:1px solid var(--bd);border-radius:5px;overflow:hidden}
.cb-pre,.cb-ta{position:absolute;inset:0;margin:0;padding:8px;border:0;font:inherit;line-height:1.5;white-space:pre;tab-size:2;overflow:auto;letter-spacing:0}
.cb-pre{pointer-events:none;overflow:hidden;color:#cbd5e1}.cb-ta{background:transparent;color:transparent;caret-color:#fff;resize:none;outline:0}
.k{color:#7dd3fc}.s{color:#86efac}.n{color:#fdba74}.b{color:#f0abfc}.t{color:#f472b6}.a{color:#fcd34d}.c{color:#64748b}.u{color:#93c5fd}.v{color:var(--mut)}
.meta{padding:6px 8px;border-bottom:1px solid var(--bd);flex:none}.warn{padding:0 8px;color:var(--wn);font-size:11px}.warn:empty{display:none}
.hdrs{padding:4px 2px;line-height:1.7;word-break:break-all}.mp{margin:0;padding:6px;white-space:pre-wrap;word-break:break-all;overflow:auto;flex:1}
.prev{flex:1;overflow:auto;display:flex}.ifr{flex:1;border:0;background:#fff;min-height:240px}.cv{max-width:100%;height:auto;margin:auto}
.rtabs{display:flex;gap:2px;background:var(--b2);border-bottom:1px solid var(--bd);overflow:auto;flex:none}
.rtab{padding:5px 10px;cursor:pointer;color:var(--mut);white-space:nowrap;border-right:1px solid var(--bd)}.rtab.act{color:var(--ac);background:var(--bg)}
.rtab i{margin-left:8px;font-style:normal;opacity:.6}.rtab i:hover{opacity:1;color:var(--er)}.rtab.plus{color:var(--ac);font-weight:700}
.rbody{flex:1;min-height:0;display:flex;flex-direction:column}.rbody>.ws{flex:1}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;padding:12px}
.card{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px}.card b{color:var(--ac)}.card p{margin:0}
.card.warnc{margin:12px 12px 0;border-color:var(--wn)}.note{padding:0 12px 12px;color:var(--mut)}
.bar2{display:flex;gap:6px;align-items:center}.bar2 span{width:90px;overflow:hidden;text-overflow:ellipsis}.bar2 i{display:block;height:6px;background:var(--ac);border-radius:3px}.bar2 b{color:var(--mut)!important}
.srow{display:flex;flex-direction:column;gap:4px;padding-bottom:10px;border-bottom:1px solid var(--bd)}.srow>label{color:var(--ac)}.wrap{display:flex;flex-wrap:wrap;gap:10px}
.modal{position:fixed;inset:0;background:#000a;display:flex;align-items:center;justify-content:center;pointer-events:auto;outline:0}
.mbox{background:var(--bg);border:1px solid var(--bd);border-radius:10px;padding:14px;max-width:min(90vw,720px);max-height:85vh;display:flex;flex-direction:column;gap:10px}
.mt{color:var(--ac);font-weight:700}.mb{overflow:auto}.mf{display:flex;justify-content:flex-end;gap:8px}
.diff{margin:0;font:inherit}.dn{color:var(--mut)}.da{background:#0d3a1f;color:#86efac}.dr{background:#3b1219;color:#fca5a5}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--b3);border:1px solid var(--ok);padding:8px 14px;border-radius:8px;pointer-events:none;max-width:80vw}.toast.bad{border-color:var(--er)}
`;
  }
}
})();
