(function () {
  if (window.__bgHookVersion >= 5) return;
  window.__bgHookVersion = 5;
  window.__bgHook = true;
  window.__bgLog = [];
  const recent = [];                 // captured {url, method, query, params, responseText} for matching
  const MAX = 100;
  const dec = new TextDecoder();
  const pendingKeys = [];
  const keyInfo = new WeakMap();
  let nextId = 1;
  let nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  let ui = null;
  const API_BASE = 'https://api.aegisbitgolden.com';
  const RESPONSE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqe46RcYXjwtFkTexvQ7F
59QY/yDd1LedrI7Haqh2vaRZo4nAV8MpvwmA4/i0gqD9CUkT8P8ha6xT+Q+6wnWu
LMv3e+4JELdddju7cmSDy+zfUrj5eKnoR68vP1q9ooRxc292uLip9WPj8/Ey5SIi
ki3kMa/nvtKGMn5rGWRt/zf/fxFKxHYhYymnJ2NTgKG/gIK/rnHRiopez4dxYchw
t6rg7f58fLH1A4v/pUkmBAduydZmqoGKymhsS0/3G5b+R7PNBNYJZyOUkpqe0NtP
2fh7XkYS8rnfApK93ZVYGY4gx8LBHcvAt615yP7SmQtIAqJosOgXFi1vZdDQ6UNn
MwIDAQAB
-----END PUBLIC KEY-----`;
  let responsePublicKey = null;

  function parseUrl(url) {
    const out = { url: String(url || ''), fullUrl: String(url || ''), query: {} };
    try {
      const u = new URL(out.url, location.href);
      out.fullUrl = u.href;
      out.path = u.pathname;
      u.searchParams.forEach((v, k) => {
        if (out.query[k] === undefined) out.query[k] = v;
        else if (Array.isArray(out.query[k])) out.query[k].push(v);
        else out.query[k] = [out.query[k], v];
      });
    } catch (e) {}
    return out;
  }

  function parseBody(body) {
    try {
      if (!body) return {};
      if (body instanceof FormData) { const o = {}; body.forEach((v, k) => o[k] = v); return o; }
      if (body instanceof URLSearchParams) { const o = {}; body.forEach((v, k) => o[k] = v); return o; }
      if (body instanceof ArrayBuffer) return '[ArrayBuffer ' + body.byteLength + ' bytes]';
      if (ArrayBuffer.isView(body)) return '[' + body.constructor.name + ' ' + body.byteLength + ' bytes]';
      if (typeof body === 'string') {
        try { return JSON.parse(body); } catch (e) {}
        const o = {}, re = /name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n--/g; let m;
        while ((m = re.exec(body))) o[m[1]] = m[2];
        return Object.keys(o).length ? o : body;
      }
    } catch (e) {}
    return body;
  }

  function stringifyBody(body) {
    if (body === undefined || body === null) return '';
    if (typeof body === 'string') return body;
    if (body instanceof FormData || body instanceof URLSearchParams) return JSON.stringify(parseBody(body), null, 2);
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return '';
    try { return JSON.stringify(body, null, 2); } catch (e) { return String(body); }
  }

  function safeJson(text, fallback) {
    try {
      if (text == null || String(text).trim() === '') return fallback;
      return JSON.parse(text);
    } catch (e) {
      return fallback;
    }
  }

  function mergeParams(query, body) {
    const hasBody = body && !(typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0);
    return {
      query,
      body,
      all: hasBody ? Object.assign({}, query || {}, typeof body === 'object' && !Array.isArray(body) ? body : { body }) : (query || {})
    };
  }

  function getHeaders(headers) {
    const out = {};
    try {
      if (!headers) return out;
      if (typeof headers.forEach === 'function') {
        headers.forEach((v, k) => out[k] = v);
        return out;
      }
      Object.keys(headers).forEach(k => out[k] = headers[k]);
    } catch (e) {}
    return out;
  }

  function setHeader(headers, key, value) {
    const existing = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
    headers[existing || key] = value;
  }

  function removeHeader(headers, key) {
    const existing = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
    if (existing) delete headers[existing];
  }

  function randomNonce(len) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    let out = '';
    for (let i = 0; i < len; i += 1) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
  }

  function sortedParamString(params) {
    if (!params || typeof params !== 'object' || Array.isArray(params)) return '';
    return Object.keys(params).sort().map(k => k + '=' + params[k]).join('&');
  }

  async function sha256Hex(text) {
    if (window.CryptoJS && window.CryptoJS.SHA256) return window.CryptoJS.SHA256(text).toString();
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function isLoginUrl(url) {
    try {
      const u = new URL(url, location.href);
      return u.pathname === '/uc/login' || u.pathname.endsWith('/uc/login');
    } catch (e) {
      return url === '/uc/login' || String(url || '').endsWith('/uc/login');
    }
  }

  async function addRuntimeHeaders(request) {
    const headers = Object.assign({}, request.headers || {});
    const token = localStorage.getItem('token') || '';
    const salt = localStorage.getItem('salt') || '';
    const login = isLoginUrl(request.url);
    if (!login) setHeader(headers, 'access-auth-token', token);
    else removeHeader(headers, 'access-auth-token');
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) setHeader(headers, 'Content-Type', 'multipart/form-data');
    setHeader(headers, 'equipment', window.innerWidth < 640 ? 'H5' : 'PC');
    setHeader(headers, 'lang', localStorage.getItem('lang') || 'zh_cn');
    if (!login && token) {
      const nonce = randomNonce(8);
      const timestamp = Date.now();
      const params = String(request.method || 'GET').toLowerCase() === 'get' ? request.query : request.bodyParams;
      const joined = sortedParamString(params);
      const signText = joined ? joined + '&' + salt : salt;
      setHeader(headers, 'nonce', nonce);
      setHeader(headers, 'timestamp', timestamp);
      setHeader(headers, 'signature', await sha256Hex(signText));
      request.__signText = signText;
    } else {
      removeHeader(headers, 'nonce');
      removeHeader(headers, 'timestamp');
      removeHeader(headers, 'signature');
    }
    request.headers = headers;
    return request;
  }

  function pemToArrayBuffer(pem) {
    const body = pem.replace(/-----BEGIN PUBLIC KEY-----/g, '').replace(/-----END PUBLIC KEY-----/g, '').replace(/\s/g, '');
    return b64(body).buffer;
  }

  function arrayBufferToB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.byteLength; i += 1) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  async function prepareEncryptedResponse(headers) {
    if (!crypto.subtle || !window.isSecureContext) return null;
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const raw = await crypto.subtle.exportKey('raw', aesKey);
    responsePublicKey = responsePublicKey || await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(RESPONSE_PUBLIC_KEY),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
    const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, responsePublicKey, raw);
    setHeader(headers, 'dev-encode-body', 'true');
    setHeader(headers, 'x-response-key', arrayBufferToB64(encryptedKey));
    return aesKey;
  }

  async function decodeMaybeEncryptedResponse(text, aesKey) {
    if (!aesKey || typeof text !== 'string' || text.indexOf('v2:') !== 0) return text;
    const bytes = b64(text.slice(3));
    const iv = bytes.slice(0, 12);
    const data = bytes.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, data);
    return dec.decode(plain);
  }

  function responseString(value) {
    if (typeof value === 'string') return value;
    try { return JSON.stringify(value); } catch (e) { return ''; }
  }

  function encryptedPayload(value) {
    let s = responseString(value).trim();
    try {
      const parsed = JSON.parse(s);
      if (typeof parsed === 'string') s = parsed;
      else if (parsed && typeof parsed.data === 'string') s = parsed.data;
    } catch (e) {}
    return s.indexOf('v2:') === 0 ? s : '';
  }

  const pushRecent = (info) => {
    const item = info || {};
    if (!item.id) item.id = nextId++;
    item.capturedAt = Date.now();
    if (recent.indexOf(item) === -1) {
      if (recent.length >= MAX) recent.shift();
      recent.push(item);
    }
    renderUi();
    return item;
  };

  const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  function cipherKey(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
    return bytes.length + ':' + btoa(s);
  }

  function isResponseAesKey(key) {
    return key && key.type === 'secret' && key.algorithm && key.algorithm.name === 'AES-GCM';
  }

  function claimPendingKey(info) {
    const now = Date.now();
    while (pendingKeys.length && now - pendingKeys[0].at > 15000) pendingKeys.shift();
    const item = pendingKeys.shift();
    if (!item) return;
    info.cryptoKeyCaptured = true;
    info.cryptoKeyAt = item.at;
    keyInfo.set(item.key, info);
  }

  function candidateSummary(item) {
    return {
      id: item.id,
      method: item.method,
      url: item.url,
      params: item.params,
      status: item.status,
      via: item.via
    };
  }

  // match a decrypt call to its source request by exact ciphertext bytes.
  // If multiple requests have the same ciphertext, do not guess a URL.
  function matchByCipher(ct) {
    const matches = [];
    const key = cipherKey(ct);
    for (let i = recent.length - 1; i >= 0; i--) {
      const s = encryptedPayload(recent[i].responseText);
      if (!s) continue;
      let d; try { d = b64(s.slice(3)); } catch (_) { continue; }
      const cand = d.slice(12);        // strip 12-byte IV -> ct+tag (== decrypt's data arg)
      if (cand.length === ct.length && eq(cand, ct)) matches.push(recent[i]);
    }
    if (matches.length === 1) return Object.assign({ __matched: true, strategy: 'ciphertext', cipherKey: key }, matches[0]);
    if (matches.length > 1) {
      return {
        __matched: false,
        __ambiguous: true,
        strategy: 'ciphertext',
        cipherKey: key,
        candidates: matches.map(candidateSummary)
      };
    }
    return { __matched: false, cipherKey: key };
  }

  function matchByCryptoKey(key, ct) {
    if (!isResponseAesKey(key) || !keyInfo.has(key)) return null;
    return Object.assign({ __matched: true, strategy: 'crypto-key', cipherKey: cipherKey(ct) }, keyInfo.get(key));
  }

  function match(key, ct) {
    return matchByCryptoKey(key, ct) || matchByCipher(ct);
  }

  function cloneForReplay(item) {
    const headers = Object.assign({}, item && item.requestHeaders || {});
    ['nonce', 'timestamp', 'signature', 'x-response-key'].forEach(k => removeHeader(headers, k));
    return {
      method: (item && item.method) || 'POST',
      url: (item && (item.rawUrl || item.url)) || API_BASE,
      headers,
      query: Object.assign({}, item && item.query || {}),
      bodyParams: item && typeof item.bodyParams === 'object' && !Array.isArray(item.bodyParams) ? Object.assign({}, item.bodyParams) : {}
    };
  }

  function buildUrl(url, query) {
    const raw = url || API_BASE;
    const u = new URL(raw, String(raw).charAt(0) === '/' ? API_BASE : location.href);
    Object.keys(query || {}).forEach(k => {
      if (query[k] !== undefined && query[k] !== null) u.searchParams.set(k, query[k]);
    });
    return u.href;
  }

  function makeBodyAndHeaders(method, bodyParams, headers) {
    if (String(method || 'GET').toUpperCase() === 'GET') return { body: undefined, headers };
    const contentTypeKey = Object.keys(headers).find(k => k.toLowerCase() === 'content-type');
    const contentType = contentTypeKey ? String(headers[contentTypeKey] || '').toLowerCase() : '';
    if (contentType.includes('application/json')) {
      setHeader(headers, 'Content-Type', 'application/json');
      return { body: JSON.stringify(bodyParams || {}), headers };
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
      return { body: new URLSearchParams(bodyParams || {}).toString(), headers };
    }
    if (contentType.includes('multipart/form-data') || !contentType) {
      if (contentTypeKey) delete headers[contentTypeKey];
      const form = new FormData();
      Object.keys(bodyParams || {}).forEach(k => {
        if (bodyParams[k] !== undefined && bodyParams[k] !== null) form.append(k, bodyParams[k]);
      });
      return { body: form, headers };
    }
    return { body: typeof bodyParams === 'string' ? bodyParams : JSON.stringify(bodyParams || {}), headers };
  }

  async function replayRequest(input) {
    if (!nativeFetch) throw new Error('当前环境没有 fetch，无法重放请求');
    const source = typeof input === 'number' ? recent.find(x => x.id === input) : input;
    const request = cloneForReplay(source || {});
    if (source && source.headers) request.headers = Object.assign(request.headers, source.headers);
    if (input && typeof input === 'object' && !Array.isArray(input)) {
      request.method = input.method || request.method;
      request.url = input.url || request.url;
      request.query = input.query || request.query;
      request.bodyParams = input.bodyParams || input.body || request.bodyParams;
      request.headers = Object.assign(request.headers, input.headers || {});
      request.encryptedResponse = !!input.encryptedResponse;
    }
    if (!input || input.autoSign !== false) await addRuntimeHeaders(request);
    else ['nonce', 'timestamp', 'signature'].forEach(k => removeHeader(request.headers, k));
    const wantsEncrypted = !!request.encryptedResponse;
    let aesKey = null;
    if (wantsEncrypted) aesKey = await prepareEncryptedResponse(request.headers);
    else {
      setHeader(request.headers, 'dev-encode-body', 'false');
      removeHeader(request.headers, 'x-response-key');
    }
    ['content-length', 'host', 'origin', 'referer'].forEach(k => removeHeader(request.headers, k));
    const finalUrl = String(request.method || 'GET').toUpperCase() === 'GET' ? buildUrl(request.url, request.query) : buildUrl(request.url, {});
    const bodyResult = makeBodyAndHeaders(request.method, request.bodyParams, request.headers);
    const started = Date.now();
    const resp = await nativeFetch(finalUrl, {
      method: request.method,
      headers: bodyResult.headers,
      body: bodyResult.body,
      credentials: 'include'
    });
    const rawText = await resp.text();
    const text = await decodeMaybeEncryptedResponse(rawText, aesKey);
    return {
      ok: resp.ok,
      status: resp.status,
      statusText: resp.statusText,
      ms: Date.now() - started,
      url: finalUrl,
      method: request.method,
      signText: request.__signText,
      requestHeaders: bodyResult.headers,
      requestBody: request.bodyParams,
      responseHeaders: getHeaders(resp.headers),
      rawText,
      text,
      json: safeJson(text, null)
    };
  }

  function createEl(tag, props, children) {
    const el = document.createElement(tag);
    Object.keys(props || {}).forEach(k => {
      if (k === 'style') Object.assign(el.style, props[k]);
      else if (k === 'text') el.textContent = props[k];
      else el.setAttribute(k, props[k]);
    });
    (children || []).forEach(c => el.appendChild(c));
    return el;
  }

  function installUi() {
    if (ui || !document.body) return;
    const css = {
      panel: {
        position: 'fixed', right: '16px', bottom: '64px', width: '560px', maxWidth: 'calc(100vw - 24px)',
        height: '680px', maxHeight: 'calc(100vh - 92px)', background: '#111827', color: '#e5e7eb',
        border: '1px solid #374151', borderRadius: '8px', zIndex: 2147483647, display: 'none',
        font: '12px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif', boxShadow: '0 18px 45px rgba(0,0,0,.35)', overflow: 'auto'
      },
      row: { display: 'flex', gap: '8px', alignItems: 'center', padding: '8px' },
      input: { background: '#030712', color: '#e5e7eb', border: '1px solid #374151', borderRadius: '6px', padding: '6px', font: '12px monospace' },
      area: { width: '100%', height: '98px', resize: 'vertical', background: '#030712', color: '#e5e7eb', border: '1px solid #374151', borderRadius: '6px', padding: '8px', font: '12px monospace', boxSizing: 'border-box' },
      btn: { background: '#2563eb', color: '#fff', border: '0', borderRadius: '6px', padding: '7px 10px', cursor: 'pointer' },
      ghost: { background: '#374151', color: '#e5e7eb', border: '0', borderRadius: '6px', padding: '7px 10px', cursor: 'pointer' }
    };
    const toggle = createEl('button', { text: 'BG API', style: Object.assign({}, css.btn, { position: 'fixed', right: '16px', bottom: '16px', zIndex: 2147483647 }) });
    const panel = createEl('div', { style: css.panel });
    const header = createEl('div', { style: Object.assign({}, css.row, { justifyContent: 'space-between', borderBottom: '1px solid #374151' }) });
    header.appendChild(createEl('strong', { text: 'BitGolden API Debugger' }));
    const close = createEl('button', { text: '收起', style: css.ghost });
    header.appendChild(close);

    const select = createEl('select', { style: Object.assign({}, css.input, { flex: '1' }) });
    const load = createEl('button', { text: '载入', style: css.ghost });
    const method = createEl('select', { style: css.input });
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].forEach(m => method.appendChild(createEl('option', { text: m, value: m })));
    const url = createEl('input', { style: Object.assign({}, css.input, { flex: '1' }) });
    const headers = createEl('textarea', { style: css.area });
    const query = createEl('textarea', { style: css.area });
    const body = createEl('textarea', { style: css.area });
    const autoSign = createEl('input', { type: 'checkbox' });
    autoSign.checked = true;
    const encrypted = createEl('input', { type: 'checkbox' });
    const send = createEl('button', { text: '发送', style: css.btn });
    const clear = createEl('button', { text: '清空日志', style: css.ghost });
    const output = createEl('pre', { style: Object.assign({}, css.input, { height: '130px', overflow: 'auto', margin: '8px', whiteSpace: 'pre-wrap' }) });

    function label(text, child) {
      const wrap = createEl('label', { style: { display: 'block', padding: '6px 8px 0', color: '#cbd5e1' } });
      wrap.appendChild(document.createTextNode(text));
      if (child) wrap.appendChild(child);
      return wrap;
    }

    panel.appendChild(header);
    panel.appendChild(createEl('div', { style: css.row }, [select, load]));
    panel.appendChild(createEl('div', { style: css.row }, [method, url]));
    panel.appendChild(label('Headers JSON'));
    panel.appendChild(createEl('div', { style: { padding: '0 8px' } }, [headers]));
    panel.appendChild(label('Query JSON'));
    panel.appendChild(createEl('div', { style: { padding: '0 8px' } }, [query]));
    panel.appendChild(label('Body JSON'));
    panel.appendChild(createEl('div', { style: { padding: '0 8px' } }, [body]));
    const opts = createEl('div', { style: css.row });
    opts.appendChild(autoSign);
    opts.appendChild(createEl('span', { text: '自动重算 token/nonce/timestamp/signature' }));
    opts.appendChild(encrypted);
    opts.appendChild(createEl('span', { text: '请求加密响应' }));
    opts.appendChild(send);
    opts.appendChild(clear);
    panel.appendChild(opts);
    panel.appendChild(output);
    document.body.appendChild(toggle);
    document.body.appendChild(panel);

    function fillFrom(item) {
      const r = cloneForReplay(item);
      method.value = r.method;
      url.value = r.url || API_BASE;
      headers.value = JSON.stringify(r.headers, null, 2);
      query.value = JSON.stringify(r.query || {}, null, 2);
      body.value = JSON.stringify(r.bodyParams || {}, null, 2);
    }

    load.onclick = () => {
      const item = recent.find(x => String(x.id) === select.value) || recent[recent.length - 1];
      if (item) fillFrom(item);
    };
    send.onclick = async () => {
      output.textContent = 'Sending...';
      try {
        const request = {
          method: method.value,
          url: url.value,
          headers: safeJson(headers.value, {}),
          query: safeJson(query.value, {}),
          bodyParams: safeJson(body.value, {}),
          autoSign: autoSign.checked,
          encryptedResponse: encrypted.checked
        };
        const result = await replayRequest(request);
        output.textContent = JSON.stringify(result.json || result.text || result, null, 2);
        console.log('[BitGolden replay]', result);
      } catch (e) {
        output.textContent = e && e.stack || String(e);
        console.error('[BitGolden replay failed]', e);
      }
    };
    clear.onclick = () => { window.__bgClear(); renderUi(); output.textContent = 'cleared'; };
    toggle.onclick = close.onclick = () => { panel.style.display = panel.style.display === 'none' ? 'block' : 'none'; };
    ui = { panel, select, fillFrom };
    renderUi();
    if (recent.length) fillFrom(recent[recent.length - 1]);
  }

  function renderUi() {
    if (!ui) return;
    const value = ui.select.value;
    ui.select.innerHTML = '';
    recent.slice().reverse().forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.id;
      opt.textContent = '#' + item.id + ' ' + (item.method || 'GET') + ' ' + (item.path || item.url || '?') + (item.status ? ' [' + item.status + ']' : '');
      ui.select.appendChild(opt);
    });
    if (value) ui.select.value = value;
  }

  const _generateKey = SubtleCrypto.prototype.generateKey;
  SubtleCrypto.prototype.generateKey = function () {
    const result = _generateKey.apply(this, arguments);
    return Promise.resolve(result).then(key => {
      try {
        if (isResponseAesKey(key)) pendingKeys.push({ key, at: Date.now() });
      } catch (e) {}
      return key;
    });
  };

  // ---- hook fetch ----
  const _fetch = window.fetch;
  nativeFetch = _fetch ? _fetch.bind(window) : nativeFetch;
  if (_fetch) {
    window.fetch = async function (input, init) {
      const requestUrl = typeof input === 'string' ? input : (input && input.url) || '';
      const urlInfo = parseUrl(requestUrl);
      const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
      let body = init && init.body;
      if (body === undefined && input && typeof input.clone === 'function') {
        try { body = await input.clone().text(); } catch (e) {}
      }
      const bodyParams = parseBody(body);
      const params = mergeParams(urlInfo.query, bodyParams);
      const requestHeaders = Object.assign({}, getHeaders(input && input.headers), getHeaders(init && init.headers));
      const info = {
        via: 'fetch',
        method,
        url: urlInfo.fullUrl,
        rawUrl: urlInfo.url,
        path: urlInfo.path,
        query: params.query,
        bodyParams: params.body,
        params: params.all,
        requestHeaders
      };
      claimPendingKey(info);
      const resp = await _fetch.apply(this, arguments);
      info.status = resp && resp.status;
      try {
        const originalText = resp.text.bind(resp);
        Object.defineProperty(resp, 'text', {
          configurable: true,
          value: async function () {
            const text = await originalText();
            info.responseText = text;
            pushRecent(info);
            return text;
          }
        });
      } catch (e) {
        try { resp.clone().text().then(t => pushRecent(Object.assign({}, info, { responseText: t }))); } catch (_) {}
      }
      return resp;
    };
  }

  // ---- hook XHR ----
  const _open = XMLHttpRequest.prototype.open, _send = XMLHttpRequest.prototype.send;
  const _setRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (m, u) {
    const urlInfo = parseUrl(u);
    this.__url = urlInfo.fullUrl;
    this.__rawUrl = urlInfo.url;
    this.__path = urlInfo.path;
    this.__query = urlInfo.query;
    this.__method = (m || 'GET').toUpperCase();
    this.__requestHeaders = {};
    return _open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    try { this.__requestHeaders[k] = v; } catch (e) {}
    return _setRequestHeader.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    const bodyParams = parseBody(body);
    const params = mergeParams(this.__query, bodyParams);
    this.__bodyParams = bodyParams;
    this.__params = params.all;
    this.__info = {
      via: 'xhr',
      method: this.__method,
      url: this.__url,
      rawUrl: this.__rawUrl,
      path: this.__path,
      query: this.__query,
      bodyParams: this.__bodyParams,
      params: this.__params,
      requestHeaders: this.__requestHeaders
    };
    claimPendingKey(this.__info);
    const finalize = () => {
      if (this.__finalized) return;
      if (this.readyState !== 4) return;
      this.__finalized = true;
      let t = null; try { t = this.responseText; } catch (e) {} if (t == null) { try { t = this.response; } catch (e) {} }
      this.__info.status = this.status;
      this.__info.responseText = t;
      pushRecent(this.__info);
    };
    this.addEventListener('readystatechange', finalize);
    this.addEventListener('loadend', finalize);
    return _send.apply(this, arguments);
  };

  // ---- hook decrypt + deterministic match ----
  const _dec = SubtleCrypto.prototype.decrypt;
  SubtleCrypto.prototype.decrypt = async function (...a) {
    const r = await _dec.apply(this, a);
    try {
      const ab = r instanceof ArrayBuffer ? r : await r.arrayBuffer();
      const plain = dec.decode(ab);
      const ct = new Uint8Array(a[2]);
      const info = match(a[1], ct);
      const entry = { i: window.__bgLog.length + 1, time: new Date().toLocaleTimeString(),
        url: info.url, rawUrl: info.rawUrl, path: info.path, method: info.method,
        query: info.query, bodyParams: info.bodyParams, params: info.params,
        requestHeaders: info.requestHeaders, status: info.status, via: info.via,
        matched: !!info.__matched, ambiguous: !!info.__ambiguous,
        strategy: info.strategy, cryptoKeyCaptured: !!info.cryptoKeyCaptured,
        cipherKey: info.cipherKey, candidates: info.candidates, plain };
      window.__bgLog.push(entry);
      const label = entry.ambiguous ? 'AMBIGUOUS' : entry.matched ? (entry.method || 'GET') : 'UNMATCHED';
      console.groupCollapsed(`%c#${entry.i} [${label}] ${entry.url || '?'}%c  ${plain.slice(0, 70)}`,
        'color:#4af;font-weight:bold', 'color:#9a9');
      console.log('Matched:', entry.matched);
      console.log('Strategy:', entry.strategy);
      console.log('Cipher :', entry.cipherKey);
      console.log('URL    :', entry.url);
      console.log('Method :', entry.method, info.via ? '(' + info.via + ')' : '');
      console.log('Query  :', entry.query);
      console.log('Body   :', entry.bodyParams);
      console.log('Params :', entry.params);
      console.log('Headers:', entry.requestHeaders);
      console.log('Status :', entry.status);
      if (entry.ambiguous) console.warn('Ambiguous ciphertext candidates:', entry.candidates);
      if (!entry.matched && !entry.ambiguous) console.warn('No request was matched for this decrypted payload.');
      console.log('Plain  :', plain);
      console.groupEnd();
    } catch (e) {}
    return r;
  };

  window.__bgFind = (kw) => window.__bgLog.filter(e => (e.url + JSON.stringify(e.params) + e.plain).includes(kw));
  window.__bgReplay = replayRequest;
  window.__bgOpen = () => { installUi(); if (ui && ui.panel) ui.panel.style.display = 'block'; };
  window.__bgClear = () => { window.__bgLog.length = 0; recent.length = 0; renderUi(); };
  window.__bgRecent = recent;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installUi, { once: true });
  else installUi();
  console.log('%c[BitGolden hook v5 ready] API debugger + replay signing + crypto-key/ciphertext match', 'color:#0c0');
})();
