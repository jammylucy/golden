(function () {
  if (window.__bgHook) return;
  window.__bgHook = true;
  window.__bgLog = [];
  const recent = [];                 // captured {url, method, query, params, responseText} for matching
  const MAX = 100;
  const dec = new TextDecoder();

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
    const item = Object.assign({ id: recent.length + 1, capturedAt: Date.now() }, info);
    if (recent.length >= MAX) recent.shift();
    recent.push(item);
    return item;
  };

  const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  function cipherKey(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
    return bytes.length + ':' + btoa(s);
  }

  // match a decrypt call to its source request by exact ciphertext bytes.
  // If multiple requests have the same ciphertext, do not guess a URL.
  function match(ct) {
    const matches = [];
    const key = cipherKey(ct);
    for (let i = recent.length - 1; i >= 0; i--) {
      const s = encryptedPayload(recent[i].responseText);
      if (!s) continue;
      let d; try { d = b64(s.slice(3)); } catch (_) { continue; }
      const cand = d.slice(12);        // strip 12-byte IV -> ct+tag (== decrypt's data arg)
      if (cand.length === ct.length && eq(cand, ct)) matches.push(recent[i]);
    }
    if (matches.length === 1) return Object.assign({ __matched: true, cipherKey: key }, matches[0]);
    if (matches.length > 1) {
      return {
        __matched: false,
        __ambiguous: true,
        cipherKey: key,
        candidates: matches.map(item => ({
          id: item.id,
          method: item.method,
          url: item.url,
          params: item.params,
          status: item.status,
          via: item.via
        }))
      };
    }
    return { __matched: false, cipherKey: key };
  }

  // ---- hook fetch ----
  const _fetch = window.fetch;
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
      const resp = await _fetch.apply(this, arguments);
      const info = {
        via: 'fetch',
        method,
        url: urlInfo.fullUrl,
        rawUrl: urlInfo.url,
        path: urlInfo.path,
        query: params.query,
        bodyParams: params.body,
        params: params.all,
        requestHeaders,
        status: resp && resp.status
      };
      try {
        const originalText = resp.text.bind(resp);
        Object.defineProperty(resp, 'text', {
          configurable: true,
          value: async function () {
            const text = await originalText();
            pushRecent(Object.assign({}, info, { responseText: text }));
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
    this.addEventListener('loadend', () => {
      let t = null; try { t = this.responseText; } catch (e) {} if (t == null) { try { t = this.response; } catch (e) {} }
      pushRecent({
        via: 'xhr',
        method: this.__method,
        url: this.__url,
        rawUrl: this.__rawUrl,
        path: this.__path,
        query: this.__query,
        bodyParams: this.__bodyParams,
        params: this.__params,
        requestHeaders: this.__requestHeaders,
        status: this.status,
        responseText: t
      });
    });
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
      const info = match(ct);
      const entry = { i: window.__bgLog.length + 1, time: new Date().toLocaleTimeString(),
        url: info.url, rawUrl: info.rawUrl, path: info.path, method: info.method,
        query: info.query, bodyParams: info.bodyParams, params: info.params,
        requestHeaders: info.requestHeaders, status: info.status, via: info.via,
        matched: !!info.__matched, ambiguous: !!info.__ambiguous,
        cipherKey: info.cipherKey, candidates: info.candidates, plain };
      window.__bgLog.push(entry);
      const label = entry.ambiguous ? 'AMBIGUOUS' : entry.matched ? (entry.method || 'GET') : 'UNMATCHED';
      console.groupCollapsed(`%c#${entry.i} [${label}] ${entry.url || '?'}%c  ${plain.slice(0, 70)}`,
        'color:#4af;font-weight:bold', 'color:#9a9');
      console.log('Matched:', entry.matched);
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
  window.__bgClear = () => { window.__bgLog.length = 0; recent.length = 0; };
  window.__bgRecent = recent;
  console.log('%c[BitGolden hook v3 ready] plaintext -> url/method/query/body/headers', 'color:#0c0');
})();
