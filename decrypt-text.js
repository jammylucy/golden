(function () {
  if (window.__bgHook) return;
  window.__bgHook = true;
  window.__bgLog = [];
  const recent = [];                 // captured {url,method,params,body} for matching
  const MAX = 30;
  const dec = new TextDecoder();

  function parseBody(body) {
    try {
      if (!body) return {};
      if (body instanceof FormData) { const o = {}; body.forEach((v, k) => o[k] = v); return o; }
      if (body instanceof URLSearchParams) { const o = {}; body.forEach((v, k) => o[k] = v); return o; }
      if (typeof body === 'string') {
        const o = {}, re = /name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n--/g; let m;
        while ((m = re.exec(body))) o[m[1]] = m[2];
        return Object.keys(o).length ? o : body;
      }
    } catch (e) {}
    return body;
  }
  const pushRecent = (info) => { if (recent.length >= MAX) recent.shift(); recent.push(info); };
  const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // match a decrypt call to its source request by ciphertext bytes
  function match(ct) {
    for (let i = recent.length - 1; i >= 0; i--) {
      let s = recent[i].body;
      try { s = JSON.parse(s); } catch (_) {}
      if (typeof s !== 'string' || s.indexOf('v2:') !== 0) continue;
      let d; try { d = b64(s.slice(3)); } catch (_) { continue; }
      const cand = d.slice(12);        // strip 12-byte IV -> ct+tag (== decrypt's data arg)
      if (cand.length === ct.length && eq(cand, ct)) return recent[i];
    }
    return null;
  }

  // ---- hook fetch ----
  const _fetch = window.fetch;
  if (_fetch) {
    window.fetch = async function (input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const method = ((init && init.method) || 'GET').toUpperCase();
      const params = parseBody(init && init.body);
      const resp = await _fetch.apply(this, arguments);
      try { resp.clone().text().then(t => pushRecent({ url, method, params, body: t, via: 'fetch' })); } catch (e) {}
      return resp;
    };
  }

  // ---- hook XHR ----
  const _open = XMLHttpRequest.prototype.open, _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__url = u; this.__method = (m || 'GET').toUpperCase(); return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (body) {
    this.__params = parseBody(body);
    this.addEventListener('loadend', () => {
      let t = null; try { t = this.responseText; } catch (e) {} if (t == null) { try { t = this.response; } catch (e) {} }
      if (typeof t === 'string') pushRecent({ url: this.__url, method: this.__method, params: this.__params, body: t, via: 'xhr' });
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
      const info = match(ct) || {};
      const entry = { i: window.__bgLog.length + 1, time: new Date().toLocaleTimeString(),
        url: info.url, method: info.method, params: info.params, via: info.via, plain };
      window.__bgLog.push(entry);
      console.groupCollapsed(`%c#${entry.i} [${entry.method || 'GET'}] ${entry.url || '?'}%c  ${plain.slice(0, 70)}`,
        'color:#4af;font-weight:bold', 'color:#9a9');
      console.log('URL    :', entry.url);
      console.log('Method :', entry.method, info.via ? '(' + info.via + ')' : '');
      console.log('Params :', entry.params);
      console.log('Plain  :', plain);
      console.groupEnd();
    } catch (e) {}
    return r;
  };

  window.__bgFind = (kw) => window.__bgLog.filter(e => (e.url + JSON.stringify(e.params) + e.plain).includes(kw));
  window.__bgClear = () => { window.__bgLog.length = 0; recent.length = 0; };
  console.log('%c[BitGolden hook v2 ready] fetch+XHR + deterministic ciphertext match', 'color:#0c0');
})();