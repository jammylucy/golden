(function () {
  if (window.__bgHook) return;
  window.__bgHook = true;
  window.__bgLog = [];

  const dec = new TextDecoder();
  const queue = []; // FIFO: {url, method, params, status} for each encrypted response

  // parse multipart/form-data or FormData body -> {field: value}
  function parseBody(body) {
    try {
      if (!body) return {};
      if (body instanceof FormData) { const o = {}; body.forEach((v, k) => o[k] = v); return o; }
      if (typeof body === 'string') {
        const o = {}, re = /name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n--/g; let m;
        while ((m = re.exec(body))) o[m[1]] = m[2];
        return o;
      }
    } catch (e) {}
    return body;
  }

  // capture request url + params at XHR layer
  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__url = url; this.__method = (method || 'GET').toUpperCase();
    return _open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    this.__params = parseBody(body);
    this.addEventListener('loadend', () => {
      const t = this.responseText;
      if (typeof t === 'string' && t.indexOf('v2:') !== -1) {
        queue.push({ url: this.__url, method: this.__method, params: this.__params, status: this.status });
      }
    });
    return _send.apply(this, arguments);
  };

  // pair each decryption with its request info from the queue
  const _dec = SubtleCrypto.prototype.decrypt;
  SubtleCrypto.prototype.decrypt = async function (...a) {
    const r = await _dec.apply(this, a);
    try {
      const ab = r instanceof ArrayBuffer ? r : await r.arrayBuffer();
      const plain = dec.decode(ab);
      const info = queue.shift() || {};
      const entry = {
        i: window.__bgLog.length + 1,
        time: new Date().toLocaleTimeString(),
        url: info.url, method: info.method, status: info.status,
        params: info.params, response: plain,
      };
      window.__bgLog.push(entry);
      console.groupCollapsed(
        `%c#${entry.i} [${entry.method}] ${entry.url}%c  ${plain.slice(0, 70)}`,
        'color:#4af;font-weight:bold', 'color:#9a9'
      );
      console.log('URL    :', entry.url);
      console.log('Params :', entry.params);
      console.log('Status :', entry.status);
      console.log('Plain  :', entry.response);
      console.groupEnd();
    } catch (e) {}
    return r;
  };

  // helpers
  window.__bgFind = (kw) => window.__bgLog.filter(e => (e.url + JSON.stringify(e.params) + e.response).includes(kw));
  window.__bgClear = () => { window.__bgLog.length = 0; };
  console.log('%c[BitGolden hook ready] window.__bgLog / __bgFind(keyword)', 'color:#0c0');
})();