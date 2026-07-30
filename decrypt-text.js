const _dec = SubtleCrypto.prototype.decrypt;
SubtleCrypto.prototype.decrypt = async function (...a) {
  const r = await _dec.apply(this, a);
  const buf = r instanceof ArrayBuffer ? r : await r.arrayBuffer();
  console.log('[解密响应]', new TextDecoder().decode(buf));
  return r;
};
