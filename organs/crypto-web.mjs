// crypto-web.mjs — the SAME Ed25519 adapter, for a browser.
//
// The node adapter that the tests run against and this one must produce interchangeable material,
// or the signature made in your tab would not verify on a server and the whole point of signing
// would quietly evaporate. So the wire formats are identical, deliberately:
//
//   pk  = the JWK 'x' — base64url of the 32-byte public key, and the wallet's id
//   sk  = "d.x"       — private scalar and public key, enough to rebuild the signing key
//   sig = lowercase hex
//
// Ed25519 in WebCrypto is available in current browsers and absent in older ones. `available()` says
// which, so the page can tell a visitor the truth instead of failing at the moment they click.
const enc = new TextEncoder();

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array((String(s).match(/../g) || []).map(h => parseInt(h, 16)));

export async function available() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) return { ok: false, why: 'this page has no WebCrypto (it needs to be served over https or localhost)' };
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    return { ok: true, why: 'Ed25519 is available in this browser' };
  } catch {
    return { ok: false, why: 'this browser does not support Ed25519 signing yet — everything else still works, but agents cannot be signed here' };
  }
}

export function webCrypto() {
  return {
    async generate() {
      const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
      const prv = await crypto.subtle.exportKey('jwk', kp.privateKey);
      return { pk: pub.x, sk: prv.d + '.' + prv.x };
    },
    async sign(msg, sk) {
      const [d, x] = String(sk).split('.');
      const key = await crypto.subtle.importKey('jwk',
        { kty: 'OKP', crv: 'Ed25519', d, x, key_ops: ['sign'], ext: true },
        { name: 'Ed25519' }, false, ['sign']);
      return hex(await crypto.subtle.sign({ name: 'Ed25519' }, key, enc.encode(msg)));
    },
    async verify(msg, sigHex, pk) {
      try {
        const key = await crypto.subtle.importKey('jwk',
          { kty: 'OKP', crv: 'Ed25519', x: pk, key_ops: ['verify'], ext: true },
          { name: 'Ed25519' }, false, ['verify']);
        return await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(sigHex), enc.encode(msg));
      } catch { return false; }
    },
  };
}

export default { available, webCrypto, b64u };
