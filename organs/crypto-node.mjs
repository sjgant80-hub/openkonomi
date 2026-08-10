// crypto-node.mjs — the REAL Ed25519 adapter for Node (node:crypto). Injected into the pure wallet kernel.
// Keys travel as portable strings: pk = the JWK 'x' (base64url of the 32-byte public key, used as the
// wallet id); sk = "d.x" (private scalar + public, enough to reconstruct the signing key). No deps.
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey } from 'node:crypto';

export function nodeCrypto() {
  return {
    async generate() {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const pub = publicKey.export({ format: 'jwk' });    // { kty:'OKP', crv:'Ed25519', x }
      const prv = privateKey.export({ format: 'jwk' });    // { ..., d, x }
      return { pk: pub.x, sk: prv.d + '.' + prv.x };
    },
    async sign(msg, sk) {
      const [d, x] = sk.split('.');
      const key = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x, d }, format: 'jwk' });
      return edSign(null, Buffer.from(msg, 'utf8'), key).toString('hex');
    },
    async verify(msg, sigHex, pk) {
      try {
        const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pk }, format: 'jwk' });
        return edVerify(null, Buffer.from(msg, 'utf8'), key, Buffer.from(sigHex, 'hex'));
      } catch { return false; }
    },
  };
}
