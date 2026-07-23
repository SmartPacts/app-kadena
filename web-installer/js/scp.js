// Port a JavaScript de ledgerblue: canal seguro SCP (deployed.py getDeployedSecretV2
// + derivación de claves y cifrado de sesión de hexLoader.py, ruta scpVersion==3 CBC).
// Cripto: @noble/curves (secp256k1) y @noble/ciphers (AES-CBC), vendorizadas.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { cbc } from '@noble/ciphers/aes.js';

const SCP_MAC_LENGTH = 0x0e;

function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function u32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function derSign(privKey, data) {
  // ledgerblue firma sha256(data) con ECDSA determinista y serializa en DER
  return secp256k1.sign(sha256(data), privKey, { prehash: false, format: 'der' });
}

function derVerify(pubKey, data, derSig) {
  return secp256k1.verify(derSig, sha256(data), pubKey, { prehash: false, format: 'der', lowS: false });
}

// Handshake del canal seguro (getDeployedSecretV2). masterPrivate aleatoria =>
// el dispositivo mostrará "Allow unsafe manager" y pedirá confirmación al usuario.
// Devuelve { ecdhSecret, devicePublicKey }.
export async function getDeployedSecretV2(transport, targetId, log = () => {}) {
  if ((targetId & 0xf) < 2) throw new Error('Target ID does not support SCP V2');

  const masterPrivate = secp256k1.utils.randomSecretKey();
  const masterPublic = secp256k1.getPublicKey(masterPrivate, false); // sin comprimir (65 bytes)

  // identify
  await transport.exchangeApdu(0xe0, 0x04, 0x00, 0x00, u32be(targetId));

  // nonces
  const nonce = randomBytes(8);
  const authInfo = await transport.exchangeApdu(0xe0, 0x50, 0x00, 0x00, nonce);
  const deviceNonce = authInfo.slice(4, 12);

  // certificado del "master" (clave efímera aleatoria => unsafe manager)
  {
    const dataToSign = concat(new Uint8Array([0x01]), masterPublic);
    const signature = derSign(masterPrivate, dataToSign);
    const certificate = concat(new Uint8Array([masterPublic.length]), masterPublic, new Uint8Array([signature.length]), signature);
    await transport.exchangeApdu(0xe0, 0x51, 0x00, 0x00, certificate);
  }

  // certificado efímero
  const ephemeralPrivate = secp256k1.utils.randomSecretKey();
  const ephemeralPublic = secp256k1.getPublicKey(ephemeralPrivate, false);
  {
    const dataToSign = concat(new Uint8Array([0x11]), nonce, deviceNonce, ephemeralPublic);
    const signature = derSign(masterPrivate, dataToSign);
    const certificate = concat(new Uint8Array([ephemeralPublic.length]), ephemeralPublic, new Uint8Array([signature.length]), signature);
    log('waiting-device'); // aquí el device muestra "Allow unsafe manager"
    await transport.exchangeApdu(0xe0, 0x51, 0x80, 0x00, certificate);
  }

  // recorrer la cadena de certificados del dispositivo
  let lastDevPubKey = masterPublic;
  let devicePublicKey = null;
  for (let index = 0; index < 2; index++) {
    const certificate = await transport.exchangeApdu(0xe0, 0x52, index === 0 ? 0x00 : 0x80, 0x00, new Uint8Array(0));
    if (certificate.length === 0) break;
    let offset = 1;
    const certificateHeader = certificate.slice(offset, offset + certificate[offset - 1]);
    offset += certificate[offset - 1] + 1;
    const certificatePublicKey = certificate.slice(offset, offset + certificate[offset - 1]);
    offset += certificate[offset - 1] + 1;
    const certificateSignature = certificate.slice(offset, offset + certificate[offset - 1]);
    let signedData;
    if (index === 0) {
      devicePublicKey = certificatePublicKey;
      signedData = concat(new Uint8Array([0x02]), certificateHeader, certificatePublicKey);
    } else {
      signedData = concat(new Uint8Array([0x12]), deviceNonce, nonce, certificatePublicKey);
    }
    const ok = derVerify(lastDevPubKey, signedData, certificateSignature);
    if (!ok) {
      if (index === 0) {
        log('user-key'); // "Broken certificate chain - loading from user key" (no es error)
      } else {
        throw new Error('Broken certificate chain');
      }
    }
    lastDevPubKey = certificatePublicKey;
  }

  // commit del canal ECDH
  await transport.exchangeApdu(0xe0, 0x53, 0x00, 0x00, new Uint8Array(0));
  // secreto ECDH estilo libsecp256k1 (= ecWrapper.ecdh): sha256 del punto compartido COMPRIMIDO
  const sharedPoint = secp256k1.getSharedSecret(ephemeralPrivate, lastDevPubKey, true);
  return { ecdhSecret: sha256(sharedPoint), devicePublicKey };
}

// Derivación de claves de sesión (hexLoader.scp_derive_key, rama no-scpv3):
// d_i = sha256(be32(i) || retry || secreto) (reintentando si >= orden de la curva)
// P_i = d_i * G ; k_i = sha256(P_i sin comprimir)
export function scpDeriveKey(ecdhSecret, keyIndex) {
  const ORDER = secp256k1.Point.Fn.ORDER;
  let retry = 0;
  let digest;
  for (;;) {
    digest = sha256(concat(u32be(keyIndex), new Uint8Array([retry]), ecdhSecret));
    let v = 0n;
    for (const b of digest) v = (v << 8n) | BigInt(b);
    if (v < ORDER && v > 0n) break;
    retry += 1;
  }
  const pubkey = secp256k1.getPublicKey(digest, false);
  return sha256(pubkey);
}

// Sesión SCP "version 3" con AES-CBC encadenado + MAC CBC truncado (ruta del Nano S+,
// mutauth_result = {ecdh_secret,...} y scpv3=False en ledgerblue).
export class ScpSession {
  constructor(ecdhSecret) {
    this.encKey = scpDeriveKey(ecdhSecret, 0).slice(0, 16);
    this.macKey = scpDeriveKey(ecdhSecret, 1).slice(0, 16);
    this.encIv = new Uint8Array(16);
    this.macIv = new Uint8Array(16);
  }

  wrap(data) {
    if (data === null || data.length === 0) return data;
    // padding ISO 9797 método 2: 0x80 + ceros hasta múltiplo de 16
    const padLen = 16 - (data.length % 16);
    const padded = concat(data, new Uint8Array([0x80]), new Uint8Array(padLen - 1));
    const encrypted = cbc(this.encKey, this.encIv, { disablePadding: true }).encrypt(padded);
    this.encIv = encrypted.slice(-16);
    const macData = cbc(this.macKey, this.macIv, { disablePadding: true }).encrypt(encrypted);
    this.macIv = macData.slice(-16);
    return concat(encrypted, this.macIv.slice(16 - SCP_MAC_LENGTH));
  }

  unwrap(data) {
    if (data === null || data.length === 0 || data.length === 2) return data;
    // MAC
    const body = data.slice(0, data.length - SCP_MAC_LENGTH);
    const macData = cbc(this.macKey, this.macIv, { disablePadding: true }).encrypt(body);
    this.macIv = macData.slice(-16);
    const expected = this.macIv.slice(16 - SCP_MAC_LENGTH);
    const received = data.slice(data.length - SCP_MAC_LENGTH);
    let diff = 0;
    for (let i = 0; i < SCP_MAC_LENGTH; i++) diff |= expected[i] ^ received[i];
    if (diff !== 0) throw new Error('Invalid SCP MAC');
    // ENC
    const nextIv = body.slice(-16);
    const decrypted = cbc(this.encKey, this.encIv, { disablePadding: true }).decrypt(body);
    this.encIv = nextIv;
    let L = decrypted.length - 1;
    while (decrypted[L] !== 0x80) {
      L -= 1;
      if (L === -1) throw new Error('Invalid SCP ENC padding');
    }
    return decrypted.slice(0, L);
  }
}

export { concat, u32be, randomBytes };
