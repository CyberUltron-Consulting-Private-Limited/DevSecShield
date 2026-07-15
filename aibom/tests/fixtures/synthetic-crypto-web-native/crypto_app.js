// Synthetic Node.js + WebCrypto fixture for the C3 call-expression scanner.
// Every asset is resolvable ONLY by binding the call's arguments (the algorithm
// string literal, the options-object modulusLength / namedCurve), not by a bare
// algorithm token — so it exercises the call-expression model, not the regex.
const crypto = require('node:crypto');

function encryptGcm(key, iv) {
  // The literal "aes-256-gcm" packs algorithm + key size (256) + mode (GCM).
  return crypto.createCipheriv('aes-256-gcm', key, iv);
}

function encryptLegacy(key, iv) {
  // 3DES + CBC from one literal — "des-ede3-cbc".
  return crypto.createCipheriv('des-ede3-cbc', key, iv);
}

function digest(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function weakDigest(data) {
  return crypto.createHash('md5').update(data).digest();
}

function mac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function genRsa() {
  // modulusLength lives in the options object on a later line — bound to the call.
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
}

function genEc() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
  });
}

async function webcrypto(subtleKey, data, iv) {
  // WebCrypto: digest by string, cipher + KDF by the {name:"…"} field.
  const h = await crypto.subtle.digest('SHA-512', data);
  const e = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, subtleKey, data);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: iv, iterations: 600000, hash: 'SHA-256' },
    subtleKey,
    256
  );
  return [h, e, bits];
}

module.exports = {
  encryptGcm, encryptLegacy, digest, weakDigest, mac, genRsa, genEc, webcrypto,
};
