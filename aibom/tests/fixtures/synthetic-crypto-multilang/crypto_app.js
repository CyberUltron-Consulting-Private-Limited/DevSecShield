/**
 * Synthetic Node.js + WebCrypto crypto usage (C3 fixture).
 *   STRONG: AES-256-GCM, RSA-2048/3072, ECDSA/P-384, Ed25519, SHA-256/384/512, HMAC, PBKDF2
 *   WEAK:   MD5, RC4, 3DES, AES-128-CBC
 */
const crypto = require("node:crypto");
const { subtle } = require("node:crypto").webcrypto;

// --- Node symmetric: algorithm + key size + mode packed in the string literal ---
function encryptGcm(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv); // AES-256-GCM
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
function legacyCbc(key, iv, data) {
  return crypto.createCipheriv("aes-128-cbc", key, iv); // AES-128-CBC (weak mode)
}
function tripleDes(key, iv) {
  return crypto.createCipheriv("des-ede3-cbc", key, iv); // 3DES (legacy)
}
function weakStream(key) {
  return crypto.createCipheriv("rc4", key, null); // RC4 (broken)
}

// --- Node hashing + MAC (function name binds the API, algorithm in the arg) ---
const legacyDigest = crypto.createHash("md5"); // MD5 (broken)
const digest = crypto.createHash("sha256"); // SHA-256
const mac = crypto.createHmac("sha512", key); // HMAC (+ SHA-512)

// --- Node asymmetric key generation (params in the options object) ---
crypto.generateKeyPair("rsa", { modulusLength: 2048 }, cb); // RSA-2048
crypto.generateKeyPair("ec", { namedCurve: "P-384" }, cb); // ECDSA / P-384
crypto.generateKeyPairSync("ed25519"); // Ed25519

// --- Node KDF ---
crypto.pbkdf2(password, salt, 100000, 64, "sha512", cb); // PBKDF2

// --- WebCrypto (crypto.subtle) — algorithm by the {name:...} field ---
async function webcryptoSuite(aesKey, ecKey) {
  await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data); // AES-GCM
  await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072 }, true, ["encrypt"]); // RSA-3072
  await subtle.sign({ name: "ECDSA", namedCurve: "P-256" }, ecKey, data); // ECDSA / P-256
  await subtle.digest("SHA-384", data); // SHA-384
}
