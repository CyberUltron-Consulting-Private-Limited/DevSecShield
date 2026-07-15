// Synthetic crypto-misuse target (C6), cross-language (Node.js).
// Weak RNG (Math.random) producing an IV that reaches an AES-CBC cipher —
// CWE-338. Proves the misuse lane is multi-language, not Python-only.
const crypto = require("crypto");

function weakEncrypt(key, data) {
  // Math.random() is a non-crypto PRNG — predictable IV material (CWE-338).
  const iv = Buffer.from(String(Math.random()).repeat(4).slice(0, 16));
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { weakEncrypt };
