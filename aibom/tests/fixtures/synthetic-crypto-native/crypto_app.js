// Synthetic Node.js + WebCrypto fixture (C3). Every asset is resolvable only by
// the call argument / algorithm-object field, not a bare identifier — so a
// line-regex that ignored arguments would mis-parametrize these.
const crypto = require("node:crypto");

// Node crypto: the OpenSSL cipher spec string carries algo + key size + mode.
const gcm = crypto.createCipheriv("aes-256-gcm", key, iv); // -> AES-256-GCM
const legacy = crypto.createCipheriv("des-ede3-cbc", k2, iv2); // -> 3DES-CBC
const stream = crypto.createDecipheriv("rc4", k3); // -> RC4

const h = crypto.createHash("sha256"); // -> SHA-256
const mac = crypto.createHmac("sha256", secret); // -> HMAC
const signer = crypto.createSign("RSA-SHA256"); // -> RSA (signature)

// Key-pair generation: modulusLength / namedCurve bound from the options object.
crypto.generateKeyPair("rsa", { modulusLength: 3072 }, cb); // -> RSA-3072
crypto.generateKeyPairSync("ec", { namedCurve: "P-384" }); // -> ECDSA + SECP384R1
