// C3 fixture — Node.js `crypto` + WebCrypto usage (EMIT-only inventory target).
// The algorithm spellings here are the ones a flat token corpus misses: the
// `aes-256-gcm` cipher-spec string, `generateKeyPairSync` (the `Sync` suffix),
// `createHmac`, and the WebCrypto `{name:"AES-GCM"|"RSA-OAEP"|"ECDSA"}` fields.
import crypto from 'node:crypto';

// Node cipher: algorithm + key size + mode packed into one string literal.
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const legacy = crypto.createCipheriv('des-ede3-cbc', key3, iv);

// Node hash + hmac.
const digest = crypto.createHash('sha256').update(data).digest();
const mac = crypto.createHmac('sha256', secret).update(data).digest();

// RSA key pair with the modulus on the same line -> RSA-2048.
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// WebCrypto (crypto.subtle) — algorithm by the {name:"..."} field.
await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, message);
await crypto.subtle.sign({ name: 'ECDSA', namedCurve: 'P-384' }, privateKey, message);
const wcDigest = await crypto.subtle.digest('SHA-512', buffer);
