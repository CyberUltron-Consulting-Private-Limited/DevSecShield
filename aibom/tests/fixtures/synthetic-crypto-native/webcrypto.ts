// Synthetic WebCrypto (SubtleCrypto) fixture (C3). The algorithm object's `name`
// field fixes the primitive; `namedCurve` / `modulusLength` / padding come from
// the same object. Kept separate from the Node fixture so the RSA-OAEP padding
// and ECDSA curve are attributable (a same-file bare `RSA` would collapse them).
async function webcrypto(subtle: SubtleCrypto): Promise<void> {
  await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]); // -> AES-GCM
  await subtle.encrypt({ name: "RSA-OAEP" }, pub, data); // -> RSA + OAEP padding
  await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k, msg); // -> ECDSA + SECP256R1
  await subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000 }, k, a, x, y); // -> PBKDF2
  await subtle.digest("SHA-512", buf); // -> SHA-512
}

const ecParams = { name: "ECDSA", namedCurve: "P-256" };
