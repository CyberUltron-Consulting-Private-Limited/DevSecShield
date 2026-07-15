// Synthetic Rust `ring` fixture for the C3 call-expression scanner. ring exposes
// algorithms as module-path constants, so the constant name fixes the algorithm,
// key size, curve, and AEAD mode.
use ring::{aead, digest, signature, hmac, pbkdf2};

fn ring_aead() {
    let gcm = &aead::AES_128_GCM;          // AES-128 + GCM
    let chacha = &aead::CHACHA20_POLY1305; // ChaCha20-Poly1305
}

fn ring_digest() {
    let strong = &digest::SHA256;                       // SHA-256
    let legacy = &digest::SHA1_FOR_LEGACY_USE_ONLY;     // SHA-1
}

fn ring_sig() {
    let ed = &signature::ED25519;                       // Ed25519
    let ec = &signature::ECDSA_P384_SHA384_ASN1_SIGNING; // ECDSA P-384
}

fn ring_mac() {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");  // HMAC
}

fn ring_kdf(out: &mut [u8]) {
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, pw, out);  // PBKDF2
}
