// Synthetic Rust crypto usage (C3 fixture): both *ring* (UPPER_SNAKE module
// constants) and *RustCrypto* (PascalCase types) — case distinguishes them.
use ring::{aead, agreement, digest, hmac, pbkdf2, signature};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use sha2::Sha256;
use md5::Md5;
use rsa::RsaPrivateKey;

fn ring_suite() {
    let alg = &aead::AES_256_GCM;                 // AES-256-GCM (ring)
    let chacha = &aead::CHACHA20_POLY1305;        // ChaCha20-Poly1305 (ring)
    let sha = digest::digest(&digest::SHA384, b"x"); // SHA-384 (ring)
    let key = signature::Ed25519KeyPair::generate(); // Ed25519 (ring)
    let ecdsa = &signature::ECDSA_P256_SHA256_ASN1;  // ECDSA / P-256 (ring)
    let x = &agreement::X25519;                    // X25519 (ring)
    let mac = hmac::Key::new(hmac::HMAC_SHA256, b"k"); // HMAC (ring)
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, pw, &mut out); // PBKDF2 (ring)
}

fn rustcrypto_suite() {
    let cipher = Aes256Gcm::new(key);             // AES-256-GCM (RustCrypto)
    let aead = ChaCha20Poly1305::new(key);        // ChaCha20-Poly1305 (RustCrypto)
    let mut hasher = Sha256::new();               // SHA-256 (RustCrypto)
    let legacy = Md5::new();                       // MD5 (RustCrypto, broken)
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap(); // RSA-2048 (RustCrypto)
}
